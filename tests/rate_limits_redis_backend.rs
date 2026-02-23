use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use serde_json::json;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

use tx_firewall_v0::{
    api,
    safety::{RateLimitConfig, RateLimiter, RedisRateLimitConfig, TenantQuotaStore},
    AppState,
};

async fn start_api_server(state: AppState) -> (String, tokio::sync::oneshot::Sender<()>) {
    let app = api::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });

    (url, tx)
}

fn evaluate_body() -> serde_json::Value {
    json!({
        "chain_id": 1,
        "from": "0x1111111111111111111111111111111111111111",
        "to": "0x2222222222222222222222222222222222222222",
        "data": "0x095ea7b30000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000ffffffffffffffff",
        "value": "0x0",
        "block_number": null
    })
}

async fn start_mock_redis() -> (String, tokio::sync::oneshot::Sender<()>) {
    let counters = Arc::new(Mutex::new(HashMap::<String, i64>::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("{}", addr);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let counters_outer = counters.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        break;
                    };
                    let counters = counters_outer.clone();
                    tokio::spawn(async move {
                        let _ = handle_mock_redis_client(stream, counters).await;
                    });
                }
            }
        }
    });

    (url, shutdown_tx)
}

async fn handle_mock_redis_client(
    stream: TcpStream,
    counters: Arc<Mutex<HashMap<String, i64>>>,
) -> Result<(), String> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    loop {
        let Some(cmd) = read_resp_array(&mut reader).await? else {
            return Ok(());
        };
        if cmd.is_empty() {
            return Ok(());
        }

        let name = cmd[0].to_ascii_uppercase();
        match name.as_str() {
            "AUTH" | "SELECT" => {
                write_half
                    .write_all(b"+OK\r\n")
                    .await
                    .map_err(|e| e.to_string())?;
            }
            "INCR" => {
                if cmd.len() < 2 {
                    write_half
                        .write_all(b"-ERR missing key\r\n")
                        .await
                        .map_err(|e| e.to_string())?;
                    continue;
                }
                let key = cmd[1].clone();
                let mut guard = counters.lock().await;
                let next = guard.get(&key).copied().unwrap_or(0).saturating_add(1);
                guard.insert(key, next);
                write_half
                    .write_all(format!(":{}\r\n", next).as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            "EXPIRE" => {
                write_half
                    .write_all(b":1\r\n")
                    .await
                    .map_err(|e| e.to_string())?;
            }
            _ => {
                write_half
                    .write_all(b"-ERR unknown command\r\n")
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
    }
}

async fn read_resp_array<R>(reader: &mut R) -> Result<Option<Vec<String>>, String>
where
    R: AsyncBufRead + AsyncRead + Unpin,
{
    let Some(line) = read_crlf_line(reader).await? else {
        return Ok(None);
    };
    if !line.starts_with('*') {
        return Err("expected RESP array header".to_string());
    }

    let count = line[1..]
        .parse::<usize>()
        .map_err(|_| format!("invalid RESP array count: {}", line))?;
    let mut parts = Vec::with_capacity(count);

    for _ in 0..count {
        let Some(len_line) = read_crlf_line(reader).await? else {
            return Err("unexpected EOF while reading bulk length".to_string());
        };
        if !len_line.starts_with('$') {
            return Err("expected RESP bulk length".to_string());
        }
        let len = len_line[1..]
            .parse::<usize>()
            .map_err(|_| format!("invalid RESP bulk length: {}", len_line))?;

        let mut raw = vec![0u8; len + 2];
        reader
            .read_exact(&mut raw)
            .await
            .map_err(|e| e.to_string())?;
        if raw[raw.len() - 2..] != *b"\r\n" {
            return Err("invalid RESP bulk terminator".to_string());
        }
        raw.truncate(raw.len() - 2);
        parts.push(String::from_utf8(raw).map_err(|_| "non-utf8 bulk string".to_string())?);
    }

    Ok(Some(parts))
}

async fn read_crlf_line<R>(reader: &mut R) -> Result<Option<String>, String>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    let read = reader
        .read_until(b'\n', &mut line)
        .await
        .map_err(|e| e.to_string())?;
    if read == 0 {
        return Ok(None);
    }
    if line.len() < 2 || line[line.len() - 2..] != *b"\r\n" {
        return Err("invalid line terminator".to_string());
    }
    line.truncate(line.len() - 2);
    let s = String::from_utf8(line).map_err(|_| "non-utf8 line".to_string())?;
    Ok(Some(s))
}

#[tokio::test]
async fn redis_backend_shares_limits_across_instances() {
    let (redis_addr, redis_shutdown) = start_mock_redis().await;

    let cfg = RateLimitConfig {
        requests_per_window: 1,
        window_secs: 60,
        max_clients: 1_000,
    };
    let redis_cfg = RedisRateLimitConfig {
        addr: redis_addr,
        key_prefix: "test:rl:".to_string(),
        connect_timeout_ms: 50,
        command_timeout_ms: 50,
        password: None,
        db: 0,
        fallback_to_in_memory: true,
    };

    let mut state_a = AppState::new("latest-1".to_string(), None);
    state_a.rate_limiter = RateLimiter::new_with_redis(cfg, redis_cfg.clone());
    state_a.tenant_quotas = TenantQuotaStore::new(cfg);

    let mut state_b = AppState::new("latest-1".to_string(), None);
    state_b.rate_limiter = RateLimiter::new_with_redis(cfg, redis_cfg);
    state_b.tenant_quotas = TenantQuotaStore::new(cfg);

    let (url_a, shutdown_a) = start_api_server(state_a).await;
    let (url_b, shutdown_b) = start_api_server(state_b).await;

    let client = reqwest::Client::new();
    let r1 = client
        .post(format!("{}/v1/evaluate/tx", url_a))
        .header("x-forwarded-for", "198.51.100.42")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    let r2 = client
        .post(format!("{}/v1/evaluate/tx", url_b))
        .header("x-forwarded-for", "198.51.100.42")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();

    assert_eq!(r1.status(), reqwest::StatusCode::OK);
    assert_eq!(r2.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    let _ = shutdown_a.send(());
    let _ = shutdown_b.send(());
    let _ = redis_shutdown.send(());
}

#[tokio::test]
async fn redis_backend_falls_back_to_memory_when_unreachable() {
    let cfg = RateLimitConfig {
        requests_per_window: 2,
        window_secs: 60,
        max_clients: 1_000,
    };

    let unreachable_addr = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        addr
    };

    let redis_cfg = RedisRateLimitConfig {
        addr: unreachable_addr,
        key_prefix: "test:rl:".to_string(),
        connect_timeout_ms: 30,
        command_timeout_ms: 30,
        password: None,
        db: 0,
        fallback_to_in_memory: true,
    };

    let mut state = AppState::new("latest-1".to_string(), None);
    state.rate_limiter = RateLimiter::new_with_redis(cfg, redis_cfg);
    state.tenant_quotas = TenantQuotaStore::new(cfg);

    let (base_url, shutdown) = start_api_server(state).await;
    let client = reqwest::Client::new();
    let url = format!("{}/v1/evaluate/tx", base_url);

    let r1 = client
        .post(&url)
        .header("x-forwarded-for", "198.51.100.200")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    let r2 = client
        .post(&url)
        .header("x-forwarded-for", "198.51.100.200")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    let r3 = client
        .post(&url)
        .header("x-forwarded-for", "198.51.100.200")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();

    assert_eq!(r1.status(), reqwest::StatusCode::OK);
    assert_eq!(r2.status(), reqwest::StatusCode::OK);
    assert_eq!(r3.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    let _ = shutdown.send(());
}
