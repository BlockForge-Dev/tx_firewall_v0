use std::net::SocketAddr;

use serde_json::json;
use tokio::net::TcpListener;

use tx_firewall_v0::{
    api, auth::ApiAuth, safety::FailClosedMode, safety::RateLimitConfig, safety::RateLimiter,
    AppState,
};

async fn start_server(state: AppState) -> (String, tokio::sync::oneshot::Sender<()>) {
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

#[tokio::test]
async fn applies_per_client_rate_limit() {
    let mut state = AppState::new("latest-1".to_string(), None);
    state.fail_closed_mode = FailClosedMode::Warn;
    let cfg = RateLimitConfig {
        requests_per_window: 2,
        window_secs: 60,
        max_clients: 128,
    };
    state.rate_limiter = RateLimiter::new(cfg);
    state.tenant_quotas = tx_firewall_v0::safety::TenantQuotaStore::new(cfg);

    let (base_url, shutdown) = start_server(state).await;
    let client = reqwest::Client::new();
    let url = format!("{}/v1/evaluate/tx", base_url);

    let r1 = client
        .post(&url)
        .header("x-forwarded-for", "198.51.100.10")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    let r2 = client
        .post(&url)
        .header("x-forwarded-for", "198.51.100.10")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    let r3 = client
        .post(&url)
        .header("x-forwarded-for", "198.51.100.10")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();

    assert_eq!(r1.status(), reqwest::StatusCode::OK);
    assert_eq!(r2.status(), reqwest::StatusCode::OK);
    assert_eq!(r3.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn keeps_separate_buckets_per_client() {
    let mut state = AppState::new("latest-1".to_string(), None);
    let cfg = RateLimitConfig {
        requests_per_window: 1,
        window_secs: 60,
        max_clients: 128,
    };
    state.rate_limiter = RateLimiter::new(cfg);
    state.tenant_quotas = tx_firewall_v0::safety::TenantQuotaStore::new(cfg);

    let (base_url, shutdown) = start_server(state).await;
    let client = reqwest::Client::new();
    let url = format!("{}/v1/evaluate/tx", base_url);

    let a1 = client
        .post(&url)
        .header("x-forwarded-for", "203.0.113.1")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    let b1 = client
        .post(&url)
        .header("x-forwarded-for", "203.0.113.2")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    let a2 = client
        .post(&url)
        .header("x-forwarded-for", "203.0.113.1")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();

    assert_eq!(a1.status(), reqwest::StatusCode::OK);
    assert_eq!(b1.status(), reqwest::StatusCode::OK);
    assert_eq!(a2.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn applies_per_tenant_quota_overrides() {
    let mut state = AppState::new("latest-1".to_string(), None);
    state.auth = ApiAuth::from_pairs(
        true,
        vec![
            ("tenant-a".to_string(), "key-a".to_string()),
            ("tenant-b".to_string(), "key-b".to_string()),
        ],
    );
    let default_cfg = RateLimitConfig {
        requests_per_window: 100,
        window_secs: 60,
        max_clients: 128,
    };
    state.rate_limiter = RateLimiter::new(default_cfg);
    state.tenant_quotas = tx_firewall_v0::safety::TenantQuotaStore::new(default_cfg);
    state
        .tenant_quotas
        .set_quota(
            "tenant-a",
            RateLimitConfig {
                requests_per_window: 1,
                window_secs: 60,
                max_clients: 128,
            },
        )
        .await;
    state
        .tenant_quotas
        .set_quota(
            "tenant-b",
            RateLimitConfig {
                requests_per_window: 3,
                window_secs: 60,
                max_clients: 128,
            },
        )
        .await;

    let (base_url, shutdown) = start_server(state).await;
    let client = reqwest::Client::new();
    let url = format!("{}/v1/evaluate/tx", base_url);

    let a1 = client
        .post(&url)
        .header("x-forwarded-for", "198.51.100.100")
        .header("x-api-key", "key-a")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    let a2 = client
        .post(&url)
        .header("x-forwarded-for", "198.51.100.100")
        .header("x-api-key", "key-a")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();

    let b1 = client
        .post(&url)
        .header("x-forwarded-for", "198.51.100.100")
        .header("x-api-key", "key-b")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    let b2 = client
        .post(&url)
        .header("x-forwarded-for", "198.51.100.100")
        .header("x-api-key", "key-b")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();

    assert_eq!(a1.status(), reqwest::StatusCode::OK);
    assert_eq!(a2.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b1.status(), reqwest::StatusCode::OK);
    assert_eq!(b2.status(), reqwest::StatusCode::OK);

    let _ = shutdown.send(());
}
