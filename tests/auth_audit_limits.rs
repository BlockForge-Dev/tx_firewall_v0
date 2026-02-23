use axum::Router;
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::net::TcpListener;

use tx_firewall_v0::{api, audit::AuditLogger, auth::ApiAuth, AppState};

async fn start_server(state: AppState) -> (String, tokio::sync::oneshot::Sender<()>) {
    let app: Router = api::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });

    (url, tx)
}

fn evaluate_body() -> Value {
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
async fn api_key_auth_enforced_when_required() {
    let mut state = AppState::new("latest-1".to_string(), None);
    state.auth = ApiAuth::from_pairs(
        true,
        vec![("tenant-a".to_string(), "secret-key-1".to_string())],
    );

    let (base_url, shutdown) = start_server(state).await;
    let client = reqwest::Client::new();
    let url = format!("{}/v1/evaluate/tx", base_url);

    let missing = client
        .post(&url)
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    let invalid = client
        .post(&url)
        .header("x-api-key", "wrong-key")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    let valid = client
        .post(&url)
        .header("x-api-key", "secret-key-1")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();

    assert_eq!(missing.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(invalid.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(valid.status(), reqwest::StatusCode::OK);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn request_body_limit_blocks_oversized_payload() {
    let mut state = AppState::new("latest-1".to_string(), None);
    state.max_request_body_bytes = 128;

    let (base_url, shutdown) = start_server(state).await;
    let client = reqwest::Client::new();
    let url = format!("{}/v1/evaluate/tx", base_url);

    let large = format!(
        "{{\"chain_id\":1,\"from\":\"{}\",\"to\":\"{}\",\"data\":\"0x{}\",\"value\":\"0x0\"}}",
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "aa".repeat(1024)
    );

    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .body(large)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 413);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn audit_logger_writes_evaluation_record() {
    let mut state = AppState::new("latest-1".to_string(), None);
    state.auth = ApiAuth::from_pairs(
        true,
        vec![("tenant-a".to_string(), "secret-key-1".to_string())],
    );
    let path: PathBuf =
        std::env::temp_dir().join(format!("tx_firewall_audit_{}.jsonl", uuid::Uuid::new_v4()));
    state.audit = AuditLogger::new(Some(path.clone()));

    let (base_url, shutdown) = start_server(state).await;
    let client = reqwest::Client::new();
    let url = format!("{}/v1/evaluate/tx", base_url);

    let resp = client
        .post(&url)
        .header("x-api-key", "secret-key-1")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let raw = std::fs::read_to_string(&path).expect("audit log should exist");
    let first_line = raw.lines().next().expect("audit log should have one line");
    let v: Value = serde_json::from_str(first_line).expect("valid json line");

    assert_eq!(v["kind"], "EVALUATE_TX");
    assert_eq!(v["tenant_id"], "tenant-a");
    assert_eq!(v["outcome"], "ok");
    assert!(v.get("evaluation_id").is_some());

    let _ = shutdown.send(());
    let _ = std::fs::remove_file(path);
}
