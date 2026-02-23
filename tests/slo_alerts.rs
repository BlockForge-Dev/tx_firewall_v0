use std::net::SocketAddr;

use serde_json::json;
use tokio::net::TcpListener;

use tx_firewall_v0::{
    api, management::ControlPlane, observability::SloConfig, safety::RateLimitConfig, AppState,
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

fn valid_body() -> serde_json::Value {
    json!({
        "chain_id": 1,
        "from": "0x1111111111111111111111111111111111111111",
        "to": "0x2222222222222222222222222222222222222222",
        "data": "0x095ea7b30000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000ffffffffffffffff",
        "value": "0x0",
        "block_number": null
    })
}

fn invalid_body() -> serde_json::Value {
    json!({
        "chain_id": 1,
        "from": "0x123",
        "to": "0x2222222222222222222222222222222222222222",
        "data": "0x095ea7b3",
        "value": "0x0",
        "block_number": null
    })
}

#[tokio::test]
async fn slo_endpoint_alerts_when_error_rate_breaches_threshold() {
    let mut state = AppState::new("latest-1".to_string(), None);
    state.slo_config = SloConfig {
        window_secs: 300,
        min_samples: 2,
        max_p95_latency_ms: 10_000.0,
        max_error_rate: 0.20,
        max_simulation_failure_rate: 1.0,
    };

    let (base_url, shutdown) = start_server(state).await;
    let client = reqwest::Client::new();
    let eval_url = format!("{}/v1/evaluate/tx", base_url);
    let slo_url = format!("{}/v1/ops/slo", base_url);

    let ok = client
        .post(&eval_url)
        .json(&valid_body())
        .send()
        .await
        .unwrap();
    let err = client
        .post(&eval_url)
        .json(&invalid_body())
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    assert_eq!(err.status(), reqwest::StatusCode::BAD_REQUEST);

    let slo = client.get(&slo_url).send().await.unwrap();
    assert_eq!(slo.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = slo.json().await.unwrap();
    assert_eq!(body["status"], "ALERT");
    let alerts = body["alerts"].as_array().cloned().unwrap_or_default();
    assert!(
        alerts
            .iter()
            .filter_map(|v| v.as_str())
            .any(|s| s.starts_with("error_rate>")),
        "expected error_rate alert, got={body}"
    );

    let _ = shutdown.send(());
}

#[tokio::test]
async fn slo_endpoint_requires_admin_token_when_control_plane_enabled() {
    let mut state = AppState::new("latest-1".to_string(), None);
    state.slo_config = SloConfig {
        window_secs: 60,
        min_samples: 0,
        max_p95_latency_ms: 10_000.0,
        max_error_rate: 1.0,
        max_simulation_failure_rate: 1.0,
    };
    state.control_plane = ControlPlane::new_enabled(
        "admin-slo-token".to_string(),
        None,
        RateLimitConfig::default(),
    );

    let (base_url, shutdown) = start_server(state).await;
    let client = reqwest::Client::new();
    let slo_url = format!("{}/v1/ops/slo", base_url);

    let unauthorized = client.get(&slo_url).send().await.unwrap();
    let authorized = client
        .get(&slo_url)
        .header("x-admin-token", "admin-slo-token")
        .send()
        .await
        .unwrap();

    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(authorized.status(), reqwest::StatusCode::OK);

    let _ = shutdown.send(());
}
