use std::net::SocketAddr;

use serde_json::json;
use tokio::net::TcpListener;

use tx_firewall_v0::{api, AppState};

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
async fn metrics_endpoint_exposes_latency_and_counters() {
    let state = AppState::new("latest-1".to_string(), None);
    let (base_url, shutdown) = start_server(state).await;
    let client = reqwest::Client::new();

    let eval_url = format!("{}/v1/evaluate/tx", base_url);
    let metrics_url = format!("{}/metrics", base_url);
    let slo_url = format!("{}/v1/ops/slo", base_url);

    let r1 = client
        .post(&eval_url)
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    let r2 = client
        .post(&eval_url)
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();

    assert!(r1.status().is_success());
    assert!(r2.status().is_success());

    let metrics_text = client
        .get(&metrics_url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(
        metrics_text.contains("tx_firewall_evaluate_latency_ms_bucket"),
        "missing evaluate latency histogram: {metrics_text}"
    );
    assert!(
        metrics_text.contains("tx_firewall_stage_latency_ms_bucket"),
        "missing stage latency histogram: {metrics_text}"
    );
    assert!(
        metrics_text.contains("stage=\"validate\""),
        "missing validate stage metric: {metrics_text}"
    );
    assert!(
        metrics_text
            .contains("tx_firewall_rule_hits_total{rule_id=\"PARTIAL_ANALYSIS_FAIL_CLOSED\"}"),
        "missing rule hit counter: {metrics_text}"
    );
    assert!(
        metrics_text
            .contains("tx_firewall_simulation_failures_total{kind=\"SIMULATION_NOT_IMPLEMENTED\"}"),
        "missing simulation failure counter: {metrics_text}"
    );
    assert!(
        metrics_text.contains("tx_firewall_slo_status"),
        "missing slo status metric: {metrics_text}"
    );
    assert!(
        metrics_text.contains("tx_firewall_slo_alert"),
        "missing slo alert metric: {metrics_text}"
    );

    let slo = client.get(&slo_url).send().await.unwrap();
    assert_eq!(slo.status(), reqwest::StatusCode::OK);
    let slo_json: serde_json::Value = slo.json().await.unwrap();
    assert_eq!(
        slo_json["status"].as_str(),
        Some("INSUFFICIENT_DATA"),
        "unexpected slo payload: {slo_json}"
    );

    let _ = shutdown.send(());
}
