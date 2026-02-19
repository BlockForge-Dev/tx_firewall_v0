use axum::{routing::post, Json, Router};
use serde_json::{json, Value};
use tokio::net::TcpListener;

use tx_firewall_v0::{chain::ChainClient, domain::EvaluateTxRequest, pipeline, AppState};

fn valid_req() -> EvaluateTxRequest {
    EvaluateTxRequest {
        chain_id: 1,
        from: "0x1111111111111111111111111111111111111111".to_string(),
        to: "0x2222222222222222222222222222222222222222".to_string(),
        data: "0x095ea7b30000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000ffffffffffffffff".to_string(),
        value: "0x0".to_string(),
        block_number: None,
    }
}

async fn rpc_handler(Json(req): Json<Value>) -> Json<Value> {
    let method = req["method"].as_str().unwrap();
    let id = req["id"].clone();

    let resp = match method {
        "eth_blockNumber" => json!({"jsonrpc":"2.0","id":id,"result":"0x10"}), // 16 => pinned=15
        "eth_getCode" => json!({"jsonrpc":"2.0","id":id,"result":"0x"}),       // ✅ no code
        "eth_call" => json!({"jsonrpc":"2.0","id":id,"result":"0x"}),
        _ => json!({"jsonrpc":"2.0","id":id,"error":{"code":-1,"message":"unknown method"}}),
    };

    Json(resp)
}

async fn start_mock_rpc() -> (String, tokio::sync::oneshot::Sender<()>) {
    let app = Router::new().route("/", post(rpc_handler));
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

#[tokio::test]
async fn adds_eth_call_no_effect_when_to_is_not_contract_and_result_empty() {
    let (rpc_url, shutdown) = start_mock_rpc().await;

    let state = AppState {
        default_block_ref: "latest-1".to_string(),
        chain: Some(ChainClient::new(rpc_url, 1)),
    };

    let resp = pipeline::evaluate_tx_v0(&state, "no-effect".to_string(), valid_req())
        .await
        .unwrap();

    // Should be pinned
    assert_eq!(resp.block_ref, "block:15");

    // Should fire both rules, in this order
    assert_eq!(resp.receipt.rules_fired.len(), 2);
    assert_eq!(resp.receipt.rules_fired[0]["rule_id"], "TO_NOT_A_CONTRACT");
    assert_eq!(resp.receipt.rules_fired[1]["rule_id"], "ETH_CALL_NO_EFFECT");

    let _ = shutdown.send(());
}
