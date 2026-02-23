use axum::{routing::post, Json, Router};
use serde_json::{json, Value};
use tokio::{net::TcpListener, time::Duration};

use tx_firewall_v0::{
    chain::{ChainClient, SimulationBudgets},
    domain::{Decision, EvaluateTxRequest},
    pipeline,
    safety::FailClosedMode,
    AppState,
};

#[derive(Clone, Copy)]
enum MockMode {
    DepthExceeded,
    SizeExceeded,
    SlowTrace,
}

fn req_transfer(amount_hex: &str) -> EvaluateTxRequest {
    let to = "3333333333333333333333333333333333333333";
    let mut amt = amount_hex.trim().to_string();
    amt = amt.strip_prefix("0x").unwrap_or(&amt).to_string();
    let amt_padded = format!("{:0>64}", amt);

    let data = format!("0xa9059cbb000000000000000000000000{}{}", to, amt_padded);

    EvaluateTxRequest {
        chain_id: 1,
        from: "0x1111111111111111111111111111111111111111".to_string(),
        to: "0x2222222222222222222222222222222222222222".to_string(),
        data,
        value: "0x0".to_string(),
        block_number: None,
    }
}

async fn rpc_handler(mode: MockMode, Json(req): Json<Value>) -> Json<Value> {
    let method = req["method"].as_str().unwrap_or("");
    let id = req["id"].clone();

    let resp = match method {
        "eth_blockNumber" => json!({"jsonrpc":"2.0","id":id,"result":"0x10"}),
        "eth_getCode" => json!({"jsonrpc":"2.0","id":id,"result":"0x6001600055"}),
        "eth_call" => json!({"jsonrpc":"2.0","id":id,"result":"0x01"}),
        "debug_traceCall" => match mode {
            MockMode::DepthExceeded => json!({
                "jsonrpc":"2.0",
                "id":id,
                "result": {
                    "call_type":"CALL",
                    "from":"0x1111111111111111111111111111111111111111",
                    "to":"0x2222222222222222222222222222222222222222",
                    "value":"0x0",
                    "input":"0x",
                    "calls":[
                        {
                            "call_type":"CALL",
                            "from":"0x2222222222222222222222222222222222222222",
                            "to":"0x3333333333333333333333333333333333333333",
                            "value":"0x0",
                            "input":"0x",
                            "calls":[
                                {
                                    "call_type":"CALL",
                                    "from":"0x3333333333333333333333333333333333333333",
                                    "to":"0x4444444444444444444444444444444444444444",
                                    "value":"0x0",
                                    "input":"0x",
                                    "calls":[]
                                }
                            ]
                        }
                    ],
                    "logs":[]
                }
            }),
            MockMode::SizeExceeded => {
                let huge_input = format!("0x{}", "aa".repeat(8192));
                json!({
                    "jsonrpc":"2.0",
                    "id":id,
                    "result": {
                        "call_type":"CALL",
                        "from":"0x1111111111111111111111111111111111111111",
                        "to":"0x2222222222222222222222222222222222222222",
                        "value":"0x0",
                        "input": huge_input,
                        "calls":[],
                        "logs":[]
                    }
                })
            }
            MockMode::SlowTrace => {
                tokio::time::sleep(Duration::from_millis(40)).await;
                json!({
                    "jsonrpc":"2.0",
                    "id":id,
                    "result": {
                        "call_type":"CALL",
                        "from":"0x1111111111111111111111111111111111111111",
                        "to":"0x2222222222222222222222222222222222222222",
                        "value":"0x0",
                        "input":"0x",
                        "calls":[],
                        "logs":[]
                    }
                })
            }
        },
        _ => json!({"jsonrpc":"2.0","id":id,"error":{"code":-1,"message":"unknown method"}}),
    };

    Json(resp)
}

async fn start_mock_rpc(mode: MockMode) -> (String, tokio::sync::oneshot::Sender<()>) {
    let app = Router::new().route(
        "/",
        post(move |payload| {
            let captured = mode;
            async move { rpc_handler(captured, payload).await }
        }),
    );
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
async fn fail_closed_block_on_depth_budget_exceeded() {
    let (rpc_url, shutdown) = start_mock_rpc(MockMode::DepthExceeded).await;

    let budgets = SimulationBudgets {
        eth_call_timeout_ms: 5000,
        trace_timeout_ms: 5000,
        max_trace_depth: 1,
        max_trace_size_bytes: 2 * 1024 * 1024,
    };

    let chain = ChainClient::new(rpc_url, 1).with_budgets(budgets);
    let mut state = AppState::new("latest-1".to_string(), Some(chain));
    state.fail_closed_mode = FailClosedMode::Block;

    let resp = pipeline::evaluate_tx_v0(&state, "safety-depth".to_string(), req_transfer("0x0a"))
        .await
        .unwrap();

    assert_eq!(resp.decision, Decision::Block);
    assert!(resp
        .receipt
        .uncertainties
        .iter()
        .any(|u| u.code == "TRACE_MAX_DEPTH_EXCEEDED"));
    assert!(resp
        .receipt
        .rules_fired
        .iter()
        .any(|r| r["rule_id"] == "PARTIAL_ANALYSIS_FAIL_CLOSED"));

    let _ = shutdown.send(());
}

#[tokio::test]
async fn marks_trace_size_budget_exceeded() {
    let (rpc_url, shutdown) = start_mock_rpc(MockMode::SizeExceeded).await;

    let budgets = SimulationBudgets {
        eth_call_timeout_ms: 5000,
        trace_timeout_ms: 5000,
        max_trace_depth: 64,
        max_trace_size_bytes: 256,
    };

    let chain = ChainClient::new(rpc_url, 1).with_budgets(budgets);
    let mut state = AppState::new("latest-1".to_string(), Some(chain));
    state.fail_closed_mode = FailClosedMode::Warn;

    let resp = pipeline::evaluate_tx_v0(&state, "safety-size".to_string(), req_transfer("0x0a"))
        .await
        .unwrap();

    assert!(resp
        .receipt
        .uncertainties
        .iter()
        .any(|u| u.code == "TRACE_MAX_SIZE_EXCEEDED"));
    assert!(resp
        .receipt
        .rules_fired
        .iter()
        .any(|r| r["rule_id"] == "PARTIAL_ANALYSIS_FAIL_CLOSED"));

    let _ = shutdown.send(());
}

#[tokio::test]
async fn marks_trace_timeout_budget_and_fail_closed() {
    let (rpc_url, shutdown) = start_mock_rpc(MockMode::SlowTrace).await;

    let budgets = SimulationBudgets {
        eth_call_timeout_ms: 5000,
        trace_timeout_ms: 1,
        max_trace_depth: 64,
        max_trace_size_bytes: 2 * 1024 * 1024,
    };

    let chain = ChainClient::new(rpc_url, 1).with_budgets(budgets);
    let mut state = AppState::new("latest-1".to_string(), Some(chain));
    state.fail_closed_mode = FailClosedMode::Warn;

    let resp = pipeline::evaluate_tx_v0(&state, "safety-timeout".to_string(), req_transfer("0x0a"))
        .await
        .unwrap();

    assert!(resp
        .receipt
        .uncertainties
        .iter()
        .any(|u| u.code == "TRACE_TIMEOUT"));
    assert!(resp
        .receipt
        .rules_fired
        .iter()
        .any(|r| r["rule_id"] == "PARTIAL_ANALYSIS_FAIL_CLOSED"));

    let _ = shutdown.send(());
}
