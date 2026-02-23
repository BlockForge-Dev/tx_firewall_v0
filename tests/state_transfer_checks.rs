use axum::{routing::post, Json, Router};
use serde_json::{json, Value};
use tokio::net::TcpListener;

use tx_firewall_v0::{chain::ChainClient, domain::EvaluateTxRequest, pipeline, AppState};

#[derive(Clone, Copy)]
enum MockMode {
    OwnerOfWorks,
    OwnerOfDecodeFails,
}

fn req_transfer(amount_hex: &str) -> EvaluateTxRequest {
    // transfer(address,uint256) selector: a9059cbb
    // to = 0x3333.., amount = amount_hex
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

fn encode_u256_32(value_hex: &str) -> String {
    let mut s = value_hex.trim().to_string();
    s = s.strip_prefix("0x").unwrap_or(&s).to_string();
    let padded = format!("{:0>64}", s);
    format!("0x{padded}")
}

fn encode_addr_32(addr: &str) -> String {
    let a = addr.trim().strip_prefix("0x").unwrap_or(addr);
    format!("0x{:0>64}", a)
}

async fn rpc_handler(mode: MockMode, Json(req): Json<Value>) -> Json<Value> {
    let method = req["method"].as_str().unwrap_or("");
    let id = req["id"].clone();

    let resp = match method {
        "eth_blockNumber" => json!({"jsonrpc":"2.0","id":id,"result":"0x10"}), // 16 => pinned=15
        "eth_getCode" => json!({"jsonrpc":"2.0","id":id,"result":"0x6001600055"}), // non-empty code
        "eth_call" => {
            let data = req["params"][0]["data"].as_str().unwrap_or("");

            if data.starts_with("0xa9059cbb") {
                // top-level transfer simulation call
                json!({"jsonrpc":"2.0","id":id,"result":"0x01"})
            } else if data.starts_with("0x6352211e") {
                // ownerOf(uint256)
                match mode {
                    MockMode::OwnerOfWorks => json!({
                        "jsonrpc":"2.0",
                        "id":id,
                        "result": encode_addr_32("0x1111111111111111111111111111111111111111")
                    }),
                    // force fallback to balanceOf by making decode_address_return fail
                    MockMode::OwnerOfDecodeFails => json!({"jsonrpc":"2.0","id":id,"result":"0x"}),
                }
            } else if data.starts_with("0x70a08231") {
                // balanceOf(address): return 5
                json!({"jsonrpc":"2.0","id":id,"result": encode_u256_32("0x05")})
            } else {
                json!({"jsonrpc":"2.0","id":id,"result":"0x"})
            }
        }
        // force trace unsupported path so inferred transfer is used
        "debug_traceCall" => {
            json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"not supported"}})
        }
        _ => json!({"jsonrpc":"2.0","id":id,"error":{"code":-1,"message":"unknown method"}}),
    };

    Json(resp)
}

async fn start_mock_rpc(mode: MockMode) -> (String, tokio::sync::oneshot::Sender<()>) {
    let app = Router::new().route(
        "/",
        post(move |payload| {
            let mode_captured = mode;
            async move { rpc_handler(mode_captured, payload).await }
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
async fn adds_erc721_owner_before_rule_when_owner_of_works() {
    let (rpc_url, shutdown) = start_mock_rpc(MockMode::OwnerOfWorks).await;

    let state = AppState::new("latest-1".to_string(), Some(ChainClient::new(rpc_url, 1)));

    let resp = pipeline::evaluate_tx_v0(&state, "m11-ownerof".to_string(), req_transfer("0x0a"))
        .await
        .unwrap();

    let has_owner_before = resp
        .receipt
        .rules_fired
        .iter()
        .any(|r| r.get("rule_id").and_then(|v| v.as_str()) == Some("ERC721_OWNER_BEFORE"));

    assert!(
        has_owner_before,
        "ERC721_OWNER_BEFORE missing. got={:?}",
        resp.receipt.rules_fired
    );

    let _ = shutdown.send(());
}

#[tokio::test]
async fn adds_erc20_insufficient_balance_when_owner_of_fails_decode() {
    let (rpc_url, shutdown) = start_mock_rpc(MockMode::OwnerOfDecodeFails).await;

    let state = AppState::new("latest-1".to_string(), Some(ChainClient::new(rpc_url, 1)));

    let resp = pipeline::evaluate_tx_v0(&state, "m11-balance".to_string(), req_transfer("0x0a"))
        .await
        .unwrap();

    let has_balance_before = resp
        .receipt
        .rules_fired
        .iter()
        .any(|r| r.get("rule_id").and_then(|v| v.as_str()) == Some("ERC20_BALANCE_BEFORE"));
    let has_insufficient =
        resp.receipt.rules_fired.iter().any(|r| {
            r.get("rule_id").and_then(|v| v.as_str()) == Some("ERC20_INSUFFICIENT_BALANCE")
        });

    assert!(
        has_balance_before,
        "ERC20_BALANCE_BEFORE missing. got={:?}",
        resp.receipt.rules_fired
    );
    assert!(
        has_insufficient,
        "ERC20_INSUFFICIENT_BALANCE missing. got={:?}",
        resp.receipt.rules_fired
    );

    let _ = shutdown.send(());
}
