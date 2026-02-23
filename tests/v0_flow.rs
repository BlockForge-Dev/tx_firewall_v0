use axum::http::StatusCode;

use tx_firewall_v0::{
    domain::{Decision, EvaluateTxRequest},
    pipeline,
    safety::FailClosedMode,
    AppState,
};

fn state() -> AppState {
    AppState::new("latest-1".to_string(), None)
}

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

#[tokio::test]
async fn v0_happy_path_returns_warn_and_placeholders() {
    let resp = pipeline::evaluate_tx_v0(&state(), "test-request".to_string(), valid_req())
        .await
        .expect("expected Ok response");

    assert!(matches!(resp.decision, Decision::Warn));
    assert_eq!(resp.block_ref, "latest-1");

    assert_eq!(resp.receipt.intents.len(), 1);
    assert_eq!(
        resp.receipt.intents[0].signature,
        "approve(address,uint256)"
    );

    assert!(resp.receipt.chain.is_none()); // ✅ still v0 path

    assert!(resp.receipt.permissions_changed.is_empty());
    assert!(resp.receipt.transfers.is_empty());

    assert!(resp.receipt.call_path.is_empty());
    assert!(resp
        .receipt
        .rules_fired
        .iter()
        .any(|r| r["rule_id"] == "PARTIAL_ANALYSIS_FAIL_CLOSED"));

    assert_eq!(resp.receipt.uncertainties.len(), 1);
    assert_eq!(
        resp.receipt.uncertainties[0].code,
        "SIMULATION_NOT_IMPLEMENTED"
    );
}

#[tokio::test]
async fn v0_placeholder_respects_fail_closed_block_mode() {
    let mut st = state();
    st.fail_closed_mode = FailClosedMode::Block;

    let resp = pipeline::evaluate_tx_v0(&st, "block-mode".to_string(), valid_req())
        .await
        .expect("expected Ok response");

    assert!(matches!(resp.decision, Decision::Block));
    assert!(resp
        .receipt
        .rules_fired
        .iter()
        .any(|r| r["rule_id"] == "PARTIAL_ANALYSIS_FAIL_CLOSED"));
}

#[tokio::test]
async fn v0_same_input_same_evaluation_id() {
    let r1 = pipeline::evaluate_tx_v0(&state(), "r1".to_string(), valid_req())
        .await
        .unwrap();
    let r2 = pipeline::evaluate_tx_v0(&state(), "r2".to_string(), valid_req())
        .await
        .unwrap();

    assert_eq!(r1.evaluation_id, r2.evaluation_id);
}

#[tokio::test]
async fn v0_normalization_makes_id_stable_across_casing_and_value_zeros() {
    let mut req_a = valid_req();
    req_a.from = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    req_a.to = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string();
    req_a.data = req_a.data.to_uppercase();
    req_a.value = "0x0000".to_string();

    let mut req_b = valid_req();
    req_b.from = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    req_b.to = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    req_b.value = "0x0".to_string();

    let a = pipeline::evaluate_tx_v0(&state(), "a".to_string(), req_a)
        .await
        .unwrap();
    let b = pipeline::evaluate_tx_v0(&state(), "b".to_string(), req_b)
        .await
        .unwrap();

    assert_eq!(a.evaluation_id, b.evaluation_id);
}

#[tokio::test]
async fn v0_invalid_from_rejected() {
    let mut req = valid_req();
    req.from = "0x123".to_string();

    let err = pipeline::evaluate_tx_v0(&state(), "bad".to_string(), req)
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(err.message.contains("Invalid 'from'"));
}

#[tokio::test]
async fn v0_invalid_to_rejected() {
    let mut req = valid_req();
    req.to = "0x123".to_string();

    let err = pipeline::evaluate_tx_v0(&state(), "bad".to_string(), req)
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(err.message.contains("Invalid 'to'"));
}

#[tokio::test]
async fn v0_invalid_data_rejected() {
    let mut req = valid_req();
    req.data = "0xabc".to_string();

    let err = pipeline::evaluate_tx_v0(&state(), "bad".to_string(), req)
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(err.message.contains("Invalid 'data'"));
}

#[tokio::test]
async fn v0_invalid_value_rejected() {
    let mut req = valid_req();
    req.value = "123".to_string();

    let err = pipeline::evaluate_tx_v0(&state(), "bad".to_string(), req)
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(err.message.contains("Invalid 'value'"));
}
