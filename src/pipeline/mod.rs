use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use tracing::{field, info_span};

use crate::{
    decode,
    domain::{
        Decision, DecodedIntent, EvaluateTxRequest, EvaluateTxResponse, Receipt, Uncertainty,
    },
    util, AppState,
};

#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub message: String,
}

impl AppError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    pub fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: message.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let body = serde_json::json!({ "error": self.message });
        (self.status, Json(body)).into_response()
    }
}

pub async fn evaluate_tx_v0(
    state: &AppState,
    request_id: String,
    req: EvaluateTxRequest,
) -> Result<EvaluateTxResponse, AppError> {
    let span = info_span!(
        "tx_firewall.evaluate_tx_v0",
        request_id = %request_id,
        chain_id = req.chain_id,
        from = %req.from,
        to = %req.to,
        evaluation_id = field::Empty
    );
    let _guard = span.enter();

    tracing::info!("stage=validate.start");
    validate(&req)?;
    tracing::info!("stage=validate.ok");

    let requested_block = req.block_number;

    tracing::info!("stage=normalize.start");
    let normalized = normalize(&req);
    tracing::info!("stage=normalize.ok");

    tracing::info!("stage=decode.start");
    let intent: DecodedIntent = decode::decode_calldata(&normalized.to, &normalized.data);
    tracing::info!(decoded_signature = %intent.signature, "stage=decode.ok");

    tracing::info!("stage=hash.start");
    let evaluation_id = compute_evaluation_id(&normalized);
    tracing::Span::current().record("evaluation_id", &evaluation_id.as_str());
    tracing::info!("stage=hash.ok");

    // ✅ Milestone 3: only if RPC is configured
    if let Some(chain) = &state.chain {
        tracing::info!("stage=chain.pin.start");
        let pinned = chain
            .pin_block(requested_block)
            .await
            .map_err(|e| AppError::bad_gateway(format!("rpc pin_block failed: {e:?}")))?;
        tracing::info!(pinned_block = pinned, "stage=chain.pin.ok");

        tracing::info!("stage=chain.get_code_info.start");
        let code_info = chain
            .get_code_info(&normalized.to, pinned)
            .await
            .map_err(|e| AppError::bad_gateway(format!("rpc eth_getCode failed: {e:?}")))?;
        tracing::info!(
            to_code_hash = %code_info.code_hash,
            to_code_size_bytes = code_info.code_size_bytes,
            "stage=chain.get_code_info.ok"
        );

        // ✅ NEW RULE: TO_NOT_A_CONTRACT when code is empty
        let mut rules_fired: Vec<serde_json::Value> = vec![];
        let mut decision = Decision::Warn; // keep WARN for now

        if code_info.is_empty {
            rules_fired.push(json!({
                "rule_id": "TO_NOT_A_CONTRACT",
                "severity": "WARN",
                "evidence": {
                    "to": normalized.to,
                    "pinned_block": pinned,
                    "code_hash": code_info.code_hash,
                    "code_size_bytes": code_info.code_size_bytes
                }
            }));

            // If later you want to BLOCK instead:
            // decision = Decision::Block;
        }

        tracing::info!("stage=chain.eth_call.start");
        let call = chain
            .eth_call_outcome(
                &normalized.from,
                &normalized.to,
                &normalized.data,
                &normalized.value,
                pinned,
            )
            .await
            .map_err(|e| AppError::bad_gateway(format!("rpc eth_call failed: {e:?}")))?;
        tracing::info!(ok = call.ok, "stage=chain.eth_call.done");

        // ✅ NEW RULE: ETH_CALL_NO_EFFECT
        // If target has no code and eth_call returns empty, explain it explicitly.
        if code_info.is_empty && call.ok && call.result.as_deref() == Some("0x") {
            rules_fired.push(json!({
                "rule_id": "ETH_CALL_NO_EFFECT",
                "severity": "INFO",
                "evidence": {
                    "to": normalized.to,
                    "pinned_block": pinned,
                    "eth_call_result": "0x",
                    "note": "Target address has no contract code at this block, so eth_call returns empty and cannot execute the intended function."
                }
            }));
        }

        tracing::info!("stage=receipt.build.start");
        let resp = build_chain_response(
            evaluation_id,
            decision,
            intent,
            pinned,
            code_info.code_hash,
            call,
            rules_fired,
        );
        tracing::info!("stage=receipt.build.ok");
        tracing::info!("stage=done");
        return Ok(resp);
    }

    // ✅ v0 placeholder path (no RPC configured)
    tracing::info!("stage=receipt.build.start");
    let resp = build_placeholder_response(state, evaluation_id, intent);
    tracing::info!("stage=receipt.build.ok");

    tracing::info!("stage=done");
    Ok(resp)
}

fn validate(req: &EvaluateTxRequest) -> Result<(), AppError> {
    if !util::is_address(&req.from) {
        return Err(AppError::bad_request(
            "Invalid 'from' address (expected 0x + 40 hex chars).",
        ));
    }
    if !util::is_address(&req.to) {
        return Err(AppError::bad_request(
            "Invalid 'to' address (expected 0x + 40 hex chars).",
        ));
    }
    if !util::is_hex_data(&req.data) {
        return Err(AppError::bad_request(
            "Invalid 'data' (expected 0x + even-length hex).",
        ));
    }
    if !util::is_hex_quantity(&req.value) {
        return Err(AppError::bad_request(
            "Invalid 'value' (expected 0x + hex quantity).",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct NormalizedTx {
    chain_id: u64,
    from: String,
    to: String,
    data: String,
    value: String,
}

fn normalize(req: &EvaluateTxRequest) -> NormalizedTx {
    NormalizedTx {
        chain_id: req.chain_id,
        from: req.from.to_lowercase(),
        to: req.to.to_lowercase(),
        data: req.data.to_lowercase(),
        value: util::normalize_hex_quantity(&req.value),
    }
}

fn compute_evaluation_id(tx: &NormalizedTx) -> String {
    let canonical = format!(
        "chain_id={}|from={}|to={}|data={}|value={}",
        tx.chain_id, tx.from, tx.to, tx.data, tx.value
    );
    format!("0x{}", util::sha256_hex(&canonical))
}

fn build_chain_response(
    evaluation_id: String,
    decision: Decision,
    intent: DecodedIntent,
    pinned: u64,
    to_code_hash: String,
    eth_call: crate::domain::EthCallOutcome,
    rules_fired: Vec<serde_json::Value>,
) -> EvaluateTxResponse {
    EvaluateTxResponse {
        evaluation_id,
        decision,
        block_ref: format!("block:{pinned}"),
        receipt: Receipt {
            summary: "Firewall v0 + Milestone 3: pinned block + eth_call + codehash."
                .to_string(),
            intents: vec![intent],
            chain: Some(crate::domain::ChainEvidence {
                pinned_block: pinned,
                to_code_hash,
                eth_call,
            }),
            asset_deltas: vec![],
            permissions: vec![],
            call_path: vec![],
            rules_fired,
            uncertainties: vec![Uncertainty {
                code: "TRACE_NOT_IMPLEMENTED".to_string(),
                message: "eth_call executed at a pinned block, but tracing/effects extraction is not implemented yet."
                    .to_string(),
            }],
        },
    }
}

fn build_placeholder_response(
    state: &AppState,
    evaluation_id: String,
    intent: DecodedIntent,
) -> EvaluateTxResponse {
    EvaluateTxResponse {
        evaluation_id,
        decision: Decision::Warn,
        block_ref: state.default_block_ref.clone(),
        receipt: Receipt {
            summary:
                "Firewall v0: received transaction for evaluation (simulation not yet enabled)."
                    .to_string(),
            intents: vec![intent],
            chain: None,
            asset_deltas: vec![],
            permissions: vec![],
            call_path: vec![],
            rules_fired: vec![],
            uncertainties: vec![Uncertainty {
                code: "SIMULATION_NOT_IMPLEMENTED".to_string(),
                message: "No chain simulation performed yet. Receipt contains placeholders only."
                    .to_string(),
            }],
        },
    }
}
