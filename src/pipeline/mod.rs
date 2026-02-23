use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use std::cmp::Ordering;
use std::time::Instant;
use tracing::{field, info_span, Instrument};

use crate::{
    decode,
    domain::{
        Decision, DecodedIntent, EvaluateTxRequest, EvaluateTxResponse, PermissionChange, Receipt,
        TransferEvent, Uncertainty,
    },
    effects, policy, reverts,
    safety::FailClosedMode,
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
    let eval_started = Instant::now();
    let span = info_span!(
        "tx_firewall.evaluate_tx_v0",
        request_id = %request_id,
        chain_id = req.chain_id,
        from = %req.from,
        to = %req.to,
        evaluation_id = field::Empty
    );
    let _guard = span.enter();

    let validate_started = Instant::now();
    {
        let _stage = info_span!("tx_firewall.stage", stage = "validate").entered();
        tracing::info!("stage=validate.start");
        if let Err(e) = validate(&req) {
            record_stage_metric(state, "validate", validate_started);
            state.metrics.inc_simulation_failure("VALIDATION_FAILED");
            return Err(e);
        }
        tracing::info!("stage=validate.ok");
    }
    record_stage_metric(state, "validate", validate_started);

    let requested_block = req.block_number;

    let normalize_started = Instant::now();
    let normalized = {
        let _stage = info_span!("tx_firewall.stage", stage = "normalize").entered();
        tracing::info!("stage=normalize.start");
        let n = normalize(&req);
        tracing::info!("stage=normalize.ok");
        n
    };
    record_stage_metric(state, "normalize", normalize_started);

    let hash_started = Instant::now();
    let evaluation_id = compute_evaluation_id(&normalized);
    tracing::Span::current().record("evaluation_id", &evaluation_id.as_str());
    tracing::info!(evaluation_id = %evaluation_id, "stage=hash.ok");
    record_stage_metric(state, "hash", hash_started);

    let decode_started = Instant::now();
    let intent: DecodedIntent = {
        let _stage = info_span!("tx_firewall.stage", stage = "decode").entered();
        tracing::info!("stage=decode.start");
        let i = decode::decode_calldata(&normalized.to, &normalized.data);
        tracing::info!(decoded_signature = %i.signature, "stage=decode.ok");
        i
    };
    record_stage_metric(state, "decode", decode_started);

    // uncertainties (some depend on decode)
    let mut uncertainties: Vec<Uncertainty> = vec![];
    if intent.signature == "unknown_selector" {
        uncertainties.push(Uncertainty {
            code: "UNKNOWN_SELECTOR".to_string(),
            message: "Selector is unknown; intent decoding is incomplete.".to_string(),
        });
    }

    // If no RPC configured, return placeholder response
    let Some(chain) = &state.chain else {
        let resp = build_placeholder_response(state, evaluation_id, intent);
        record_eval_metrics(
            state,
            &resp.receipt.rules_fired,
            &resp.receipt.uncertainties,
            None,
        );
        state
            .metrics
            .observe_stage_latency_ms("pipeline_total", elapsed_ms(eval_started));
        tracing::info!(
            evaluation_id = %resp.evaluation_id,
            decision = ?resp.decision,
            total_latency_ms = elapsed_ms(eval_started),
            "evaluation.completed"
        );
        return Ok(resp);
    };

    // ---- chain: pin block ----
    let pin_started = Instant::now();
    let pinned = {
        tracing::info!("stage=chain.pin.start");
        match chain
            .pin_block(requested_block)
            .instrument(info_span!("tx_firewall.stage", stage = "chain.pin"))
            .await
        {
            Ok(v) => {
                tracing::info!(pinned_block = v, "stage=chain.pin.ok");
                v
            }
            Err(e) => {
                record_stage_metric(state, "chain_pin", pin_started);
                state.metrics.inc_simulation_failure("PIN_BLOCK_FAILED");
                return Err(AppError::bad_gateway(format!(
                    "rpc pin_block failed: {e:?}"
                )));
            }
        }
    };
    record_stage_metric(state, "chain_pin", pin_started);

    // ---- chain: code info ----
    let code_started = Instant::now();
    let code_info = {
        tracing::info!("stage=chain.get_code_info.start");
        match chain
            .get_code_info(&normalized.to, pinned)
            .instrument(info_span!(
                "tx_firewall.stage",
                stage = "chain.get_code_info"
            ))
            .await
        {
            Ok(info) => {
                tracing::info!(
                    to_code_hash = %info.code_hash,
                    to_code_size_bytes = info.code_size_bytes,
                    "stage=chain.get_code_info.ok"
                );
                info
            }
            Err(e) => {
                record_stage_metric(state, "chain_get_code_info", code_started);
                state.metrics.inc_simulation_failure("GET_CODE_FAILED");
                return Err(AppError::bad_gateway(format!(
                    "rpc eth_getCode failed: {e:?}"
                )));
            }
        }
    };
    record_stage_metric(state, "chain_get_code_info", code_started);

    let mut rules_fired: Vec<serde_json::Value> = vec![];
    let mut decision = Decision::Warn;

    // Rule: TO_NOT_A_CONTRACT
    if code_info.is_empty {
        rules_fired.push(json!({
            "rule_id": "TO_NOT_A_CONTRACT",
            "severity": "WARN",
            "evidence": {
                "to": normalized.to.clone(),
                "pinned_block": pinned,
                "code_hash": code_info.code_hash.clone(),
                "code_size_bytes": code_info.code_size_bytes
            }
        }));
    }

    // ---- chain: eth_call ----
    let eth_call_started = Instant::now();
    let call = {
        tracing::info!("stage=chain.eth_call.start");
        chain
            .eth_call_outcome(
                &normalized.from,
                &normalized.to,
                &normalized.data,
                &normalized.value,
                pinned,
            )
            .instrument(info_span!("tx_firewall.stage", stage = "chain.eth_call"))
            .await
    };
    record_stage_metric(state, "chain_eth_call", eth_call_started);

    tracing::info!(
        ok = call.ok,
        error_class = ?call.error_class,
        retryable = call.retryable,
        "stage=chain.eth_call.done"
    );

    // Rule: ETH_CALL_NO_EFFECT
    if code_info.is_empty && call.ok && call.result.as_deref() == Some("0x") {
        rules_fired.push(json!({
            "rule_id": "ETH_CALL_NO_EFFECT",
            "severity": "INFO",
            "evidence": {
                "to": normalized.to.clone(),
                "pinned_block": pinned,
                "eth_call_result": "0x",
                "note": "Target has no contract code at this block, so the intended function cannot execute."
            }
        }));
    }

    // Rule: WOULD_REVERT
    if call.error_class.as_deref() == Some("REVERT") {
        let revert_reason = call
            .revert_data
            .as_deref()
            .and_then(reverts::decode_revert_reason);

        rules_fired.push(json!({
            "rule_id": "WOULD_REVERT",
            "severity": "WARN",
            "evidence": {
                "to": normalized.to.clone(),
                "pinned_block": pinned,
                "revert_data": call.revert_data.clone(),
                "revert_reason": revert_reason,
                "message": call.error_message.clone()
            }
        }));

        decision = Decision::Warn;
    }

    // Rule: RPC transient failures (retryable)
    if call.retryable {
        rules_fired.push(json!({
            "rule_id": "RPC_TRANSIENT_FAILURE",
            "severity": "INFO",
            "evidence": {
                "pinned_block": pinned,
                "error_class": call.error_class.clone(),
                "message": call.error_message.clone()
            }
        }));

        uncertainties.push(Uncertainty {
            code: "RPC_TRANSIENT".to_string(),
            message: "RPC failure classified as transient; a retry may succeed.".to_string(),
        });
    }

    // -------------------------------------------------------------------------
    // Milestone 7/9 fix:
    // Do NOT push EFFECTS_INFERRED_FROM_CALLDATA immediately.
    // Infer from calldata first, try trace/logs, then only push the uncertainty
    // if we *end up* relying on the calldata-inferred effects.
    // -------------------------------------------------------------------------

    // calldata fallback (best-effort)
    let (mut permissions_changed, mut transfers, inferred_any) =
        infer_effects_from_intent(&normalized, &intent);

    // We delay the uncertainty until AFTER trace, in case trace provides facts
    let mut inferred_pending = inferred_any;

    tracing::info!(
        inferred_any = inferred_any,
        inferred_pending = inferred_pending,
        perms = permissions_changed.len(),
        transfers = transfers.len(),
        "stage=effects.fallback.done"
    );

    // ---- trace + logs (FACTS) ----
    let trace_started = Instant::now();
    tracing::info!("stage=chain.trace_with_logs.start");
    let mut trace_summary: Option<crate::domain::TraceSummary> = None;
    let mut call_path: Vec<serde_json::Value> = vec![];
    let mut used_trace_facts = false;
    let budgets = chain.budgets();

    {
        match chain
            .trace_call_with_logs(
                &normalized.from,
                &normalized.to,
                &normalized.data,
                &normalized.value,
                pinned,
            )
            .instrument(info_span!(
                "tx_firewall.stage",
                stage = "chain.trace_with_logs"
            ))
            .await
        {
            Ok(Some((root, logs))) => {
                tracing::info!(logs_len = logs.len(), "stage=chain.trace_with_logs.ok");

                let stats = crate::trace::compute_stats(&root);
                let trace_size = estimate_trace_payload_size(&root, &logs);
                let mut over_budget = false;

                if stats.max_depth > budgets.max_trace_depth {
                    over_budget = true;
                    uncertainties.push(Uncertainty {
                        code: "TRACE_MAX_DEPTH_EXCEEDED".to_string(),
                        message: format!(
                            "Trace depth {} exceeded max_depth budget {}.",
                            stats.max_depth, budgets.max_trace_depth
                        ),
                    });
                }

                if let Some(size) = trace_size {
                    if size > budgets.max_trace_size_bytes {
                        over_budget = true;
                        uncertainties.push(Uncertainty {
                            code: "TRACE_MAX_SIZE_EXCEEDED".to_string(),
                            message: format!(
                                "Trace payload {} bytes exceeded max_trace_size budget {} bytes.",
                                size, budgets.max_trace_size_bytes
                            ),
                        });
                    }
                }

                if !over_budget {
                    // trace summary (optional UI)
                    let path = crate::trace::longest_path(&root);
                    let call_path_summary = format_call_path_summary(&normalized.from, &path);

                    trace_summary = Some(crate::domain::TraceSummary {
                        contains_delegatecall: stats.contains_delegatecall,
                        max_depth: stats.max_depth as usize,
                        max_fanout: stats.max_fanout as usize,
                        call_path_summary: call_path_summary.clone(),
                        call_tree: root.clone(),
                    });

                    call_path.push(json!({
                        "call_path_summary": call_path_summary,
                        "contains_delegatecall": stats.contains_delegatecall,
                        "max_depth": stats.max_depth,
                        "max_fanout": stats.max_fanout
                    }));

                    // FACTS from logs
                    let (perms_fact, txs_fact) = effects::extract_effects(&logs);

                    // Only overwrite if tracer actually produced facts.
                    if !perms_fact.is_empty() || !txs_fact.is_empty() {
                        permissions_changed = perms_fact;
                        transfers = txs_fact;

                        // IMPORTANT: we are no longer relying on calldata inference
                        inferred_pending = false;
                        used_trace_facts = true;
                    } else {
                        // Trace returned no logs; keep calldata inferred effects (if any)
                        uncertainties.push(Uncertainty {
                            code: "TRACE_LOGS_EMPTY".to_string(),
                            message:
                                "Trace succeeded but returned no logs; keeping calldata-inferred effects."
                                    .to_string(),
                        });
                    }
                }
            }

            Ok(None) => {
                tracing::info!("stage=chain.trace_with_logs.unavailable");
                uncertainties.push(Uncertainty {
                    code: "TRACE_UNAVAILABLE".to_string(),
                    message:
                        "RPC does not support debug_traceCall(callTracer) (or it is disabled)."
                            .to_string(),
                });
            }

            Err(e) => {
                tracing::info!("stage=chain.trace_with_logs.failed");
                match e {
                    crate::chain::rpc::RpcError::HttpTimeout(msg) => {
                        uncertainties.push(Uncertainty {
                            code: "TRACE_TIMEOUT".to_string(),
                            message: format!("Trace timed out: {msg}"),
                        })
                    }
                    other => uncertainties.push(Uncertainty {
                        code: "TRACE_FAILED".to_string(),
                        message: format!("Trace call failed: {other:?}"),
                    }),
                }
            }
        }
    }
    record_stage_metric(state, "chain_trace_with_logs", trace_started);

    // Now (and only now) emit calldata inference uncertainty if still pending
    if inferred_pending {
        uncertainties.push(Uncertainty {
            code: "EFFECTS_INFERRED_FROM_CALLDATA".to_string(),
            message:
                "Trace/logs unavailable; effects inferred from calldata (may differ with proxy/internal calls/revert)."
                    .to_string(),
        });
    }

    tracing::info!(
        inferred_pending = inferred_pending,
        perms = permissions_changed.len(),
        transfers = transfers.len(),
        "stage=effects.final"
    );

    let effects_confidence = if used_trace_facts {
        "HIGH"
    } else if inferred_pending {
        "LOW"
    } else {
        "MEDIUM"
    };

    // ---- Milestone 11: state-backed deltas + transfer sanity checks ----
    let state_deltas_started = Instant::now();
    {
        tracing::info!("stage=state.deltas.start");
        apply_state_deltas(
            chain,
            pinned,
            &normalized.from,
            &permissions_changed,
            &transfers,
            effects_confidence,
            &mut rules_fired,
            &mut uncertainties,
        )
        .instrument(info_span!("tx_firewall.stage", stage = "state.deltas"))
        .await;
        tracing::info!("stage=state.deltas.ok");
    }
    record_stage_metric(state, "state_deltas", state_deltas_started);

    // ---- Milestone 8/9: policy engine (uses final effects) ----
    let policy_started = Instant::now();
    {
        let _stage = info_span!("tx_firewall.stage", stage = "policy.apply").entered();
        tracing::info!("stage=policy.apply.start");

        let (policy_decision, policy_rules) = policy::apply_policy_v1(
            &normalized.from,
            &permissions_changed,
            &transfers,
            &uncertainties,
        );

        bump_decision(&mut decision, policy_decision);
        rules_fired.extend(policy_rules);
        apply_fail_closed_mode(
            state.fail_closed_mode,
            &uncertainties,
            &mut decision,
            &mut rules_fired,
        );

        tracing::info!(
            decision = ?decision,
            rules_len = rules_fired.len(),
            "stage=policy.apply.ok"
        );
    }
    record_stage_metric(state, "policy_apply", policy_started);

    let receipt_started = Instant::now();
    let resp = {
        let _stage = info_span!("tx_firewall.stage", stage = "receipt.build").entered();
        tracing::info!("stage=receipt.build.start");
        let out = EvaluateTxResponse {
            evaluation_id,
            decision,
            block_ref: format!("block:{pinned}"),
            receipt: Receipt {
                summary: "Firewall v0 + Milestone 13: eth_call + trace (optional) + effects + policy + state-backed deltas + safety budgets + observability."
                    .to_string(),
                intents: vec![intent],
                chain: Some(crate::domain::ChainEvidence {
                    pinned_block: pinned,
                    to_code_hash: code_info.code_hash.clone(),
                    eth_call: call,
                    trace: trace_summary,
                }),
                permissions_changed,
                transfers,
                call_path,
                rules_fired,
                uncertainties,
            },
        };
        tracing::info!("stage=receipt.build.ok");
        out
    };
    record_stage_metric(state, "receipt_build", receipt_started);

    record_eval_metrics(
        state,
        &resp.receipt.rules_fired,
        &resp.receipt.uncertainties,
        resp.receipt.chain.as_ref().map(|c| &c.eth_call),
    );
    let total_ms = elapsed_ms(eval_started);
    state
        .metrics
        .observe_stage_latency_ms("pipeline_total", total_ms);
    tracing::info!(
        evaluation_id = %resp.evaluation_id,
        decision = ?resp.decision,
        total_latency_ms = total_ms,
        rules_len = resp.receipt.rules_fired.len(),
        uncertainties_len = resp.receipt.uncertainties.len(),
        "evaluation.completed"
    );
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

fn build_placeholder_response(
    state: &AppState,
    evaluation_id: String,
    intent: DecodedIntent,
) -> EvaluateTxResponse {
    let (decision, fail_closed_rule) = match state.fail_closed_mode {
        FailClosedMode::Block => (
            Decision::Block,
            Some(json!({
                "rule_id": "PARTIAL_ANALYSIS_FAIL_CLOSED",
                "severity": "BLOCK",
                "confidence": "HIGH",
                "recommendation": "RPC simulation is unavailable, so evaluation is partial.",
                "evidence": { "mode": "BLOCK", "partial_uncertainty_codes": ["SIMULATION_NOT_IMPLEMENTED"] }
            })),
        ),
        FailClosedMode::Warn => (
            Decision::Warn,
            Some(json!({
                "rule_id": "PARTIAL_ANALYSIS_FAIL_CLOSED",
                "severity": "WARN",
                "confidence": "HIGH",
                "recommendation": "RPC simulation is unavailable, so evaluation is partial.",
                "evidence": { "mode": "WARN", "partial_uncertainty_codes": ["SIMULATION_NOT_IMPLEMENTED"] }
            })),
        ),
        FailClosedMode::Off => (Decision::Warn, None),
    };
    let mut rules_fired = Vec::new();
    if let Some(rule) = fail_closed_rule {
        rules_fired.push(rule);
    }

    EvaluateTxResponse {
        evaluation_id,
        decision,
        block_ref: state.default_block_ref.clone(),
        receipt: Receipt {
            summary:
                "Firewall v0: received transaction for evaluation (simulation not yet enabled)."
                    .to_string(),
            intents: vec![intent],
            chain: None,
            permissions_changed: vec![],
            transfers: vec![],
            call_path: vec![],
            rules_fired,
            uncertainties: vec![Uncertainty {
                code: "SIMULATION_NOT_IMPLEMENTED".to_string(),
                message: "No chain simulation performed yet. Receipt contains placeholders only."
                    .to_string(),
            }],
        },
    }
}

// -------- effects inference (calldata-only fallback) --------
fn infer_effects_from_intent(
    tx: &NormalizedTx,
    intent: &DecodedIntent,
) -> (Vec<PermissionChange>, Vec<TransferEvent>, bool) {
    let mut perms = Vec::new();
    let mut transfers = Vec::new();
    let mut inferred = false;

    match intent.signature.as_str() {
        "approve(address,uint256)" => {
            let spender = intent
                .args
                .get("spender")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let amount = intent
                .args
                .get("amount")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if !spender.is_empty() {
                perms.push(PermissionChange {
                    kind: "ERC20_APPROVAL".to_string(),
                    token: tx.to.clone(),
                    owner: tx.from.clone(),
                    spender,
                    amount,
                    approved: None,
                });
                inferred = true;
            }
        }

        "setApprovalForAll(address,bool)" => {
            let operator = intent
                .args
                .get("operator")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let approved = intent.args.get("approved").and_then(|v| v.as_bool());

            if !operator.is_empty() {
                perms.push(PermissionChange {
                    kind: "ERC721_APPROVAL_FOR_ALL".to_string(),
                    token: tx.to.clone(),
                    owner: tx.from.clone(),
                    spender: operator,
                    amount: None,
                    approved,
                });
                inferred = true;
            }
        }

        "transfer(address,uint256)" => {
            let to = intent
                .args
                .get("to")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let amount = intent
                .args
                .get("amount")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if !to.is_empty() && amount.is_some() {
                transfers.push(TransferEvent {
                    standard: "ERC20_OR_ERC721".to_string(),
                    token: tx.to.clone(),
                    from: tx.from.clone(),
                    to,
                    amount_or_token_id: amount,
                    ids: None,
                    amounts: None,
                });
                inferred = true;
            }
        }

        "transferFrom(address,address,uint256)" => {
            let from = intent
                .args
                .get("from")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let to = intent
                .args
                .get("to")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let amount = intent
                .args
                .get("amount")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if !from.is_empty() && !to.is_empty() && amount.is_some() {
                transfers.push(TransferEvent {
                    standard: "ERC20_OR_ERC721".to_string(),
                    token: tx.to.clone(),
                    from,
                    to,
                    amount_or_token_id: amount,
                    ids: None,
                    amounts: None,
                });
                inferred = true;
            }
        }

        _ => {}
    }

    (perms, transfers, inferred)
}

// -------- Milestone 11: state lookups (best-effort) --------

// Hardcoded selectors (no keccak needed)
const SEL_ALLOWANCE: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e]; // allowance(address,address)
const SEL_IS_APPROVED_FOR_ALL: [u8; 4] = [0xe9, 0x85, 0xe9, 0xc5]; // isApprovedForAll(address,address)
const SEL_BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31]; // balanceOf(address)
const SEL_OWNER_OF: [u8; 4] = [0x63, 0x52, 0x21, 0x1e]; // ownerOf(uint256)

async fn apply_state_deltas(
    chain: &crate::chain::ChainClient,
    pinned: u64,
    tx_from: &str,
    permissions: &[PermissionChange],
    transfers: &[TransferEvent],
    effects_confidence: &str,
    rules_fired: &mut Vec<serde_json::Value>,
    uncertainties: &mut Vec<Uncertainty>,
) {
    // ---- permission deltas ----
    for p in permissions {
        match p.kind.as_str() {
            "ERC20_APPROVAL" => {
                let after = match p.amount.as_deref() {
                    Some(x) => x,
                    None => continue,
                };

                let owner = p.owner.as_str();
                let spender = p.spender.as_str();
                let token = p.token.as_str();

                let Some(data) = calldata_allowance(owner, spender) else {
                    uncertainties.push(Uncertainty {
                        code: "STATE_LOOKUP_BUILD_FAILED".to_string(),
                        message: "Failed to build allowance(owner,spender) calldata.".to_string(),
                    });
                    continue;
                };

                let call = chain
                    .eth_call_outcome(tx_from, token, &data, "0x0", pinned)
                    .await;

                if call.ok {
                    let before = call.result.as_deref().and_then(decode_u256_return);

                    if let Some(before) = before {
                        rules_fired.push(json!({
                            "rule_id": "ERC20_ALLOWANCE_DELTA",
                            "severity": "INFO",
                            "confidence": effects_confidence,
                            "recommendation": "Compare before/after allowance. Prefer exact approvals and revoke after use.",
                            "evidence": {
                                "token": token,
                                "owner": owner,
                                "spender": spender,
                                "before": before,
                                "after": after
                            }
                        }));
                    } else {
                        uncertainties.push(Uncertainty {
                            code: "STATE_LOOKUP_DECODE_FAILED".to_string(),
                            message: "allowance() eth_call succeeded but decode failed."
                                .to_string(),
                        });
                    }
                } else {
                    uncertainties.push(Uncertainty {
                        code: "STATE_LOOKUP_FAILED".to_string(),
                        message: format!(
                            "allowance() eth_call failed: class={:?} msg={:?}",
                            call.error_class, call.error_message
                        ),
                    });
                }
            }

            "ERC721_APPROVAL_FOR_ALL" => {
                let owner = p.owner.as_str();
                let operator = p.spender.as_str();
                let token = p.token.as_str();
                let after = p.approved;

                let Some(data) = calldata_is_approved_for_all(owner, operator) else {
                    uncertainties.push(Uncertainty {
                        code: "STATE_LOOKUP_BUILD_FAILED".to_string(),
                        message: "Failed to build isApprovedForAll(owner,operator) calldata."
                            .to_string(),
                    });
                    continue;
                };

                let call = chain
                    .eth_call_outcome(tx_from, token, &data, "0x0", pinned)
                    .await;

                if call.ok {
                    let before = call.result.as_deref().and_then(decode_bool_return);

                    if let Some(before) = before {
                        rules_fired.push(json!({
                            "rule_id": "APPROVAL_FOR_ALL_DELTA",
                            "severity": "INFO",
                            "confidence": effects_confidence,
                            "recommendation": "ApprovalForAll is powerful. Only enable for operators you fully trust.",
                            "evidence": {
                                "token": token,
                                "owner": owner,
                                "operator": operator,
                                "before": before,
                                "after": after
                            }
                        }));
                    } else {
                        uncertainties.push(Uncertainty {
                            code: "STATE_LOOKUP_DECODE_FAILED".to_string(),
                            message: "isApprovedForAll() eth_call succeeded but decode failed."
                                .to_string(),
                        });
                    }
                } else {
                    uncertainties.push(Uncertainty {
                        code: "STATE_LOOKUP_FAILED".to_string(),
                        message: format!(
                            "isApprovedForAll() eth_call failed: class={:?} msg={:?}",
                            call.error_class, call.error_message
                        ),
                    });
                }
            }

            _ => {}
        }
    }

    // ---- transfer sanity checks ----
    for t in transfers {
        // only care about outgoing transfers from signer
        if !eq_addr(&t.from, tx_from) {
            continue;
        }

        let token = t.token.as_str();
        let from = t.from.as_str();
        let token_id_or_amount = match t.amount_or_token_id.as_deref() {
            Some(v) => v,
            None => continue,
        };

        // 1) Try ERC721 ownerOf(tokenId)
        if let Some(data_owner_of) = calldata_owner_of(token_id_or_amount) {
            let call = chain
                .eth_call_outcome(tx_from, token, &data_owner_of, "0x0", pinned)
                .await;

            if call.ok {
                if let Some(owner_before) = call.result.as_deref().and_then(decode_address_return) {
                    rules_fired.push(json!({
                        "rule_id": "ERC721_OWNER_BEFORE",
                        "severity": "INFO",
                        "confidence": effects_confidence,
                        "recommendation": "If this is an NFT transfer, confirm you own this tokenId and the recipient is correct.",
                        "evidence": {
                            "token": token,
                            "token_id": token_id_or_amount,
                            "owner_before": owner_before,
                            "from": from
                        }
                    }));

                    if !eq_addr(&owner_before, from) {
                        rules_fired.push(json!({
                            "rule_id": "ERC721_NOT_OWNER",
                            "severity": "WARN",
                            "confidence": effects_confidence,
                            "recommendation": "This will likely fail (you are not the current owner). If you did not expect this, do not sign.",
                            "evidence": {
                                "token": token,
                                "token_id": token_id_or_amount,
                                "owner_before": owner_before,
                                "from": from
                            }
                        }));
                    }

                    // If ownerOf worked, treat it as ERC721 and stop here
                    continue;
                }
            }
        }

        // 2) Fallback: try ERC20 balanceOf(from)
        let Some(data_balance) = calldata_balance_of(from) else {
            uncertainties.push(Uncertainty {
                code: "STATE_LOOKUP_BUILD_FAILED".to_string(),
                message: "Failed to build balanceOf(owner) calldata.".to_string(),
            });
            continue;
        };

        let call = chain
            .eth_call_outcome(tx_from, token, &data_balance, "0x0", pinned)
            .await;

        if call.ok {
            let balance_before = call.result.as_deref().and_then(decode_u256_return);

            if let Some(balance_before) = balance_before {
                rules_fired.push(json!({
                    "rule_id": "ERC20_BALANCE_BEFORE",
                    "severity": "INFO",
                    "confidence": effects_confidence,
                    "recommendation": "Confirm the token and amount. If balance is low, this may revert.",
                    "evidence": {
                        "token": token,
                        "owner": from,
                        "balance_before": balance_before,
                        "transfer_amount": token_id_or_amount
                    }
                }));

                if let Some(ord) = cmp_u256_hex(&balance_before, token_id_or_amount) {
                    if ord == Ordering::Less {
                        rules_fired.push(json!({
                            "rule_id": "ERC20_INSUFFICIENT_BALANCE",
                            "severity": "WARN",
                            "confidence": effects_confidence,
                            "recommendation": "Balance looks smaller than transfer amount; this likely fails unless another internal step funds you.",
                            "evidence": {
                                "token": token,
                                "owner": from,
                                "balance_before": balance_before,
                                "transfer_amount": token_id_or_amount
                            }
                        }));
                    }
                }
            } else {
                uncertainties.push(Uncertainty {
                    code: "STATE_LOOKUP_DECODE_FAILED".to_string(),
                    message: "balanceOf() eth_call succeeded but decode failed.".to_string(),
                });
            }
        } else {
            uncertainties.push(Uncertainty {
                code: "STATE_LOOKUP_FAILED".to_string(),
                message: format!(
                    "balanceOf() eth_call failed: class={:?} msg={:?}",
                    call.error_class, call.error_message
                ),
            });
        }
    }
}

fn calldata_allowance(owner: &str, spender: &str) -> Option<String> {
    let mut out = Vec::with_capacity(4 + 32 + 32);
    out.extend_from_slice(&SEL_ALLOWANCE);
    out.extend_from_slice(&encode_address_word(owner)?);
    out.extend_from_slice(&encode_address_word(spender)?);
    Some(format!("0x{}", hex::encode(out)))
}

fn calldata_is_approved_for_all(owner: &str, operator: &str) -> Option<String> {
    let mut out = Vec::with_capacity(4 + 32 + 32);
    out.extend_from_slice(&SEL_IS_APPROVED_FOR_ALL);
    out.extend_from_slice(&encode_address_word(owner)?);
    out.extend_from_slice(&encode_address_word(operator)?);
    Some(format!("0x{}", hex::encode(out)))
}

fn calldata_balance_of(owner: &str) -> Option<String> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&SEL_BALANCE_OF);
    out.extend_from_slice(&encode_address_word(owner)?);
    Some(format!("0x{}", hex::encode(out)))
}

fn calldata_owner_of(token_id_hex: &str) -> Option<String> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&SEL_OWNER_OF);
    out.extend_from_slice(&encode_u256_word(token_id_hex)?);
    Some(format!("0x{}", hex::encode(out)))
}

fn encode_address_word(addr: &str) -> Option<[u8; 32]> {
    let a = addr.trim().to_lowercase();
    let a = a.strip_prefix("0x").unwrap_or(&a);
    if a.len() != 40 {
        return None;
    }
    let raw = hex::decode(a).ok()?;
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&raw);
    Some(word)
}

fn encode_u256_word(v: &str) -> Option<[u8; 32]> {
    let s = v.trim().to_ascii_lowercase();
    let s = s.strip_prefix("0x").unwrap_or(&s);

    let mut hex_s = if s.is_empty() {
        "0".to_string()
    } else {
        s.to_string()
    };
    if hex_s.len() % 2 == 1 {
        hex_s.insert(0, '0');
    }

    let raw = hex::decode(hex_s).ok()?;
    if raw.len() > 32 {
        return None;
    }

    let mut word = [0u8; 32];
    word[32 - raw.len()..].copy_from_slice(&raw);
    Some(word)
}

fn decode_u256_return(data: &str) -> Option<String> {
    let bytes = util::hex_to_bytes(data).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    let word = &bytes[bytes.len() - 32..];
    Some(normalize_u256_word(word))
}

fn decode_bool_return(data: &str) -> Option<bool> {
    let bytes = util::hex_to_bytes(data).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    Some(bytes[bytes.len() - 1] == 1u8)
}

fn decode_address_return(data: &str) -> Option<String> {
    let bytes = util::hex_to_bytes(data).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    let word = &bytes[bytes.len() - 32..];
    let addr = &word[12..];
    Some(format!("0x{}", hex::encode(addr)))
}

fn normalize_u256_word(word32: &[u8]) -> String {
    let mut i = 0usize;
    while i < word32.len() && word32[i] == 0 {
        i += 1;
    }
    let tail = if i == word32.len() {
        &word32[word32.len() - 1..]
    } else {
        &word32[i..]
    };
    format!("0x{}", hex::encode(tail))
}

fn hex_quantity_to_bytes(v: &str) -> Option<Vec<u8>> {
    let s = v.trim().to_ascii_lowercase();
    let s = s.strip_prefix("0x").unwrap_or(&s);

    let s = s.trim_start_matches('0');
    let mut hex_s = if s.is_empty() {
        "0".to_string()
    } else {
        s.to_string()
    };

    if hex_s.len() % 2 == 1 {
        hex_s.insert(0, '0');
    }

    let mut raw = hex::decode(hex_s).ok()?;
    while raw.len() > 1 && raw.first().copied() == Some(0) {
        raw.remove(0);
    }
    Some(raw)
}

fn cmp_u256_hex(a: &str, b: &str) -> Option<Ordering> {
    let aa = hex_quantity_to_bytes(a)?;
    let bb = hex_quantity_to_bytes(b)?;
    if aa.len() != bb.len() {
        return Some(aa.len().cmp(&bb.len()));
    }
    Some(aa.cmp(&bb))
}

fn eq_addr(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn record_stage_metric(state: &AppState, stage: &str, started: Instant) {
    let ms = elapsed_ms(started);
    state.metrics.observe_stage_latency_ms(stage, ms);
    tracing::info!(stage = stage, stage_latency_ms = ms, "stage.metric");
}

fn record_eval_metrics(
    state: &AppState,
    rules_fired: &[serde_json::Value],
    uncertainties: &[Uncertainty],
    call: Option<&crate::domain::EthCallOutcome>,
) {
    for r in rules_fired {
        if let Some(rule_id) = r.get("rule_id").and_then(|v| v.as_str()) {
            state.metrics.inc_rule_hit(rule_id);
        }
    }

    if let Some(call) = call {
        if !call.ok {
            state.metrics.inc_simulation_failure(&format!(
                "ETH_CALL_{}",
                call.error_class
                    .as_deref()
                    .unwrap_or("UNKNOWN")
                    .to_ascii_uppercase()
            ));
        }
    }

    for u in uncertainties {
        if is_sim_failure_uncertainty(&u.code) {
            state.metrics.inc_simulation_failure(&u.code);
        }
    }
}

fn is_sim_failure_uncertainty(code: &str) -> bool {
    matches!(
        code,
        "SIMULATION_NOT_IMPLEMENTED"
            | "TRACE_FAILED"
            | "TRACE_TIMEOUT"
            | "TRACE_UNAVAILABLE"
            | "TRACE_LOGS_EMPTY"
            | "TRACE_MAX_DEPTH_EXCEEDED"
            | "TRACE_MAX_SIZE_EXCEEDED"
            | "RPC_TRANSIENT"
            | "STATE_LOOKUP_FAILED"
            | "STATE_LOOKUP_DECODE_FAILED"
            | "STATE_LOOKUP_BUILD_FAILED"
    )
}

fn estimate_trace_payload_size(
    root: &crate::domain::CallFrame,
    logs: &[crate::domain::LogEntry],
) -> Option<usize> {
    serde_json::to_vec(&json!({ "root": root, "logs": logs }))
        .ok()
        .map(|v| v.len())
}

fn apply_fail_closed_mode(
    mode: FailClosedMode,
    uncertainties: &[Uncertainty],
    decision: &mut Decision,
    rules_fired: &mut Vec<serde_json::Value>,
) {
    if mode == FailClosedMode::Off {
        return;
    }

    let partial_codes = partial_analysis_codes(uncertainties);
    if partial_codes.is_empty() {
        return;
    }

    let (target_decision, severity, mode_str) = match mode {
        FailClosedMode::Warn => (Decision::Warn, "WARN", "WARN"),
        FailClosedMode::Block => (Decision::Block, "BLOCK", "BLOCK"),
        FailClosedMode::Off => return,
    };

    bump_decision(decision, target_decision);
    rules_fired.push(json!({
        "rule_id": "PARTIAL_ANALYSIS_FAIL_CLOSED",
        "severity": severity,
        "confidence": "HIGH",
        "recommendation": "Analysis was partial due to safety limits or missing trace facts. Retry with richer RPC support or reduce transaction complexity.",
        "evidence": {
            "mode": mode_str,
            "partial_uncertainty_codes": partial_codes
        }
    }));
}

fn partial_analysis_codes(uncertainties: &[Uncertainty]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for u in uncertainties {
        let is_partial = matches!(
            u.code.as_str(),
            "TRACE_FAILED"
                | "TRACE_TIMEOUT"
                | "TRACE_UNAVAILABLE"
                | "TRACE_LOGS_EMPTY"
                | "TRACE_MAX_DEPTH_EXCEEDED"
                | "TRACE_MAX_SIZE_EXCEEDED"
                | "EFFECTS_INFERRED_FROM_CALLDATA"
                | "RPC_TRANSIENT"
        );

        if is_partial && !out.iter().any(|c| c == &u.code) {
            out.push(u.code.clone());
        }
    }
    out
}

// minimal readable path: "EOA -> 0xabc.. -> 0xdef.."
fn format_call_path_summary(from: &str, path: &[&crate::domain::CallFrame]) -> String {
    let mut parts = Vec::new();
    parts.push("EOA".to_string());

    for f in path {
        if !f.to.is_empty() {
            parts.push(short_addr(&f.to));
        }
    }

    if parts.len() == 1 {
        format!("EOA({})", short_addr(from))
    } else {
        parts.join(" -> ")
    }
}

fn short_addr(a: &str) -> String {
    if a.len() <= 12 {
        return a.to_string();
    }
    let a = a.to_lowercase();
    let start = &a[..6];
    let end = &a[a.len() - 4..];
    format!("{start}..{end}")
}

fn bump_decision(current: &mut Decision, next: Decision) {
    fn rank(d: &Decision) -> u8 {
        match d {
            Decision::Allow => 0,
            Decision::Warn => 1,
            Decision::Block => 2,
        }
    }
    if rank(&next) > rank(current) {
        *current = next;
    }
}
