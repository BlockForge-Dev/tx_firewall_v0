use serde_json::json;

use crate::domain::{Decision, PermissionChange, TransferEvent, Uncertainty};

/// Milestone 9: Actionable Policy Engine v1 (Option A++)
/// Adds:
/// - confidence tagging (HIGH/LOW)
/// - recommendations per rule
/// - risk score summary
pub fn apply_policy_v1(
    tx_from: &str,
    permissions: &[PermissionChange],
    transfers: &[TransferEvent],
    uncertainties: &[Uncertainty],
) -> (Decision, Vec<serde_json::Value>) {
    let mut decision = Decision::Allow;
    let mut rules: Vec<serde_json::Value> = vec![];

    // Evidence quality (confidence)
    // Evidence quality (confidence)
    // - HIGH: no trace issues + no calldata inference
    // - MEDIUM: trace missing, but also no calldata inference
    // - LOW: calldata inference exists (we're guessing effects)
    let has_calldata_inference = uncertainties
        .iter()
        .any(|u| u.code.as_str() == "EFFECTS_INFERRED_FROM_CALLDATA");

    let has_trace_issue = uncertainties.iter().any(|u| {
        matches!(
            u.code.as_str(),
            "TRACE_FAILED"
                | "TRACE_TIMEOUT"
                | "TRACE_UNAVAILABLE"
                | "TRACE_LOGS_EMPTY"
                | "TRACE_MAX_DEPTH_EXCEEDED"
                | "TRACE_MAX_SIZE_EXCEEDED"
        )
    });

    let confidence = if has_calldata_inference {
        "LOW"
    } else if has_trace_issue {
        "MEDIUM"
    } else {
        "HIGH"
    };
    // Risk score 0..100 (simple + deterministic)
    let mut risk: i32 = 0;

    // ---- Evidence-quality policy (uncertainties) ----
    for u in uncertainties {
        match u.code.as_str() {
            "EFFECTS_INFERRED_FROM_CALLDATA" => {
                rules.push(json!({
                    "rule_id": "EVIDENCE_WEAK_CALLDATA_ONLY",
                    "severity": "INFO",
                    "confidence": confidence,
                    "recommendation": "Treat effect detection as best-effort; prefer running with a tracing-capable RPC for facts.",
                    "evidence": { "code": u.code, "message": u.message }
                }));
                bump(&mut decision, Decision::Warn);
            }
            "TRACE_FAILED"
            | "TRACE_TIMEOUT"
            | "TRACE_UNAVAILABLE"
            | "TRACE_LOGS_EMPTY"
            | "TRACE_MAX_DEPTH_EXCEEDED"
            | "TRACE_MAX_SIZE_EXCEEDED" => {
                rules.push(json!({
                    "rule_id": "EVIDENCE_NO_TRACE_LOGS",
                    "severity": "INFO",
                    "confidence": confidence,
                    "recommendation": "Use a node/provider that supports debug_traceCall so effects come from logs, not guesses.",
                    "evidence": { "code": u.code, "message": u.message }
                }));
                bump(&mut decision, Decision::Warn);
            }
            "UNKNOWN_SELECTOR" => {
                rules.push(json!({
                    "rule_id": "UNKNOWN_INTENT",
                    "severity": "INFO",
                    "confidence": confidence,
                    "recommendation": "If you don’t recognize this action, don’t sign. Add decoder support for this selector.",
                    "evidence": { "code": u.code, "message": u.message }
                }));
                bump(&mut decision, Decision::Warn);
            }
            _ => {}
        }
    }

    // ---- Permission policy ----
    for p in permissions {
        match p.kind.as_str() {
            "ERC20_APPROVAL" => {
                if let Some(amount) = p.amount.as_deref() {
                    if is_max_u256(amount) {
                        rules.push(json!({
                            "rule_id": "UNLIMITED_ERC20_APPROVAL",
                            "severity": "WARN",
                            "confidence": confidence,
                            "recommendation": "Only approve exact amounts when possible. If you must approve, prefer small, one-time approvals and revoke later.",
                            "evidence": {
                                "token": p.token,
                                "owner": p.owner,
                                "spender": p.spender,
                                "amount": amount
                            }
                        }));
                        risk += 35;
                        bump(&mut decision, Decision::Warn);
                    } else {
                        rules.push(json!({
                            "rule_id": "ERC20_APPROVAL",
                            "severity": "INFO",
                            "confidence": confidence,
                            "recommendation": "Check the spender address carefully. Approvals give spending power without moving funds immediately.",
                            "evidence": {
                                "token": p.token,
                                "owner": p.owner,
                                "spender": p.spender,
                                "amount": amount
                            }
                        }));
                        risk += 10;
                    }
                }
            }

            "ERC721_APPROVAL_FOR_ALL" => {
                if p.approved == Some(true) {
                    rules.push(json!({
                        "rule_id": "APPROVAL_FOR_ALL_ENABLED",
                        "severity": "BLOCK",
                        "confidence": confidence,
                        "recommendation": "Do NOT sign unless you fully trust the operator. This can allow moving ALL NFTs in that collection.",
                        "evidence": {
                            "token": p.token,
                            "owner": p.owner,
                            "operator": p.spender,
                            "approved": p.approved
                        }
                    }));
                    risk += 80;
                    bump(&mut decision, Decision::Block);
                } else {
                    rules.push(json!({
                        "rule_id": "APPROVAL_FOR_ALL",
                        "severity": "INFO",
                        "confidence": confidence,
                        "recommendation": "Disabling approval-for-all is generally safe; still confirm the operator address is correct.",
                        "evidence": {
                            "token": p.token,
                            "owner": p.owner,
                            "operator": p.spender,
                            "approved": p.approved
                        }
                    }));
                }
            }

            _ => {}
        }
    }

    // ---- Transfer policy ----
    for t in transfers {
        if eq_addr(&t.from, tx_from) {
            rules.push(json!({
                "rule_id": "TRANSFER_OUT",
                "severity": "WARN",
                "confidence": confidence,
                "recommendation": "Confirm the destination address and amount/token-id. If unexpected, do not sign.",
                "evidence": {
                    "standard": t.standard,
                    "token": t.token,
                    "from": t.from,
                    "to": t.to,
                    "amount_or_token_id": t.amount_or_token_id,
                    "ids": t.ids,
                    "amounts": t.amounts
                }
            }));
            risk += 25;
            bump(&mut decision, Decision::Warn);
        }

        if eq_addr(&t.to, "0x0000000000000000000000000000000000000000") {
            rules.push(json!({
                "rule_id": "BURN_ADDRESS_TRANSFER",
                "severity": "BLOCK",
                "confidence": confidence,
                "recommendation": "This looks like a burn. Only sign if you intended to permanently destroy the asset.",
                "evidence": {
                    "standard": t.standard,
                    "token": t.token,
                    "from": t.from,
                    "to": t.to,
                    "amount_or_token_id": t.amount_or_token_id,
                    "ids": t.ids,
                    "amounts": t.amounts
                }
            }));
            risk += 90;
            bump(&mut decision, Decision::Block);
        }
    }

    // Clamp risk and add summary rule
    if risk < 0 {
        risk = 0;
    }
    if risk > 100 {
        risk = 100;
    }

    rules.push(json!({
        "rule_id": "RISK_SCORE",
        "severity": "INFO",
        "confidence": confidence,
        "recommendation": "Use the score as a quick signal; always read the specific rules and evidence before signing.",
        "evidence": { "score": risk }
    }));

    (decision, rules)
}

// --- helpers ---
fn bump(current: &mut Decision, next: Decision) {
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

fn eq_addr(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

fn is_max_u256(v: &str) -> bool {
    let s = v.trim().to_ascii_lowercase();
    let s = s.strip_prefix("0x").unwrap_or(&s);
    if s.len() < 16 {
        return false;
    }
    s.chars().all(|c| c == 'f')
}
