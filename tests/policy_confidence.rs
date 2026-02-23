use tx_firewall_v0::domain::{Decision, PermissionChange, Uncertainty};
use tx_firewall_v0::policy::apply_policy_v1;

fn find_rule<'a>(rules: &'a [serde_json::Value], id: &str) -> &'a serde_json::Value {
    rules
        .iter()
        .find(|r| r.get("rule_id").and_then(|v| v.as_str()) == Some(id))
        .unwrap_or_else(|| panic!("rule_id {id} not found"))
}

#[test]
fn confidence_is_high_when_no_trace_or_calldata_uncertainties() {
    let perms = vec![PermissionChange {
        kind: "ERC20_APPROVAL".to_string(),
        token: "0xtoken".to_string(),
        owner: "0xowner".to_string(),
        spender: "0xspender".to_string(),
        amount: Some(
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        ),
        approved: None,
    }];

    let (decision, rules) = apply_policy_v1(
        "0xowner",
        &perms,
        &[],
        &[], // no uncertainties
    );

    assert_eq!(decision, Decision::Warn);

    let r = find_rule(&rules, "UNLIMITED_ERC20_APPROVAL");
    assert_eq!(r.get("confidence").and_then(|v| v.as_str()), Some("HIGH"));
}

#[test]
fn confidence_is_low_when_calldata_inference_exists() {
    let perms = vec![PermissionChange {
        kind: "ERC20_APPROVAL".to_string(),
        token: "0xtoken".to_string(),
        owner: "0xowner".to_string(),
        spender: "0xspender".to_string(),
        amount: Some(
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        ),
        approved: None,
    }];

    let uncertainties = vec![Uncertainty {
        code: "EFFECTS_INFERRED_FROM_CALLDATA".to_string(),
        message: "guessed".to_string(),
    }];

    let (_decision, rules) = apply_policy_v1("0xowner", &perms, &[], &uncertainties);

    let r = find_rule(&rules, "UNLIMITED_ERC20_APPROVAL");
    assert_eq!(r.get("confidence").and_then(|v| v.as_str()), Some("LOW"));
}

#[test]
fn confidence_is_medium_when_trace_missing_but_no_calldata_inference() {
    let uncertainties = vec![Uncertainty {
        code: "TRACE_FAILED".to_string(),
        message: "trace not available".to_string(),
    }];

    let (_decision, rules) = apply_policy_v1("0xowner", &[], &[], &uncertainties);

    let r = find_rule(&rules, "EVIDENCE_NO_TRACE_LOGS");
    assert_eq!(r.get("confidence").and_then(|v| v.as_str()), Some("MEDIUM"));
}
