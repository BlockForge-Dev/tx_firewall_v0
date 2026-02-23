use tx_firewall_v0::domain::{Decision, PermissionChange, TransferEvent, Uncertainty};
use tx_firewall_v0::policy::apply_policy_v1;

#[test]
fn unlimited_approval_triggers_warn_rule() {
    let tx_from = "0x1111111111111111111111111111111111111111";

    let perms = vec![PermissionChange {
        kind: "ERC20_APPROVAL".to_string(),
        token: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
        owner: tx_from.to_string(),
        spender: "0x3333333333333333333333333333333333333333".to_string(),
        amount: Some(
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        ),
        approved: None,
    }];

    let transfers: Vec<TransferEvent> = vec![];
    let uncertainties: Vec<Uncertainty> = vec![];

    let (decision, rules) = apply_policy_v1(tx_from, &perms, &transfers, &uncertainties);

    assert!(matches!(decision, Decision::Warn));
    assert!(rules
        .iter()
        .any(|r| r["rule_id"] == "UNLIMITED_ERC20_APPROVAL"));
}
