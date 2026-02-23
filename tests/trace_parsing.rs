use tx_firewall_v0::domain::CallFrame;
use tx_firewall_v0::trace::{compute_stats, longest_path};

#[test]
fn trace_stats_and_longest_path_work() {
    // Root call: 0x11 -> 0x22
    // Child: DELEGATECALL 0x22 -> 0x33
    let root = CallFrame {
        calls: vec![CallFrame::new(
            "DELEGATECALL",
            "0x2222222222222222222222222222222222222222",
            "0x3333333333333333333333333333333333333333",
            "0x0",
            "0x",
        )],
        ..CallFrame::new(
            "CALL",
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
            "0x0",
            "0x",
        )
    };

    let stats = compute_stats(&root);
    assert!(stats.contains_delegatecall);

    let path = longest_path(&root);
    assert_eq!(path.len(), 2);
}
