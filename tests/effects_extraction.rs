use tx_firewall_v0::domain::LogEntry;
use tx_firewall_v0::effects::extract_effects;

const TOPIC_APPROVAL: &str = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const TOPIC_TRANSFER: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

fn topic_addr(addr: &str) -> String {
    let a = addr.strip_prefix("0x").unwrap();
    format!("0x{:0>64}", a)
}

fn word_u256(hex_no_0x: &str) -> String {
    format!("0x{:0>64}", hex_no_0x)
}

#[test]
fn extracts_erc20_approval_and_transfer() {
    let token = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"; // USDC (just as a label)

    let owner = "0x1111111111111111111111111111111111111111";
    let spender = "0x2222222222222222222222222222222222222222";
    let to = "0x3333333333333333333333333333333333333333";

    let logs = vec![
        LogEntry {
            address: token.to_string(),
            topics: vec![
                TOPIC_APPROVAL.to_string(),
                topic_addr(owner),
                topic_addr(spender),
            ],
            data: word_u256("05"), // approve 5
        },
        LogEntry {
            address: token.to_string(),
            topics: vec![
                TOPIC_TRANSFER.to_string(),
                topic_addr(owner),
                topic_addr(to),
            ],
            data: word_u256("0a"), // transfer 10
        },
    ];

    let (perms, transfers) = extract_effects(&logs);

    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].kind, "ERC20_APPROVAL");
    assert_eq!(perms[0].owner, owner);
    assert_eq!(perms[0].spender, spender);

    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0].standard, "ERC20_OR_ERC721");
    assert_eq!(transfers[0].from, owner);
    assert_eq!(transfers[0].to, to);
}
