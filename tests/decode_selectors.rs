use tx_firewall_v0::decode;

fn to() -> &'static str {
    "0x2222222222222222222222222222222222222222"
}

#[test]
fn decodes_erc20_approve() {
    let data = "0x095ea7b3\
0000000000000000000000003333333333333333333333333333333333333333\
0000000000000000000000000000000000000000000000000000000000000005";
    let intent = decode::decode_calldata(to(), data);

    assert_eq!(intent.signature, "approve(address,uint256)");
    assert_eq!(
        intent.args["spender"],
        "0x3333333333333333333333333333333333333333"
    );
    assert_eq!(intent.args["amount"], "0x5");
}

#[test]
fn decodes_erc20_transfer() {
    let data = "0xa9059cbb\
0000000000000000000000003333333333333333333333333333333333333333\
000000000000000000000000000000000000000000000000000000000000000a";
    let intent = decode::decode_calldata(to(), data);

    assert_eq!(intent.signature, "transfer(address,uint256)");
    assert_eq!(
        intent.args["to"],
        "0x3333333333333333333333333333333333333333"
    );
    assert_eq!(intent.args["amount"], "0xa");
}

#[test]
fn decodes_transfer_from_generic() {
    let data = "0x23b872dd\
0000000000000000000000001111111111111111111111111111111111111111\
0000000000000000000000003333333333333333333333333333333333333333\
0000000000000000000000000000000000000000000000000000000000000042";
    let intent = decode::decode_calldata(to(), data);

    assert_eq!(intent.signature, "transferFrom(address,address,uint256)");
    assert_eq!(
        intent.args["from"],
        "0x1111111111111111111111111111111111111111"
    );
    assert_eq!(
        intent.args["to"],
        "0x3333333333333333333333333333333333333333"
    );
}

#[test]
fn decodes_set_approval_for_all() {
    let data = "0xa22cb465\
0000000000000000000000003333333333333333333333333333333333333333\
0000000000000000000000000000000000000000000000000000000000000001";
    let intent = decode::decode_calldata(to(), data);

    assert_eq!(intent.signature, "setApprovalForAll(address,bool)");
    assert_eq!(
        intent.args["operator"],
        "0x3333333333333333333333333333333333333333"
    );
    assert_eq!(intent.args["approved"], true);
}

#[test]
fn unknown_selector_is_reported() {
    let data = "0xdeadbeef00000000";
    let intent = decode::decode_calldata(to(), data);

    assert_eq!(intent.signature, "unknown_selector");
    assert_eq!(intent.args["selector"], "0xdeadbeef");
}
