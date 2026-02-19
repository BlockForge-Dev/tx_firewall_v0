use tx_firewall_v0::decode;

fn to() -> &'static str {
    "0x2222222222222222222222222222222222222222"
}

// ---- helpers for ABI encoding (minimal) ----

fn strip_0x(addr: &str) -> &str {
    addr.strip_prefix("0x").unwrap_or(addr)
}

// 32-byte ABI word for an address (right-aligned)
fn addr_word(addr: &str) -> String {
    let a = strip_0x(addr).to_lowercase();
    assert_eq!(a.len(), 40, "address must be 20 bytes (40 hex chars)");
    format!("{}{}", "0".repeat(24), a) // 24 zeros + 40 addr hex = 64
}

// 32-byte ABI word for a u256 from u64 (big-endian, padded)
fn u256_word_u64(v: u64) -> String {
    format!("{:064x}", v)
}

// ABI bytes padding (to 32-byte multiple)
fn pad_bytes(len: usize) -> String {
    let padded = ((len + 31) / 32) * 32;
    let pad_len = padded - len;
    "00".repeat(pad_len)
}

#[test]
fn decodes_erc721_safe_transfer_from_3args() {
    // selector: 0x42842e0e
    // safeTransferFrom(address from, address to, uint256 tokenId)
    let from = "0x1111111111111111111111111111111111111111";
    let to_addr = "0x3333333333333333333333333333333333333333";
    let token_id = 0x2a_u64;

    let data = format!(
        "0x{}{}{}{}",
        "42842e0e",
        addr_word(from),
        addr_word(to_addr),
        u256_word_u64(token_id),
    );

    let intent = decode::decode_calldata(to(), &data);

    assert_eq!(
        intent.signature,
        "safeTransferFrom(address,address,uint256)"
    );
    assert_eq!(intent.args["from"], from.to_lowercase());
    assert_eq!(intent.args["to"], to_addr.to_lowercase());
    assert_eq!(intent.args["token_id"], "0x2a");
}

#[test]
fn decodes_erc721_safe_transfer_from_bytes_empty() {
    // selector: 0xb88d4fde
    // safeTransferFrom(address from, address to, uint256 tokenId, bytes data)
    // We'll encode data as empty bytes:
    // offset = 0x80 (128) because 4 static words = 4*32 bytes
    // dynamic part = [len=0]
    let from = "0x1111111111111111111111111111111111111111";
    let to_addr = "0x3333333333333333333333333333333333333333";
    let token_id = 0x2a_u64;

    let offset = 128_u64; // 0x80
    let dyn_len = 0_u64;

    let data = format!(
        "0x{}{}{}{}{}{}",
        "b88d4fde",
        addr_word(from),
        addr_word(to_addr),
        u256_word_u64(token_id),
        u256_word_u64(offset),
        u256_word_u64(dyn_len), // bytes length = 0
    );

    let intent = decode::decode_calldata(to(), &data);

    assert_eq!(
        intent.signature,
        "safeTransferFrom(address,address,uint256,bytes)"
    );
    assert_eq!(intent.args["from"], from.to_lowercase());
    assert_eq!(intent.args["to"], to_addr.to_lowercase());
    assert_eq!(intent.args["token_id"], "0x2a");
    assert_eq!(intent.args["data_len"], 0);
}

#[test]
fn decodes_erc1155_safe_transfer_from_bytes_empty() {
    // selector: 0xf242432a
    // safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes data)
    // empty bytes:
    // offset = 0xa0 (160) because 5 static words = 5*32 bytes
    // dynamic part = [len=0]
    let from = "0x1111111111111111111111111111111111111111";
    let to_addr = "0x3333333333333333333333333333333333333333";
    let id = 0x7_u64;
    let amount = 0x5_u64;

    let offset = 160_u64; // 0xa0
    let dyn_len = 0_u64;

    let data = format!(
        "0x{}{}{}{}{}{}{}",
        "f242432a",
        addr_word(from),
        addr_word(to_addr),
        u256_word_u64(id),
        u256_word_u64(amount),
        u256_word_u64(offset),
        u256_word_u64(dyn_len), // bytes length = 0
    );

    let intent = decode::decode_calldata(to(), &data);

    assert_eq!(
        intent.signature,
        "safeTransferFrom(address,address,uint256,uint256,bytes)"
    );
    assert_eq!(intent.args["from"], from.to_lowercase());
    assert_eq!(intent.args["to"], to_addr.to_lowercase());
    assert_eq!(intent.args["id"], "0x7");
    assert_eq!(intent.args["amount"], "0x5");
    assert_eq!(intent.args["data_len"], 0);
}

#[test]
fn decodes_multicall_lists_subcalls() {
    // selector: 0x5ae401dc  (multicall(bytes[]))
    // We'll build multicall with 2 subcalls:
    //  1) approve(address,uint256)   selector 0x095ea7b3
    //  2) transfer(address,uint256)  selector 0xa9059cbb
    //
    // ABI layout:
    // selector + offset_to_array (0x20)
    // array: len=2, offsets[0]=0x60, offsets[1]=0xe0
    // elem0: len=0x44 (68 bytes), data(padded)
    // elem1: len=0x44 (68 bytes), data(padded)

    // subcall 1: approve(spender, amount)
    let spender = "0x3333333333333333333333333333333333333333";
    let amount1 = 0x5_u64;

    let sub1 = format!(
        "{}{}{}",
        "095ea7b3",
        addr_word(spender),
        u256_word_u64(amount1)
    );
    let sub1_len_bytes = sub1.len() / 2;
    assert_eq!(sub1_len_bytes, 68);
    let sub1_padded = format!("{}{}", sub1, pad_bytes(sub1_len_bytes));

    // subcall 2: transfer(to, amount)
    let to_addr = "0x1111111111111111111111111111111111111111";
    let amount2 = 0xa_u64;

    let sub2 = format!(
        "{}{}{}",
        "a9059cbb",
        addr_word(to_addr),
        u256_word_u64(amount2)
    );
    let sub2_len_bytes = sub2.len() / 2;
    assert_eq!(sub2_len_bytes, 68);
    let sub2_padded = format!("{}{}", sub2, pad_bytes(sub2_len_bytes));

    // multicall encoding pieces
    let offset_to_array = u256_word_u64(32); // 0x20
    let array_len = u256_word_u64(2);

    // offsets relative to array_start (where array_len word begins)
    let off0 = u256_word_u64(96); // 0x60 (after len + 2 offsets = 3 words = 96 bytes)
    let off1 = u256_word_u64(224); // 0xe0 (0x60 + elem0_size(128))

    // element encoding: [len word][data padded]
    let elem_len = u256_word_u64(68); // 0x44

    let elem0 = format!("{}{}", elem_len, sub1_padded);
    let elem1 = format!("{}{}", elem_len, sub2_padded);

    let data = format!(
        "0x{}{}{}{}{}{}{}",
        "5ae401dc", offset_to_array, array_len, off0, off1, elem0, elem1
    );

    let intent = decode::decode_calldata(to(), &data);

    assert_eq!(intent.signature, "multicall(bytes[])");
    assert_eq!(intent.args["count"], 2);

    let subcalls = intent.args["subcalls"].as_array().unwrap();
    assert_eq!(subcalls.len(), 2);

    assert_eq!(subcalls[0]["selector"], "0x095ea7b3");
    assert_eq!(subcalls[0]["signature"], "approve(address,uint256)");

    assert_eq!(subcalls[1]["selector"], "0xa9059cbb");
    assert_eq!(subcalls[1]["signature"], "transfer(address,uint256)");
}
