// src/reverts.rs
//
// Minimal revert reason decoder for EVM revert data.
// Supports Solidity ABI error: Error(string) selector 0x08c379a0

pub fn decode_revert_reason(revert_data: &str) -> Option<String> {
    const ERROR_STRING_SELECTOR: &str = "0x08c379a0";

    let s = revert_data.trim();
    if !s.starts_with(ERROR_STRING_SELECTOR) {
        return None;
    }

    let hex = s.strip_prefix("0x")?;

    // selector(8) + offset(64) + len(64)
    if hex.len() < (8 + 64 + 64) {
        return None;
    }

    let len_hex = &hex[72..136];
    let len_u64 = u64::from_str_radix(len_hex, 16).ok()?;
    let len = usize::try_from(len_u64).ok()?;

    let data_start = 136;
    let data_end = data_start + (len * 2);
    if hex.len() < data_end {
        return None;
    }

    let bytes_hex = &hex[data_start..data_end];
    let bytes = hex_to_bytes(bytes_hex)?;

    String::from_utf8(bytes).ok()
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let b = u8::from_str_radix(&hex[i..i + 2], 16).ok()?;
        out.push(b);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::decode_revert_reason;

    #[test]
    fn returns_none_for_non_error_string_selector() {
        assert!(decode_revert_reason("0xdeadbeef").is_none());
    }

    #[test]
    fn decodes_uniswap_example() {
        let data = "0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000025556e697377617056323a20494e53554646494349454e545f4f55545055545f414d4f554e54000000000000000000000000000000000000000000000000000000";
        let reason = decode_revert_reason(data).expect("should decode");
        assert_eq!(reason, "UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT");
    }
}
