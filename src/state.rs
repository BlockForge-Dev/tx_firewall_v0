use crate::{domain::Uncertainty, util};

/// Minimal state lookups for Milestone 10.
///
/// NOTE:
/// - We return hex quantities as strings ("0x...") to match your existing style.
/// - All lookups are "best effort". Failures -> uncertainty entries.

pub fn selector(sig: &str) -> [u8; 4] {
    let h = util::keccak256(sig.as_bytes()); // if you don't have this, I’ll give you a fallback below
    [h[0], h[1], h[2], h[3]]
}

// allowance(address,address)
pub fn calldata_allowance(owner: &str, spender: &str) -> Option<String> {
    let sel = selector("allowance(address,address)");
    let mut out = Vec::with_capacity(4 + 32 + 32);
    out.extend_from_slice(&sel);
    out.extend_from_slice(&encode_address_word(owner)?);
    out.extend_from_slice(&encode_address_word(spender)?);
    Some(format!("0x{}", hex::encode(out)))
}

// isApprovedForAll(address,address)
pub fn calldata_is_approved_for_all(owner: &str, operator: &str) -> Option<String> {
    let sel = selector("isApprovedForAll(address,address)");
    let mut out = Vec::with_capacity(4 + 32 + 32);
    out.extend_from_slice(&sel);
    out.extend_from_slice(&encode_address_word(owner)?);
    out.extend_from_slice(&encode_address_word(operator)?);
    Some(format!("0x{}", hex::encode(out)))
}

// Decode a 32-byte return value as uint256 (hex quantity)
pub fn decode_u256_return(data: &str) -> Option<String> {
    let bytes = util::hex_to_bytes(data).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    let word = &bytes[bytes.len() - 32..]; // last 32 bytes
    Some(normalize_u256_word(word))
}

// Decode a 32-byte return as bool (0 or 1)
pub fn decode_bool_return(data: &str) -> Option<bool> {
    let bytes = util::hex_to_bytes(data).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    Some(bytes[bytes.len() - 1] == 1u8)
}

fn encode_address_word(addr: &str) -> Option<[u8; 32]> {
    let a = addr.trim().to_lowercase();
    let a = a.strip_prefix("0x").unwrap_or(&a);
    if a.len() != 40 {
        return None;
    }
    let mut word = [0u8; 32];
    let raw = hex::decode(a).ok()?;
    // address goes in last 20 bytes
    word[12..].copy_from_slice(&raw);
    Some(word)
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
