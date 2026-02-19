use sha2::{Digest, Sha256};
use sha3::Keccak256;
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let out = hasher.finalize();
    hex::encode(out)
}

pub fn is_address(s: &str) -> bool {
    // 0x + 40 hex chars = 42 total
    if s.len() != 42 {
        return false;
    }
    if !s.starts_with("0x") && !s.starts_with("0X") {
        return false;
    }
    s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

pub fn is_hex_data(s: &str) -> bool {
    if !s.starts_with("0x") && !s.starts_with("0X") {
        return false;
    }
    let hexpart = &s[2..];
    if hexpart.len() % 2 != 0 {
        return false;
    }
    hexpart.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn is_hex_quantity(s: &str) -> bool {
    if !s.starts_with("0x") && !s.starts_with("0X") {
        return false;
    }
    let hexpart = &s[2..];
    if hexpart.is_empty() {
        return false;
    }
    hexpart.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn normalize_hex_quantity(s: &str) -> String {
    // Normalize: lowercase, strip leading zeros after 0x, ensure at least "0x0"
    let s = s.to_lowercase();
    let hexpart = &s[2..];
    let trimmed = hexpart.trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".to_string()
    } else {
        format!("0x{}", trimmed)
    }
}

pub fn hex_to_bytes(hexstr: &str) -> Result<Vec<u8>, String> {
    let s = hexstr
        .strip_prefix("0x")
        .or_else(|| hexstr.strip_prefix("0X"))
        .unwrap_or(hexstr);
    if s.is_empty() {
        return Ok(vec![]);
    }
    hex::decode(s).map_err(|e| e.to_string())
}

pub fn keccak256_0x(bytes: &[u8]) -> String {
    let mut h = Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    format!("0x{}", hex::encode(out))
}
