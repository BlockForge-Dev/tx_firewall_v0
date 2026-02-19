use serde_json::json;

use crate::domain::DecodedIntent;

/// Decode calldata into a human-readable intent.
/// - For known selectors, returns one intent (approve/transfer/etc.)
/// - For multicall(bytes[]), returns one intent that lists subcalls.
/// - Otherwise returns unknown_selector(selector=0x....)
pub fn decode_calldata(to: &str, data: &str) -> DecodedIntent {
    let data_lc = data.to_lowercase();
    let hex = strip_0x(&data_lc);

    // Need at least 4 bytes selector
    if hex.len() < 8 {
        return unknown_intent("0x????????");
    }

    let selector = format!("0x{}", &hex[0..8]);

    match &hex[0..8] {
        // ERC20 approve(address,uint256)
        "095ea7b3" => {
            if let (Some(spender_word), Some(amount_word)) = (word(hex, 0), word(hex, 1)) {
                let spender = decode_address(spender_word);
                let amount = decode_u256_hex_quantity(amount_word);
                let unlimited = is_all_f(amount_word);

                DecodedIntent {
                    signature: "approve(address,uint256)".to_string(),
                    args: json!({
                        "token": to.to_lowercase(),
                        "spender": spender,
                        "amount": amount,
                        "unlimited": unlimited
                    }),
                }
            } else {
                unknown_intent(&selector)
            }
        }

        // ERC20 transfer(address,uint256)
        "a9059cbb" => {
            if let (Some(to_word), Some(amount_word)) = (word(hex, 0), word(hex, 1)) {
                let to_addr = decode_address(to_word);
                let amount = decode_u256_hex_quantity(amount_word);

                DecodedIntent {
                    signature: "transfer(address,uint256)".to_string(),
                    args: json!({
                        "token": to.to_lowercase(),
                        "to": to_addr,
                        "amount": amount
                    }),
                }
            } else {
                unknown_intent(&selector)
            }
        }

        // transferFrom(address,address,uint256) used by ERC20 + ERC721
        "23b872dd" => {
            if let (Some(from_word), Some(to_word), Some(amount_word)) =
                (word(hex, 0), word(hex, 1), word(hex, 2))
            {
                let from_addr = decode_address(from_word);
                let to_addr = decode_address(to_word);
                let amount_or_token_id = decode_u256_hex_quantity(amount_word);

                DecodedIntent {
                    signature: "transferFrom(address,address,uint256)".to_string(),
                    args: json!({
                        "to_contract": to.to_lowercase(),
                        "from": from_addr,
                        "to": to_addr,
                        "value_or_token_id": amount_or_token_id,
                        "note": "This selector is shared by ERC20 and ERC721; without chain calls we label it generically."
                    }),
                }
            } else {
                unknown_intent(&selector)
            }
        }

        // setApprovalForAll(address,bool) used by ERC721 + ERC1155
        "a22cb465" => {
            if let (Some(op_word), Some(approved_word)) = (word(hex, 0), word(hex, 1)) {
                let operator = decode_address(op_word);
                let approved = decode_bool(approved_word);

                DecodedIntent {
                    signature: "setApprovalForAll(address,bool)".to_string(),
                    args: json!({
                        "collection": to.to_lowercase(),
                        "operator": operator,
                        "approved": approved
                    }),
                }
            } else {
                unknown_intent(&selector)
            }
        }

        // ERC721 safeTransferFrom(address,address,uint256)
        "42842e0e" => {
            if let (Some(from_word), Some(to_word), Some(id_word)) =
                (word(hex, 0), word(hex, 1), word(hex, 2))
            {
                DecodedIntent {
                    signature: "safeTransferFrom(address,address,uint256)".to_string(),
                    args: json!({
                        "collection": to.to_lowercase(),
                        "from": decode_address(from_word),
                        "to": decode_address(to_word),
                        "token_id": decode_u256_hex_quantity(id_word)
                    }),
                }
            } else {
                unknown_intent(&selector)
            }
        }

        // ERC721 safeTransferFrom(address,address,uint256,bytes)
        "b88d4fde" => {
            if let (Some(from_word), Some(to_word), Some(id_word), Some(offset_word)) =
                (word(hex, 0), word(hex, 1), word(hex, 2), word(hex, 3))
            {
                let bytes_len = decode_dynamic_bytes_len(hex, offset_word).unwrap_or(0);

                DecodedIntent {
                    signature: "safeTransferFrom(address,address,uint256,bytes)".to_string(),
                    args: json!({
                        "collection": to.to_lowercase(),
                        "from": decode_address(from_word),
                        "to": decode_address(to_word),
                        "token_id": decode_u256_hex_quantity(id_word),
                        "data_len": bytes_len
                    }),
                }
            } else {
                unknown_intent(&selector)
            }
        }

        // ERC1155 safeTransferFrom(address,address,uint256,uint256,bytes)
        "f242432a" => {
            if let (
                Some(from_word),
                Some(to_word),
                Some(id_word),
                Some(amount_word),
                Some(offset_word),
            ) = (
                word(hex, 0),
                word(hex, 1),
                word(hex, 2),
                word(hex, 3),
                word(hex, 4),
            ) {
                let bytes_len = decode_dynamic_bytes_len(hex, offset_word).unwrap_or(0);

                DecodedIntent {
                    signature: "safeTransferFrom(address,address,uint256,uint256,bytes)"
                        .to_string(),
                    args: json!({
                        "collection": to.to_lowercase(),
                        "from": decode_address(from_word),
                        "to": decode_address(to_word),
                        "id": decode_u256_hex_quantity(id_word),
                        "amount": decode_u256_hex_quantity(amount_word),
                        "data_len": bytes_len
                    }),
                }
            } else {
                unknown_intent(&selector)
            }
        }

        // Uniswap V3 multicall(bytes[])
        "5ae401dc" => decode_multicall_bytes_array(hex),

        _ => {
            // Try registry name for nicer unknowns
            let name = signature_registry_name(&selector);
            if let Some(sig) = name {
                DecodedIntent {
                    signature: sig.to_string(),
                    args: json!({
                        "to_contract": to.to_lowercase(),
                        "note": "Known selector, args decoding not implemented for this signature yet."
                    }),
                }
            } else {
                unknown_intent(&selector)
            }
        }
    }
}

// ----------------- helpers -----------------

fn unknown_intent(selector: &str) -> DecodedIntent {
    DecodedIntent {
        signature: "unknown_selector".to_string(),
        args: json!({ "selector": selector }),
    }
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

/// word index i after selector (i=0 is first param word)
fn word(hex: &str, i: usize) -> Option<&str> {
    let start = 8 + i * 64;
    let end = start + 64;
    if hex.len() < end {
        None
    } else {
        Some(&hex[start..end])
    }
}

fn decode_address(word64: &str) -> String {
    // address is last 20 bytes = 40 hex chars
    format!("0x{}", &word64[24..64])
}

fn decode_bool(word64: &str) -> bool {
    // last byte (2 hex chars)
    let last = &word64[62..64];
    u8::from_str_radix(last, 16).unwrap_or(0) != 0
}

fn decode_u256_hex_quantity(word64: &str) -> String {
    let trimmed = word64.trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".to_string()
    } else {
        format!("0x{}", trimmed)
    }
}

fn is_all_f(word64: &str) -> bool {
    word64.chars().all(|c| c == 'f')
}

/// offset_word is a 32-byte word containing an offset (bytes) from start of args (after selector)
fn decode_dynamic_bytes_len(hex: &str, offset_word: &str) -> Option<usize> {
    let offset = decode_usize_u256(offset_word)?;
    let args_start = 8; // after selector in hex string
    let dyn_start = args_start + offset * 2; // offset bytes -> hex chars
                                             // length word at dyn_start
    let len_word = hex.get(dyn_start..dyn_start + 64)?;
    let len = decode_usize_u256(len_word)?;
    Some(len)
}

fn decode_usize_u256(word64: &str) -> Option<usize> {
    // For MVP: parse as u128, clamp to usize
    let trimmed = word64.trim_start_matches('0');
    if trimmed.is_empty() {
        return Some(0);
    }
    let val = u128::from_str_radix(trimmed, 16).ok()?;
    usize::try_from(val).ok()
}

fn decode_multicall_bytes_array(hex: &str) -> DecodedIntent {
    // multicall(bytes[]) encoding:
    // selector + offset_to_array(32 bytes)
    // array: length N, then N offsets, then each bytes element (len + data padded)
    let offset_word = match word(hex, 0) {
        Some(w) => w,
        None => return unknown_intent("0x5ae401dc"),
    };

    let offset = match decode_usize_u256(offset_word) {
        Some(v) => v,
        None => return unknown_intent("0x5ae401dc"),
    };

    let args_start = 8;
    let array_start = args_start + offset * 2;

    let n_word = match hex.get(array_start..array_start + 64) {
        Some(w) => w,
        None => return unknown_intent("0x5ae401dc"),
    };

    let n = decode_usize_u256(n_word).unwrap_or(0);
    let n = n.min(32); // budget

    let mut subcalls = Vec::new();

    // offsets start immediately after length word
    let offsets_start = array_start + 64;
    for i in 0..n {
        let off_i = match hex.get(offsets_start + i * 64..offsets_start + (i + 1) * 64) {
            Some(w) => w,
            None => break,
        };
        let elem_off = match decode_usize_u256(off_i) {
            Some(v) => v,
            None => break,
        };

        let elem_start = array_start + elem_off * 2;
        let elem_len_word = match hex.get(elem_start..elem_start + 64) {
            Some(w) => w,
            None => break,
        };
        let elem_len = decode_usize_u256(elem_len_word).unwrap_or(0);
        let elem_data_start = elem_start + 64;
        let elem_data_hex_len = elem_len * 2;

        let elem_data = match hex.get(elem_data_start..elem_data_start + elem_data_hex_len) {
            Some(d) => d,
            None => break,
        };

        let sel = if elem_data.len() >= 8 {
            format!("0x{}", &elem_data[0..8])
        } else {
            "0x????????".to_string()
        };

        let sig = signature_registry_name(&sel).unwrap_or("unknown_selector");

        subcalls.push(json!({
            "selector": sel,
            "signature": sig
        }));
    }

    DecodedIntent {
        signature: "multicall(bytes[])".to_string(),
        args: json!({
            "count": subcalls.len(),
            "subcalls": subcalls
        }),
    }
}

/// Minimal signature registry (selector -> signature)
fn signature_registry_name(selector: &str) -> Option<&'static str> {
    match selector {
        "0x095ea7b3" => Some("approve(address,uint256)"),
        "0xa9059cbb" => Some("transfer(address,uint256)"),
        "0x23b872dd" => Some("transferFrom(address,address,uint256)"),
        "0xa22cb465" => Some("setApprovalForAll(address,bool)"),
        "0x42842e0e" => Some("safeTransferFrom(address,address,uint256)"),
        "0xb88d4fde" => Some("safeTransferFrom(address,address,uint256,bytes)"),
        "0xf242432a" => Some("safeTransferFrom(address,address,uint256,uint256,bytes)"),
        "0x5ae401dc" => Some("multicall(bytes[])"),
        _ => None,
    }
}
