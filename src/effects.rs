use crate::domain::{LogEntry, PermissionChange, TransferEvent};
use crate::util;

// keccak256(eventSignature)
const TOPIC_TRANSFER: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const TOPIC_APPROVAL: &str = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const TOPIC_APPROVAL_FOR_ALL: &str =
    "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31";
const TOPIC_ERC1155_SINGLE: &str =
    "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62";
const TOPIC_ERC1155_BATCH: &str =
    "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb";

pub fn extract_effects(logs: &[LogEntry]) -> (Vec<PermissionChange>, Vec<TransferEvent>) {
    let mut perms = Vec::new();
    let mut transfers = Vec::new();

    for l in logs {
        let topic0 = match l.topics.get(0) {
            Some(t) => t.as_str(),
            None => continue,
        };

        match topic0 {
            TOPIC_APPROVAL => {
                // Approval(address owner, address spender, uint256 value)
                if l.topics.len() < 3 {
                    continue;
                }
                let owner = match topic_to_address(&l.topics[1]) {
                    Some(a) => a,
                    None => continue,
                };
                let spender = match topic_to_address(&l.topics[2]) {
                    Some(a) => a,
                    None => continue,
                };
                let amount = data_u256_word(&l.data, 0);

                perms.push(PermissionChange {
                    kind: "ERC20_APPROVAL".to_string(),
                    token: l.address.clone(),
                    owner,
                    spender,
                    amount,
                    approved: None,
                });
            }

            TOPIC_APPROVAL_FOR_ALL => {
                // ApprovalForAll(address owner, address operator, bool approved)
                if l.topics.len() < 3 {
                    continue;
                }
                let owner = match topic_to_address(&l.topics[1]) {
                    Some(a) => a,
                    None => continue,
                };
                let operator = match topic_to_address(&l.topics[2]) {
                    Some(a) => a,
                    None => continue,
                };
                let approved = data_bool_word0(&l.data);

                perms.push(PermissionChange {
                    kind: "ERC721_APPROVAL_FOR_ALL".to_string(),
                    token: l.address.clone(),
                    owner,
                    spender: operator,
                    amount: None,
                    approved,
                });
            }

            TOPIC_TRANSFER => {
                // Transfer(address from, address to, uint256 valueOrTokenId)
                if l.topics.len() < 3 {
                    continue;
                }
                let from = match topic_to_address(&l.topics[1]) {
                    Some(a) => a,
                    None => continue,
                };
                let to = match topic_to_address(&l.topics[2]) {
                    Some(a) => a,
                    None => continue,
                };
                let v = data_u256_word(&l.data, 0);

                transfers.push(TransferEvent {
                    standard: "ERC20_OR_ERC721".to_string(),
                    token: l.address.clone(),
                    from,
                    to,
                    amount_or_token_id: v,
                    ids: None,
                    amounts: None,
                });
            }

            TOPIC_ERC1155_SINGLE => {
                // TransferSingle(address operator, address from, address to, uint256 id, uint256 value)
                if l.topics.len() < 4 {
                    continue;
                }
                let from = match topic_to_address(&l.topics[2]) {
                    Some(a) => a,
                    None => continue,
                };
                let to = match topic_to_address(&l.topics[3]) {
                    Some(a) => a,
                    None => continue,
                };
                let id = data_u256_word(&l.data, 0);
                let value = data_u256_word(&l.data, 1);

                transfers.push(TransferEvent {
                    standard: "ERC1155_SINGLE".to_string(),
                    token: l.address.clone(),
                    from,
                    to,
                    amount_or_token_id: None,
                    ids: id.map(|x| vec![x]),
                    amounts: value.map(|x| vec![x]),
                });
            }

            TOPIC_ERC1155_BATCH => {
                // TransferBatch(address operator, address from, address to, uint256[] ids, uint256[] values)
                if l.topics.len() < 4 {
                    continue;
                }
                let from = match topic_to_address(&l.topics[2]) {
                    Some(a) => a,
                    None => continue,
                };
                let to = match topic_to_address(&l.topics[3]) {
                    Some(a) => a,
                    None => continue,
                };

                if let Some((ids, amounts)) = decode_erc1155_batch_arrays(&l.data) {
                    transfers.push(TransferEvent {
                        standard: "ERC1155_BATCH".to_string(),
                        token: l.address.clone(),
                        from,
                        to,
                        amount_or_token_id: None,
                        ids: Some(ids),
                        amounts: Some(amounts),
                    });
                }
            }

            _ => {}
        }
    }

    (perms, transfers)
}

// ---------- helpers ----------

fn topic_to_address(topic32: &str) -> Option<String> {
    let t = topic32.strip_prefix("0x")?;
    if t.len() != 64 {
        return None;
    }
    let addr = &t[24..]; // last 40 hex chars
    Some(format!("0x{}", addr.to_lowercase()))
}

fn data_u256_word(data: &str, word_index: usize) -> Option<String> {
    let bytes = util::hex_to_bytes(data).ok()?;
    let start = word_index.checked_mul(32)?;
    let end = start.checked_add(32)?;
    if end > bytes.len() {
        return None;
    }
    let word = &bytes[start..end];
    Some(normalize_u256_word(word))
}

fn normalize_u256_word(word32: &[u8]) -> String {
    // keep "0x" quantity form (strip leading zeros but keep at least one digit)
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

fn data_bool_word0(data: &str) -> Option<bool> {
    let bytes = util::hex_to_bytes(data).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    Some(bytes[31] == 1u8)
}

// ABI for TransferBatch data = [offset_ids, offset_values, ...dynamic...]
fn decode_erc1155_batch_arrays(data: &str) -> Option<(Vec<String>, Vec<String>)> {
    let b = util::hex_to_bytes(data).ok()?;
    if b.len() < 64 {
        return None;
    }

    let off_ids = read_u256_as_usize(&b, 0)?;
    let off_vals = read_u256_as_usize(&b, 32)?;

    let ids = read_u256_array(&b, off_ids)?;
    let vals = read_u256_array(&b, off_vals)?;
    Some((ids, vals))
}

fn read_u256_as_usize(b: &[u8], start: usize) -> Option<usize> {
    let end = start.checked_add(32)?;
    if end > b.len() {
        return None;
    }
    // take last 8 bytes as usize (safe for typical traces)
    let tail = &b[end - 8..end];
    let mut n: u64 = 0;
    for x in tail {
        n = (n << 8) | (*x as u64);
    }
    Some(n as usize)
}

fn read_u256_array(b: &[u8], offset: usize) -> Option<Vec<String>> {
    if offset + 32 > b.len() {
        return None;
    }
    let len = read_u256_as_usize(b, offset)?;
    let mut out = Vec::with_capacity(len);
    let mut cursor = offset + 32;

    for _ in 0..len {
        if cursor + 32 > b.len() {
            return None;
        }
        out.push(normalize_u256_word(&b[cursor..cursor + 32]));
        cursor += 32;
    }
    Some(out)
}
