use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct EvaluateTxRequest {
    pub chain_id: u64,
    pub from: String,
    pub to: String,
    pub data: String,
    pub value: String,
    pub block_number: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct EvaluateTxResponse {
    pub evaluation_id: String,
    pub decision: Decision,
    pub block_ref: String,
    pub receipt: Receipt,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Warn,
    Block,
}

#[derive(Debug, Serialize)]
pub struct Receipt {
    pub summary: String,
    pub intents: Vec<DecodedIntent>,
    pub chain: Option<ChainEvidence>,

    // ✅ Milestone 7 outputs
    #[serde(default)]
    pub permissions_changed: Vec<PermissionChange>,
    #[serde(default)]
    pub transfers: Vec<TransferEvent>,

    pub call_path: Vec<serde_json::Value>,
    pub rules_fired: Vec<serde_json::Value>,
    pub uncertainties: Vec<Uncertainty>,
}

#[derive(Debug, Serialize)]
pub struct ChainEvidence {
    pub pinned_block: u64,
    pub to_code_hash: String,
    pub eth_call: EthCallOutcome,

    // ✅ Milestone 6: tracing info (optional)
    pub trace: Option<TraceSummary>,
}

#[derive(Debug, Serialize)]
pub struct EthCallOutcome {
    pub ok: bool,
    pub result: Option<String>,
    pub error_message: Option<String>,
    pub error_data: Option<String>,
    pub error_class: Option<String>, // "REVERT", "RPC_TIMEOUT", "RPC_TRANSPORT", "RPC_RESPONSE", "BAD_INPUT"
    pub retryable: bool,             // true only for transient RPC failures
    pub revert_data: Option<String>, // only when REVERT
}

#[derive(Debug, Serialize)]
pub struct TraceSummary {
    pub contains_delegatecall: bool,
    pub max_depth: usize,
    pub max_fanout: usize,
    pub call_path_summary: String,

    // optional but useful to keep for later UI
    pub call_tree: CallFrame,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CallFrame {
    pub call_type: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub input: String,
    pub error: Option<String>,
    pub calls: Vec<CallFrame>,
}

impl CallFrame {
    pub fn new(call_type: &str, from: &str, to: &str, value: &str, input: &str) -> Self {
        Self {
            call_type: call_type.to_string(),
            from: from.to_string(),
            to: to.to_string(),
            value: value.to_string(),
            input: input.to_string(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Uncertainty {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct DecodedIntent {
    pub signature: String,
    pub args: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEntry {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct PermissionChange {
    pub kind: String,  // "ERC20_APPROVAL" | "ERC721_APPROVAL_FOR_ALL"
    pub token: String, // contract address emitting the event
    pub owner: String,
    pub spender: String,        // spender or operator
    pub amount: Option<String>, // ERC20 Approval value
    pub approved: Option<bool>, // ApprovalForAll bool
}

#[derive(Debug, Serialize, Clone)]
pub struct TransferEvent {
    pub standard: String, // "ERC20_OR_ERC721" | "ERC1155_SINGLE" | "ERC1155_BATCH"
    pub token: String,    // contract address emitting the event
    pub from: String,
    pub to: String,

    // ERC20 / ERC721
    pub amount_or_token_id: Option<String>,

    // ERC1155
    pub ids: Option<Vec<String>>,
    pub amounts: Option<Vec<String>>,
}
