use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct EvaluateTxRequest {
    pub chain_id: u64,
    pub from: String,
    pub to: String,
    pub data: String,
    pub value: String,
    pub block_number: Option<u64>, // hex quantity like "0x0"
}

#[derive(Debug, Serialize)]
pub struct EvaluateTxResponse {
    pub evaluation_id: String,
    pub decision: Decision,
    pub block_ref: String,
    pub receipt: Receipt,
}

#[derive(Debug, Serialize)]
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
    pub asset_deltas: Vec<serde_json::Value>,
    pub permissions: Vec<serde_json::Value>,
    pub call_path: Vec<serde_json::Value>,
    pub rules_fired: Vec<serde_json::Value>,
    pub uncertainties: Vec<Uncertainty>,
}
#[derive(Debug, Serialize)]
pub struct ChainEvidence {
    pub pinned_block: u64,
    pub to_code_hash: String,
    pub eth_call: EthCallOutcome,
}

#[derive(Debug, Serialize)]
pub struct EthCallOutcome {
    pub ok: bool,
    pub result: Option<String>,
    pub error_message: Option<String>,
    pub error_data: Option<String>,
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
