// src/chain/mod.rs
pub mod rpc;

use crate::{domain, util};
use rpc::RpcClient;
use std::time::Duration;
use tokio::time;

#[derive(Clone)]
pub struct ChainClient {
    rpc: RpcClient,
    safe_offset: u64, // usually 1 => latest-1
    budgets: SimulationBudgets,
}

#[derive(Clone, Debug)]
pub struct CodeInfo {
    pub code_hash: String,
    pub code_size_bytes: usize,
    pub is_empty: bool,
}

use crate::domain::LogEntry;

#[derive(Clone, Copy, Debug)]
pub struct SimulationBudgets {
    pub eth_call_timeout_ms: u64,
    pub trace_timeout_ms: u64,
    pub max_trace_depth: usize,
    pub max_trace_size_bytes: usize,
}

impl Default for SimulationBudgets {
    fn default() -> Self {
        Self {
            eth_call_timeout_ms: 10_000,
            trace_timeout_ms: 12_000,
            max_trace_depth: 48,
            max_trace_size_bytes: 2 * 1024 * 1024,
        }
    }
}

/// We decode the debug_traceCall(callTracer) result into:
/// - a root CallFrame (call tree)
/// - optional logs (when tracer supports it / provider includes it)
#[derive(serde::Deserialize)]
struct CallTracerResult {
    #[serde(flatten)]
    frame: crate::domain::CallFrame,
    #[serde(default)]
    logs: Vec<LogEntry>,
}

impl ChainClient {
    pub fn new(rpc_url: String, safe_offset: u64) -> Self {
        Self {
            rpc: RpcClient::new(rpc_url),
            safe_offset,
            budgets: SimulationBudgets::default(),
        }
    }

    pub fn with_budgets(mut self, budgets: SimulationBudgets) -> Self {
        self.budgets = budgets;
        self
    }

    pub fn budgets(&self) -> SimulationBudgets {
        self.budgets
    }

    pub async fn pin_block(&self, requested: Option<u64>) -> Result<u64, rpc::RpcError> {
        if let Some(b) = requested {
            return Ok(b);
        }
        let latest = self.rpc.eth_block_number().await?;
        Ok(latest.saturating_sub(self.safe_offset))
    }

    pub async fn get_code_info(
        &self,
        address: &str,
        block: u64,
    ) -> Result<CodeInfo, rpc::RpcError> {
        let code_hex = self.rpc.eth_get_code(address, block).await?;
        let bytes = util::hex_to_bytes(&code_hex).map_err(rpc::RpcError::Parse)?;

        let size = bytes.len();
        let is_empty = size == 0;
        let code_hash = util::keccak256_0x(&bytes);

        Ok(CodeInfo {
            code_hash,
            code_size_bytes: size,
            is_empty,
        })
    }

    pub async fn code_hash_0x(&self, address: &str, block: u64) -> Result<String, rpc::RpcError> {
        Ok(self.get_code_info(address, block).await?.code_hash)
    }

    pub async fn eth_call_outcome(
        &self,
        from: &str,
        to: &str,
        data: &str,
        value: &str,
        block: u64,
    ) -> domain::EthCallOutcome {
        let timeout_budget = Duration::from_millis(self.budgets.eth_call_timeout_ms.max(1));
        let call_res = time::timeout(
            timeout_budget,
            self.rpc.eth_call(from, to, data, value, block),
        )
        .await;

        let rpc_res = match call_res {
            Ok(v) => v,
            Err(_) => {
                return domain::EthCallOutcome {
                    ok: false,
                    result: None,
                    error_message: Some(format!(
                        "eth_call timeout budget exceeded ({}ms)",
                        self.budgets.eth_call_timeout_ms
                    )),
                    error_data: None,
                    error_class: Some("RPC_TIMEOUT".to_string()),
                    retryable: true,
                    revert_data: None,
                };
            }
        };

        match rpc_res {
            Ok(result) => domain::EthCallOutcome {
                ok: true,
                result: Some(result),
                error_message: None,
                error_data: None,
                error_class: None,
                retryable: false,
                revert_data: None,
            },

            // JSON-RPC error (often contains "execution reverted" + data)
            Err(rpc::RpcError::Rpc { message, data, .. }) => {
                let msg_l = message.to_lowercase();
                let is_revert = msg_l.contains("revert");

                domain::EthCallOutcome {
                    ok: false,
                    result: None,
                    error_message: Some(message),
                    error_data: data.clone(),
                    error_class: Some(
                        if is_revert { "REVERT" } else { "RPC_RESPONSE" }.to_string(),
                    ),
                    retryable: false,
                    revert_data: if is_revert { data } else { None },
                }
            }

            // Timeout => retryable
            Err(rpc::RpcError::HttpTimeout(e)) => domain::EthCallOutcome {
                ok: false,
                result: None,
                error_message: Some(e),
                error_data: None,
                error_class: Some("RPC_TIMEOUT".to_string()),
                retryable: true,
                revert_data: None,
            },

            // Transport => retryable
            Err(rpc::RpcError::HttpTransport(e)) => domain::EthCallOutcome {
                ok: false,
                result: None,
                error_message: Some(e),
                error_data: None,
                error_class: Some("RPC_TRANSPORT".to_string()),
                retryable: true,
                revert_data: None,
            },

            // JSON decode => usually retryable
            Err(rpc::RpcError::Json(e)) => domain::EthCallOutcome {
                ok: false,
                result: None,
                error_message: Some(e),
                error_data: None,
                error_class: Some("RPC_RESPONSE".to_string()),
                retryable: true,
                revert_data: None,
            },

            // Parse => likely our bug / bad input (not retryable)
            Err(rpc::RpcError::Parse(e)) => domain::EthCallOutcome {
                ok: false,
                result: None,
                error_message: Some(e),
                error_data: None,
                error_class: Some("BAD_INPUT".to_string()),
                retryable: false,
                revert_data: None,
            },
        }
    }

    /// ✅ Milestone 6 + 7:
    /// Try to get call tree + logs in one shot.
    ///
    /// Returns:
    /// - Ok(Some((root_call_frame, logs))) if supported
    /// - Ok(None) if tracer unsupported / method not found
    /// - Err(e) for real failures
    pub async fn trace_call_with_logs(
        &self,
        from: &str,
        to: &str,
        data: &str,
        value: &str,
        block: u64,
    ) -> Result<Option<(crate::domain::CallFrame, Vec<LogEntry>)>, rpc::RpcError> {
        let timeout_budget = Duration::from_millis(self.budgets.trace_timeout_ms.max(1));
        let trace_res = time::timeout(
            timeout_budget,
            self.rpc
                .debug_trace_call_calltracer(from, to, data, value, block),
        )
        .await;

        let rpc_res = match trace_res {
            Ok(v) => v,
            Err(_) => {
                return Err(rpc::RpcError::HttpTimeout(format!(
                    "trace timeout budget exceeded ({}ms)",
                    self.budgets.trace_timeout_ms
                )));
            }
        };

        match rpc_res {
            Ok(v) => {
                let parsed: CallTracerResult =
                    serde_json::from_value(v).map_err(|e| rpc::RpcError::Json(e.to_string()))?;
                Ok(Some((parsed.frame, parsed.logs)))
            }

            // method not found / not supported => TRACE_UNAVAILABLE
            Err(e) if rpc::is_method_not_found(&e) => Ok(None),

            Err(e) => Err(e),
        }
    }
}
