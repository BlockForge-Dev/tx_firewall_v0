use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug)]
pub enum RpcError {
    HttpTimeout(String),
    HttpTransport(String),
    Json(String),
    Parse(String),
    Rpc {
        code: i64,
        message: String,
        data: Option<String>,
    },
}

#[derive(Clone)]
pub struct RpcClient {
    url: String,
    client: Client,
}

impl RpcClient {
    pub async fn debug_trace_call_calltracer(
        &self,
        from: &str,
        to: &str,
        data: &str,
        value: &str,
        block: u64,
    ) -> Result<serde_json::Value, RpcError> {
        let block_tag = format!("0x{:x}", block);
        let call_obj = serde_json::json!({
            "from": from,
            "to": to,
            "data": data,
            "value": value
        });

        // Geth tracer config (logs require withLog=true on supported versions)
        let trace_opts = serde_json::json!({
            "tracer": "callTracer",
            "tracerConfig": { "withLog": true }
        });

        self.call(
            "debug_traceCall",
            serde_json::json!([call_obj, block_tag, trace_opts]),
        )
        .await
    }

    pub fn new(url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client build failed");
        Self { url, client }
    }

    async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, RpcError> {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });

        let resp = self
            .client
            .post(&self.url)
            .json(&req)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    RpcError::HttpTimeout(e.to_string())
                } else {
                    RpcError::HttpTransport(e.to_string())
                }
            })?;

        let v: Value = resp
            .json()
            .await
            .map_err(|e| RpcError::Json(e.to_string()))?;

        if let Some(err) = v.get("error") {
            let code = err.get("code").and_then(|x| x.as_i64()).unwrap_or(-1);
            let message = err
                .get("message")
                .and_then(|x| x.as_str())
                .unwrap_or("rpc error")
                .to_string();
            let data = match err.get("data") {
                Some(v) if v.is_string() => v.as_str().map(|s| s.to_string()),
                Some(v) => Some(v.to_string()),
                None => None,
            };

            return Err(RpcError::Rpc {
                code,
                message,
                data,
            });
        }

        let result = v
            .get("result")
            .ok_or_else(|| RpcError::Json("missing result".into()))?;
        serde_json::from_value::<T>(result.clone()).map_err(|e| RpcError::Json(e.to_string()))
    }

    pub async fn eth_block_number(&self) -> Result<u64, RpcError> {
        let hex: String = self.call("eth_blockNumber", json!([])).await?;
        parse_hex_u64(&hex).ok_or_else(|| RpcError::Parse(format!("bad blockNumber: {hex}")))
    }

    pub async fn eth_get_code(&self, address: &str, block: u64) -> Result<String, RpcError> {
        let block_tag = format!("0x{:x}", block);
        self.call("eth_getCode", json!([address, block_tag])).await
    }

    pub async fn eth_call(
        &self,
        from: &str,
        to: &str,
        data: &str,
        value: &str,
        block: u64,
    ) -> Result<String, RpcError> {
        let block_tag = format!("0x{:x}", block);
        let call_obj = json!({
            "from": from,
            "to": to,
            "data": data,
            "value": value
        });
        self.call("eth_call", json!([call_obj, block_tag])).await
    }

    // ✅ Milestone 6: debug_traceCall with callTracer
    pub async fn debug_trace_call(
        &self,
        from: &str,
        to: &str,
        data: &str,
        value: &str,
        block: u64,
    ) -> Result<CallTracerFrame, RpcError> {
        let block_tag = format!("0x{:x}", block);

        let call_obj = json!({
            "from": from,
            "to": to,
            "data": data,
            "value": value
        });

        // callTracer gives a nested call tree
        let opts = json!({
            "tracer": "callTracer",
            "timeout": "10s"
        });

        self.call("debug_traceCall", json!([call_obj, block_tag, opts]))
            .await
    }
}

// debug_traceCall(callTracer) frame shape (nested)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallTracerFrame {
    #[serde(rename = "type")]
    pub typ: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub value: Option<String>,
    pub input: Option<String>,
    pub error: Option<String>,
    pub calls: Option<Vec<CallTracerFrame>>,
}

pub fn is_method_not_found(e: &RpcError) -> bool {
    matches!(e, RpcError::Rpc { code, .. } if *code == -32601)
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    u64::from_str_radix(s, 16).ok()
}
