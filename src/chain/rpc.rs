use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug)]
pub enum RpcError {
    Http(String),
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
    pub fn new(url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client build failed");
        Self { url, client }
    }

    async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, RpcError> {
        // simple monotonic id: ok for a single process
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
            .map_err(|e| RpcError::Http(e.to_string()))?;

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
            let data = err
                .get("data")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
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
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    u64::from_str_radix(s, 16).ok()
}
