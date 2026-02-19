pub mod rpc;

use crate::util;
use rpc::RpcClient;

#[derive(Clone)]
pub struct ChainClient {
    rpc: RpcClient,
    safe_offset: u64, // usually 1 => latest-1
}

#[derive(Clone, Debug)]
pub struct CodeInfo {
    pub code_hash: String,
    pub code_size_bytes: usize,
    pub is_empty: bool,
}

impl ChainClient {
    pub fn new(rpc_url: String, safe_offset: u64) -> Self {
        Self {
            rpc: RpcClient::new(rpc_url),
            safe_offset,
        }
    }

    pub async fn pin_block(&self, requested: Option<u64>) -> Result<u64, rpc::RpcError> {
        if let Some(b) = requested {
            return Ok(b);
        }
        let latest = self.rpc.eth_block_number().await?;
        Ok(latest.saturating_sub(self.safe_offset))
    }

    // ✅ NEW: fetch code, compute hash, and expose if it's empty
    pub async fn get_code_info(
        &self,
        address: &str,
        block: u64,
    ) -> Result<CodeInfo, rpc::RpcError> {
        let code_hex = self.rpc.eth_get_code(address, block).await?;
        let bytes = util::hex_to_bytes(&code_hex).map_err(|e| rpc::RpcError::Parse(e))?;

        let size = bytes.len();
        let is_empty = size == 0;
        let code_hash = util::keccak256_0x(&bytes);

        Ok(CodeInfo {
            code_hash,
            code_size_bytes: size,
            is_empty,
        })
    }

    // Keep old helper for callers that only want the hash
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
    ) -> Result<crate::domain::EthCallOutcome, rpc::RpcError> {
        match self.rpc.eth_call(from, to, data, value, block).await {
            Ok(result) => Ok(crate::domain::EthCallOutcome {
                ok: true,
                result: Some(result),
                error_message: None,
                error_data: None,
            }),
            Err(rpc::RpcError::Rpc { message, data, .. }) => Ok(crate::domain::EthCallOutcome {
                ok: false,
                result: None,
                error_message: Some(message),
                error_data: data,
            }),
            Err(e) => Err(e),
        }
    }
}
