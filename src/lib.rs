pub mod api;
pub mod chain;
pub mod decode;
pub mod domain;
pub mod pipeline;
pub mod util;

#[derive(Clone)]
pub struct AppState {
    pub default_block_ref: String,
    pub chain: Option<chain::ChainClient>,
}
