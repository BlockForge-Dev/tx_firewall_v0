pub mod api;
pub mod audit;
pub mod auth;
pub mod chain;
pub mod decode;
pub mod domain;
pub mod effects;
pub mod management;
pub mod observability;
pub mod pipeline;
pub mod policy;
pub mod reverts;
pub mod safety;
pub mod trace;
pub mod util;
#[derive(Clone)]
pub struct AppState {
    pub default_block_ref: String,
    pub chain: Option<chain::ChainClient>,
    pub rate_limiter: safety::RateLimiter,
    pub tenant_quotas: safety::TenantQuotaStore,
    pub fail_closed_mode: safety::FailClosedMode,
    pub metrics: observability::MetricsRegistry,
    pub slo_config: observability::SloConfig,
    pub auth: auth::ApiAuth,
    pub audit: audit::AuditLogger,
    pub control_plane: management::ControlPlane,
    pub max_request_body_bytes: usize,
}

impl AppState {
    pub fn new(default_block_ref: String, chain: Option<chain::ChainClient>) -> Self {
        let default_rl_cfg = safety::RateLimitConfig::default();
        let auth = auth::ApiAuth::disabled();
        let tenant_quotas = safety::TenantQuotaStore::new(default_rl_cfg);
        Self {
            default_block_ref,
            chain,
            rate_limiter: safety::RateLimiter::new(default_rl_cfg),
            tenant_quotas: tenant_quotas.clone(),
            fail_closed_mode: safety::FailClosedMode::Warn,
            metrics: observability::MetricsRegistry::new(),
            slo_config: observability::SloConfig::default(),
            auth: auth.clone(),
            audit: audit::AuditLogger::disabled(),
            control_plane: management::ControlPlane::disabled(default_rl_cfg),
            max_request_body_bytes: 64 * 1024,
        }
    }
}
