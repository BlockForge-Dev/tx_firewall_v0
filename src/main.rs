use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    use tx_firewall_v0::{
        api,
        audit::AuditLogger,
        auth::ApiAuth,
        chain::{self, SimulationBudgets},
        management::ControlPlane,
        observability::SloConfig,
        safety::{FailClosedMode, RateLimitConfig, RateLimiter, TenantQuotaStore},
        AppState,
    };

    let sim_budgets = SimulationBudgets {
        eth_call_timeout_ms: env_u64("ETH_CALL_TIMEOUT_MS", 10_000),
        trace_timeout_ms: env_u64("TRACE_TIMEOUT_MS", 12_000),
        max_trace_depth: env_usize("MAX_TRACE_DEPTH", 48),
        max_trace_size_bytes: env_usize("MAX_TRACE_SIZE_BYTES", 2 * 1024 * 1024),
    };

    let chain_client = std::env::var("RPC_URL")
        .ok()
        .map(|url| chain::ChainClient::new(url, 1).with_budgets(sim_budgets));

    let mut state = AppState::new("latest-1".to_string(), chain_client);
    let default_rl_cfg = RateLimitConfig {
        requests_per_window: env_u32("RATE_LIMIT_REQUESTS_PER_WINDOW", 120),
        window_secs: env_u64("RATE_LIMIT_WINDOW_SECS", 60),
        max_clients: env_usize("RATE_LIMIT_MAX_CLIENTS", 10_000),
    };
    state.rate_limiter = RateLimiter::from_env(default_rl_cfg);
    tracing::info!(
        rate_limit_backend = state.rate_limiter.backend_name(),
        "rate limiter initialized"
    );
    state.tenant_quotas = TenantQuotaStore::new(default_rl_cfg);
    let loaded = state.tenant_quotas.load_from_env().await;
    tracing::info!(tenant_quota_overrides = loaded, "tenant quotas loaded");
    state.fail_closed_mode = FailClosedMode::from_env(
        &std::env::var("FAIL_CLOSED_MODE").unwrap_or_else(|_| "warn".to_string()),
    );
    state.auth = ApiAuth::from_env();
    state.control_plane = ControlPlane::from_env(default_rl_cfg).await;
    state
        .control_plane
        .apply_to_runtime(&state.auth, &state.tenant_quotas)
        .await;
    state.slo_config = SloConfig::from_env();
    tracing::info!(
        control_plane_enabled = state.control_plane.is_enabled(),
        slo_window_secs = state.slo_config.window_secs,
        slo_min_samples = state.slo_config.min_samples,
        "control plane initialized"
    );
    state.audit = AuditLogger::from_env();
    state.max_request_body_bytes = env_usize("MAX_REQUEST_BODY_BYTES", 64 * 1024);

    let app = api::router(state).layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));
    tracing::info!("listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}
