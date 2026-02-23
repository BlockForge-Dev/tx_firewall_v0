pub mod handlers;

use axum::routing::{get, post};
use axum::{extract::DefaultBodyLimit, Router};

use crate::AppState;

pub fn router(state: AppState) -> Router {
    let max_body = state.max_request_body_bytes;
    Router::new()
        .route("/health", get(handlers::health))
        .route("/metrics", get(handlers::metrics))
        .route("/v1/ops/slo", get(handlers::ops_slo))
        .route("/v1/evaluate/tx", post(handlers::evaluate_tx))
        .route("/v1/admin/config", get(handlers::admin_get_config))
        .route("/v1/admin/keys/upsert", post(handlers::admin_upsert_key))
        .route("/v1/admin/keys/disable", post(handlers::admin_disable_key))
        .route("/v1/admin/keys/delete", post(handlers::admin_delete_key))
        .route(
            "/v1/admin/quotas/upsert",
            post(handlers::admin_upsert_quota),
        )
        .route(
            "/v1/admin/quotas/delete",
            post(handlers::admin_delete_quota),
        )
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}
