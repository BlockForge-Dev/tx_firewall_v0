pub mod handlers;

use axum::routing::{get, post};
use axum::Router;

use crate::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/v1/evaluate/tx", post(handlers::evaluate_tx))
        .with_state(state)
}
