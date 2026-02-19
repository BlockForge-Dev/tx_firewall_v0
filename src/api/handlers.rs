use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use uuid::Uuid;

use crate::{domain::EvaluateTxRequest, pipeline, AppState};

pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub async fn evaluate_tx(
    State(state): State<AppState>,
    Json(req): Json<EvaluateTxRequest>,
) -> impl IntoResponse {
    // request_id helps trace this one evaluation through logs
    let request_id = Uuid::new_v4().to_string();

    match pipeline::evaluate_tx_v0(&state, request_id, req).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => err.into_response(),
    }
}
