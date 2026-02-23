use axum::{
    extract::{Json, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::json;
use std::time::Instant;
use uuid::Uuid;

use crate::{
    audit::unix_timestamp_ms,
    domain::EvaluateTxRequest,
    management::{
        DeleteApiKeyRequest, DeleteQuotaRequest, SetApiKeyDisabledRequest, UpsertApiKeyRequest,
        UpsertQuotaRequest,
    },
    pipeline, AppState,
};

pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.metrics.render_prometheus_with_slo(state.slo_config);
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

pub async fn ops_slo(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if state.control_plane.is_enabled() && !state.control_plane.verify_admin_token(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "admin unauthorized" })),
        )
            .into_response();
    }

    let report = state.metrics.evaluate_slo(state.slo_config);
    let code = if report.status == "ALERT" {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (code, Json(json!(report))).into_response()
}

pub async fn evaluate_tx(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EvaluateTxRequest>,
) -> impl IntoResponse {
    let started = Instant::now();
    let request_id = Uuid::new_v4().to_string();
    let req_from = req.from.clone();
    let req_to = req.to.clone();
    let req_chain_id = req.chain_id;
    let client_identity = client_identity(&headers, &req_from);

    let auth = match state.auth.authenticate(&headers) {
        Ok(a) => a,
        Err(e) => {
            let code = e.code();
            let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            state.metrics.observe_evaluate_latency_ms(elapsed_ms);
            state.metrics.inc_request("unauthorized");
            let body = json!({
                "error": "unauthorized",
                "code": code
            });
            tracing::warn!(
                request_id = %request_id,
                client = %client_identity,
                error_code = code,
                latency_ms = elapsed_ms,
                "evaluate_tx.unauthorized"
            );
            append_audit(
                &state,
                &json!({
                    "ts_ms": unix_timestamp_ms(),
                    "kind": "EVALUATE_TX",
                    "request_id": request_id,
                    "tenant_id": "unknown",
                    "client": client_identity,
                    "chain_id": req_chain_id,
                    "from": req_from,
                    "to": req_to,
                    "outcome": "unauthorized",
                    "error_code": code,
                    "latency_ms": elapsed_ms
                }),
            );
            return (StatusCode::UNAUTHORIZED, Json(body)).into_response();
        }
    };

    let tenant_id = auth.tenant_id;
    let key_id = auth.key_id;
    let rate_key = format!(
        "tenant:{}|key:{}|client:{}",
        tenant_id, key_id, client_identity
    );
    let client_key = rate_key;
    let quota_cfg = state.tenant_quotas.resolve(&tenant_id, &key_id).await;
    let rate = state
        .rate_limiter
        .check_with_config(&client_key, quota_cfg)
        .await;
    if !rate.allowed {
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        state.metrics.observe_evaluate_latency_ms(elapsed_ms);
        state.metrics.inc_request("rate_limited");
        let body = json!({
            "error": "rate limit exceeded",
            "client": client_key,
            "retry_after_secs": rate.retry_after_secs
        });
        tracing::warn!(
            request_id = %request_id,
            tenant_id = %tenant_id,
            key_id = %key_id,
            client = %client_key,
            latency_ms = elapsed_ms,
            retry_after_secs = rate.retry_after_secs,
            quota_requests = quota_cfg.requests_per_window,
            quota_window_secs = quota_cfg.window_secs,
            "evaluate_tx.rate_limited"
        );
        append_audit(
            &state,
            &json!({
                "ts_ms": unix_timestamp_ms(),
                "kind": "EVALUATE_TX",
                "request_id": request_id,
                "tenant_id": tenant_id,
                "key_id": key_id,
                "client": client_key,
                "chain_id": req_chain_id,
                "from": req_from,
                "to": req_to,
                "outcome": "rate_limited",
                "retry_after_secs": rate.retry_after_secs,
                "quota_requests_per_window": quota_cfg.requests_per_window,
                "quota_window_secs": quota_cfg.window_secs,
                "latency_ms": elapsed_ms
            }),
        );
        return (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    }

    let result = pipeline::evaluate_tx_v0(&state, request_id.clone(), req).await;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    state.metrics.observe_evaluate_latency_ms(elapsed_ms);

    match result {
        Ok(resp) => {
            state.metrics.inc_request("ok");
            tracing::info!(
                request_id = %request_id,
                tenant_id = %tenant_id,
                key_id = %key_id,
                evaluation_id = %resp.evaluation_id,
                decision = ?resp.decision,
                latency_ms = elapsed_ms,
                "evaluate_tx.completed"
            );
            append_audit(
                &state,
                &json!({
                    "ts_ms": unix_timestamp_ms(),
                    "kind": "EVALUATE_TX",
                    "request_id": request_id,
                    "tenant_id": tenant_id,
                    "key_id": key_id,
                    "client": client_key,
                    "chain_id": req_chain_id,
                    "from": req_from,
                    "to": req_to,
                    "outcome": "ok",
                    "evaluation_id": resp.evaluation_id,
                    "decision": format!("{:?}", resp.decision),
                    "latency_ms": elapsed_ms,
                    "rules_count": resp.receipt.rules_fired.len(),
                    "uncertainties_count": resp.receipt.uncertainties.len()
                }),
            );
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => {
            state.metrics.inc_request("error");
            state.metrics.inc_simulation_failure("PIPELINE_ERROR");
            tracing::warn!(
                request_id = %request_id,
                tenant_id = %tenant_id,
                key_id = %key_id,
                latency_ms = elapsed_ms,
                status = ?err.status,
                message = %err.message,
                "evaluate_tx.failed"
            );
            append_audit(
                &state,
                &json!({
                    "ts_ms": unix_timestamp_ms(),
                    "kind": "EVALUATE_TX",
                    "request_id": request_id,
                    "tenant_id": tenant_id,
                    "key_id": key_id,
                    "client": client_key,
                    "chain_id": req_chain_id,
                    "from": req_from,
                    "to": req_to,
                    "outcome": "error",
                    "status": err.status.as_u16(),
                    "message": err.message,
                    "latency_ms": elapsed_ms
                }),
            );
            err.into_response()
        }
    }
}

pub async fn admin_get_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.control_plane.is_enabled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "control plane disabled" })),
        )
            .into_response();
    }
    if !state.control_plane.verify_admin_token(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "admin unauthorized" })),
        )
            .into_response();
    }

    let snapshot = state
        .control_plane
        .snapshot(&state.auth, &state.tenant_quotas)
        .await;
    (StatusCode::OK, Json(json!(snapshot))).into_response()
}

pub async fn admin_upsert_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpsertApiKeyRequest>,
) -> impl IntoResponse {
    if !state.control_plane.is_enabled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "control plane disabled" })),
        )
            .into_response();
    }
    if !state.control_plane.verify_admin_token(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "admin unauthorized" })),
        )
            .into_response();
    }

    match state.control_plane.upsert_api_key(&state.auth, req).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn admin_disable_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SetApiKeyDisabledRequest>,
) -> impl IntoResponse {
    if !state.control_plane.is_enabled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "control plane disabled" })),
        )
            .into_response();
    }
    if !state.control_plane.verify_admin_token(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "admin unauthorized" })),
        )
            .into_response();
    }

    match state
        .control_plane
        .set_api_key_disabled(&state.auth, req)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn admin_delete_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeleteApiKeyRequest>,
) -> impl IntoResponse {
    if !state.control_plane.is_enabled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "control plane disabled" })),
        )
            .into_response();
    }
    if !state.control_plane.verify_admin_token(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "admin unauthorized" })),
        )
            .into_response();
    }

    match state.control_plane.delete_api_key(&state.auth, req).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn admin_upsert_quota(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpsertQuotaRequest>,
) -> impl IntoResponse {
    if !state.control_plane.is_enabled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "control plane disabled" })),
        )
            .into_response();
    }
    if !state.control_plane.verify_admin_token(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "admin unauthorized" })),
        )
            .into_response();
    }

    match state
        .control_plane
        .upsert_quota(&state.tenant_quotas, req)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn admin_delete_quota(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeleteQuotaRequest>,
) -> impl IntoResponse {
    if !state.control_plane.is_enabled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "control plane disabled" })),
        )
            .into_response();
    }
    if !state.control_plane.verify_admin_token(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "admin unauthorized" })),
        )
            .into_response();
    }

    match state
        .control_plane
        .delete_quota(&state.tenant_quotas, req)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

fn client_identity(headers: &HeaderMap, req_from: &str) -> String {
    if let Some(v) = headers.get("x-forwarded-for") {
        if let Ok(raw) = v.to_str() {
            if let Some(first) = raw.split(',').next() {
                let xff = first.trim();
                if !xff.is_empty() {
                    return xff.to_string();
                }
            }
        }
    }

    req_from.to_ascii_lowercase()
}

fn append_audit(state: &AppState, event: &serde_json::Value) {
    if let Err(e) = state.audit.append_event(event) {
        tracing::warn!(error = %e, "audit.append_failed");
    }
}
