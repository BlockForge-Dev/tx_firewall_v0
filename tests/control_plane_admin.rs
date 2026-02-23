use std::{net::SocketAddr, path::PathBuf};

use serde_json::json;
use tokio::net::TcpListener;

use tx_firewall_v0::{
    api,
    auth::ApiAuth,
    management::ControlPlane,
    safety::{RateLimitConfig, RateLimiter, TenantQuotaStore},
    AppState,
};

async fn start_server(state: AppState) -> (String, tokio::sync::oneshot::Sender<()>) {
    let app = api::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });

    (url, tx)
}

fn evaluate_body() -> serde_json::Value {
    json!({
        "chain_id": 1,
        "from": "0x1111111111111111111111111111111111111111",
        "to": "0x2222222222222222222222222222222222222222",
        "data": "0x095ea7b30000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000ffffffffffffffff",
        "value": "0x0",
        "block_number": null
    })
}

fn temp_control_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "tx_firewall_control_plane_{}.json",
        uuid::Uuid::new_v4()
    ))
}

#[tokio::test]
async fn admin_token_required_for_control_plane_routes() {
    let mut state = AppState::new("latest-1".to_string(), None);
    let default_cfg = RateLimitConfig::default();
    let path = temp_control_path();
    state.control_plane =
        ControlPlane::new_enabled("admin-token-1".to_string(), Some(path.clone()), default_cfg);

    let (base_url, shutdown) = start_server(state).await;
    let client = reqwest::Client::new();

    let missing = client
        .get(format!("{}/v1/admin/config", base_url))
        .send()
        .await
        .unwrap();
    let ok = client
        .get(format!("{}/v1/admin/config", base_url))
        .header("x-admin-token", "admin-token-1")
        .send()
        .await
        .unwrap();

    assert_eq!(missing.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(ok.status(), reqwest::StatusCode::OK);

    let _ = shutdown.send(());
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn admin_can_upsert_disable_and_delete_api_key_live() {
    let mut state = AppState::new("latest-1".to_string(), None);
    state.auth = ApiAuth::from_entries(true, String::new(), Vec::new());
    let default_cfg = RateLimitConfig::default();
    state.rate_limiter = RateLimiter::new(default_cfg);
    state.tenant_quotas = TenantQuotaStore::new(default_cfg);
    let path = temp_control_path();
    state.control_plane =
        ControlPlane::new_enabled("admin-token-2".to_string(), Some(path.clone()), default_cfg);

    let (base_url, shutdown) = start_server(state).await;
    let client = reqwest::Client::new();
    let eval_url = format!("{}/v1/evaluate/tx", base_url);
    let upsert_url = format!("{}/v1/admin/keys/upsert", base_url);
    let disable_url = format!("{}/v1/admin/keys/disable", base_url);
    let delete_url = format!("{}/v1/admin/keys/delete", base_url);

    let add = client
        .post(&upsert_url)
        .header("x-admin-token", "admin-token-2")
        .json(&json!({
            "tenant_id": "tenant-a",
            "key_id": "k1",
            "key": "live-secret"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(add.status(), reqwest::StatusCode::OK);

    let allowed = client
        .post(&eval_url)
        .header("x-api-key", "live-secret")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), reqwest::StatusCode::OK);

    let disable = client
        .post(&disable_url)
        .header("x-admin-token", "admin-token-2")
        .json(&json!({
            "tenant_id": "tenant-a",
            "key_id": "k1",
            "disabled": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(disable.status(), reqwest::StatusCode::OK);

    let blocked = client
        .post(&eval_url)
        .header("x-api-key", "live-secret")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), reqwest::StatusCode::UNAUTHORIZED);

    let delete = client
        .post(&delete_url)
        .header("x-admin-token", "admin-token-2")
        .json(&json!({
            "tenant_id": "tenant-a",
            "key_id": "k1"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), reqwest::StatusCode::OK);

    let _ = shutdown.send(());
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn admin_can_update_tenant_quota_live() {
    let mut state = AppState::new("latest-1".to_string(), None);
    state.auth = ApiAuth::from_pairs(
        true,
        vec![("tenant-a".to_string(), "tenant-key".to_string())],
    );
    let default_cfg = RateLimitConfig {
        requests_per_window: 100,
        window_secs: 60,
        max_clients: 1024,
    };
    state.rate_limiter = RateLimiter::new(default_cfg);
    state.tenant_quotas = TenantQuotaStore::new(default_cfg);
    let path = temp_control_path();
    state.control_plane =
        ControlPlane::new_enabled("admin-token-3".to_string(), Some(path.clone()), default_cfg);

    let (base_url, shutdown) = start_server(state).await;
    let client = reqwest::Client::new();
    let eval_url = format!("{}/v1/evaluate/tx", base_url);
    let upsert_quota_url = format!("{}/v1/admin/quotas/upsert", base_url);
    let delete_quota_url = format!("{}/v1/admin/quotas/delete", base_url);

    let pre1 = client
        .post(&eval_url)
        .header("x-api-key", "tenant-key")
        .header("x-forwarded-for", "203.0.113.55")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    let pre2 = client
        .post(&eval_url)
        .header("x-api-key", "tenant-key")
        .header("x-forwarded-for", "203.0.113.55")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    assert_eq!(pre1.status(), reqwest::StatusCode::OK);
    assert_eq!(pre2.status(), reqwest::StatusCode::OK);

    let quota_set = client
        .post(&upsert_quota_url)
        .header("x-admin-token", "admin-token-3")
        .json(&json!({
            "scope": "tenant-a",
            "requests_per_window": 1,
            "window_secs": 60
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(quota_set.status(), reqwest::StatusCode::OK);

    let limited = client
        .post(&eval_url)
        .header("x-api-key", "tenant-key")
        .header("x-forwarded-for", "203.0.113.55")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    let quota_del = client
        .post(&delete_quota_url)
        .header("x-admin-token", "admin-token-3")
        .json(&json!({
            "scope": "tenant-a"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(quota_del.status(), reqwest::StatusCode::OK);

    let allowed_again = client
        .post(&eval_url)
        .header("x-api-key", "tenant-key")
        .header("x-forwarded-for", "203.0.113.55")
        .json(&evaluate_body())
        .send()
        .await
        .unwrap();
    assert_eq!(allowed_again.status(), reqwest::StatusCode::OK);

    let _ = shutdown.send(());
    let _ = std::fs::remove_file(path);
}
