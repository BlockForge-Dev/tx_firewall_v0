use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{
    auth::{ApiAuth, ApiKeyEntry},
    safety::{RateLimitConfig, TenantQuotaStore},
};

const ADMIN_TOKEN_HEADER: &str = "x-admin-token";

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
struct ManagedState {
    api_keys: Vec<ApiKeyEntry>,
    tenant_quotas: Vec<ManagedQuotaEntry>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct ManagedQuotaEntry {
    scope: String,
    requests_per_window: u32,
    window_secs: u64,
    max_clients: usize,
}

#[derive(Clone)]
pub struct ControlPlane {
    enabled: bool,
    admin_token: Option<String>,
    path: Option<PathBuf>,
    default_quota_cfg: RateLimitConfig,
    state: Arc<Mutex<ManagedState>>,
}

#[derive(Clone, Deserialize)]
pub struct UpsertApiKeyRequest {
    pub tenant_id: String,
    pub key_id: String,
    pub key: String,
    pub not_before_ms: Option<u128>,
    pub expires_at_ms: Option<u128>,
    pub disabled: Option<bool>,
}

#[derive(Clone, Deserialize)]
pub struct DeleteApiKeyRequest {
    pub tenant_id: String,
    pub key_id: String,
}

#[derive(Clone, Deserialize)]
pub struct SetApiKeyDisabledRequest {
    pub tenant_id: String,
    pub key_id: String,
    pub disabled: bool,
}

#[derive(Clone, Deserialize)]
pub struct UpsertQuotaRequest {
    pub scope: String,
    pub requests_per_window: u32,
    pub window_secs: u64,
    pub max_clients: Option<usize>,
}

#[derive(Clone, Deserialize)]
pub struct DeleteQuotaRequest {
    pub scope: String,
}

#[derive(Clone, Serialize)]
pub struct ControlPlaneSnapshot {
    pub enabled: bool,
    pub path: Option<String>,
    pub auth_required: bool,
    pub api_keys: Vec<ApiKeySummary>,
    pub tenant_quotas: Vec<QuotaSummary>,
}

#[derive(Clone, Serialize)]
pub struct ApiKeySummary {
    pub tenant_id: String,
    pub key_id: String,
    pub disabled: bool,
    pub not_before_ms: Option<u128>,
    pub expires_at_ms: Option<u128>,
}

#[derive(Clone, Serialize)]
pub struct QuotaSummary {
    pub scope: String,
    pub requests_per_window: u32,
    pub window_secs: u64,
    pub max_clients: usize,
}

impl ControlPlane {
    pub fn disabled(default_quota_cfg: RateLimitConfig) -> Self {
        Self {
            enabled: false,
            admin_token: None,
            path: None,
            default_quota_cfg,
            state: Arc::new(Mutex::new(ManagedState::default())),
        }
    }

    pub async fn from_env(default_quota_cfg: RateLimitConfig) -> Self {
        let token = std::env::var("ADMIN_API_TOKEN")
            .ok()
            .map(|v| v.trim().to_string());
        let token = token.filter(|v| !v.is_empty());
        let Some(token) = token else {
            return Self::disabled(default_quota_cfg);
        };

        let path = std::env::var("CONTROL_PLANE_PATH")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("control_plane.json"));

        Self::new_enabled(token, Some(path), default_quota_cfg)
    }

    pub fn new_enabled(
        admin_token: String,
        path: Option<PathBuf>,
        default_quota_cfg: RateLimitConfig,
    ) -> Self {
        let initial_state = path
            .as_deref()
            .and_then(|p| load_state(p).ok())
            .unwrap_or_default();
        Self {
            enabled: true,
            admin_token: Some(admin_token),
            path,
            default_quota_cfg,
            state: Arc::new(Mutex::new(initial_state)),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn verify_admin_token(&self, headers: &HeaderMap) -> bool {
        if !self.enabled {
            return false;
        }
        let Some(expected) = &self.admin_token else {
            return false;
        };
        let provided = headers
            .get(ADMIN_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());
        matches!(provided, Some(v) if constant_time_eq(v.as_bytes(), expected.as_bytes()))
    }

    pub async fn apply_to_runtime(&self, auth: &ApiAuth, tenant_quotas: &TenantQuotaStore) {
        if !self.enabled {
            return;
        }
        let state = self.state.lock().await.clone();
        for k in state.api_keys {
            let _ = auth.upsert_entry(k);
        }
        for q in state.tenant_quotas {
            tenant_quotas
                .set_quota(
                    q.scope,
                    RateLimitConfig {
                        requests_per_window: q.requests_per_window,
                        window_secs: q.window_secs.max(1),
                        max_clients: q.max_clients,
                    },
                )
                .await;
        }
    }

    pub async fn snapshot(
        &self,
        auth: &ApiAuth,
        tenant_quotas: &TenantQuotaStore,
    ) -> ControlPlaneSnapshot {
        let api_keys = auth
            .list_entries()
            .into_iter()
            .map(|k| ApiKeySummary {
                tenant_id: k.tenant_id,
                key_id: k.key_id,
                disabled: k.disabled,
                not_before_ms: k.not_before_ms,
                expires_at_ms: k.expires_at_ms,
            })
            .collect::<Vec<_>>();

        let tenant_quotas = tenant_quotas
            .list_quotas()
            .await
            .into_iter()
            .map(|(scope, cfg)| QuotaSummary {
                scope,
                requests_per_window: cfg.requests_per_window,
                window_secs: cfg.window_secs,
                max_clients: cfg.max_clients,
            })
            .collect();

        ControlPlaneSnapshot {
            enabled: self.enabled,
            path: self.path.as_ref().map(|p| p.to_string_lossy().to_string()),
            auth_required: auth.required(),
            api_keys,
            tenant_quotas,
        }
    }

    pub async fn upsert_api_key(
        &self,
        auth: &ApiAuth,
        req: UpsertApiKeyRequest,
    ) -> Result<(), String> {
        if !self.enabled {
            return Err("control plane disabled".to_string());
        }

        let entry = ApiKeyEntry {
            tenant_id: req.tenant_id.trim().to_string(),
            key_id: req.key_id.trim().to_string(),
            key: req.key.trim().to_string(),
            not_before_ms: req.not_before_ms,
            expires_at_ms: req.expires_at_ms,
            disabled: req.disabled.unwrap_or(false),
        };
        if entry.tenant_id.is_empty() || entry.key_id.is_empty() || entry.key.is_empty() {
            return Err("tenant_id, key_id, key are required".to_string());
        }

        let mut guard = self.state.lock().await;
        if let Some(slot) = guard.api_keys.iter_mut().find(|e| {
            e.tenant_id.eq_ignore_ascii_case(&entry.tenant_id)
                && e.key_id.eq_ignore_ascii_case(&entry.key_id)
        }) {
            *slot = entry.clone();
        } else {
            guard.api_keys.push(entry.clone());
        }
        let snapshot = guard.clone();
        drop(guard);

        persist_state(self.path.as_deref(), &snapshot)?;
        if !auth.upsert_entry(entry) {
            return Err("failed to apply api key entry".to_string());
        }
        Ok(())
    }

    pub async fn set_api_key_disabled(
        &self,
        auth: &ApiAuth,
        req: SetApiKeyDisabledRequest,
    ) -> Result<(), String> {
        if !self.enabled {
            return Err("control plane disabled".to_string());
        }

        let mut guard = self.state.lock().await;
        let Some(slot) = guard.api_keys.iter_mut().find(|e| {
            e.tenant_id.eq_ignore_ascii_case(req.tenant_id.trim())
                && e.key_id.eq_ignore_ascii_case(req.key_id.trim())
        }) else {
            return Err("api key not found".to_string());
        };
        slot.disabled = req.disabled;
        let updated = slot.clone();
        let snapshot = guard.clone();
        drop(guard);

        persist_state(self.path.as_deref(), &snapshot)?;
        if !auth.upsert_entry(updated) {
            return Err("failed to update api key entry".to_string());
        }
        Ok(())
    }

    pub async fn delete_api_key(
        &self,
        auth: &ApiAuth,
        req: DeleteApiKeyRequest,
    ) -> Result<(), String> {
        if !self.enabled {
            return Err("control plane disabled".to_string());
        }

        let tenant_id = req.tenant_id.trim().to_string();
        let key_id = req.key_id.trim().to_string();
        let mut guard = self.state.lock().await;
        let before = guard.api_keys.len();
        guard.api_keys.retain(|e| {
            !(e.tenant_id.eq_ignore_ascii_case(&tenant_id)
                && e.key_id.eq_ignore_ascii_case(&key_id))
        });
        if guard.api_keys.len() == before {
            return Err("api key not found".to_string());
        }
        let snapshot = guard.clone();
        drop(guard);

        persist_state(self.path.as_deref(), &snapshot)?;
        let _ = auth.remove_entry(&tenant_id, &key_id);
        Ok(())
    }

    pub async fn upsert_quota(
        &self,
        tenant_quotas: &TenantQuotaStore,
        req: UpsertQuotaRequest,
    ) -> Result<(), String> {
        if !self.enabled {
            return Err("control plane disabled".to_string());
        }
        let scope = req.scope.trim().to_string();
        if scope.is_empty() {
            return Err("scope is required".to_string());
        }
        let entry = ManagedQuotaEntry {
            scope: scope.clone(),
            requests_per_window: req.requests_per_window,
            window_secs: req.window_secs.max(1),
            max_clients: req
                .max_clients
                .unwrap_or(self.default_quota_cfg.max_clients),
        };

        let mut guard = self.state.lock().await;
        if let Some(slot) = guard
            .tenant_quotas
            .iter_mut()
            .find(|e| e.scope.eq_ignore_ascii_case(&scope))
        {
            *slot = entry.clone();
        } else {
            guard.tenant_quotas.push(entry.clone());
        }
        let snapshot = guard.clone();
        drop(guard);

        persist_state(self.path.as_deref(), &snapshot)?;
        tenant_quotas
            .set_quota(
                scope,
                RateLimitConfig {
                    requests_per_window: entry.requests_per_window,
                    window_secs: entry.window_secs,
                    max_clients: entry.max_clients,
                },
            )
            .await;
        Ok(())
    }

    pub async fn delete_quota(
        &self,
        tenant_quotas: &TenantQuotaStore,
        req: DeleteQuotaRequest,
    ) -> Result<(), String> {
        if !self.enabled {
            return Err("control plane disabled".to_string());
        }

        let scope = req.scope.trim().to_string();
        if scope.is_empty() {
            return Err("scope is required".to_string());
        }
        let mut guard = self.state.lock().await;
        let before = guard.tenant_quotas.len();
        guard
            .tenant_quotas
            .retain(|e| !e.scope.eq_ignore_ascii_case(&scope));
        if guard.tenant_quotas.len() == before {
            return Err("quota not found".to_string());
        }
        let snapshot = guard.clone();
        drop(guard);

        persist_state(self.path.as_deref(), &snapshot)?;
        let _ = tenant_quotas.remove_quota(&scope).await;
        Ok(())
    }
}

fn load_state(path: &Path) -> Result<ManagedState, String> {
    if !path.exists() {
        return Ok(ManagedState::default());
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("read state failed: {}", e))?;
    serde_json::from_str::<ManagedState>(&raw).map_err(|e| format!("parse state failed: {}", e))
}

fn persist_state(path: Option<&Path>, state: &ManagedState) -> Result<(), String> {
    let Some(path) = path else {
        return Ok(());
    };

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("create dir failed: {}", e))?;
        }
    }

    let data =
        serde_json::to_vec_pretty(state).map_err(|e| format!("serialize state failed: {}", e))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data).map_err(|e| format!("write temp state failed: {}", e))?;
    fs::rename(&tmp, path).map_err(|e| format!("replace state failed: {}", e))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
