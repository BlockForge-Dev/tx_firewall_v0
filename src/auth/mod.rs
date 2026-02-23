use axum::http::HeaderMap;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::util;

const API_KEY_HEADER: &str = "x-api-key";

#[derive(Clone, Debug)]
pub struct AuthContext {
    pub tenant_id: String,
    pub key_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    MissingApiKey,
    InvalidApiKey,
    KeyDisabled,
    KeyNotYetValid,
    KeyExpired,
}

impl AuthError {
    pub fn code(self) -> &'static str {
        match self {
            AuthError::MissingApiKey => "MISSING_API_KEY",
            AuthError::InvalidApiKey => "INVALID_API_KEY",
            AuthError::KeyDisabled => "API_KEY_DISABLED",
            AuthError::KeyNotYetValid => "API_KEY_NOT_YET_VALID",
            AuthError::KeyExpired => "API_KEY_EXPIRED",
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ApiKeyEntry {
    pub tenant_id: String,
    pub key_id: String,
    pub key: String,
    pub not_before_ms: Option<u128>,
    pub expires_at_ms: Option<u128>,
    pub disabled: bool,
}

#[derive(Clone)]
pub struct ApiAuth {
    required: bool,
    salt: String,
    keys: Arc<RwLock<HashMap<String, ApiKeyEntry>>>, // key_hash -> entry
}

impl Default for ApiAuth {
    fn default() -> Self {
        Self::disabled()
    }
}

impl ApiAuth {
    pub fn disabled() -> Self {
        Self {
            required: false,
            salt: String::new(),
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn from_pairs(required: bool, pairs: Vec<(String, String)>) -> Self {
        let mut entries = Vec::new();
        for (idx, (tenant, key)) in pairs.into_iter().enumerate() {
            if tenant.trim().is_empty() || key.trim().is_empty() {
                continue;
            }
            entries.push(ApiKeyEntry {
                tenant_id: tenant,
                key_id: format!("legacy-{}", idx + 1),
                key,
                not_before_ms: None,
                expires_at_ms: None,
                disabled: false,
            });
        }
        Self::from_entries(required, String::new(), entries)
    }

    pub fn from_entries(required: bool, salt: String, entries: Vec<ApiKeyEntry>) -> Self {
        let mut m = HashMap::new();
        for e in entries {
            if e.tenant_id.trim().is_empty()
                || e.key_id.trim().is_empty()
                || e.key.trim().is_empty()
            {
                continue;
            }

            let key_hash = if is_sha256_prefixed(&e.key) {
                normalize_prefixed_sha256(&e.key)
            } else {
                hash_api_key(&salt, &e.key)
            };
            m.insert(key_hash, e);
        }
        Self {
            required,
            salt,
            keys: Arc::new(RwLock::new(m)),
        }
    }

    pub fn from_env() -> Self {
        let required = parse_bool_env("AUTH_REQUIRED", false);
        let salt = std::env::var("AUTH_KEY_SALT").unwrap_or_default();
        let raw = std::env::var("API_KEYS").unwrap_or_default();
        if raw.trim().is_empty() {
            return Self {
                required,
                salt,
                keys: Arc::new(RwLock::new(HashMap::new())),
            };
        }

        // Supported formats:
        // 1) legacy: tenant:key
        // 2) tenant:key_id:key[:not_before_ms][:expires_at_ms][:status]
        //    status: active|disabled
        // key can also be pre-hashed as `sha256$<hex>` to avoid raw key storage in env.
        let mut entries = Vec::new();
        for item in raw.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }

            let parts: Vec<&str> = item.split(':').map(|p| p.trim()).collect();
            if parts.len() == 2 {
                let tenant_id = parts[0].to_string();
                let key = parts[1].to_string();
                if tenant_id.is_empty() || key.is_empty() {
                    continue;
                }
                entries.push(ApiKeyEntry {
                    tenant_id,
                    key_id: "legacy".to_string(),
                    key,
                    not_before_ms: None,
                    expires_at_ms: None,
                    disabled: false,
                });
                continue;
            }

            if parts.len() >= 3 {
                let tenant_id = parts[0].to_string();
                let key_id = parts[1].to_string();
                let key = parts[2].to_string();
                if tenant_id.is_empty() || key_id.is_empty() || key.is_empty() {
                    continue;
                }

                let not_before_ms = parts.get(3).and_then(|s| parse_u128_opt(s));
                let expires_at_ms = parts.get(4).and_then(|s| parse_u128_opt(s));
                let status = parts
                    .get(5)
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_else(|| "active".to_string());
                let disabled = status == "disabled";

                entries.push(ApiKeyEntry {
                    tenant_id,
                    key_id,
                    key,
                    not_before_ms,
                    expires_at_ms,
                    disabled,
                });
            }
        }

        Self::from_entries(required, salt, entries)
    }

    pub fn authenticate(&self, headers: &HeaderMap) -> Result<AuthContext, AuthError> {
        let provided_key = headers
            .get(API_KEY_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());

        match provided_key {
            Some(k) => {
                let hash = hash_api_key(&self.salt, k);
                let entry = self.keys.read().ok().and_then(|m| m.get(&hash).cloned());
                if let Some(entry) = entry {
                    if entry.disabled {
                        return Err(AuthError::KeyDisabled);
                    }

                    let now_ms = now_unix_ms();
                    if let Some(nbf) = entry.not_before_ms {
                        if now_ms < nbf {
                            return Err(AuthError::KeyNotYetValid);
                        }
                    }
                    if let Some(exp) = entry.expires_at_ms {
                        if now_ms >= exp {
                            return Err(AuthError::KeyExpired);
                        }
                    }

                    Ok(AuthContext {
                        tenant_id: entry.tenant_id,
                        key_id: entry.key_id,
                    })
                } else {
                    Err(AuthError::InvalidApiKey)
                }
            }
            None => {
                if self.required {
                    Err(AuthError::MissingApiKey)
                } else {
                    Ok(AuthContext {
                        tenant_id: "public".to_string(),
                        key_id: "public".to_string(),
                    })
                }
            }
        }
    }

    pub fn upsert_entry(&self, entry: ApiKeyEntry) -> bool {
        if entry.tenant_id.trim().is_empty()
            || entry.key_id.trim().is_empty()
            || entry.key.trim().is_empty()
        {
            return false;
        }
        let key_hash = if is_sha256_prefixed(&entry.key) {
            normalize_prefixed_sha256(&entry.key)
        } else {
            hash_api_key(&self.salt, &entry.key)
        };
        if let Ok(mut guard) = self.keys.write() {
            guard.insert(key_hash, entry);
            return true;
        }
        false
    }

    pub fn remove_entry(&self, tenant_id: &str, key_id: &str) -> bool {
        if let Ok(mut guard) = self.keys.write() {
            let before = guard.len();
            guard.retain(|_, e| {
                !(eq_ignore_case(&e.tenant_id, tenant_id) && eq_ignore_case(&e.key_id, key_id))
            });
            return guard.len() != before;
        }
        false
    }

    pub fn list_entries(&self) -> Vec<ApiKeyEntry> {
        if let Ok(guard) = self.keys.read() {
            let mut out: Vec<ApiKeyEntry> = guard.values().cloned().collect();
            out.sort_by(|a, b| {
                a.tenant_id
                    .cmp(&b.tenant_id)
                    .then_with(|| a.key_id.cmp(&b.key_id))
            });
            return out;
        }
        Vec::new()
    }

    pub fn required(&self) -> bool {
        self.required
    }
}

fn hash_api_key(salt: &str, key: &str) -> String {
    util::sha256_hex(&format!("{salt}:{key}"))
}

fn parse_u128_opt(s: &str) -> Option<u128> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    t.parse::<u128>().ok()
}

fn is_sha256_prefixed(v: &str) -> bool {
    v.starts_with("sha256$")
}

fn normalize_prefixed_sha256(v: &str) -> String {
    v.strip_prefix("sha256$")
        .unwrap_or(v)
        .trim()
        .to_ascii_lowercase()
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_key(key: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(API_KEY_HEADER, HeaderValue::from_str(key).unwrap());
        h
    }

    #[test]
    fn hashed_auth_with_key_id_works() {
        let auth = ApiAuth::from_entries(
            true,
            "salt1".to_string(),
            vec![ApiKeyEntry {
                tenant_id: "tenant-a".to_string(),
                key_id: "key-v1".to_string(),
                key: "super-secret".to_string(),
                not_before_ms: None,
                expires_at_ms: None,
                disabled: false,
            }],
        );

        let ctx = auth
            .authenticate(&headers_with_key("super-secret"))
            .unwrap();
        assert_eq!(ctx.tenant_id, "tenant-a");
        assert_eq!(ctx.key_id, "key-v1");
    }

    #[test]
    fn rejects_expired_key() {
        let now = now_unix_ms();
        let auth = ApiAuth::from_entries(
            true,
            String::new(),
            vec![ApiKeyEntry {
                tenant_id: "tenant-a".to_string(),
                key_id: "key-old".to_string(),
                key: "super-secret".to_string(),
                not_before_ms: None,
                expires_at_ms: Some(now.saturating_sub(1)),
                disabled: false,
            }],
        );

        let err = auth
            .authenticate(&headers_with_key("super-secret"))
            .unwrap_err();
        assert_eq!(err, AuthError::KeyExpired);
    }

    #[test]
    fn rejects_disabled_key() {
        let auth = ApiAuth::from_entries(
            true,
            String::new(),
            vec![ApiKeyEntry {
                tenant_id: "tenant-a".to_string(),
                key_id: "key-off".to_string(),
                key: "super-secret".to_string(),
                not_before_ms: None,
                expires_at_ms: None,
                disabled: true,
            }],
        );

        let err = auth
            .authenticate(&headers_with_key("super-secret"))
            .unwrap_err();
        assert_eq!(err, AuthError::KeyDisabled);
    }

    #[test]
    fn can_upsert_and_remove_entries_at_runtime() {
        let auth = ApiAuth::from_entries(true, String::new(), Vec::new());
        assert_eq!(
            auth.authenticate(&headers_with_key("runtime-key"))
                .unwrap_err(),
            AuthError::InvalidApiKey
        );

        assert!(auth.upsert_entry(ApiKeyEntry {
            tenant_id: "tenant-r".to_string(),
            key_id: "key-r1".to_string(),
            key: "runtime-key".to_string(),
            not_before_ms: None,
            expires_at_ms: None,
            disabled: false,
        }));

        let ctx = auth.authenticate(&headers_with_key("runtime-key")).unwrap();
        assert_eq!(ctx.tenant_id, "tenant-r");
        assert_eq!(ctx.key_id, "key-r1");

        assert!(auth.remove_entry("tenant-r", "key-r1"));
        assert_eq!(
            auth.authenticate(&headers_with_key("runtime-key"))
                .unwrap_err(),
            AuthError::InvalidApiKey
        );
    }
}
