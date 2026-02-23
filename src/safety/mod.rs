use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream},
    net::TcpStream,
    sync::{Mutex, RwLock},
    time::timeout,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailClosedMode {
    Off,
    Warn,
    Block,
}

impl FailClosedMode {
    pub fn from_env(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Self::Off,
            "block" => Self::Block,
            "warn" => Self::Warn,
            _ => Self::Warn,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    pub requests_per_window: u32,
    pub window_secs: u64,
    pub max_clients: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_window: 120,
            window_secs: 60,
            max_clients: 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimitVerdict {
    pub allowed: bool,
    pub retry_after_secs: u64,
}

#[derive(Clone, Debug)]
pub struct RedisRateLimitConfig {
    pub addr: String,
    pub key_prefix: String,
    pub connect_timeout_ms: u64,
    pub command_timeout_ms: u64,
    pub password: Option<String>,
    pub db: u8,
    pub fallback_to_in_memory: bool,
}

impl RedisRateLimitConfig {
    pub fn from_env() -> Option<Self> {
        let addr = std::env::var("RATE_LIMIT_REDIS_ADDR").ok()?;
        let addr = addr.trim().to_string();
        if addr.is_empty() {
            return None;
        }

        let key_prefix =
            std::env::var("RATE_LIMIT_REDIS_KEY_PREFIX").unwrap_or_else(|_| "txfw:rl:".to_string());

        let connect_timeout_ms = parse_u64_env("RATE_LIMIT_REDIS_CONNECT_TIMEOUT_MS", 80).max(1);
        let command_timeout_ms = parse_u64_env("RATE_LIMIT_REDIS_COMMAND_TIMEOUT_MS", 80).max(1);

        let password = std::env::var("RATE_LIMIT_REDIS_PASSWORD")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        let db = parse_u8_env("RATE_LIMIT_REDIS_DB", 0);
        let fallback_to_in_memory = parse_bool_env("RATE_LIMIT_REDIS_FALLBACK_TO_MEMORY", true);

        Some(Self {
            addr,
            key_prefix,
            connect_timeout_ms,
            command_timeout_ms,
            password,
            db,
            fallback_to_in_memory,
        })
    }
}

#[derive(Clone)]
struct RedisRateLimitStore {
    cfg: RedisRateLimitConfig,
}

impl RedisRateLimitStore {
    fn new(cfg: RedisRateLimitConfig) -> Self {
        Self { cfg }
    }

    async fn check(
        &self,
        client_key: &str,
        cfg: RateLimitConfig,
    ) -> Result<RateLimitVerdict, String> {
        if cfg.requests_per_window == 0 {
            return Ok(RateLimitVerdict {
                allowed: true,
                retry_after_secs: 0,
            });
        }

        let window_secs = cfg.window_secs.max(1);
        let now = now_unix_secs();
        let window_slot = now / window_secs;
        let redis_key = format!(
            "{}{}:{}:{}:{}",
            self.cfg.key_prefix, client_key, window_secs, cfg.requests_per_window, window_slot
        );

        let mut conn = self.connect().await?;
        let count = self
            .exec_integer(&mut conn, vec!["INCR".to_string(), redis_key.clone()])
            .await?;

        if count == 1 {
            let expire_secs = window_secs.saturating_add(1);
            let _ = self
                .exec_integer(
                    &mut conn,
                    vec!["EXPIRE".to_string(), redis_key, expire_secs.to_string()],
                )
                .await?;
        }

        let window_end = window_slot.saturating_add(1).saturating_mul(window_secs);
        let retry_after_secs = window_end.saturating_sub(now).max(1);

        Ok(RateLimitVerdict {
            allowed: count <= cfg.requests_per_window as i64,
            retry_after_secs,
        })
    }

    async fn connect(&self) -> Result<BufStream<TcpStream>, String> {
        let connect_timeout = Duration::from_millis(self.cfg.connect_timeout_ms.max(1));
        let stream = timeout(connect_timeout, TcpStream::connect(self.cfg.addr.as_str()))
            .await
            .map_err(|_| {
                format!(
                    "redis connect timeout after {}ms to {}",
                    self.cfg.connect_timeout_ms, self.cfg.addr
                )
            })?
            .map_err(|e| format!("redis connect failed to {}: {}", self.cfg.addr, e))?;
        let _ = stream.set_nodelay(true);
        let mut conn = BufStream::new(stream);

        if let Some(password) = &self.cfg.password {
            self.exec_simple_ok(
                &mut conn,
                vec!["AUTH".to_string(), password.clone()],
                "AUTH",
            )
            .await?;
        }

        if self.cfg.db != 0 {
            self.exec_simple_ok(
                &mut conn,
                vec!["SELECT".to_string(), self.cfg.db.to_string()],
                "SELECT",
            )
            .await?;
        }

        Ok(conn)
    }

    async fn exec_simple_ok(
        &self,
        conn: &mut BufStream<TcpStream>,
        parts: Vec<String>,
        cmd: &str,
    ) -> Result<(), String> {
        match self.exec(conn, parts).await? {
            RedisResponse::Simple(v) if v.eq_ignore_ascii_case("OK") => Ok(()),
            RedisResponse::Integer(v) if v == 1 => Ok(()),
            other => Err(format!("unexpected {} response: {:?}", cmd, other)),
        }
    }

    async fn exec_integer(
        &self,
        conn: &mut BufStream<TcpStream>,
        parts: Vec<String>,
    ) -> Result<i64, String> {
        match self.exec(conn, parts).await? {
            RedisResponse::Integer(v) => Ok(v),
            other => Err(format!("unexpected integer response: {:?}", other)),
        }
    }

    async fn exec(
        &self,
        conn: &mut BufStream<TcpStream>,
        parts: Vec<String>,
    ) -> Result<RedisResponse, String> {
        let payload = encode_redis_command(&parts);
        let command_timeout = Duration::from_millis(self.cfg.command_timeout_ms.max(1));

        timeout(command_timeout, conn.write_all(&payload))
            .await
            .map_err(|_| "redis write timeout".to_string())?
            .map_err(|e| format!("redis write failed: {}", e))?;
        timeout(command_timeout, conn.flush())
            .await
            .map_err(|_| "redis flush timeout".to_string())?
            .map_err(|e| format!("redis flush failed: {}", e))?;

        self.read_response(conn, command_timeout).await
    }

    async fn read_response(
        &self,
        conn: &mut BufStream<TcpStream>,
        command_timeout: Duration,
    ) -> Result<RedisResponse, String> {
        let mut prefix = [0u8; 1];
        timeout(command_timeout, conn.read_exact(&mut prefix))
            .await
            .map_err(|_| "redis read timeout".to_string())?
            .map_err(|e| format!("redis read failed: {}", e))?;

        match prefix[0] {
            b'+' => {
                let line = read_crlf_line(conn, command_timeout).await?;
                Ok(RedisResponse::Simple(line))
            }
            b':' => {
                let line = read_crlf_line(conn, command_timeout).await?;
                let parsed = line
                    .parse::<i64>()
                    .map_err(|_| format!("invalid redis integer response: {}", line))?;
                Ok(RedisResponse::Integer(parsed))
            }
            b'$' => {
                let len_line = read_crlf_line(conn, command_timeout).await?;
                let len = len_line
                    .parse::<i64>()
                    .map_err(|_| format!("invalid redis bulk length response: {}", len_line))?;
                if len < 0 {
                    return Ok(RedisResponse::NullBulk);
                }
                let mut data = vec![0u8; len as usize + 2];
                timeout(command_timeout, conn.read_exact(&mut data))
                    .await
                    .map_err(|_| "redis bulk read timeout".to_string())?
                    .map_err(|e| format!("redis bulk read failed: {}", e))?;
                if data.len() < 2 || data[data.len() - 2..] != *b"\r\n" {
                    return Err("invalid redis bulk terminator".to_string());
                }
                data.truncate(data.len() - 2);
                let _ = data;
                Ok(RedisResponse::Bulk)
            }
            b'-' => {
                let line = read_crlf_line(conn, command_timeout).await?;
                Err(format!("redis error: {}", line))
            }
            other => Err(format!("unsupported redis response prefix: {}", other)),
        }
    }
}

#[derive(Debug)]
enum RedisResponse {
    Simple(String),
    Integer(i64),
    Bulk,
    NullBulk,
}

#[derive(Clone)]
pub struct RateLimiter {
    cfg: RateLimitConfig, // default/fallback
    state: Arc<Mutex<HashMap<String, ClientWindow>>>,
    redis: Option<RedisRateLimitStore>,
    redis_fallback_to_memory: bool,
}

#[derive(Clone, Copy, Debug)]
struct ClientWindow {
    window_start: Instant,
    last_seen: Instant,
    count: u32,
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            state: Arc::new(Mutex::new(HashMap::new())),
            redis: None,
            redis_fallback_to_memory: true,
        }
    }

    pub fn new_with_redis(cfg: RateLimitConfig, redis_cfg: RedisRateLimitConfig) -> Self {
        let fallback = redis_cfg.fallback_to_in_memory;
        Self {
            cfg,
            state: Arc::new(Mutex::new(HashMap::new())),
            redis: Some(RedisRateLimitStore::new(redis_cfg)),
            redis_fallback_to_memory: fallback,
        }
    }

    pub fn from_env(cfg: RateLimitConfig) -> Self {
        let backend = std::env::var("RATE_LIMIT_BACKEND")
            .unwrap_or_else(|_| "memory".to_string())
            .to_ascii_lowercase();

        if backend == "redis" {
            if let Some(redis_cfg) = RedisRateLimitConfig::from_env() {
                return Self::new_with_redis(cfg, redis_cfg);
            }
            tracing::warn!(
                "RATE_LIMIT_BACKEND=redis but RATE_LIMIT_REDIS_ADDR is missing; using in-memory limiter"
            );
        }

        Self::new(cfg)
    }

    pub fn backend_name(&self) -> &'static str {
        match (self.redis.is_some(), self.redis_fallback_to_memory) {
            (true, true) => "redis+memory-fallback",
            (true, false) => "redis",
            (false, _) => "memory",
        }
    }

    pub async fn check(&self, client_key: &str) -> RateLimitVerdict {
        self.check_with_config(client_key, self.cfg).await
    }

    pub async fn check_with_config(
        &self,
        client_key: &str,
        cfg: RateLimitConfig,
    ) -> RateLimitVerdict {
        if let Some(redis) = &self.redis {
            match redis.check(client_key, cfg).await {
                Ok(v) => return v,
                Err(e) => {
                    tracing::warn!(
                        client_key = %client_key,
                        backend = self.backend_name(),
                        error = %e,
                        fallback_to_memory = self.redis_fallback_to_memory,
                        "rate_limiter.redis_error"
                    );
                    if !self.redis_fallback_to_memory {
                        return RateLimitVerdict {
                            allowed: true,
                            retry_after_secs: 0,
                        };
                    }
                }
            }
        }

        self.check_in_memory(client_key, cfg).await
    }

    async fn check_in_memory(&self, client_key: &str, cfg: RateLimitConfig) -> RateLimitVerdict {
        if cfg.requests_per_window == 0 {
            return RateLimitVerdict {
                allowed: true,
                retry_after_secs: 0,
            };
        }

        let now = Instant::now();
        let window = Duration::from_secs(cfg.window_secs.max(1));
        let mut guard = self.state.lock().await;

        if !guard.contains_key(client_key) && guard.len() >= cfg.max_clients && cfg.max_clients > 0
        {
            evict_least_recently_seen(&mut guard);
        }

        let entry = guard
            .entry(client_key.to_string())
            .or_insert_with(|| ClientWindow {
                window_start: now,
                last_seen: now,
                count: 0,
            });

        let elapsed = now.saturating_duration_since(entry.window_start);
        if elapsed >= window {
            entry.window_start = now;
            entry.count = 0;
        }

        entry.last_seen = now;

        if entry.count < cfg.requests_per_window {
            entry.count += 1;
            return RateLimitVerdict {
                allowed: true,
                retry_after_secs: 0,
            };
        }

        let elapsed_now = now.saturating_duration_since(entry.window_start);
        let retry_after = window.saturating_sub(elapsed_now).as_secs().max(1);

        RateLimitVerdict {
            allowed: false,
            retry_after_secs: retry_after,
        }
    }
}

#[derive(Clone)]
pub struct TenantQuotaStore {
    default_cfg: RateLimitConfig,
    // keys:
    // - "tenant-a" => tenant-wide override
    // - "tenant-a:key-v2" => tenant+key override
    overrides: Arc<RwLock<HashMap<String, RateLimitConfig>>>,
}

impl TenantQuotaStore {
    pub fn new(default_cfg: RateLimitConfig) -> Self {
        Self {
            default_cfg,
            overrides: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn set_quota(&self, key: impl Into<String>, cfg: RateLimitConfig) {
        let mut guard = self.overrides.write().await;
        guard.insert(key.into(), cfg);
    }

    pub async fn clear(&self) {
        self.overrides.write().await.clear();
    }

    pub async fn remove_quota(&self, key: &str) -> bool {
        self.overrides.write().await.remove(key).is_some()
    }

    pub async fn resolve(&self, tenant_id: &str, key_id: &str) -> RateLimitConfig {
        let guard = self.overrides.read().await;
        let key_scope = format!("{}:{}", tenant_id.trim(), key_id.trim());

        if let Some(cfg) = guard.get(&key_scope) {
            return *cfg;
        }
        if let Some(cfg) = guard.get(tenant_id.trim()) {
            return *cfg;
        }
        self.default_cfg
    }

    pub async fn load_from_env(&self) -> usize {
        let raw = std::env::var("TENANT_RATE_LIMITS").unwrap_or_default();
        let parsed = parse_tenant_rate_limits(raw.as_str(), self.default_cfg);
        let mut guard = self.overrides.write().await;
        *guard = parsed;
        guard.len()
    }

    pub async fn list_quotas(&self) -> Vec<(String, RateLimitConfig)> {
        let guard = self.overrides.read().await;
        let mut out: Vec<(String, RateLimitConfig)> =
            guard.iter().map(|(k, v)| (k.clone(), *v)).collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

fn parse_tenant_rate_limits(
    raw: &str,
    default_cfg: RateLimitConfig,
) -> HashMap<String, RateLimitConfig> {
    // Format:
    // TENANT_RATE_LIMITS="tenant-a:20:60,tenant-b:200:60,tenant-c:key-v2:5:60"
    // tokens:
    //  - 3 parts -> <tenant>:<requests>:<window_secs>
    //  - 4 parts -> <tenant>:<key_id>:<requests>:<window_secs>
    // max_clients uses default_cfg.max_clients
    let mut out = HashMap::new();

    for item in raw.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let parts: Vec<&str> = item.split(':').map(|s| s.trim()).collect();

        match parts.len() {
            3 => {
                let tenant = parts[0];
                if tenant.is_empty() {
                    continue;
                }
                let Some(requests) = parts[1].parse::<u32>().ok() else {
                    continue;
                };
                let Some(window_secs) = parts[2].parse::<u64>().ok() else {
                    continue;
                };
                out.insert(
                    tenant.to_string(),
                    RateLimitConfig {
                        requests_per_window: requests,
                        window_secs: window_secs.max(1),
                        max_clients: default_cfg.max_clients,
                    },
                );
            }
            4 => {
                let tenant = parts[0];
                let key_id = parts[1];
                if tenant.is_empty() || key_id.is_empty() {
                    continue;
                }
                let Some(requests) = parts[2].parse::<u32>().ok() else {
                    continue;
                };
                let Some(window_secs) = parts[3].parse::<u64>().ok() else {
                    continue;
                };
                out.insert(
                    format!("{tenant}:{key_id}"),
                    RateLimitConfig {
                        requests_per_window: requests,
                        window_secs: window_secs.max(1),
                        max_clients: default_cfg.max_clients,
                    },
                );
            }
            _ => {}
        }
    }

    out
}

fn evict_least_recently_seen(map: &mut HashMap<String, ClientWindow>) {
    if map.is_empty() {
        return;
    }

    let mut oldest_key: Option<String> = None;
    let mut oldest_time = Instant::now();
    let mut first = true;

    for (k, v) in map.iter() {
        if first || v.last_seen < oldest_time {
            oldest_time = v.last_seen;
            oldest_key = Some(k.clone());
            first = false;
        }
    }

    if let Some(k) = oldest_key {
        map.remove(&k);
    }
}

fn encode_redis_command(parts: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("*{}\r\n", parts.len()).as_bytes());
    for part in parts {
        out.extend_from_slice(format!("${}\r\n", part.as_bytes().len()).as_bytes());
        out.extend_from_slice(part.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

async fn read_crlf_line(
    conn: &mut BufStream<TcpStream>,
    command_timeout: Duration,
) -> Result<String, String> {
    let mut line = Vec::new();
    timeout(command_timeout, conn.read_until(b'\n', &mut line))
        .await
        .map_err(|_| "redis read line timeout".to_string())?
        .map_err(|e| format!("redis read line failed: {}", e))?;

    if line.len() < 2 || line[line.len() - 2..] != *b"\r\n" {
        return Err("invalid redis line ending".to_string());
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line).map_err(|_| "redis line is not valid utf8".to_string())
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

fn parse_u64_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn parse_u8_env(name: &str, default: u8) -> u8 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u8>().ok())
        .unwrap_or(default)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tenant_and_tenant_key_quotas() {
        let default_cfg = RateLimitConfig {
            requests_per_window: 120,
            window_secs: 60,
            max_clients: 999,
        };
        let m = parse_tenant_rate_limits("tenant-a:10:30,tenant-b:key-v2:3:60", default_cfg);

        let a = m.get("tenant-a").expect("tenant-a quota");
        assert_eq!(a.requests_per_window, 10);
        assert_eq!(a.window_secs, 30);
        assert_eq!(a.max_clients, 999);

        let b = m.get("tenant-b:key-v2").expect("tenant-b:key-v2 quota");
        assert_eq!(b.requests_per_window, 3);
        assert_eq!(b.window_secs, 60);
    }

    #[tokio::test]
    async fn tenant_key_override_precedence_over_tenant() {
        let default_cfg = RateLimitConfig {
            requests_per_window: 100,
            window_secs: 60,
            max_clients: 128,
        };
        let store = TenantQuotaStore::new(default_cfg);
        store
            .set_quota(
                "tenant-a",
                RateLimitConfig {
                    requests_per_window: 10,
                    window_secs: 60,
                    max_clients: 128,
                },
            )
            .await;
        store
            .set_quota(
                "tenant-a:key-v2",
                RateLimitConfig {
                    requests_per_window: 2,
                    window_secs: 60,
                    max_clients: 128,
                },
            )
            .await;

        let tenant_only = store.resolve("tenant-a", "key-v1").await;
        let tenant_key = store.resolve("tenant-a", "key-v2").await;

        assert_eq!(tenant_only.requests_per_window, 10);
        assert_eq!(tenant_key.requests_per_window, 2);
    }

    #[test]
    fn encode_redis_command_has_valid_resp_shape() {
        let cmd = encode_redis_command(&["INCR".to_string(), "k1".to_string()]);
        let as_text = String::from_utf8(cmd).expect("valid utf8");
        assert_eq!(as_text, "*2\r\n$4\r\nINCR\r\n$2\r\nk1\r\n");
    }
}
