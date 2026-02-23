use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AuditLogger {
    cfg: Option<AuditConfig>,
    lock: Arc<Mutex<()>>,
}

#[derive(Clone)]
struct AuditConfig {
    sink_path: PathBuf,
    queue_path: PathBuf,
    dead_letter_path: PathBuf,
    max_attempts: u32,
    drain_batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueuedEvent {
    event: Value,
    attempts: u32,
    first_failed_ts_ms: u128,
    last_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeadLetterEvent {
    ts_ms: u128,
    reason: String,
    source: String,
    queued: Option<QueuedEvent>,
    raw_line: Option<String>,
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::disabled()
    }
}

impl AuditLogger {
    pub fn disabled() -> Self {
        Self {
            cfg: None,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn new(path: Option<PathBuf>) -> Self {
        match path {
            Some(sink_path) => {
                let queue_path = derive_queue_path(&sink_path);
                let dead_letter_path = derive_dead_letter_path(&sink_path);
                Self::with_paths(
                    Some(sink_path),
                    Some(queue_path),
                    Some(dead_letter_path),
                    8,
                    128,
                )
            }
            None => Self::disabled(),
        }
    }

    pub fn with_paths(
        sink_path: Option<PathBuf>,
        queue_path: Option<PathBuf>,
        dead_letter_path: Option<PathBuf>,
        max_attempts: u32,
        drain_batch_size: usize,
    ) -> Self {
        let Some(sink_path) = sink_path else {
            return Self::disabled();
        };

        let queue = queue_path.unwrap_or_else(|| derive_queue_path(&sink_path));
        let dlq = dead_letter_path.unwrap_or_else(|| derive_dead_letter_path(&sink_path));

        Self {
            cfg: Some(AuditConfig {
                sink_path,
                queue_path: queue,
                dead_letter_path: dlq,
                max_attempts: max_attempts.max(1),
                drain_batch_size: drain_batch_size.max(1),
            }),
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn from_env() -> Self {
        let sink = std::env::var("AUDIT_LOG_PATH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        let queue = std::env::var("AUDIT_QUEUE_PATH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        let dead_letter = std::env::var("AUDIT_DEAD_LETTER_PATH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        let max_attempts = env_u32("AUDIT_RETRY_MAX_ATTEMPTS", 8);
        let drain_batch_size = env_usize("AUDIT_DRAIN_BATCH_SIZE", 128);

        Self::with_paths(sink, queue, dead_letter, max_attempts, drain_batch_size)
    }

    pub fn is_enabled(&self) -> bool {
        self.cfg.is_some()
    }

    pub fn append_event(&self, event: &Value) -> Result<(), String> {
        let Some(cfg) = &self.cfg else {
            return Ok(());
        };

        let _guard = self
            .lock
            .lock()
            .map_err(|_| "audit lock poisoned".to_string())?;

        // Retry queued events first, so the sink catches up naturally under recovery.
        self.drain_queue_locked(cfg)?;

        match append_json_line(&cfg.sink_path, event) {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    sink = %cfg.sink_path.display(),
                    "audit.sink_write_failed"
                );
                let queued = QueuedEvent {
                    event: event.clone(),
                    attempts: 0,
                    first_failed_ts_ms: unix_timestamp_ms(),
                    last_error: e.clone(),
                };
                enqueue_record(&cfg.queue_path, &queued)?;
                Ok(())
            }
        }
    }

    fn drain_queue_locked(&self, cfg: &AuditConfig) -> Result<(), String> {
        if !cfg.queue_path.exists() {
            return Ok(());
        }

        let file = OpenOptions::new()
            .read(true)
            .open(&cfg.queue_path)
            .map_err(|e| e.to_string())?;
        let reader = BufReader::new(file);

        let mut queued_records: Vec<QueuedEvent> = Vec::new();
        for line in reader.lines() {
            let line = line.map_err(|e| e.to_string())?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            match serde_json::from_str::<QueuedEvent>(trimmed) {
                Ok(rec) => queued_records.push(rec),
                Err(e) => {
                    let dl = DeadLetterEvent {
                        ts_ms: unix_timestamp_ms(),
                        reason: format!("QUEUE_PARSE_FAILED: {e}"),
                        source: "queue".to_string(),
                        queued: None,
                        raw_line: Some(trimmed.to_string()),
                    };
                    let _ = append_json_line(&cfg.dead_letter_path, &dl);
                }
            }
        }

        if queued_records.is_empty() {
            let _ = std::fs::remove_file(&cfg.queue_path);
            return Ok(());
        }

        let mut remaining: Vec<QueuedEvent> = Vec::new();
        for (idx, mut rec) in queued_records.into_iter().enumerate() {
            if idx >= cfg.drain_batch_size {
                remaining.push(rec);
                continue;
            }

            match append_json_line(&cfg.sink_path, &rec.event) {
                Ok(()) => {}
                Err(e) => {
                    rec.attempts = rec.attempts.saturating_add(1);
                    rec.last_error = e.clone();

                    if rec.attempts >= cfg.max_attempts {
                        let dl = DeadLetterEvent {
                            ts_ms: unix_timestamp_ms(),
                            reason: format!("MAX_ATTEMPTS_EXCEEDED: {e}"),
                            source: "retry".to_string(),
                            queued: Some(rec),
                            raw_line: None,
                        };
                        let _ = append_json_line(&cfg.dead_letter_path, &dl);
                    } else {
                        remaining.push(rec);
                    }
                }
            }
        }

        rewrite_queue(&cfg.queue_path, &remaining)
    }
}

fn rewrite_queue(path: &Path, records: &[QueuedEvent]) -> Result<(), String> {
    if records.is_empty() {
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
        }
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;

    for rec in records {
        let line = serde_json::to_string(rec).map_err(|e| e.to_string())?;
        file.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
        file.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn enqueue_record(path: &Path, rec: &QueuedEvent) -> Result<(), String> {
    append_json_line(path, rec)
}

fn append_json_line<P: AsRef<Path>, T: Serialize>(path: P, payload: &T) -> Result<(), String> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;

    let line = serde_json::to_string(payload).map_err(|e| e.to_string())?;
    file.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    file.write_all(b"\n").map_err(|e| e.to_string())?;
    Ok(())
}

fn derive_queue_path(sink_path: &Path) -> PathBuf {
    derive_sibling_path(sink_path, "queue")
}

fn derive_dead_letter_path(sink_path: &Path) -> PathBuf {
    derive_sibling_path(sink_path, "deadletter")
}

fn derive_sibling_path(sink_path: &Path, suffix: &str) -> PathBuf {
    let parent = sink_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let stem = sink_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("audit");
    parent.join(format!("{stem}.{suffix}.jsonl"))
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

pub fn unix_timestamp_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn queues_when_sink_fails_then_flushes_on_recovery() {
        let tmp = std::env::temp_dir().join(format!("audit_q_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();

        let sink_path = tmp.join("sink");
        let queue_path = tmp.join("q.jsonl");
        let dead_path = tmp.join("dead.jsonl");

        // Create sink path as a directory so file append fails.
        std::fs::create_dir_all(&sink_path).unwrap();

        let logger = AuditLogger::with_paths(
            Some(sink_path.clone()),
            Some(queue_path.clone()),
            Some(dead_path.clone()),
            4,
            64,
        );

        logger.append_event(&json!({"id": 1})).unwrap();
        assert!(queue_path.exists());

        // Recover sink by replacing directory with a writable file path.
        std::fs::remove_dir_all(&sink_path).unwrap();
        logger.append_event(&json!({"id": 2})).unwrap();

        let raw = std::fs::read_to_string(&sink_path).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2, "expected queued + fresh events flushed");

        let _ = std::fs::remove_file(&sink_path);
        let _ = std::fs::remove_file(&queue_path);
        let _ = std::fs::remove_file(&dead_path);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn moves_to_dead_letter_after_max_attempts() {
        let tmp = std::env::temp_dir().join(format!("audit_dlq_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();

        let sink_path = tmp.join("sink");
        let queue_path = tmp.join("q.jsonl");
        let dead_path = tmp.join("dead.jsonl");
        std::fs::create_dir_all(&sink_path).unwrap(); // force write failure

        let logger = AuditLogger::with_paths(
            Some(sink_path.clone()),
            Some(queue_path.clone()),
            Some(dead_path.clone()),
            2, // max attempts
            128,
        );

        logger.append_event(&json!({"id": 1})).unwrap();
        logger.append_event(&json!({"id": 2})).unwrap();
        logger.append_event(&json!({"id": 3})).unwrap();

        let dead_raw = std::fs::read_to_string(&dead_path).unwrap();
        assert!(
            !dead_raw.trim().is_empty(),
            "expected dead-letter records after max attempts"
        );

        let _ = std::fs::remove_dir_all(&sink_path);
        let _ = std::fs::remove_file(&queue_path);
        let _ = std::fs::remove_file(&dead_path);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
