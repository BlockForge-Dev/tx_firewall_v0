use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const HIST_BUCKETS_MS: [f64; 12] = [
    1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
];
const MAX_RECENT_EVENTS: usize = 200_000;

#[derive(Clone, Copy, Debug)]
pub struct SloConfig {
    pub window_secs: u64,
    pub min_samples: u64,
    pub max_p95_latency_ms: f64,
    pub max_error_rate: f64,
    pub max_simulation_failure_rate: f64,
}

impl Default for SloConfig {
    fn default() -> Self {
        Self {
            window_secs: 300,
            min_samples: 50,
            max_p95_latency_ms: 1200.0,
            max_error_rate: 0.05,
            max_simulation_failure_rate: 0.20,
        }
    }
}

impl SloConfig {
    pub fn from_env() -> Self {
        Self {
            window_secs: parse_u64_env("SLO_WINDOW_SECS", 300).max(1),
            min_samples: parse_u64_env("SLO_MIN_SAMPLES", 50),
            max_p95_latency_ms: parse_f64_env("SLO_MAX_P95_LATENCY_MS", 1200.0).max(0.0),
            max_error_rate: clamp01(parse_f64_env("SLO_MAX_ERROR_RATE", 0.05)),
            max_simulation_failure_rate: clamp01(parse_f64_env(
                "SLO_MAX_SIMULATION_FAILURE_RATE",
                0.20,
            )),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SloStatus {
    pub status: String,
    pub window_secs: u64,
    pub min_samples: u64,
    pub request_samples: u64,
    pub p95_latency_ms: Option<f64>,
    pub error_rate: f64,
    pub simulation_failure_rate: f64,
    pub alerts: Vec<String>,
}

#[derive(Clone)]
pub struct MetricsRegistry {
    inner: Arc<Mutex<MetricsState>>,
}

#[derive(Default)]
struct MetricsState {
    evaluate_latency_ms: Histogram,
    stage_latency_ms: HashMap<String, Histogram>,
    requests_total: HashMap<String, u64>,
    rule_hits_total: HashMap<String, u64>,
    simulation_failures_total: HashMap<String, u64>,
    recent_latencies_ms: VecDeque<TimedF64>,
    recent_request_outcomes: VecDeque<TimedOutcome>,
    recent_sim_failures: VecDeque<u64>,
}

#[derive(Clone)]
struct TimedF64 {
    ts: u64,
    value: f64,
}

#[derive(Clone)]
struct TimedOutcome {
    ts: u64,
    outcome: String,
}

#[derive(Clone)]
struct Histogram {
    buckets: Vec<f64>,
    counts: Vec<u64>,
    count: u64,
    sum: f64,
}

impl Histogram {
    fn with_buckets(bounds: &[f64]) -> Self {
        Self {
            buckets: bounds.to_vec(),
            counts: vec![0; bounds.len()],
            count: 0,
            sum: 0.0,
        }
    }

    fn observe(&mut self, value: f64) {
        let v = if value.is_finite() && value >= 0.0 {
            value
        } else {
            0.0
        };
        self.count = self.count.saturating_add(1);
        self.sum += v;

        for (i, b) in self.buckets.iter().enumerate() {
            if v <= *b {
                self.counts[i] = self.counts[i].saturating_add(1);
            }
        }
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::with_buckets(&HIST_BUCKETS_MS)
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MetricsState::default())),
        }
    }

    pub fn observe_evaluate_latency_ms(&self, value_ms: f64) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.evaluate_latency_ms.observe(value_ms);
            push_timed_f64(&mut guard.recent_latencies_ms, value_ms);
        }
    }

    pub fn observe_stage_latency_ms(&self, stage: &str, value_ms: f64) {
        if let Ok(mut guard) = self.inner.lock() {
            let h = guard
                .stage_latency_ms
                .entry(stage.to_string())
                .or_insert_with(Histogram::default);
            h.observe(value_ms);
        }
    }

    pub fn inc_request(&self, outcome: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            let v = guard.requests_total.entry(outcome.to_string()).or_insert(0);
            *v = v.saturating_add(1);
            push_timed_outcome(&mut guard.recent_request_outcomes, outcome);
        }
    }

    pub fn inc_rule_hit(&self, rule_id: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            let v = guard
                .rule_hits_total
                .entry(rule_id.to_string())
                .or_insert(0);
            *v = v.saturating_add(1);
        }
    }

    pub fn inc_simulation_failure(&self, kind: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            let v = guard
                .simulation_failures_total
                .entry(kind.to_string())
                .or_insert(0);
            *v = v.saturating_add(1);
            push_timed_u64(&mut guard.recent_sim_failures);
        }
    }

    pub fn render_prometheus(&self) -> String {
        self.render_prometheus_with_slo(SloConfig::default())
    }

    pub fn render_prometheus_with_slo(&self, slo_cfg: SloConfig) -> String {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return "# metrics unavailable\n".to_string(),
        };

        let mut out = String::new();

        render_histogram(
            &mut out,
            "tx_firewall_evaluate_latency_ms",
            None,
            &guard.evaluate_latency_ms,
        );

        for (stage, hist) in guard.stage_latency_ms.iter() {
            render_histogram(
                &mut out,
                "tx_firewall_stage_latency_ms",
                Some(vec![("stage", stage.as_str())]),
                hist,
            );
        }

        render_counter_map(
            &mut out,
            "tx_firewall_requests_total",
            "counter",
            "outcome",
            &guard.requests_total,
        );
        render_counter_map(
            &mut out,
            "tx_firewall_rule_hits_total",
            "counter",
            "rule_id",
            &guard.rule_hits_total,
        );
        render_counter_map(
            &mut out,
            "tx_firewall_simulation_failures_total",
            "counter",
            "kind",
            &guard.simulation_failures_total,
        );

        let status = evaluate_slo_from_state(&guard, slo_cfg);
        render_slo_gauges(&mut out, &status);

        out
    }

    pub fn evaluate_slo(&self, cfg: SloConfig) -> SloStatus {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => {
                return SloStatus {
                    status: "ALERT".to_string(),
                    window_secs: cfg.window_secs,
                    min_samples: cfg.min_samples,
                    request_samples: 0,
                    p95_latency_ms: None,
                    error_rate: 1.0,
                    simulation_failure_rate: 1.0,
                    alerts: vec!["metrics_unavailable".to_string()],
                }
            }
        };
        evaluate_slo_from_state(&guard, cfg)
    }
}

fn evaluate_slo_from_state(state: &MetricsState, cfg: SloConfig) -> SloStatus {
    let now = now_unix_secs();
    let cutoff = now.saturating_sub(cfg.window_secs.max(1));

    let mut request_samples = 0u64;
    let mut error_samples = 0u64;
    for x in state.recent_request_outcomes.iter() {
        if x.ts < cutoff {
            continue;
        }
        request_samples = request_samples.saturating_add(1);
        if x.outcome == "error" {
            error_samples = error_samples.saturating_add(1);
        }
    }

    let mut latency_values: Vec<f64> = Vec::new();
    for x in state.recent_latencies_ms.iter() {
        if x.ts >= cutoff {
            latency_values.push(x.value);
        }
    }
    let p95_latency_ms = quantile(&mut latency_values, 0.95);

    let mut sim_failure_samples = 0u64;
    for ts in state.recent_sim_failures.iter() {
        if *ts >= cutoff {
            sim_failure_samples = sim_failure_samples.saturating_add(1);
        }
    }

    let denom = request_samples.max(1) as f64;
    let error_rate = (error_samples as f64) / denom;
    let simulation_failure_rate = (sim_failure_samples as f64) / denom;

    if request_samples < cfg.min_samples {
        return SloStatus {
            status: "INSUFFICIENT_DATA".to_string(),
            window_secs: cfg.window_secs,
            min_samples: cfg.min_samples,
            request_samples,
            p95_latency_ms,
            error_rate,
            simulation_failure_rate,
            alerts: Vec::new(),
        };
    }

    let mut alerts = Vec::new();
    if let Some(p95) = p95_latency_ms {
        if p95 > cfg.max_p95_latency_ms {
            alerts.push(format!(
                "p95_latency_ms>{}",
                trim_float(cfg.max_p95_latency_ms)
            ));
        }
    }
    if error_rate > cfg.max_error_rate {
        alerts.push(format!("error_rate>{}", trim_float(cfg.max_error_rate)));
    }
    if simulation_failure_rate > cfg.max_simulation_failure_rate {
        alerts.push(format!(
            "simulation_failure_rate>{}",
            trim_float(cfg.max_simulation_failure_rate)
        ));
    }

    let status = if alerts.is_empty() { "OK" } else { "ALERT" }.to_string();
    SloStatus {
        status,
        window_secs: cfg.window_secs,
        min_samples: cfg.min_samples,
        request_samples,
        p95_latency_ms,
        error_rate,
        simulation_failure_rate,
        alerts,
    }
}

fn render_counter_map(
    out: &mut String,
    metric: &str,
    metric_type: &str,
    label_name: &str,
    map: &HashMap<String, u64>,
) {
    out.push_str(&format!("# TYPE {metric} {metric_type}\n"));
    for (k, v) in map {
        out.push_str(&format!(
            "{metric}{{{label_name}=\"{}\"}} {v}\n",
            escape_label_value(k)
        ));
    }
}

fn render_histogram(
    out: &mut String,
    metric: &str,
    labels: Option<Vec<(&str, &str)>>,
    h: &Histogram,
) {
    out.push_str(&format!("# TYPE {metric} histogram\n"));

    for (i, b) in h.buckets.iter().enumerate() {
        let mut ls: Vec<(String, String)> = Vec::new();
        if let Some(base) = &labels {
            for (k, v) in base {
                ls.push(((*k).to_string(), (*v).to_string()));
            }
        }
        ls.push(("le".to_string(), format!("{b}")));
        out.push_str(&format!(
            "{metric}_bucket{} {}\n",
            fmt_labels(&ls),
            h.counts.get(i).copied().unwrap_or(0)
        ));
    }

    let mut ls_inf: Vec<(String, String)> = Vec::new();
    if let Some(base) = &labels {
        for (k, v) in base {
            ls_inf.push(((*k).to_string(), (*v).to_string()));
        }
    }
    ls_inf.push(("le".to_string(), "+Inf".to_string()));
    out.push_str(&format!(
        "{metric}_bucket{} {}\n",
        fmt_labels(&ls_inf),
        h.count
    ));

    let sum_labels = labels.unwrap_or_default();
    let sum_fmt = fmt_labels(
        &sum_labels
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<Vec<_>>(),
    );
    out.push_str(&format!("{metric}_sum{sum_fmt} {}\n", h.sum));
    out.push_str(&format!("{metric}_count{sum_fmt} {}\n", h.count));
}

fn fmt_labels(labels: &[(String, String)]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    for (k, v) in labels {
        parts.push(format!("{k}=\"{}\"", escape_label_value(v)));
    }
    format!("{{{}}}", parts.join(","))
}

fn escape_label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn push_timed_f64(q: &mut VecDeque<TimedF64>, value: f64) {
    q.push_back(TimedF64 {
        ts: now_unix_secs(),
        value,
    });
    while q.len() > MAX_RECENT_EVENTS {
        q.pop_front();
    }
}

fn push_timed_outcome(q: &mut VecDeque<TimedOutcome>, outcome: &str) {
    q.push_back(TimedOutcome {
        ts: now_unix_secs(),
        outcome: outcome.to_string(),
    });
    while q.len() > MAX_RECENT_EVENTS {
        q.pop_front();
    }
}

fn push_timed_u64(q: &mut VecDeque<u64>) {
    q.push_back(now_unix_secs());
    while q.len() > MAX_RECENT_EVENTS {
        q.pop_front();
    }
}

fn render_slo_gauges(out: &mut String, status: &SloStatus) {
    out.push_str("# TYPE tx_firewall_slo_status gauge\n");
    let status_num = match status.status.as_str() {
        "OK" => 0.0,
        "INSUFFICIENT_DATA" => 0.5,
        _ => 1.0,
    };
    out.push_str(&format!("tx_firewall_slo_status {}\n", status_num));

    out.push_str("# TYPE tx_firewall_slo_request_samples gauge\n");
    out.push_str(&format!(
        "tx_firewall_slo_request_samples {}\n",
        status.request_samples
    ));

    out.push_str("# TYPE tx_firewall_slo_error_rate gauge\n");
    out.push_str(&format!(
        "tx_firewall_slo_error_rate {}\n",
        status.error_rate
    ));

    out.push_str("# TYPE tx_firewall_slo_simulation_failure_rate gauge\n");
    out.push_str(&format!(
        "tx_firewall_slo_simulation_failure_rate {}\n",
        status.simulation_failure_rate
    ));

    out.push_str("# TYPE tx_firewall_slo_p95_latency_ms gauge\n");
    out.push_str(&format!(
        "tx_firewall_slo_p95_latency_ms {}\n",
        status.p95_latency_ms.unwrap_or(0.0)
    ));

    out.push_str("# TYPE tx_firewall_slo_alert gauge\n");
    let kinds = [
        "p95_latency_ms",
        "error_rate",
        "simulation_failure_rate",
        "metrics_unavailable",
    ];
    for kind in kinds {
        let hit = if status.alerts.iter().any(|a| a.starts_with(kind)) {
            1
        } else {
            0
        };
        out.push_str(&format!(
            "tx_firewall_slo_alert{{kind=\"{}\"}} {}\n",
            kind, hit
        ));
    }
}

fn quantile(values: &mut [f64], q: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let q = clamp01(q);
    let rank = ((values.len() as f64) * q).ceil() as usize;
    let idx = rank.saturating_sub(1).min(values.len() - 1);
    values.get(idx).copied()
}

fn parse_u64_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn parse_f64_env(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .unwrap_or(default)
}

fn clamp01(x: f64) -> f64 {
    if !x.is_finite() {
        return 0.0;
    }
    x.clamp(0.0, 1.0)
}

fn trim_float(v: f64) -> String {
    let s = format!("{:.6}", v);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
