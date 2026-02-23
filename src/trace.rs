use crate::{
    decode,
    domain::{CallFrame, TraceSummary},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceStats {
    pub contains_delegatecall: bool,
    pub max_depth: usize,
    pub max_fanout: usize,
}

pub fn compute_stats(root: &CallFrame) -> TraceStats {
    TraceStats {
        contains_delegatecall: contains_delegatecall(root),
        max_depth: max_depth(root),
        max_fanout: max_fanout(root),
    }
}

pub fn build_trace_summary(eoa_from: &str, root: CallFrame) -> TraceSummary {
    let stats = compute_stats(&root);
    let call_path_summary = call_path_summary(eoa_from, &root);

    TraceSummary {
        contains_delegatecall: stats.contains_delegatecall,
        max_depth: stats.max_depth,
        max_fanout: stats.max_fanout,
        call_path_summary,
        call_tree: root,
    }
}

fn contains_delegatecall(f: &CallFrame) -> bool {
    if f.call_type.eq_ignore_ascii_case("DELEGATECALL") {
        return true;
    }
    f.calls.iter().any(contains_delegatecall)
}

// depth in frames (root=1)
fn max_depth(f: &CallFrame) -> usize {
    if f.calls.is_empty() {
        return 1;
    }
    1 + f.calls.iter().map(max_depth).max().unwrap_or(0)
}

fn max_fanout(f: &CallFrame) -> usize {
    let here = f.calls.len();
    let below = f.calls.iter().map(max_fanout).max().unwrap_or(0);
    here.max(below)
}

// ✅ make public because tests import it
pub fn longest_path<'a>(f: &'a CallFrame) -> Vec<&'a CallFrame> {
    if f.calls.is_empty() {
        return vec![f];
    }

    let mut best = vec![f];

    for c in &f.calls {
        let mut cand = vec![f];
        cand.extend(longest_path(c));

        if cand.len() > best.len() {
            best = cand;
        }
    }

    best
}

fn call_path_summary(eoa_from: &str, root: &CallFrame) -> String {
    let path = longest_path(root);

    let mut parts: Vec<String> = Vec::new();
    parts.push("EOA".to_string());

    for frame in path {
        let decoded = decode::decode_calldata(&frame.to, &frame.input);
        let sig = decoded.signature;

        let label = if sig == "unknown_selector" {
            short_addr(&frame.to)
        } else {
            let fname = sig.split('(').next().unwrap_or(&sig);
            format!("{}::{}", short_addr(&frame.to), fname)
        };

        if frame.call_type.eq_ignore_ascii_case("DELEGATECALL") {
            parts.push(format!("{label} [DELEGATECALL]"));
        } else {
            parts.push(label);
        }
    }

    format!("{} (from {})", parts.join(" → "), short_addr(eoa_from))
}

fn short_addr(a: &str) -> String {
    if a.len() < 10 {
        return a.to_string();
    }
    let start = &a[..6];
    let end = &a[a.len().saturating_sub(4)..];
    format!("{start}…{end}")
}
