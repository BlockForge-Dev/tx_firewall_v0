# tx_firewall_v0

Rust service that simulates and risk-scores EVM transactions before signing.

It takes a proposed transaction, runs deterministic evaluation with RPC simulation and trace analysis, and returns a decision with evidence:
`ALLOW`, `WARN`, or `BLOCK`.

## Recruiter Snapshot

- Domain: blockchain security, transaction safety, pre-sign protection.
- Language and runtime: Rust + Tokio + Axum.
- Production focus: rate limiting, simulation budgets, fail-closed behavior, audit logging, SLO signals, admin control plane.
- Architecture style: modular pipeline with deterministic IDs, structured evidence, and observability-first operations.

## Why This Project Exists

Users sign transactions with incomplete visibility into internal effects.
This service reduces blind signing risk by turning raw calldata and trace output into explicit security evidence and policy decisions.

## What The Service Does

1. Validates and normalizes input transaction fields.
2. Pins a deterministic block (`requested block` or `latest-1`).
3. Decodes intent from calldata selectors.
4. Simulates execution (`eth_call`) and classifies failure modes.
5. Optionally traces execution (`debug_traceCall`) and extracts log facts.
6. Detects permission changes and token transfers (ERC20, ERC721, ERC1155).
7. Runs policy and confidence logic.
8. Returns a structured receipt with fired rules, uncertainties, and recommendations.

## Production Engineering Implemented

- Deterministic evaluation IDs for stable deduplication and auditability.
- Safety budgets for simulation and tracing:
  - timeout limits
  - max trace depth
  - max trace payload size
- Fail-closed behavior (`off|warn|block`) when analysis is partial.
- Rate limiting:
  - per-client buckets
  - per-tenant and per-key quotas
  - Redis-backed distributed mode with in-memory fallback option
- Admin control plane:
  - runtime key lifecycle (upsert, disable, delete)
  - runtime quota lifecycle (upsert, delete)
  - file-backed persistence and live application without restart
- Security controls:
  - API-key auth with optional salt and key metadata windows
  - admin-token protected management routes
  - request body size limits
- Observability:
  - structured logs with request/evaluation context
  - Prometheus metrics (latency, rule hits, failures, request outcomes)
  - rolling SLO evaluator with alert signals and ops endpoint

## System Architecture

- `src/api/*`: HTTP handlers and routes.
- `src/pipeline/mod.rs`: orchestration and rule wiring.
- `src/chain/*`: RPC client, block pinning, simulation and trace wrappers.
- `src/decode/mod.rs`: calldata intent decoding.
- `src/effects.rs`: fact extraction from logs.
- `src/policy.rs`: decision and confidence policy.
- `src/reverts.rs`: revert reason decoding.
- `src/safety/*`: rate limiters and safety controls.
- `src/management/*`: admin control plane and persisted runtime config.
- `src/observability/*`: metrics and SLO evaluation.

## API Overview

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness check |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/v1/ops/slo` | Rolling SLO report (`OK`, `INSUFFICIENT_DATA`, `ALERT`) |
| `POST` | `/v1/evaluate/tx` | Main transaction risk evaluation |
| `GET` | `/v1/admin/config` | Control-plane snapshot |
| `POST` | `/v1/admin/keys/upsert` | Add or update API key |
| `POST` | `/v1/admin/keys/disable` | Enable or disable API key |
| `POST` | `/v1/admin/keys/delete` | Delete API key |
| `POST` | `/v1/admin/quotas/upsert` | Add or update quota |
| `POST` | `/v1/admin/quotas/delete` | Delete quota |

Admin routes are active when `ADMIN_API_TOKEN` is set and require `x-admin-token`.

## Quick Start

```bash
cargo run
```

Service binds to `http://127.0.0.1:8000`.

Use an RPC for full simulation:

```powershell
$env:RPC_URL="https://your-evm-rpc"
cargo run
```

If `RPC_URL` is not set, the service still responds with placeholder chain evidence and uncertainty `SIMULATION_NOT_IMPLEMENTED`.

## Example Request

```bash
curl -s -X POST "http://127.0.0.1:8000/v1/evaluate/tx" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_id": 1,
    "from": "0x1111111111111111111111111111111111111111",
    "to": "0x2222222222222222222222222222222222222222",
    "data": "0x095ea7b30000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000ffffffffffffffff",
    "value": "0x0",
    "block_number": null
  }'
```

## Metrics And SLO Signals

Key exported metrics:

- `tx_firewall_evaluate_latency_ms` (histogram)
- `tx_firewall_stage_latency_ms{stage="..."}` (histogram)
- `tx_firewall_rule_hits_total{rule_id="..."}`
- `tx_firewall_simulation_failures_total{kind="..."}`
- `tx_firewall_requests_total{outcome="ok|error|rate_limited|unauthorized"}`
- `tx_firewall_slo_status` (`0=OK`, `0.5=INSUFFICIENT_DATA`, `1=ALERT`)
- `tx_firewall_slo_p95_latency_ms`
- `tx_firewall_slo_error_rate`
- `tx_firewall_slo_simulation_failure_rate`
- `tx_firewall_slo_alert{kind="..."}`

This supports post-incident questions such as:

- Which pipeline stage increased latency?
- Did simulation failures spike?
- Did a specific risk rule suddenly increase?
- Is the service inside SLO right now?

## Configuration

Authentication and admin:

- `AUTH_REQUIRED` (default `false`)
- `AUTH_KEY_SALT`
- `API_KEYS`
- `ADMIN_API_TOKEN` (enables admin routes)
- `CONTROL_PLANE_PATH` (default `control_plane.json`)

Request and safety limits:

- `MAX_REQUEST_BODY_BYTES` (default `65536`)
- `FAIL_CLOSED_MODE` (`off|warn|block`, default `warn`)
- `ETH_CALL_TIMEOUT_MS` (default `10000`)
- `TRACE_TIMEOUT_MS` (default `12000`)
- `MAX_TRACE_DEPTH` (default `48`)
- `MAX_TRACE_SIZE_BYTES` (default `2097152`)

Rate limits:

- `RATE_LIMIT_REQUESTS_PER_WINDOW` (default `120`)
- `RATE_LIMIT_WINDOW_SECS` (default `60`)
- `RATE_LIMIT_MAX_CLIENTS` (default `10000`)
- `TENANT_RATE_LIMITS` (tenant overrides)
- `RATE_LIMIT_BACKEND` (`memory|redis`, default `memory`)
- `RATE_LIMIT_REDIS_ADDR`
- `RATE_LIMIT_REDIS_KEY_PREFIX` (default `txfw:rl:`)
- `RATE_LIMIT_REDIS_CONNECT_TIMEOUT_MS` (default `80`)
- `RATE_LIMIT_REDIS_COMMAND_TIMEOUT_MS` (default `80`)
- `RATE_LIMIT_REDIS_PASSWORD`
- `RATE_LIMIT_REDIS_DB` (default `0`)
- `RATE_LIMIT_REDIS_FALLBACK_TO_MEMORY` (default `true`)

SLO:

- `SLO_WINDOW_SECS` (default `300`)
- `SLO_MIN_SAMPLES` (default `50`)
- `SLO_MAX_P95_LATENCY_MS` (default `1200`)
- `SLO_MAX_ERROR_RATE` (default `0.05`)
- `SLO_MAX_SIMULATION_FAILURE_RATE` (default `0.20`)

Audit:

- `AUDIT_LOG_PATH`
- `AUDIT_QUEUE_PATH`
- `AUDIT_DEAD_LETTER_PATH`
- `AUDIT_RETRY_MAX_ATTEMPTS` (default `8`)
- `AUDIT_DRAIN_BATCH_SIZE` (default `128`)

## Testing

Run all tests:

```bash
cargo test
```

Current suite covers:

- validation and deterministic IDs
- decode and selector handling
- chain pinning and call behavior
- trace extraction and effect confidence
- policy/rules and fail-closed behavior
- simulation budget enforcement
- auth, audit logging, and request limits
- in-memory and Redis rate-limiting paths
- admin control-plane lifecycle
- SLO endpoint and alert conditions

## Recruiter-Facing Engineering Signals

- Designed and implemented a safety-critical decision pipeline in Rust.
- Built abuse resistance and graceful degradation controls.
- Added distributed systems behavior (Redis-backed limiter) with fallback strategy.
- Implemented runtime operability (control plane, live config changes, persistent state).
- Implemented metrics and SLO-driven operational visibility suitable for on-call workflows.
- Backed features with automated tests across functional and operational scenarios.

## Known Limits

- EVM-only architecture at present.
- Trace quality depends on provider support for `debug_traceCall`.
- Some effects remain best-effort when traces are unavailable.

## Roadmap

- provider capability matrix and adaptive fallback policy
- additional decoder coverage (routers, bridges, permits, AA flows)
- policy profile presets and externalized policy config
- OpenAPI spec and response schemas
- benchmark and soak-test profiles

## License

No license file is currently defined in this repository.
