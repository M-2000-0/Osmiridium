# API Reference (REST)

Base: `http://localhost:8080` (override `OSMOSMPC_API_URL`). Auth: `x-api-key` or `Authorization: Bearer $OSMOSMPC_API_KEY`; `/health` and `/metrics` are open (firewall `/metrics`).

See `openapi.yaml` for full schema. Key endpoints:

- `GET /health` → `ok` (liveness, no auth)
- `GET /metrics` → Prometheus text (no auth)
- `POST /sessions` — body `{"name":string,"num_parties":1..64}` → `201 {id,name,status,num_participants}` (validated `crates/api/src/lib.rs:303`)
- `GET /sessions/:id` → `{id,name,status,num_participants}` (real `ComputationSession` via `coordinator.get_session`)
- `POST /sessions/:id/participants` — body `{"party_id":usize,"name":string,"endpoint":"host:port","role":"DataProvider|ComputationRunner|Auditor|Administrator"}` — validates `endpoint` host:port, `party_id` range, duplicate check (→ `409` if session `Running`, `403` if policy denies)
- `POST /sessions/:id/execute` → `{results: [hex]}` — runs `Coordinator::execute_session` (SPDZ), stores `result`
- `GET /sessions/:id/results` → same as execute, `200` with `[]` if not yet executed, `404` if unknown UUID

Errors: `400` invalid UUID/name/role, `401` missing/invalid API key, `403` policy, `404` unknown session, `409` conflict (e.g. add after Running), `429` per-IP rate limit (`OSMOSMPC_RATE_LIMIT` default 60/min), `500` protocol failure. All errors are JSON `{error,code,message,details}` with `x-request-id` correlation.

Rate limit skipped for `/health`/`/metrics`; body limit 1 MiB (`tower_http::limit`). Metrics middleware counts `metrics.requests` etc. (`crates/api/src/metrics.rs`).
