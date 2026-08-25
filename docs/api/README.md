# Osmiridium API

REST + gRPC API for the coordinator. Canonical spec is [`openapi.yaml`](openapi.yaml) (`openapi: 3.0.3`, version `0.1.0-alpha`).

## Endpoints (REST, base `http://localhost:8080`)

- `GET /health` — liveness, no auth
- `GET /metrics` — Prometheus text, no auth (firewall it)
- `POST /sessions`, `GET /sessions/{id}`, `POST /sessions/{id}/participants`, `POST /sessions/{id}/execute`, `GET /sessions/{id}/results`

Auth: `x-api-key: $OSMOSMPC_API_KEY` (or `Authorization: Bearer`). Rate limit `OSMOSMPC_RATE_LIMIT` (default 60/min, `/health`/`/metrics` exempt). Body limit 1 MiB.

## gRPC

Proto at `crates/api/proto/osmiridium.proto` — see [grpc-reference.md](grpc-reference.md). Same coordinator, disable with `--grpc-port 0`.

## References

- Design: [../design/architecture.md](../design/architecture.md)
- Threat model: [../design/threat-model.md](../design/threat-model.md)
- REST detail: [api-reference.md](api-reference.md), [openapi.yaml](openapi.yaml)

---

Version: 0.1.0-alpha | Last updated: 2026-08-24
