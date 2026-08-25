# Operations

Deployment topology, backup/restore, monitoring, and on-call.

## Topology

- **Single-host (dev):** `docker compose up --build` → coordinator `:8080` (`:50051` gRPC) + 3 mock parties. See `DEPLOYMENT.md`.
- **Multi-host (prod):** each `Party` on separate VPC/host, coordinator on hardened host, inter-party TCP `9000-9009` + coordinator `8080` firewalled to allowlist. Use WireGuard/VPC for G-1 mitigation until Noise/mTLS.

## Config

`config.example.toml` + env overrides (`OSMOSMPC_*`). Precedence: CLI `--config` > `OSMOSMPC_CONFIG` > `./config.toml`/`osmiridium.toml` > env > defaults. See `crates/cli/src/config.rs:66`.

Key envs: `OSMOSMPC_LISTEN_ADDR/PORT`, `NUM_PARTIES`, `PARTY_ID`, `TLS_ENABLED`, `CERT_DIR`, `SECURITY_BITS`, `MAX_ROUNDS`, `MALICIOUS`, `API_ENABLED/ADDR/PORT`, `API_KEY`, `RATE_LIMIT`, `LOG_FORMAT`.

## Backup / Restore

- Coordinator state is **in-memory only** (item 949) — no durable session DB yet. Persist via `POST /sessions/:id/results` export and `./data/sessions/*.json` CLI fallback.
- Scripts: `./scripts/backup.sh` / `restore.sh` tar `data/` + `backups/` retention 30d via cron (see `docs/runbook.md:41`).
- Restore drill: `cargo test --workspace` + `docker compose logs coord` + `curl /health`.

## Monitoring

- `/health` (open) and `/metrics` (Prometheus, open — firewall it) at `crates/api/src/lib.rs:204`. Counters: requests, errors, rate-limited, sessions active/executed (`crates/api/src/metrics.rs`).
- Stack: Prometheus `:9090`, Grafana `:3000` via `deploy/monitoring` (see runbook).
- Alerts: `Trivy` scan in `ci.yml:60`, `cargo audit`/`deny` checks.

## On-call

- Severity: P1 (protocol MAC failure / coordinator down) → immediate; P2 (rate-limit spike) → next business day.
- Runbook: `docs/runbook.md`. Escalation: `@M-2000-0` (CODEOWNERS).

## Sizing

- 3–10 parties: 2 vCPU / 4 GB per party, 2 vCPU / 8 GB coordinator. 32 parties: 4 vCPU / 16 GB. See benchmarks for scaling.

## Certificate rotation

`osmiridium keygen --parties N` regenerates CA + per-party certs in `data/certs/`; restart parties with new `OSMOSMPC_CERT_DIR`. See `crates/network/src/cert.rs`.
