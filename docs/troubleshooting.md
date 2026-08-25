# Troubleshooting

Quick index — full guide is [troubleshooting.md](troubleshooting.md).

## Build

- `protoc not found` → `protoc` is vendored via `protoc-bin-vendored`; try `cargo clean && cargo build`.
- `openssl/ring build failed` → install `libssl-dev` / `build-essential` (Debian) or `xcode-select --install` (macOS).

## Runtime

- `Address already in use` → `lsof -i :9000` / change `OSMOSMPC_LISTEN_PORT`.
- `Connection refused` → `curl /health`, check firewall `ufw status`, `netstat -tlnp`.
- `TLS handshake failed` → check `data/certs/` exists, `chmod 600`, `OSMOSMPC_TLS_ENABLED=true` + pinned fingerprints match `cert_fingerprint` (`crates/network/src/cert.rs:166`).
- `Session not found` → UUID format, check `GET /sessions`, coordinator logs.

## See also

- [design/architecture.md](design/architecture.md) · [design/threat-model.md](design/threat-model.md) · [api/openapi.yaml](api/openapi.yaml) · [runbook.md](runbook.md)

---

Version: 0.1.0-alpha | Last updated: 2026-08-24
