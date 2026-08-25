# Deployment Guide

This guide covers deploying Osmiridium for production use.

## Architecture Overview

A production Osmiridium deployment consists of:

- **Coordinator** — The central service managing sessions, policies, and audit logs
- **N Party Nodes** — Each party runs the SMPC protocol with their private inputs
- **REST API** — Exposed by the coordinator for external integration

```
                +-------------+
                |   Clients   |
                +------+------+
                       | HTTPS
                +------v------+
                | Coordinator |   REST API on :8080
                |  (API)      |
                +------+------+
                       |
          +------------+------------+
          |            |            |
   +------v------+ +---v------+ +--v------+
   |  Party 0    | | Party 1  | | Party 2 |
   |  :9000      | | :9001    | | :9002   |
   +-------------+ +----------+ +---------+
     TCP channels — plaintext by default;
     optional TLS 1.3 with cert pinning (see TLS Configuration)
```

## Prerequisites

- Docker 24+ and Docker Compose v2 (for Option 1)
- Rust 1.97+ (for Option 2)
- Open ports: 8080 (coordinator API), 9000-9009 (party communication)

## Deployment Options

### Option 1: Docker Compose (Recommended)

The `docker-compose.yml` starts a coordinator and 3 party nodes.

```bash
# Build images and start all services
docker compose up --build -d

# Check service status
docker compose ps

# View coordinator logs
docker compose logs coord
```

The coordinator API is available at `http://localhost:8080`.

### Option 2: Bare Metal

Build the release binary:

```bash
cargo build --release --workspace
```

Start the coordinator:

```bash
OSMOSMPC_API_PORT=8080 \
./target/release/osmiridium verify --addr 0.0.0.0 --port 8080
```

Start party nodes (each on a different host or port):

```bash
# Party 0
OSMOSMPC_PARTY_ID=0 \
OSMOSMPC_LISTEN_PORT=9000 \
./target/release/osmiridium execute --session demo-session

# Party 1
OSMOSMPC_PARTY_ID=1 \
OSMOSMPC_LISTEN_PORT=9001 \
./target/release/osmiridium execute --session demo-session
```

## TLS Configuration

> **Plaintext is the default.** Without TLS, all inter-party TCP traffic is unencrypted
> and must only run inside a trusted network (VPC, private LAN, or WireGuard tunnel).
> This is the honest current wire state; the deployment ran plaintext until the
> `TlsConfig` pinning path landed.

When enabled, `TcpTransport` (`crates/network/src/tcp.rs:46`) upgrades to **TLS 1.3
with certificate-fingerprint pinning** (`crates/network/src/tls.rs:20`). The
handshake is still fully verified; a copied certificate without the matching private
key fails. The wire is encrypted only when a `TlsConfig` is attached.

### TransportType::TcpNoise semantics (#35)

`TransportType::TcpNoise` (`crates/network/src/transport.rs:8`) is a **label** for
the TCP transport: it means *"TLS with pinning when a `TlsConfig` is configured via
`TcpTransport::with_tls()`, plaintext otherwise"*. It is **not** Noise-protocol
encryption and it is not automatic mTLS — the enum variant does not by itself
change the wire. Historically the name implied Noise/mTLS while the wire was
plaintext; now TLS is optional and explicit.

### How to enable TLS

**Option A — environment (CLI / coordinator):**

1. Generate per-party self-signed certificates and print fingerprints:

   ```bash
   cargo run -p osmiridium-cli -- keygen --parties 3
   # prints: Party 0 certificate generated, fingerprint: [ab, cd, ...]
   # writes data/certs/party-{id}.crt, party-{id}.key, and ca.crt
   ```

   Fingerprints are `SHA-256(cert DER)` via `cert_fingerprint`
   (`crates/network/src/cert.rs:166`).

2. Configure environment:

   ```bash
   export OSMOSMPC_TLS_ENABLED=true
   export OSMOSMPC_CERT_DIR=./data/certs
   ```

   `Config::from_env` (`crates/cli/src/config.rs:191`) reads
   `OSMOSMPC_TLS_ENABLED` (`"true"` enables TLS, any other value keeps plaintext;
   default `false`). The process that builds a `TcpTransport` must then call
   `with_tls()` with the local cert/key and the set of peer fingerprints to pin.

**Option B — programmatic (Rust):**

```rust
use osmiridium_network::{TcpTransport, TlsConfig, transport::SessionConfig, Identity};

let pinned: Vec<[u8; 32]> = peer_certs.iter().map(|c| osmiridium_network::cert_fingerprint(c)).collect();
let tls = TlsConfig::new(local_cert_der, local_key_der, pinned)?;
let transport = TcpTransport::new(SessionConfig::default(), identity, "0.0.0.0:9000".into())
    .with_tls(tls); // <- without this call the transport stays plaintext
assert!(transport.has_tls());
```

Without `with_tls()` the transport stays plaintext regardless of
`TransportType::TcpNoise`. With `with_tls()`, outgoing connections verify the peer's
leaf fingerprint against `pinned_fingerprints` and incoming connections are
terminated with the local cert/key via `TlsConfig::acceptor()` / `connector()`.

## Multi-Party Network Setup

For a truly distributed deployment (parties on different machines):

1. Ensure each party can reach the others' TCP ports.
2. Configure endpoints via the coordinator API:

```bash
# Register parties with the coordinator
curl -X POST http://coordinator:8080/sessions \
  -H "Content-Type: application/json" \
  -d '{"name":"my-session","num_parties":3}'

# Add participants with their endpoints
curl -X POST http://coordinator:8080/sessions/{id}/participants \
  -H "Content-Type: application/json" \
  -d '{"party_id":0,"name":"alice","endpoint":"alice-host:9000","role":"DataProvider"}'
```

3. Set firewall rules to allow only inter-party traffic (ports 9000-9009) and coordinator API (port 8080).

## Operational Guidelines

### Security Considerations

- **TLS**: Always enable TLS in production via `TcpTransport::with_tls()` /
  `OSMOSMPC_TLS_ENABLED=true` with pinned peer fingerprints. Without it traffic is
  plaintext and must be confined to a private network (VPC / WireGuard). Current
  implementation uses self-signed certificates pinned by SHA-256 fingerprint
  (`cert_fingerprint` in `crates/network/src/cert.rs:166`, `TlsConfig` in
  `crates/network/src/tls.rs:20`) — not a CA trust chain. CA files written by
  `keygen` are retained for future mTLS work but are not used for peer
  authentication today. Client-certificate mTLS is roadmap, planned to layer on
  the same `TlsConfig`.
- **Network isolation**: Run parties on separate hosts with restricted network access.
- **Key management**: Store MAC key shares and TLS private keys in a secure secrets manager.
- **Audit logs**: The coordinator maintains audit logs; ship them to a SIEM for compliance.

### Monitoring

- Health checks: `GET /health` returns `ok`.
- Watch session lifecycle: `GET /sessions/:id` returns status (`Created`, `Configured`, `Running`, `Completed`, `Failed`).
- Logs use `tracing`; set `RUST_LOG=osmiridium=debug` for verbose output.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `Connection refused` | Party port not open / wrong endpoint | Verify ports and endpoints in coordinator |
| `MacVerificationFailed` | Tampered share or wrong MAC key | Re-run keygen; ensure all parties share the same alpha |
| `InsufficientShares` | Not enough parties joined | Add participants before executing |
| TLS handshake failure | Fingerprint mismatch or missing/invalid certs | Regenerate via `cargo run -p osmiridium-cli -- keygen`, ensure `TlsConfig::new(..., pinned_fingerprints)` contains all peer `cert_fingerprint`s, and `OSMOSMPC_TLS_ENABLED=true` is set consistently across parties |
| `SessionNotFound` | Wrong session ID | Use the UUID returned by `POST /sessions` |

## Kubernetes and Terraform (Unshipped)

`deploy/kubernetes/` and `deploy/terraform/` are **placeholders and not yet shipped**.
Each contains a `README.md` stub stating "coming soon". Do not expect
`kubectl apply -k deploy/kubernetes` or `terraform apply deploy/terraform` to work.

- Shipped deployment paths: `docker-compose.yml` (root) and bare-metal via
  `cargo build --release --workspace` (see Deployment Options above).
- Kubernetes manifests and Terraform modules are tracked in
  `LAUNCH_READINESS.md` items 705-782 and will land there when ready. Until then,
  the `deploy/kubernetes/README.md:1` and `deploy/terraform/README.md:1` stubs
  are the source of truth that these targets are unshipped.
- This section exists to close checklist item #15 (doc-only, fixable) and to
  reconcile the prior claim that Kubernetes/Terraform were ready.

## See also

- Architecture: [docs/design/architecture.md](docs/design/architecture.md)
- Threat model: [docs/design/threat-model.md](docs/design/threat-model.md)
- REST API spec: [docs/api/openapi.yaml](docs/api/openapi.yaml) — summary in [docs/api/README.md](docs/api/README.md)
- Runbook (backup/restore, incident response): [docs/runbook.md](docs/runbook.md)
- Troubleshooting: [docs/troubleshooting.md](docs/troubleshooting.md) / [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

---

Version: 0.1.0-alpha | Last updated: 2026-08-24