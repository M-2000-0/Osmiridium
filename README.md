# Osmiridium

Secure Multi-Party Computation (SMPC) platform implementing SPDZ-family protocols with malicious security.

## Overview

Osmiridium is a Rust workspace for privacy-preserving computation. Multiple parties can jointly compute a function over their private inputs without revealing those inputs to each other.

### Core Features

- **SPDZ Protocol** — Maliciously secure MPC with information-theoretic MACs
  - Offline phase: Beaver triples, MAC key shares
  - Online phase: authenticated circuit evaluation
  - MAC verification to detect tampering
- **Hybrid FHE + SPDZ** — Switch between homomorphic and secret-shared computation
- **Coordinator Layer** — Session management, policy enforcement, audit logging
- **Network Transport** — TCP and in-memory transports, TLS certificates, Ed25519 identity
- **REST API** — HTTP interface for session management and computation
- **CLI** — Command-line tools for testing, keygen, sessions, and benchmarking

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLI (osmiridium-cli)                  │
│  test · keygen · create-session · execute · verify · bench│
├─────────────────────────────────────────────────────────┤
│                    API (osmiridium-api)                  │
│                    REST + gRPC server                    │
├─────────────────────────────────────────────────────────┤
│        Coordinator (osmiridium-coordinator)             │
│    Session Mgmt · Policy · Audit · Orchestration         │
├─────────────────────────────────────────────────────────┤
│  Network (osmiridium-network)                           │
│  TCP / In-Memory · TLS Certs · Ed25519 Identity           │
├─────────────────────────────────────────────────────────┤
│      Protocol (osmiridium-protocol)                    │
│  SPDZ Offline · Online · Verification · Circuit          │
├─────────────────────────────────────────────────────────┤
│      Crypto (osmiridium-crypto)                        │
│  Field · Sharing · MAC · PRSS · OT · Hash               │
├─────────────────────────────────────────────────────────┤
│      FHE (osmiridium-fhe)                              │
│  Threshold FHE · Hybrid Computation                     │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Rust 1.97+
- Cargo

### Build

```bash
cargo build --workspace
```

### Run tests

```bash
cargo test --workspace
```

### Run the CLI

```bash
# Run a test SPDZ computation with 3 parties
cargo run -p osmiridium-cli -- test --parties 3

# Generate key shares
cargo run -p osmiridium-cli -- keygen --parties 3

# Execute a session
cargo run -p osmiridium-cli -- execute --session my-session

# Start the API server (REST on :8080, gRPC on :50051, shared coordinator)
cargo run -p osmiridium-cli -- verify --addr 0.0.0.0 --port 8080

# Disable the gRPC server (default port 50051):
cargo run -p osmiridium-cli -- verify --addr 0.0.0.0 --port 8080 --grpc-port 0

# Run benchmarks
cargo run -p osmiridium-cli -- bench --size 100 --repeats 10

# Show current configuration
cargo run -p osmiridium-cli -- config
```

### Docker Deployment

```bash
# Build and start all services
docker compose up --build

# Start just the coordinator API
docker compose up coord
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/sessions` | Create a computation session |
| GET | `/sessions/:id` | Get session status |
| POST | `/sessions/:id/participants` | Add a participant |
| POST | `/sessions/:id/execute` | Execute the session |
| GET | `/sessions/:id/results` | Get computation results |

## Configuration

Configuration is loaded from environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `OSMOSMPC_LISTEN_ADDR` | `0.0.0.0` | Network listen address |
| `OSMOSMPC_LISTEN_PORT` | `9000` | Network listen port |
| `OSMOSMPC_NUM_PARTIES` | `3` | Number of parties |
| `OSMOSMPC_PARTY_ID` | `0` | This party's ID |
| `OSMOSMPC_TLS_ENABLED` | `false` | Enable TLS |
| `OSMOSMPC_CERT_DIR` | `./data/certs` | Certificate directory |
| `OSMOSMPC_SECURITY_BITS` | `128` | Security parameter |
| `OSMOSMPC_API_PORT` | `8080` | API server port |
| `OSMOSMPC_LOG_FORMAT` | `text` | Log output format (`text` or `json`) |

### TLS

- By default, inter-party TCP traffic is **plaintext**.
- To enable TLS with certificate-fingerprint pinning, set `OSMOSMPC_TLS_ENABLED=true` and `OSMOSMPC_CERT_DIR=./data/certs`.
- Each party must have its certificate fingerprint added to the pinned list on every other party's `TcpTransport::with_tls()` call.
- Without TLS, traffic must run inside a trusted network (VPC, private LAN, or WireGuard tunnel).

### Identity

- Identities use **Ed25519 signatures** (replacing the earlier self-HMAC scheme).
- Each party generates a key pair via `cargo run -p osmiridium-cli -- keygen --parties N`.
- Public keys are distributed out of band; signatures are verified with `identity.verify_signature(msg, sig)` using the peer's public key.
- This replaces the previous self-HMAC scheme which could only authenticate a party's own messages.

### Persistence

- Session state can be made durable by setting `OSMOSMPC_DATA_DIR=/path/to/sessions`.
- The coordinator will persist every session mutation to `{session_id}.json` in the given directory.
- On startup, the coordinator restores any previously persisted sessions.

### Benchmarks

```bash
cargo run -p osmiridium-cli -- bench --size 100 --repeats 10
```

## Workspace Crates

| Crate | Description |
|-------|-------------|
| `osmiridium-crypto` | Field arithmetic (BN254), secret sharing, MACs, PRSS, OT, hashing |
| `osmiridium-protocol` | SPDZ offline/online phases, circuit evaluation, verification |
| `osmiridium-network` | TCP and in-memory transports, TLS certificates, Ed25519 identity |
| `osmiridium-coordinator` | Session lifecycle, policy engine, audit logging |
| `osmiridium-api` | REST API server |
| `osmiridium-cli` | Command-line interface |
| `osmiridium-fhe` | Threshold FHE, hybrid FHE+SPDZ computation |
| `osmiridium-testing` | Integration and unit tests |

## Protocol Details

### SPDZ

- **Field**: BN254 scalar field (~128-bit security)
- **Sharing**: Additive secret sharing with MACs
- **Security**: Malicious adversary model
- **MAC scheme**: `sum(mac_i) = alpha * sum(share_i)` where `alpha` is a secret-shared key
- **Offline phase**: Generates authenticated Beaver triples and MAC keys
- **Online phase**: Evaluates arithmetic circuits (add, mul, scalar mul)

### FHE

- Threshold FHE scheme for non-interactive computation
- Hybrid mode switches between FHE (for isolated sub-computations) and SPDZ (for the full circuit)

## See also

- Architecture: [docs/design/architecture.md](docs/design/architecture.md)
- Threat model: [docs/design/threat-model.md](docs/design/threat-model.md)
- REST API spec: [docs/api/openapi.yaml](docs/api/openapi.yaml) — summary in [docs/api/README.md](docs/api/README.md)
- Deployment guide: [DEPLOYMENT.md](DEPLOYMENT.md)
- Runbook: [docs/runbook.md](docs/runbook.md)
- Troubleshooting: [docs/troubleshooting.md](docs/troubleshooting.md)

## License

BUSL-1.1

---

Version: 0.1.0-alpha | Last updated: 2026-08-24