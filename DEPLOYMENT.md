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
              TLS-encrypted mTLS channels
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

To enable TLS between parties and the coordinator:

1. Generate certificates (via the certificate module in `osmiridium-network`).
2. Configure environment:

```bash
export OSMOSMPC_TLS_ENABLED=true
export OSMOSMPC_CERT_DIR=./data/certs
```

3. Each party should have:
   - `data/certs/party-{id}.crt` — party certificate
   - `data/certs/party-{id}.key` — party private key
   - `data/certs/ca.crt` — shared CA certificate

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

- **TLS**: Always enable TLS in production. Use a proper CA, not self-signed certificates.
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
| TLS handshake failure | Missing/invalid certs | Regenerate certs; verify CA trust chain |
| `SessionNotFound` | Wrong session ID | Use the UUID returned by `POST /sessions` |