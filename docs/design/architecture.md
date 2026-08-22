# Architecture

Status: draft, reflects the codebase as of 0.1.0-alpha.

## Overview

Osmiridium is a Secure Multi-Party Computation (SMPC) platform implementing
SPDZ-family protocols with malicious security. Parties jointly evaluate an
arithmetic circuit over secret-shared inputs without revealing them to each
other.

## Layered view

```
┌─────────────────────────────────────────────────────────┐
│                    CLI (osmiridium-cli)                  │
│  test · keygen · create-session · execute · verify · bench│
├─────────────────────────────────────────────────────────┤
│                    API (osmiridium-api)                  │
│        REST (axum) + gRPC (tonic), shared coordinator    │
├─────────────────────────────────────────────────────────┤
│            Coordinator (osmiridium-coordinator)          │
│      Session lifecycle · Policy engine · Audit log       │
├─────────────────────────────────────────────────────────┤
│                Network (osmiridium-network)              │
│     TCP / in-memory transports · Identity · HMAC         │
├─────────────────────────────────────────────────────────┤
│               Protocol (osmiridium-protocol)             │
│   SPDZ offline/online phases · Circuit eval · MAC check  │
├─────────────────────────────────────────────────────────┤
│                 Crypto (osmiridium-crypto)               │
│  Field (BN254) · Sharing · MAC · PRSS · OT · Hashing     │
├─────────────────────────────────────────────────────────┤
│                   FHE (osmiridium-fhe)                   │
│   Threshold FHE prototype · Hybrid FHE+SPDZ switching    │
└─────────────────────────────────────────────────────────┘
```

Dependencies point strictly downward; `osmiridium-crypto` has no in-workspace
dependencies.

## Process model

The shipped binary is `osmiridium-cli`. The `verify` subcommand starts the
API server process:

- **REST** (default port 8080) — axum router with, in layer order:
  request-body limit (1 MB) → tracing → metrics → rate limiting → API-key auth.
- **gRPC** (default port 50051, disable with `--grpc-port 0`) — tonic server
  mirroring the REST session lifecycle.
- Both servers share a single in-process `Coordinator`, so sessions created
  via REST are visible via gRPC and vice versa.

## Session lifecycle

```
Created → ParticipantsJoining → CircuitDefined → Executing → Completed
                                                     └────→ Aborted
```

1. `POST /sessions` creates a session with a `SessionPolicy`
   (num_parties, source tag).
2. Participants register via `POST /sessions/:id/participants` with a role
   (`DataProvider`, `ComputationRunner`, `Auditor`, `Administrator`).
3. Circuits are attached (`DefineCircuit` over gRPC).
4. `execute` runs the SPDZ protocol: key agreement → offline (Beaver triples,
   MAC keys) → input sharing → online evaluation → output reconstruction.
5. Results are retrievable from the coordinator.

Sessions currently live in memory only; restarting the coordinator loses
state (tracked in LAUNCH_READINESS.md).

## Protocol summary

- Field: BN254 scalar field (~128-bit security).
- Sharing: additive secret sharing with information-theoretic MACs:
  `sum(mac_i) = alpha * sum(share_i)` where `alpha` is secret-shared.
- Offline phase: authenticated Beaver triples via PRSS-derived randomness.
- Online phase: circuit evaluation with MAC-preserving add/sub/scalar-mul and
  triple-consuming mul.
- Verification: batch MAC check before output reveal.

See `docs/protocol-specs/` for phase-level detail.

## Network transport

Two transports implement the same `Transport` trait:

- `TcpTransport`: length-prefixed (4-byte u32 + payload) bincode frames,
  max message size enforced on send and receive.
- `InMemoryTransport`: deterministic, for tests and single-process runs.

`TransportType::TcpNoise` is currently a label only — wire traffic is
plaintext TCP. See the threat model for implications.

## FHE subsystem

Prototype threshold scheme: additive-homomorphic operations plus a
feature-gated multiplication path (`--features fhe-mul`). Multiplication
requires a non-empty evaluation key and enforces `max_depth`. The hybrid
orchestrator routes computation steps between SPDZ and FHE based on depth
and interaction thresholds.

## Observability

- `/metrics` endpoint exposing Prometheus text format counters
  (requests, errors, rate-limited requests, active/executed sessions).
- `tracing` spans/logs; JSON output available via `--log-format json` or
  `OSMOSMPC_LOG_FORMAT=json`.
- Panic hook logs location + payload through `tracing` before the process
  aborts (release profile builds with `panic = "abort"`).
- Coordinator audit log entries are Blake3-hash chained for tamper evidence.

## Known gaps

Documented honestly rather than hidden:

- TCP transport is not encrypted (no Noise/mTLS yet).
- Identity verification uses self-HMAC, not signatures.
- Sessions are not persisted.
- FHE is a functional prototype, not production homomorphic encryption.
