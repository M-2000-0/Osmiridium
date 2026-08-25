# Threat Model

## Overview

This document describes the threat model for the Osmiridium SMPC platform,
covering all identified threats, their mitigations, and verification tests.

## Trust Boundaries

```
┌──────────────────────────────────────────────────┐
│  Coordinator                                     │
│  - Manages sessions                              │
│  - Enforces policies                             │
│  - Trusted by parties for orchestration only      │
│  - Does NOT see plaintext inputs/outputs          │
├──────────────────────────────────────────────────┤
│  Party Process                                   │
│  - Holds secret shares and key material           │
│  - Runs protocol logic locally                    │
│  - Communicates with other parties via transport  │
│  - Protected by mTLS/Noise encryption             │
├──────────────────────────────────────────────────┤
│  Network (TCP/QUIC)                              │
│  - Encrypted channel between parties              │
│  - Authenticated via certificates                 │
│  - Messages signed with MAC                       │
└──────────────────────────────────────────────────┘
```

## Threat Catalog

### MITM (Man-in-the-Middle)

- **Description**: Attacker intercepts and modifies messages between parties.
- **Mitigation**: All transport channels use TLS 1.3 or Noise protocol. Message
  integrity verified via HMAC-MAC scheme. Certificate pinning prevents CA
  compromise exploitation.
- **Regression Test**: `test: TLS handshake failure produces clear error`,
  `test: hostname mismatch rejected with clear error`

### Replay

- **Description**: Attacker captures valid messages and replays them later.
- **Mitigation**: Each session has a unique random seed for PRSS. Round
  counters prevent message replay within a session. Session IDs are UUIDs.
- **Regression Test**: `test: duplicate messages handled or rejected`,
  `test: session token reuse prevention`

### Replay-of-Stale-Round

- **Description**: Attacker replays messages from a previous protocol round.
- **Mitigation**: Round counters are monotonically increasing. Each round
  barrier prevents proceeding until all expected messages are received.
  Transport layer enforces FIFO ordering per sender.
- **Regression Test**: `test: out-of-order messages handled or rejected`

### Message-Forgery

- **Description**: Attacker creates fake protocol messages.
- **Mitigation**: All messages are authenticated via MAC using shared session
  keys derived from key agreement. MAC verification happens before any
  message processing. Invalid MACs produce `MacVerificationError`.
- **Regression Test**: `test: MAC verification catches tampered share`,
  `test: MAC verification catches missing MAC`

### Share-Tampering

- **Description**: Attacker modifies secret shares in transit.
- **Mitigation**: MAC scheme binds shares to the computation. Any share
  modification will cause MAC verification failure at reconstruction time.
  Authenticated shares carry both the share value and its MAC.
- **Regression Test**: `test: MAC verification catches tampered share`,
  `property test: MAC verification holds with various operands`

### Premature-Abort

- **Description**: Malicious party aborts protocol early to cause denial of
  service or selective abort.
- **Mitigation**: Protocol design is resilient to party dropout. Remaining
  parties detect timeout and abort cleanly. Session status transitions to
  `Failed`. Audit log records the event.
- **Regression Test**: `test: party crashes mid-protocol, others fail cleanly`,
  `test: graceful shutdown drains pending messages`

### Length-Prefix-Bomb

- **Description**: Attacker sends a frame with an absurdly large length prefix
  to exhaust memory.
- **Mitigation**: `max_message_size` enforced in `TcpTransport` frame reader
  (default 1MB). Frame reader rejects any length exceeding the configured
  maximum before allocating buffers.
- **Regression Test**: `test: message exceeding max size rejected`,
  `fuzz: oversize length-prefix frame`

### Deserialization-Bomb

- **Description**: Attacker sends a payload that causes quadratic blowup during
  deserialization.
- **Mitigation**: bincode is used for wire format with fixed-size integer
  headers. `max_message_size` limits input size. Serde bincode does not have
  known bomb vectors for our data types.
- **Regression Test**: `fuzz: truncated frame`, `fuzz: negative/absurd lengths`

### Resource-Exhaustion

- **Description**: Attacker exhausts CPU, memory, or file descriptors.
- **Mitigation**: Rate limiting per IP/API key. Max concurrent connections
  enforced. Request body size limits via tower-http. Session quotas per API
  key. Circuit gate limit per policy.
- **Regression Test**: `test: 100 concurrent connections don't exhaust file
  descriptors`, `stress test: memory pressure`

### Timing-Side-Channel

- **Description**: Attacker infers secrets from timing variations.
- **Mitigation**: Field arithmetic uses constant-time operations where
  possible via ark-ff. MAC comparison should use constant-time comparison.
  Timing of operations is logged but not secret-dependent.
- **Regression Test**: `test: side-channel audit of scalar comparisons`,
  `verify: crates/crypto field operations are constant-time`

### Cache-Side-Channel

- **Description**: Attacker infers secrets from cache access patterns.
- **Mitigation**: Secret-dependent data is not used as array indices.
  Share values are accessed uniformly during protocol execution. PRSS output
  is independent of secret data.
- **Regression Test**: `verify: no secret-dependent array indexing`

### Entropy-Exhaustion

- **Description**: Attacker forces the system to exhaust its entropy pool,
  causing weak randomness.
- **Mitigation**: OS CSPRNG (`/dev/urandom` on Linux) provides unlimited
  entropy. `OsRng` is used for key generation. PRSS seeds are derived from
  HKDF, not direct randomness.
- **Regression Test**: `test: key generation randomness quality`,
  `property test: random element is uniformly distributed`

### Key-Leak

- **Description**: Secret key material is leaked through logs, error messages,
  or debug output.
- **Mitigation**: `#[derive(Zeroize)]` on all secret key types. Keys
  zeroized on drop. No secret data in log messages at INFO level. Secret
  redaction in tracing subscriber. Debug output filtered.
- **Regression Test**: `test: verify no secret data in logs`,
  `test: verify no secret data in error messages`,
  `test: secret memory zeroization`

### Cert-Theft

- **Description**: Attacker steals TLS certificates to impersonate a party.
- **Mitigation**: Certificates are stored with restrictive file permissions
  (0600). mTLS requires both client and server certificates. Certificate
  pinning ties connections to specific certificate fingerprints.
- **Regression Test**: `test: cert files reject world-readable mode`,
  `test: self-signed cert rejected with clear error`

### Coordinator-Compromise

- **Description**: Attacker compromises the coordinator process.
- **Mitigation**: Coordinator never sees plaintext inputs or outputs. Session
  data is encrypted at rest. Coordinator only orchestrates, not computes.
  Audit log records all coordinator actions. Compromised coordinator can
  cause denial of service but cannot learn computation results.
- **Regression Test**: `test: coordinator trust model in architecture`,
  `test: audit log commitment verifies`

### Insider-Party

- **Description**: A legitimate party deviates from the protocol.
- **Mitigation**: Semi-honest model assumed for MVP. MAC scheme detects share
  tampering during reconstruction. Circuit validation prevents oversized
  computations. Protocol state machine prevents invalid transitions.
- **Regression Test**: `test: MAC verification catches tampered share`,
  `test: circuit validation rejects invalid circuits`

### Colluding-Parties

- **Description**: Multiple parties collude to learn other parties' inputs.
- **Mitigation**: Secret sharing with threshold t < n/2 ensures no
  information leakage with fewer than threshold corruptions. Each party
  holds only a share of each input. Reconstruction requires threshold
  parties.
- **Regression Test**: `test: reconstruction with n-1 parties fails cleanly`,
  `test: protocol with 2 parties produces correct result`

### Rogue-Joiner

- **Description**: Unauthorized party joins a session.
- **Mitigation**: API key authentication required for all API calls.
  Session-specific participant registration with party_id validation.
  Party IDs must be within [0, num_parties). Duplicate party IDs rejected.
- **Regression Test**: `test: add participant to full session rejected`,
  `test: API key rotation mid-session`

### Session-Hijack

- **Description**: Attacker takes over an active session.
- **Mitigation**: Sessions are identified by UUID v4 (unpredictable).
  API key required for all session operations. Session state machine
  prevents invalid transitions. Audit log records all state changes.
- **Regression Test**: `test: session hijacking prevention`,
  `test: cross-session data isolation`

### Replay-Session-ID

- **Description**: Attacker replays a session ID to access session data.
- **Mitigation**: Session IDs are UUID v4 (128-bit random). Session data
  includes full state that cannot be faked. Results only available after
  execution completes. API key auth required for all accesses.
- **Regression Test**: `test: session token reuse prevention`,
  `test: results only available after execution`

## Security Properties

### Confidentiality
- Inputs are secret-shared across parties; no single party sees others' inputs
- Transport encryption prevents eavesdropping
- Coordinator never sees plaintext data

### Integrity
- MAC scheme detects any share modification
- Certificate pinning prevents impersonation
- Audit log commitment (hash chain) prevents tampering

### Availability
- Rate limiting prevents DoS
- Timeout prevents resource exhaustion
- Graceful degradation under load

### Authentication
- API key authentication for REST/gRPC APIs
- mTLS for inter-party communication
- Certificate-based identity for parties

### Non-Repudiation
- Audit log records all actions with timestamps
- Audit log commitment enables tamper detection
- Structured logging for forensics

## Security Testing

All threats are verified through:
1. Unit tests for specific threat scenarios
2. Property-based tests for mathematical invariants
3. Fuzz testing for parser robustness
4. Integration tests for end-to-end security
5. Stress/chaos tests for resilience under attack
