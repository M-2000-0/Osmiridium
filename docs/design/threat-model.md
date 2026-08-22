# Threat Model

Status: draft, reflects the codebase as of 0.1.0-alpha. Read together with
`architecture.md`.

## Assets

1. **Party inputs** — private values contributed by data providers.
2. **Computation outputs** — revealed only to authorized parties.
3. **MAC key `alpha`** — secret-shared; compromise breaks authenticity.
4. **Beaver triples** — preprocessed material; reuse leaks correlations.
5. **Identity keys / API keys** — authenticate participants and API callers.
6. **Coordinator audit log** — integrity evidence for operators.

## Adversaries

| Adversary | Capability | Currently addressed |
|-----------|------------|---------------------|
| Semi-honest party | Follows protocol, tries to learn from its view | Yes (SPDZ sharing + MACs) |
| Malicious party | Deviates arbitrarily, sends malformed shares | Partially: MAC checks detect tampering; abort-only fairness |
| External network attacker | Reads/injects/drops TCP traffic | **No** — transport is plaintext; see gap G-1 |
| Malicious API caller | Unauthenticated endpoint access | Yes: API-key auth middleware + rate limiting |
| Coordinator compromise | Full session metadata, participant list, audit log | Input privacy survives (shares never at coordinator); availability does not |
| Colluding minority (< threshold) | Pool views | Yes within SPDZ honest-majority assumptions for the current configuration |

## Trust boundaries

- Party ↔ Party: mutual distrust; all messages MAC-authenticated at the
  protocol layer.
- Caller ↔ Coordinator API: trust established by shared API key
  (`x-api-key` header or Bearer token). `/health` and `/metrics` are open
  and must be network-firewalled appropriately.
- Coordinator ↔ Parties: the coordinator orchestrates but never reconstructs
  secrets during normal operation.

## Known gaps (tracked in LAUNCH_READINESS.md)

- **G-1 Plaintext TCP.** Frames are length-prefixed bincode without
  encryption or peer authentication on the wire. `TransportType::TcpNoise`
  is a label only. Mitigation until fixed: run inside a mutually
  authenticated network fabric (e.g., WireGuard mesh, private VPC).
- **G-2 Self-HMAC identity.** `Identity::verify` validates a message against
  the sender's own HMAC key rather than verifying a signature from a
  published public key. Key distribution/trust setup is undefined.
- **G-3 No replay protection.** Round numbers exist but stale-round
  rejection is not enforced end-to-end.
- **G-4 Prototype FHE.** The FHE scheme is not semantically secure
  encryption; do not use `osmiridium-fhe` to protect real inputs yet.
- **G-5 In-memory sessions.** No durable state; availability and audit
  continuity depend on process uptime.

## Security properties delivered

- **Privacy (semi-honest):** inputs remain secret-shared throughout;
  reconstruction only at output wires for listed parties.
- **Integrity:** any share tampering that passes MAC check would require
  forging MACs under secret-shared `alpha`.
- **Aborts:** MAC verification failure surfaces as `MacVerification` error
  instead of releasing incorrect output (fail-closed).

## Recommendations before production use

1. Ship encrypted transport (Noise or mTLS) — closes G-1.
2. Replace self-HMAC with signature-based identity and defined key
   ceremony — closes G-2.
3. Enforce round-number freshness windows — closes G-3.
4. Keep `fhe-mul` feature disabled for sensitive workloads until the scheme
   is replaced with a real one — contains G-4.

## Reporting

See SECURITY.md for vulnerability reporting instructions.
