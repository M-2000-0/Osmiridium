# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x-alpha | :white_check_mark: (development) |
| < 0.1 | :x: |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Email: `security@osmiridium.tech` (or open a private security advisory via GitHub: `Security → Report a vulnerability`).

Include:
- Description, impact, and reproduction steps
- Affected version / commit
- Proof-of-concept if available

We will acknowledge within 48h and aim to provide a fix/mitigation within 14 days. We follow coordinated disclosure — please allow us to publish a fix before public disclosure.

## Scope

In-scope: `crates/crypto`, `crates/protocol`, `crates/network` (TLS/framing), `crates/coordinator` (policy/authz), `crates/api` (auth/validation), `crates/cli` (key handling).

Out-of-scope pre-launch: FHE prototype `crates/fhe` (gated behind `fhe-prototype`).

## Security Model

- Threat model: `docs/design/threat-model.md`
- Assumptions: semi-honest parties by default; malicious variant planned. MACs provide integrity, not confidentiality alone — transport must be encrypted (mTLS).
- Secrets: `SecretKey` zeroizes on drop (`zeroize` crate). Never log secrets; errors redact field elements.

## Hardening Checklist (operators)

- Set `OSMOSMPC_API_KEY` (no default in prod), enable `OSMOSMPC_TLS_ENABLED=1`, pin peer cert fingerprints.
- Put `/metrics` behind internal firewall.
- Run `cargo audit` / `cargo deny` in CI (see `.github/workflows/ci.yml`).
- Rotate certs/keys per runbook `docs/runbook.md`.

## Disclosure Process

1. Triage → 2. Fix on private branch → 3. Release + advisory → 4. Credit reporter (if desired).

## See also

- Threat model: [docs/design/threat-model.md](docs/design/threat-model.md)
- Architecture: [docs/design/architecture.md](docs/design/architecture.md)
- API spec: [docs/api/openapi.yaml](docs/api/openapi.yaml)

---

Version: 0.1.0-alpha | Last updated: 2026-08-24
