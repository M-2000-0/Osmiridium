# Compliance

## Data handling

- **Minimization:** coordinator never sees private inputs (additive shares + MACs only). Audit log stores session metadata, participant endpoints, hashed transcript entries — no plaintext inputs.
- **Retention:** audit log is in-memory HashMap (`Coordinator:60`) + optional JSON-lines export (item 1300). Operators should ship to SIEM and retain per policy (default 30d via `scripts/backup.sh`).
- **Deletion (GDPR/CCPA):** `DELETE` not yet exposed; operator must drop `./data/sessions/<id>.json` and restart coordinator to purge in-memory state (item 1069). Right-to-erasure requires manual session purge + backup rotation.

## BUSL-1.1

Workspace `Cargo.toml:18` declares `BUSL-1.1`; see `LICENSE`. Commercial use requires separate license. Third-party licenses tracked via `deny.toml:1` (allow: MIT/Apache-2.0/BSD/etc.) and `cargo deny check`.

## Security controls

Mapping to SOC2/ISO27001 is tracked in `docs/design/threat-model.md` (assets, G-1..G-5). Controls: API-key auth + rate limiting (`crates/api/src/lib.rs:68`), body limit 1 MiB, max-message-size 64 MiB (`crates/network/src/tcp.rs:89`), hash-chained audit log, panic hook (`crates/cli/src/main.rs:97`).

## Export control

No export-controlled crypto beyond standard BN254 (ark-ff). Operators in restricted jurisdictions should review local regulations.

## Responsible disclosure

See `SECURITY.md`. Do not file public issues for vulns.
