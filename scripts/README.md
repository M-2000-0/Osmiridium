# Scripts

- `deploy.sh` — builds and starts coordinator (`docker compose up --build` or bare-metal `cargo run -- verify`), see `docs/runbook.md:1`
- `backup.sh` / `restore.sh` — tar `data/` + `backups/` for coordinator state (see runbook)
- CLI-driven keygen/certs: `cargo run -p osmiridium-cli -- keygen --parties 3` (generates CA + per-party certs in `OSMOSMPC_CERT_DIR`, see `crates/network/src/cert.rs`)

For setup/keygen/certs ceremony, prefer the CLI (`osmiridium keygen`, `osmiridium verify --tls-cert/--tls-key`) over shell wrappers; scripts are thin operators for the single-host flow.
