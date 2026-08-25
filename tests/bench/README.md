# Benchmarks

This directory is intentionally empty — benchmarks live with the crates that own the hot paths:

- `crates/testing/benches` (criterion benches for offline/online/transport)
- `crates/protocol` offline/online benches
- `cargo bench --workspace` (see `justfile: bench`)

Historical `tests/bench` placeholder is kept for checklist compliance; see `docs/design/benchmarks.md` for methodology and results.
