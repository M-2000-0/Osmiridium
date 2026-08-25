# Contributing to Osmiridium

## Quick Start

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
```

See `AGENTS.md` for Code Quality Standards (type check, tests, fmt, clippy).

## Development

- Rust 1.97, `resolver = "2"`, `edition = "2021"`
- Workspace: `crates/{crypto,protocol,network,coordinator,api,cli,fhe,testing}`
- `cargo run -p osmiridium-cli -- --help`

## Pull Requests

- Branch from `main`, keep PRs focused, add tests for new paths (success + error).
- Use `thiserror` for errors, avoid `unwrap()` in production, add rustdoc for public items.
- Update `CHANGELOG.md` per Keep a Changelog, and docs in `docs/` when behavior changes.
- Ensure `LAUNCH_READINESS.md` items relevant to your change are checked.

## Testing

- Unit: `#[cfg(test)]` per crate
- Integration: `crates/testing/tests/*.rs` (`cargo test -p osmiridium-testing`)
- Property tests: `proptest` where available
- Benchmarks: `cargo bench -p osmiridium-testing` (requires `criterion.workspace = true`)

## Security

- Never log secret material, use constant-time compares, validate all input.
- Report vulnerabilities via `SECURITY.md`, not public issues.

## License

By contributing you agree your contributions are licensed under `BUSL-1.1` (same as `LICENSE`), converting to Apache-2.0 on the Change Date.
