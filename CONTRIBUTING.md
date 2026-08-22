# Contributing to Osmiridium

## Development Setup

1. Fork the repository and clone locally
2. Ensure Rust 1.97+ is installed
3. Run `cargo build --workspace` to verify the build
4. Run `cargo test --workspace` to verify tests pass

## Branch & PR Guidelines

- Create a branch from `main` for each feature/bugfix
- Commit with clear, descriptive messages
- Submit a Pull Request against `main`
- Ensure all CI checks pass before requesting review
- Address review feedback promptly

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy -- -D warnings` and fix all warnings
- Add doc comments for all public API items
- Write tests for new functionality
- Follow existing patterns in the codebase

## Adding New Crates

- Ensure the crate is added to the workspace members in `Cargo.toml`
- Add appropriate dependencies (avoid unused deps)
- Update `rust-toolchain.toml` if nightly features are used
- Add crate-level README and rustdoc examples

## Protocol & Crypto Changes

- Protocol changes require review of the SPDZ/MAC/security model
- Crypto changes should maintain backward compatibility where possible
- Update documentation for any behavioral changes
- Add unit tests for new functionality

## Testing

- Add unit tests for public API
- Add integration tests for new features
- Ensure tests run without network access when possible
- Property-based tests using proptest are encouraged
- Fuzz targets should be added for new code paths

## Release Process

- Version following semantic versioning
- Update CHANGELOG.md for all changes
- Tag releases with `vX.Y.Z` format
- Build and verify release binaries
- Publish Docker images if applicable