# AGENTS.md

## AI Contributor Guidelines

This document provides guidelines for AI agents contributing to the
Osmiridium project.

## Code Quality Standards

### Mandatory Checks

Before submitting any changes, ensure:

1. **Type checking**: `cargo check --workspace` passes
2. **Tests**: `cargo test --workspace` passes
3. **Formatting**: `cargo fmt --all -- --check` passes
4. **Linting**: `cargo clippy --workspace -- -D warnings` passes

### Code Style

- Follow existing patterns in the codebase
- Use meaningful variable and function names
- Add doc comments to all public items
- Keep functions focused and under 50 lines where possible
- Prefer `Result` over `unwrap()` in production code
- Use `thiserror` for error types

### Testing

- Add unit tests for new functions
- Add integration tests for API changes
- Use `proptest` for property-based testing
- Test both success and error paths
- Test edge cases and boundary conditions

### Documentation

- Update README for user-facing changes
- Add rustdoc for API changes
- Update DEPLOYMENT.md for operational changes
- Follow [Keep a Changelog](https://keepachangelog.com/) for CHANGELOG.md

## Project Structure

```
crates/
├── crypto/          # Cryptographic primitives
├── protocol/        # SPDZ protocol
├── network/         # Transport layer
├── coordinator/     # Session management
├── api/             # REST and gRPC servers
├── cli/             # Command-line interface
├── fhe/             # FHE prototype
└── testing/         # Test utilities
```

## Key Conventions

### Error Handling

- Use `thiserror` for error enums
- Provide descriptive error messages
- Include context where helpful
- Never use `unwrap()` in production code paths

### Async Code

- Use `tokio` for async runtime
- Prefer structured concurrency
- Use `Arc<Mutex<T>>` for shared state
- Consider `tokio::sync::RwLock` for read-heavy workloads

### Cryptography

- Never implement custom crypto
- Use `ark-ff` for field arithmetic
- Use `zeroize` for secret material
- Document security assumptions

### Testing

- Use `#[cfg(test)]` for test modules
- Name tests descriptively
- Use `proptest` for property testing
- Keep tests deterministic

## Common Tasks

### Adding a New API Endpoint

1. Add handler function in `crates/api/src/lib.rs`
2. Add route in `create_router_with()`
3. Add request/response types
4. Add input validation
5. Add error handling with proper HTTP status codes
6. Add tests
7. Update API documentation

### Adding a New Protocol Phase

1. Add phase implementation in `crates/protocol/`
2. Add message types
3. Add serialization support
4. Add unit tests
5. Add integration tests
6. Update protocol documentation

### Adding a New CLI Command

1. Add command enum variant in `crates/cli/src/lib.rs`
2. Add command handler in `crates/cli/src/commands.rs`
3. Add argument parsing with `clap`
4. Add tests
5. Update CLI documentation

## Security Considerations

- Never log secret material
- Use constant-time comparisons for secrets
- Validate all user input
- Follow principle of least privilege
- Document security assumptions
- Run security audits regularly

## Performance Considerations

- Profile before optimizing
- Use criterion for benchmarks
- Consider memory allocation patterns
- Use `Arc` for shared read-only data
- Avoid unnecessary cloning
