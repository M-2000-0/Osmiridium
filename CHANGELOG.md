# Changelog

All notable changes to Osmiridium are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/) with pre-release tags
(`0.1.0-alpha`) until 1.0.

## [Unreleased]

### Added

- gRPC server now ships in the `verify` command: REST (default :8080) and
  gRPC (default :50051) share one coordinator; `--grpc-port 0` disables it.
- Panic hook logs panic location and message through `tracing` and stderr
  before the release build's `panic = "abort"` terminates the process.
- JSON structured logging: `--log-format json|text` or
  `OSMOSMPC_LOG_FORMAT=json` for log shippers.
- Feature-gated FHE multiplication (`osmiridium-fhe` feature `fhe-mul`);
  hybrid orchestrator supports `"mul"` steps when enabled.
- Unit tests for the FHE mul paths (error without flag, eval-key check,
  depth enforcement, hybrid step).
- Docs: architecture overview, threat model, OpenAPI specification.
- This changelog.

### Fixed

- gRPC `GetSession` returns real session name and participant count.
- API integration tests authenticate against the API-key middleware.

## [0.1.0-alpha] - Initial codebase

Initial public snapshot of the workspace:

- SPDZ protocol (offline/online phases, MAC verification, circuit
  evaluation) over the BN254 scalar field.
- Coordinator with session lifecycle, policy engine, hash-chained audit log.
- REST API (axum) with API-key auth, per-IP rate limiting, request body
  limits, Prometheus `/metrics`.
- gRPC API definitions and service implementation.
- TCP transport (length-prefixed frames, max-message-size enforcement) and
  deterministic in-memory transport for tests.
- CLI subcommands: test, create-session, execute, keygen, verify, bench,
  config.
- Prototype threshold FHE crate with hybrid FHE+SPDZ orchestration.

Known limitations at this snapshot are tracked in LAUNCH_READINESS.md and
summarized in docs/design/threat-model.md (plaintext TCP transport,
self-HMAC identity scheme, in-memory session state, prototype FHE).

[Unreleased]: https://github.com/M-2000-0/Osmiridium/compare/HEAD...HEAD
[0.1.0-alpha]: https://github.com/M-2000-0/Osmiridium/releases/tag/v0.1.0-alpha
