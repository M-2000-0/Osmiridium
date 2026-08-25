# Changelog

All notable changes to the Osmiridium project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha] - 2026-08-23

### Added

- Core SPDZ protocol implementation
  - Key agreement phase
  - Beaver triple generation (offline phase)
  - Secret sharing and input distribution
  - Online computation with MAC verification
  - Output reconstruction
- Cryptographic primitives
  - BLS12-381 field arithmetic
  - HMAC-SHA256 message authentication
  - PRSS (Pseudo-Random Secret Sharing)
  - Blake3 hashing
- Transport layer
  - TCP transport with length-prefixed framing
  - TLS 1.3 encryption with certificate pinning
  - In-memory transport for testing
- Coordinator
  - Session lifecycle management
  - Policy engine for access control
  - Audit logging with hash chain commitment
  - Persistent session storage
- REST API
  - Health check endpoint
  - Session CRUD operations
  - Participant management
  - Execution and results endpoints
  - Rate limiting and authentication
  - Metrics endpoint (Prometheus)
- gRPC API
  - Health service
  - Session management RPCs
  - Circuit definition RPC
  - Execution RPC with distributed protocol
  - Authentication interceptor
- CLI
  - Session management commands
  - Key generation
  - Circuit validation
  - Protocol testing
  - Benchmarking
  - Configuration management
- FHE prototype
  - CKKS-style encryption (placeholder)
  - Hybrid MPC+FHE mode
- Docker support
  - Multi-arch builds (amd64, arm64)
  - Docker Compose for multi-party testing
- Kubernetes support
  - Deployment manifests
  - Helm chart
  - Service monitoring
- CI/CD
  - GitHub Actions workflows
  - Release automation
  - Security scanning
  - Performance benchmarks
- Documentation
  - Architecture overview
  - Threat model
  - Deployment guide
  - API reference
