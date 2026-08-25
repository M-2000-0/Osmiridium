# Osmiridium Makefile
# Common development targets

.PHONY: build test lint fmt bench doc clean docker

# Build
build:
	cargo build --workspace

release:
	cargo build --workspace --release

# Testing
test:
	cargo test --workspace

test-verbose:
	cargo test --workspace -- --nocapture

# Linting
lint:
	cargo clippy --workspace -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

# Documentation
doc:
	cargo doc --workspace --no-deps

doc-open:
	cargo doc --workspace --no-deps --open

# Benchmarks
bench:
	cargo bench --workspace

# Security audit
audit:
	cargo audit

deny:
	cargo deny check

# Docker
docker-build:
	docker build -t osmiridium:latest .

docker-run:
	docker compose up

docker-down:
	docker compose down

# Clean
clean:
	cargo clean
	docker compose down -v

# Development
check:
	cargo check --workspace

# Format and lint all
verify: fmt-check lint test
	@echo "All checks passed!"

# Quick development cycle
dev: fmt lint test
	@echo "Dev cycle complete!"

# Release preparation
prepare-release: fmt-check lint test audit deny doc
	@echo "Release preparation complete!"
