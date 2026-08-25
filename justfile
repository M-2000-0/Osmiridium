# Osmiridium justfile — common targets (also see `cargo` directly)
# Requires: https://github.com/casey/just

set shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]

default:
    @just --list

build:
    cargo build --workspace

check:
    cargo check --workspace

test:
    cargo test --workspace

lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings

fmt:
    cargo fmt --all

bench:
    cargo bench --workspace --no-run

docker:
    docker compose build

audit:
    cargo audit || echo "cargo-audit not installed: cargo install cargo-audit"

deny:
    cargo deny check || echo "cargo-deny not installed: cargo install cargo-deny"

coverage:
    cargo llvm-cov --workspace --summary-only || echo "cargo-llvm-cov not installed"

clean:
    cargo clean
