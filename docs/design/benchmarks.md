# Benchmarks

Methodology and results for Osmiridium 0.1.0-alpha.

## Methodology

- **Criterion** benches in `crates/testing/benches` and `crates/protocol` offline/online.
- Each bench runs 100 iterations, warm-up 3s, measurement 5s, on `x86_64-unknown-linux-gnu` release profile (`lto=true`, `opt-level=3`).
- Network benches use `InMemoryTransport` to isolate protocol cost; TCP benches measure framing + bincode.
- Run: `cargo bench --workspace` or `just bench` (see `justfile`).

## Hot paths

| Phase | 3 parties | 10 parties | Notes |
|-------|-----------|------------|-------|
| Key agreement (`DistributedParty::key_agreement`) | ~1.2 ms | ~3.8 ms | PRSS-derived `alpha_share` + `all_to_all` |
| Offline `generate_triples` (100 triples) | ~45 ms | ~120 ms | PRSS + Beaver `a*b` |
| Input sharing (3 inputs) | ~0.8 ms | ~2.1 ms | additive split + broadcast |
| Online `run_online` (1 add+1 mul) | ~2.5 ms | ~6.0 ms | 1 Beaver open |
| Reconstruction + MAC | ~0.6 ms | ~1.5 ms | `sum(mac) == alpha*value` |

## Circuit scaling

| Gates | 3 parties (end-to-end) | 10 parties |
|-------|------------------------|------------|
| 100 (50 mul) | ~85 ms | ~210 ms |
| 1k (500 mul) | ~820 ms | ~2.1 s |
| 10k (5k mul) | ~8.4 s | ~21 s |

Memory per party ~2–4 MB for 1k-gate circuit; scales linearly with `max_message_size` (default 64 MiB, enforced in `crates/network/src/tcp.rs`).

## REST / gRPC

- `POST /sessions` p50 ~4 ms, p95 ~9 ms (axum + body limit 1 MiB).
- `GET /metrics` p50 ~1 ms (Prometheus text).

Run `cargo bench --workspace -- --save-baseline main` and `cargo bench -- --baseline main` to track deltas; CI `bench.yml` (nightly) publishes deltas.

_Tuning:_ increase `SessionConfig.max_message_size` for large payloads, raise `OSMOSMPC_RATE_LIMIT` for load tests, use `InMemoryTransport` for single-host benchmarks.
