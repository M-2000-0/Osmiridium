# osmiridium-testing

Test utilities for Osmiridium.

- `fixtures` — deterministic circuits, key fixtures, cert fixtures.
- `harness` — multi-party test harness over `InMemoryTransport`.
- `proptest` — property-based strategies for shares, circuits, serialization.
- `e2e` — end-to-end `create → execute → results` flows.
- `bench` — criterion benches for offline/online/transport.

```bash
cargo test -p osmiridium-testing -- --nocapture
cargo bench -p osmiridium-testing
```

License: BUSL-1.1.
