# osmiridium-cli

Command-line interface — the shipped binary.

```bash
cargo run -p osmiridium-cli -- test --parties 3
cargo run -p osmiridium-cli -- keygen --parties 3
cargo run -p osmiridium-cli -- create-session --name demo --circuit ./circuit.json
cargo run -p osmiridium-cli -- execute --session <uuid>
cargo run -p osmiridium-cli -- verify --addr 0.0.0.0 --port 8080 --grpc-port 50051 --tls-cert ./data/certs/ca.crt --tls-key ./data/certs/ca.key
cargo run -p osmiridium-cli -- bench --size 100 --repeats 10
cargo run -p osmiridium-cli -- config --config ./config.toml
```

Config via `config.example.toml` or env (`OSMOSMPC_*`), `--config` flag, and `--log-format json|text` / `OSMOSMPC_LOG_FORMAT`.

License: BUSL-1.1.
