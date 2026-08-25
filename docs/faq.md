# FAQ

**Q: Do parties learn each other’s inputs?** No — inputs stay additive-shared; only outputs at `Output` wires are reconstructed after MAC check.

**Q: Is the coordinator trusted with inputs?** No — coordinator stores shares/MACs, never plaintext. Compromise leaks metadata, not inputs (see threat model).

**Q: Why is TCP plaintext?** `TcpNoise` is currently a label; encryption is roadmap G-1. Mitigate with WireGuard/VPC until Noise/mTLS ships.

**Q: What are comparison gates?** `Equal`/`GreaterThan` currently return `ProtocolError::Online("not implemented")` in both `crates/protocol/src/online/mod.rs:268` and `distributed.rs:323`. Use arithmetic circuits or feature-gate when available.

**Q: How many parties?** Tested 3–10; config `num_parties` 2–64. 32-party bench ~21s for 10k gates.

**Q: How to run locally?** `cargo run -p osmiridium-cli -- test --parties 3` or `docker compose up --build`. See `README.md` Quick Start.
