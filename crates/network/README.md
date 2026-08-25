# osmiridium-network

Transport layer for SMPC parties.

- **Transports:** `TcpTransport` (length-prefixed 4-byte + bincode, max-message-size enforced) and `InMemoryTransport` (deterministic, for tests).
- **Channel:** `PartyChannel` demuxes per-sender inboxes, `all_to_all`/`recv_all` barriers.
- **Identity:** `Identity::generate` + HMAC `sign`/`verify` (self-HMAC, see threat model G-2).
- **Certs:** `generate_self_signed`, `create_ca`, `cert_fingerprint`, `make_server_config`/`make_client_config`.

```rust
use osmiridium_network::{TcpTransport, SessionConfig, Identity};

let cfg = SessionConfig { num_parties: 3, party_id: 0, ..Default::default() };
let id = Identity::generate(0, "alice");
let t = TcpTransport::new(cfg, id, "127.0.0.1:9000".into());
```

License: BUSL-1.1. Part of Osmiridium workspace.
