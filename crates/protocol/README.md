# osmiridium-protocol

SPDZ-family maliciously-secure MPC protocol.

- **Offline:** `OfflinePhase` generates authenticated Beaver triples, MAC keys, random shares via PRSS.
- **Online:** `OnlinePhase` evaluates `ArithmeticCircuit` (add/sub/scalar-mul/mul/neg/output) with MAC preservation; `DistributedParty` runs key-agreement → offline → input sharing → online → reconstruction over `PartyChannel`.
- **Verification:** `MacVerifier` + hash-chained transcript.

```rust
use osmiridium_protocol::{ArithmeticCircuit, Gate, PartyConfig, SpdzParty};
use osmiridium_crypto::field::Scalar;

let mut c = ArithmeticCircuit::new();
let a = c.constant(Scalar::from_u64(2));
let b = c.constant(Scalar::from_u64(3));
let sum = c.add(a,b);
c.output(sum, vec![0]);

let parties = vec![PartyConfig { party_id: 0, num_parties: 1, endpoint: "localhost:9000".into(), ..Default::default() }];
let mut spdz = SpdzParty::new(parties).unwrap();
let results = spdz.execute(&c).unwrap();
```

License: BUSL-1.1. See `crates/protocol`.
