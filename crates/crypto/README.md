# osmiridium-crypto

Cryptographic primitives for Osmiridium SMPC.

- **Field:** BN254 scalar field via `ark-ff` (~128-bit security).
- **Sharing:** Additive & Shamir secret sharing, reconstruction, share verification.
- **MAC:** Information-theoretic MACs `sum(mac)=alpha*sum(share)`, authenticated shares.
- **PRSS:** Pseudorandom secret sharing for deterministic triple/MAC-key derivation.
- **OT:** Oblivious transfer (base, COT, IKNP).
- **Hash:** Blake3/SHA2/SHA3.

```rust
use osmiridium_crypto::field::Scalar;
use osmiridium_crypto::sharing::{AdditiveShare, SharingScheme};

let secret = Scalar::from_u64(42);
let shares = AdditiveShare::<Scalar>::split(&secret, 3, 0).unwrap();
let recon = AdditiveShare::<Scalar>::reconstruct(&shares).unwrap();
assert_eq!(recon, secret);
```

License: BUSL-1.1. Part of the Osmiridium workspace (`crates/crypto`).
