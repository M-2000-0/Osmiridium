# osmiridium-fhe

Threshold FHE prototype + hybrid FHE+SPDZ orchestration.

- **Scheme:** `ThresholdFhe` (Paillier-like additive homomorphism, `encrypt`/`partial_decrypt`/`combine_decryptions`/`decrypt`), `FheParams` (security_bits, threshold, max_depth).
- **Ops:** `FheOps::add`, `scalar_mul`, `neg` always; `mul` requires `fhe-mul` feature + non-empty `eval_key` and depth check.
- **Hybrid:** `HybridComputation` routes `ComputationStep::Fhe` vs `Spdz` per `HybridConfig`.

```rust
use osmiridium_fhe::{ThresholdFhe, FheParams, scheme::FheOps};
use osmiridium_fhe::ciphertext::Plaintext;

let (pk, mut sks) = ThresholdFhe::keygen(FheParams::default()).unwrap();
let fhe = ThresholdFhe::new(FheParams::default(), sks.remove(0), pk);
let ct = fhe.encrypt(&Plaintext::from_u64(5)).unwrap();
let ct2 = fhe.add(&ct, &ct).unwrap();
```

Status: prototype, not production encryption (see threat model G-4). License: BUSL-1.1.
