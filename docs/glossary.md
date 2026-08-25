# Glossary

- **SPDZ:** Maliciously-secure MPC with offline preprocessing (Beaver triples) and online MAC-authenticated evaluation.
- **Beaver triple:** `(a,b,c)` where `c=a*b`, secret-shared; consumed per multiplication.
- **MAC / alpha:** Information-theoretic tag `sum(mac)=alpha*sum(share)`; `alpha` secret-shared across parties.
- **PRSS:** Pseudorandom secret sharing — deterministic derivation of correlated randomness from shared seed.
- **PartyChannel:** `osmiridium-network::channel::PartyChannel` — per-sender inbox demux over `Transport`.
- **Coordinator:** Central service (`crates/coordinator`) managing sessions, policy, audit log; not trusted with inputs.
- **Circuit / Gate:** `ArithmeticCircuit` with gates `Input/Const/Add/Sub/ScalarMul/Mul/Neg/Output/Equal/GreaterThan`.
- **FHE / Hybrid:** Threshold FHE prototype (`crates/fhe`); `HybridMode` switches FHE↔SPDZ per depth.
- **TransportType::TcpNoise:** Label only — wire is plaintext TCP until Noise/mTLS lands (G-1).
