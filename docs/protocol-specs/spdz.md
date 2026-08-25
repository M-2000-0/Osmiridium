# SPDZ Protocol Specification

## Overview

SPDZ (pronounced "speedz") is a secure multi-party computation protocol that
provides proactive security against a static dishonest majority. This document
describes the implementation in Osmiridium.

## Security Model

- **Semi-honest (honest-majority)**: Parties follow the protocol but may try
  to learn from the transcript
- **Threshold**: Up to t < n/2 parties may be corrupted
- **Computational security**: 128-bit security level

## Protocol Phases

### 1. Key Agreement

Each party generates a random secret α_i and shares it with all other parties
using additive secret sharing. The global MAC key α = Σ α_i is never
revealed.

```
Party i:
  α_i ←$ F_p
  share α_i among all parties
  receive shares of α_j from all j ≠ i
  α_share_i = Σ_j share_j(i)  // party i's share of α
```

**Invariant**: Σ_i α_share_i = α (the global MAC key)

### 2. Offline Phase (Beaver Triple Generation)

Generate Beaver triples (a, b, c) where c = a × b using PRSS:

```
For each triple:
  a_i, b_i ←$ F_p  (random shares)
  c_i = a_i × b_i   (local computation)
  
  // Verify triple correctness using cut-and-choose:
  // - Open random subset of triples
  // - Verify a × b = c for opened triples
  // - Use remaining triples for computation
```

### 3. Input Sharing

Party i distributes its input x_i to all parties:

```
Party i:
  r_j ←$ F_p  for j ≠ i
  r_i = x_i - Σ_{j≠i} r_j
  send r_j to party j
  
Party j:
  x_share_j(i) = r_j  // party j's share of party i's input
```

### 4. Online Computation

#### Add Gate
```
[x] + [y] = [x + y]
// Add shares element-wise
[x]_i + [y]_i = [x+y]_i
```

#### Multiplication Gate (using Beaver triple)
```
// Given [a], [b], [c] where c = a × b
[x] = [a] + [e]  (open [e] = [x] - [a])
[y] = [b] + [d]  (open [d] = [y] - [b])
[x] × [y] = [c] + e×[b] + d×[a] + e×d
```

#### Scalar Multiplication
```
[x] × s = [x × s]
// Multiply shares by scalar
[x]_i × s = [x×s]_i
```

#### Negation
```
-[x] = [(-x)]
// Negate shares
-[x]_i = [(-x)]_i
```

### 5. Output Reconstruction

Reveal computation results to designated parties:

```
// Open [z] to party i
Each party j sends [z]_j to party i
Party i computes: z = Σ_j [z]_j
```

## MAC Verification

Each share carries a MAC: [x]_i, [m]_i where m = α × x

Verification during reconstruction:
```
// Verify: Σ m_i = α × Σ x_i
// This detects any share tampering
```

## Wire Protocol

### Frame Format
```
[4 bytes: length (big-endian u32)] [payload]
```

### Message Types
- `KeyShareMessage`: Shares of MAC key α
- `OpenShareMessage`: Opening shares for verification
- `InputShareMessage`: Shares of party inputs
- `OutputShareMessage`: Reconstructed outputs

### Serialization
- Binary format: bincode (compact, fast)
- API format: JSON (human-readable)

## Performance Characteristics

| Phase | Communication | Computation |
|-------|--------------|-------------|
| Key Agreement | O(n²) | O(n) |
| Triple Generation | O(n² × t) | O(n × t) |
| Input Sharing | O(n) | O(n) |
| Add Gate | O(1) | O(1) |
| Mul Gate | O(n) | O(n) |
| Output | O(n) | O(n) |

Where n = number of parties, t = number of triples needed

## Security Properties

1. **Privacy**: No party learns anything beyond its own input and the output
2. **Correctness**: The output is correct if a majority of parties are honest
3. **Robustness**: Protocol completes if majority is honest
4. **MAC Verification**: Detects any share tampering during reconstruction
