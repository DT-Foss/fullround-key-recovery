# A246 — Full-round SIMON64/128 W43 residual-key recovery

A fresh public relation was frozen before candidate execution. The native Apple Metal runner then executed every one of the `2^43` residual-key assignments for the standard 44-round SIMON64/128 cipher, without early stopping.

## Result

- Complete domain: **8,796,093,022,208 / 8,796,093,022,208**
- Recovered assignment: **`4109884320956`**
- Unknown / known master-key bits: **43 / 85**
- Independent confirmation: **128 output bits across 2 blocks**
- Exact factual models: **1**
- Exact one-bit-control models: **0**
- GPU time: **4070.049 s**
- Volatile wall time: **4078.938 s**

## Exact scope

This is executed full-round partial-key recovery in a 43-bit residual domain: all 32 bits of `K0` and the low 11 bits of `K1` are unknown; the upper 21 bits of `K1` and all of `K2` and `K3` are known. The complete residual domain is enumerated on commodity Apple Silicon.

## AI-native Causal artifact

- Authentic Reader integrity gate: **True**
- Explicit / materialized inferred edges: **5 / 2**
- Embedded rules / clusters / gaps: **2 / 2 / 1**
- Inference is materialized in-file; reopening does not rerun generic amplification.
- The retained next gap is a prospectively frozen strict-subset reader for W43.

## Primary algorithm source

- Beaulieu et al., *The SIMON and SPECK Families of Lightweight Block Ciphers*, IACR ePrint 2013/404.
