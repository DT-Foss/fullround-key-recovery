# A237 — Full-round Speck32/64 W42 residual-key recovery

A fresh public relation was frozen before candidate execution. The native Apple Metal runner then executed every one of the `2^42` residual-key assignments for the standard 22-round Speck32/64 cipher, without early stopping.

## Result

- Complete domain: **4,398,046,511,104 / 4,398,046,511,104**
- Recovered assignment: **`3099631123999`**
- Unknown / known master-key bits: **42 / 22**
- Independent confirmation: **96 output bits across 3 blocks**
- Exact factual models: **1**
- Exact one-bit-control models: **0**
- GPU time: **959.816 s**
- Volatile wall time: **375.544 s**

## Exact scope

This is executed full-round partial-key recovery in a 42-bit residual domain: `K0`, `K1`, and the low ten bits of `K2` are unknown; the upper six bits of `K2` and all of `K3` are known. It establishes a commodity-hardware full-round recovery point. The complete residual domain was enumerated, so this result alone does not claim an asymptotic advantage over generic search.

## AI-native Causal artifact

- Authentic Reader integrity gate: **True**
- Explicit / materialized inferred edges: **5 / 2**
- Embedded rules / clusters / gaps: **2 / 2 / 1**
- Inference is materialized in-file; reopening does not rerun generic amplification.
- The retained next gap is a prospectively frozen strict-subset reader for W42.

## Primary algorithm source

- Beaulieu et al., *The SIMON and SPECK Families of Lightweight Block Ciphers*, IACR ePrint 2013/404.
