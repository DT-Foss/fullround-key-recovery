# A240 — Full-round Threefish-256 W38 residual-key recovery

A fresh public relation was frozen before candidate execution. The native Apple Metal runner executed every one of the `2^38` residual-key assignments for standard 72-round Threefish-256 without early stopping.

## Result

- Complete domain: **274,877,906,944 / 274,877,906,944**
- Recovered assignment: **`68427043728`**
- Unknown / known master-key bits: **38 / 218**
- Independent confirmation: **256 output bits**
- Exact factual / control models: **1 / 0**
- GPU time: **860.741 s**
- Volatile wall time: **861.883 s**

## Exact scope

This is executed full-round partial-key recovery in a 38-bit residual domain: the low 38 bits of `K0` are unknown; the upper 26 bits of `K0`, `K1..K3`, and the 128-bit tweak are known. The complete residual domain was enumerated, so the result is a commodity-hardware full-round recovery point rather than an asymptotic search reduction.

## AI-native Causal artifact

- Reader integrity gate: **True**
- Explicit / materialized inferred: **5 / 2**
- Rules / clusters / gaps: **2 / 2 / 1**
- The retained next gap is a prospectively frozen strict-subset W38 reader.
