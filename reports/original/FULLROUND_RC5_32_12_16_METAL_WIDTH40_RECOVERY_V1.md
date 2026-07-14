# A248 — Full-round RC5-32/12/16 W40 residual-key recovery

The frozen public relation was searched over every one of its `2^40` residual-key assignments for all 12 standard rounds, without early stopping.

## Result

- Complete domain: **1,099,511,627,776 / 1,099,511,627,776**
- Recovered assignment: **`964575894496`**
- Unknown / known master-key bits: **40 / 88**
- Independent confirmation: **128 output bits across 2 blocks**
- Exact factual models: **1**
- Exact one-bit-control models: **0**
- GPU time: **4593.603 s**
- Volatile wall time: **4595.526 s**

## Exact scope

All 32 bits of `K0` and the low 8 bits of `K1` are unknown; 88 key bits are public. The complete residual domain is enumerated on commodity Apple Silicon.

## AI-native Causal artifact

- Authentic Reader integrity gate: **True**
- Explicit / materialized inferred edges: **5 / 2**
- Embedded rules / clusters / gaps: **2 / 2 / 1**
- The amplified inference state is retained in-file and reopened by the authoritative Causal Reader.

## Primary sources

- Ronald L. Rivest, *The RC5 Encryption Algorithm*, FSE 1994 / LNCS 1008.
- RFC 2040, *The RC5, RC5-CBC, RC5-CBC-Pad, and RC5-CTS Algorithms*.
