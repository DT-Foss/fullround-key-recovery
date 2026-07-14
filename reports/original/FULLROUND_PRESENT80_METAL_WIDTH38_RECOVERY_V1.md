# A253 — Full-round PRESENT-80 W38 residual-key recovery

The frozen public relation was searched over every one of its `2^38` residual-key assignments for all 31 standard rounds plus final K32 whitening, without early stopping.

## Result

- Complete domain: **274,877,906,944 / 274,877,906,944**
- Recovered assignment: **`250884064964`**
- Unknown / known master-key bits: **38 / 42**
- Independent confirmation: **128 output bits across 2 blocks**
- Exact factual models: **1**
- Exact one-bit-control models: **0**
- GPU time: **4244.285 s**
- Volatile wall time: **4244.963 s**

## Exact scope

Master-key bits 0..31 and the low 6 bits of the middle32 key part are unknown; 42 key bits are public. The complete residual domain is enumerated on commodity Apple Silicon.

## AI-native Causal artifact

- Authentic Reader integrity gate: **True**
- Explicit / materialized inferred edges: **5 / 2**
- Embedded rules / clusters / gaps: **2 / 2 / 1**
- The amplified inference state is retained in-file and reopened by the authoritative Causal Reader.

## Primary sources

- A. Bogdanov et al., *PRESENT: An Ultra-Lightweight Block Cipher*, CHES 2007, DOI 10.1007/978-3-540-74735-2_31.
- ISO/IEC 29192-2:2012, Annex B.1.1.
