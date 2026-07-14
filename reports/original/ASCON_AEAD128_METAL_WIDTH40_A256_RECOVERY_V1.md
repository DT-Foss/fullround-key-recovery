# A256 — Ascon-AEAD128 W40 residual-key recovery

The public NIST SP 800-232 relation was searched over its complete `2^40` residual-key domain without early stopping.

## Result

- Complete domain: **1,099,511,627,776 / 1,099,511,627,776**
- Recovered assignment(s): **`[56559342585]`**
- Exact factual/control models: **1 / 0**
- Independent confirmation: **32 ciphertext bytes plus 16 tag bytes (384 bits)**
- GPU / volatile wall time: **4615.997 / 4617.907 s**

The factual and one-bit-flipped control relations used identical inputs, candidate enumeration, kernel invocations, and completion criteria.

## AI-native Causal artifact

- Reader integrity gate: **True**
- Explicit / retained inferred edges: **5 / 2**
- Embedded rules / clusters / gaps: **2 / 2 / 1**
- Amplified inference state is retained in-file and reopened by the authoritative Causal Reader.
