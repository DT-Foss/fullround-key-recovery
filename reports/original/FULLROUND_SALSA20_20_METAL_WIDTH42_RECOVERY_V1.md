# A264 — Full-round Salsa20/20 W42 residual-key recovery

Every assignment in the frozen `2^42` residual domain was evaluated through all 20 standard Salsa20 rounds without early stopping.

## Result

- Complete domain: **4,398,046,511,104 / 4,398,046,511,104**
- Recovered assignment: **`1767048180590`**
- Unknown / known master-key bits: **42 / 214**
- Independent confirmation: **complete 512-bit Salsa20/20 block**
- Exact factual models: **1**
- Exact one-bit-control models: **0**
- GPU time: **3153.316 s**

## AI-native Causal artifact

- Reader integrity gate: **True**
- Explicit / retained inferred edges: **5 / 2**
- Amplified inference state is retained in-file and reopened by the authoritative Causal Reader.

## Primary sources

- Daniel J. Bernstein, *Salsa20 specification*, 2005.
- Daniel J. Bernstein, public-domain Salsa20 reference implementation, version 20051118.
