# Verified claim matrix

The repository contains three executed full-round recovery anchors. Each row is
bound to a frozen public challenge, complete residual-domain execution, an exact
matched control, and independent full-output confirmation.

All three native executions were performed on a base Apple M4 Mac mini
(`Mac16,10`, 10 CPU cores, 16 GB unified memory) through Apple Metal.

| Property | A184 | A237 | A240 |
|---|---|---|---|
| Primitive | ChaCha20 block function | Speck32/64 | Threefish-256 |
| Semantics | 20 rounds plus standard feed-forward | standard 22-round encryption | raw standard 72-round block encryption |
| Unknown key material | key word 0 and low 8 bits of key word 1 | K0, K1, low 10 bits of K2 | low 38 bits of K0 |
| Known key material | remaining 216 bits | upper 6 bits of K2 and K3: 22 bits | upper 26 bits of K0 and K1–K3: 218 bits |
| Other public input | counter, nonce, one output block | 3 plaintext/ciphertext pairs | 128-bit tweak and 1 plaintext/ciphertext pair |
| Executed domain | `2^40` | `2^42` | `2^38` |
| Early stop | no | no | no |
| Exact factual models | 1 | 1 | 1 |
| One-bit-control models | 0 | 0 | 0 |
| Confirmation | all 512 output bits | all 96 output bits | all 256 output bits |
| Reconstructed master key | complete 256-bit key | complete 64-bit key | complete 256-bit key |
| Retained result SHA-256 | `d467c061…e12a9` | `2b8f77c2…59c2` | `bde3c083…25e6a` |

## Evidence mapping

| Anchor | Frozen protocol | Result | Causal graph | Original report |
|---|---|---|---|---|
| A184 | `configs/chacha20_metal_width40_partial_key_recovery_v1.json` | `results/chacha20_metal_width40_partial_key_recovery_v1.json` | `causal/chacha20_metal_width40_partial_key_recovery_v1.causal` | `reports/original/FULLROUND_CAUSAL_CHACHA20_METAL_WIDTH40_PARTIAL_KEY_RECOVERY_V1.md` |
| A237 | `configs/speck32_64_metal_width42_recovery_v1.json` | `results/speck32_64_metal_width42_recovery_v1.json` | `causal/speck32_64_metal_width42_recovery_v1.causal` | `reports/original/FULLROUND_SPECK32_64_METAL_WIDTH42_RECOVERY_V1.md` |
| A240 | `configs/threefish256_metal_width38_recovery_v1.json` | `results/threefish256_metal_width38_recovery_v1.json` | `causal/threefish256_metal_width38_recovery_v1.causal` | `reports/original/FULLROUND_THREEFISH256_METAL_WIDTH38_RECOVERY_V1.md` |

## Interpretation boundary

The demonstrated operation is exact key recovery inside a declared known-key
model: the public relation fixes most master-key bits and complete enumeration
resolves the retained residual uncertainty. The evidence supports executed
full-round recovery, commodity-hardware feasibility at the listed widths,
cross-family transfer, unique factual reconstruction, and control rejection.

Search advantage from executing a strict subset of the residual domain and
recovery when all master-key bits are initially unknown are distinct claims and
require their own frozen experiments.
