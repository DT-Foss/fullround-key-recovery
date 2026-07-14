# Verified claim matrix

The twelve complete-domain records are bound to frozen public challenges,
complete residual-domain executions, exact matched controls, and independent
complete-output confirmation. The five strict-subset ChaCha20-R20 recoveries
are bound to target-blind frozen schedules, exact solver evidence, matched
controls, and full-output recomputation. All native executions ran on a base
Apple M4 Mac mini (`Mac16,10`, 10 CPU cores, 16 GB unified memory).

| Record | Primitive | Semantics | Unknown / known bits | Public relation | Domain | Models | Confirmation |
|---|---|---|---:|---|---:|---:|---:|
| A184 | ChaCha20 | 20 rounds plus feed-forward | 40 / 216 | counter, nonce, 1 output block | `2^40` | 1 / 0 | 512 bits |
| A237 | Speck32/64 | 22-round encryption | 42 / 22 | 3 block pairs | `2^42` | 1 / 0 | 96 bits |
| A240 | Threefish-256 | raw 72-round encryption | 38 / 218 | tweak, 1 block pair | `2^38` | 1 / 0 | 256 bits |
| A244 | Speck64/128 | 27-round encryption | 44 / 84 | 2 block pairs | `2^44` | 1 / 0 | 128 bits |
| A246 | SIMON64/128 | 44-round encryption | 43 / 85 | 2 block pairs | `2^43` | 1 / 0 | 128 bits |
| A248 | RC5-32/12/16 | 12-round encryption | 40 / 88 | 2 block pairs | `2^40` | 1 / 0 | 128 bits |
| A253 | PRESENT-80 | 31-round encryption | 38 / 42 | 2 block pairs | `2^38` | 1 / 0 | 128 bits |
| A256 | Ascon-AEAD128 | complete AEAD operation | 40 / 88 | nonce, AD, message, ciphertext and tag | `2^40` | 1 / 0 | 384 bits |
| AES-W41 | AES-128 | 10-round encryption | 41 / 87 | 2 block pairs | `2^41` | 1 / 0 | 256 bits |
| A264 | Salsa20/20 | 20 rounds plus feed-forward | 42 / 214 | nonce, counter, 1 output block | `2^42` | 1 / 0 | 512 bits |
| P128R1 | PRESENT-128 | 31 rounds plus K32 whitening | 38 / 90 | 2 block pairs | `2^38` | 1 / 0 | 128 bits |
| AES256R1 | AES-256 | 14-round FIPS 197 encryption | 41 / 215 | 2 block pairs | `2^41` | 1 / 0 | 256 bits |

`Models` gives exact factual/control models. Every row has `early_stop=false`.

## Strict-subset ChaCha20-R20 matrix

| Record | Fresh targets | Unknown / known bits per target | Frozen-order result | Search completion | Confirmation |
|---|---:|---:|---|---|---:|
| A281 | 1 | 20 / 236 | rank 37; 36 exact UNSAT then SAT | 37/256 cells; 151,552 assignments; no full enumeration | 4,096 bits |
| A286 | 4 | 20 / 236 | modes `fallback`, `top128`, `top128`, `global`; ranks 254, 55, 107 where applicable | four recoveries; no full enumeration | 16,384 bits |

A286 uses a third direct RFC-style implementation for every output block and
rejects all four one-bit controls. The authentic A286 Causal Reader retains the
four-target confirmation and the next W24 transfer gap.

## Evidence mapping

| Record | Frozen protocol | Result | Causal graph | Original report |
|---|---|---|---|---|
| A184 | `configs/chacha20_metal_width40_partial_key_recovery_v1.json` | `results/chacha20_metal_width40_partial_key_recovery_v1.json` | `causal/chacha20_metal_width40_partial_key_recovery_v1.causal` | `reports/original/FULLROUND_CAUSAL_CHACHA20_METAL_WIDTH40_PARTIAL_KEY_RECOVERY_V1.md` |
| A237 | `configs/speck32_64_metal_width42_recovery_v1.json` | `results/speck32_64_metal_width42_recovery_v1.json` | `causal/speck32_64_metal_width42_recovery_v1.causal` | `reports/original/FULLROUND_SPECK32_64_METAL_WIDTH42_RECOVERY_V1.md` |
| A240 | `configs/threefish256_metal_width38_recovery_v1.json` | `results/threefish256_metal_width38_recovery_v1.json` | `causal/threefish256_metal_width38_recovery_v1.causal` | `reports/original/FULLROUND_THREEFISH256_METAL_WIDTH38_RECOVERY_V1.md` |
| A244 | `configs/speck64_128_metal_width44_recovery_v1.json` | `results/speck64_128_metal_width44_recovery_v1.json` | `causal/speck64_128_metal_width44_recovery_v1.causal` | `reports/original/FULLROUND_SPECK64_128_METAL_WIDTH44_RECOVERY_V1.md` |
| A246 | `configs/simon64_128_metal_width43_recovery_v1.json` | `results/simon64_128_metal_width43_recovery_v1.json` | `causal/simon64_128_metal_width43_recovery_v1.causal` | `reports/original/FULLROUND_SIMON64_128_METAL_WIDTH43_RECOVERY_V1.md` |
| A248 | `configs/rc5_32_12_16_metal_width40_recovery_v1.json` | `results/rc5_32_12_16_metal_width40_recovery_v1.json` | `causal/rc5_32_12_16_metal_width40_recovery_v1.causal` | `reports/original/FULLROUND_RC5_32_12_16_METAL_WIDTH40_RECOVERY_V1.md` |
| A253 | `configs/present80_metal_width38_recovery_v1.json` | `results/present80_metal_width38_recovery_v1.json` | `causal/present80_metal_width38_recovery_v1.causal` | `reports/original/FULLROUND_PRESENT80_METAL_WIDTH38_RECOVERY_V1.md` |
| A256 | `configs/ascon_aead128_metal_width40_a256_recovery_v1.json` | `results/ascon_aead128_metal_width40_a256_recovery_v1.json` | `causal/ascon_aead128_metal_width40_a256_recovery_v1.causal` | `reports/original/ASCON_AEAD128_METAL_WIDTH40_A256_RECOVERY_V1.md` |
| AES-W41 | `configs/aes128_fips197_metal_width41_recovery_v1.json` | `results/aes128_fips197_metal_width41_recovery_v1.json` | `causal/aes128_fips197_metal_width41_recovery_v1.causal` | no originating Markdown report; result and manifest are canonical |
| A264 | `configs/salsa20_20_metal_width42_recovery_v1.json` | `results/salsa20_20_metal_width42_recovery_v1.json` | `causal/salsa20_20_metal_width42_recovery_v1.causal` | `reports/original/FULLROUND_SALSA20_20_METAL_WIDTH42_RECOVERY_V1.md` |
| P128R1 | `configs/present128_metal_width38_recovery_v1.json` | `results/present128_metal_width38_recovery_v1.json` | `causal/present128_metal_width38_recovery_v1.causal` | `reports/original/FULLROUND_PRESENT128_METAL_WIDTH38_RECOVERY_V1.md` |
| AES256R1 | `configs/aes256_metal_width41_recovery_v1.json` | `results/aes256_fips197_metal_width41_recovery_v1.json` | `causal/aes256_fips197_metal_width41_recovery_v1.causal` | result and manifest are canonical |
| A281 | `configs/chacha20_round20_cross_material_target_v1.json` | `results/chacha20_round20_cross_material_composite_recovery_v1.json` | `causal/chacha20_round20_cross_material_composite_recovery_canonical_v1.causal` | `reports/original/CAUSAL_CHACHA20_ROUND20_CROSS_MATERIAL_COMPOSITE_RECOVERY_CANONICAL_V1.md` |
| A286 | `configs/chacha20_round20_multitarget_panel_master_v1.json` | `results/chacha20_round20_multitarget_panel_root_confirmation_a286_v1.json` | `causal/chacha20_round20_multitarget_panel_root_confirmation_a286_v1.causal` | `reports/original/CHACHA20_ROUND20_MULTITARGET_PANEL_ROOT_CONFIRMATION_A286_V1.md` |

Every immutable path above is byte-pinned in `provenance/ARTIFACTS.sha256`.
Qualification records, native sources, factories, recovery runners, every A286
target/canonical/order artifact, and result manifests are pinned in the same
inventory.

## Interpretation boundary

The demonstrated operation is exact key recovery inside a declared known-key
model. The public relation fixes most master-key bits and complete enumeration
resolves the retained residual uncertainty. The evidence supports executed
full-round recovery, commodity-hardware feasibility at the listed widths,
cross-family transfer, unique factual reconstruction, and control rejection.

The A281/A286 records directly establish strict-subset recovery in their
declared 20-bit residual domains. Recovery when every master-key bit is
initially unknown remains a distinct experimental scope.
