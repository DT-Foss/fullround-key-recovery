# Full-round recovery completeness audit

This audit reconciles terminal recovery artifacts in the originating
`arx-carry-leak` tree, the complete F8-Causal archive, the original `f8`
snapshot, and the compact `fullround-key-recovery` package. It classifies an
item as a recovery only when a terminal artifact contains a recovered residual
assignment and an independent recomputation of the standard full-round public
relation. Qualification-only, order-only, schedule-only, distinguisher, and
unfinished progress artifacts are excluded.

## Reconciled headline

The current primary frontier contains **46 verified full-round recovery
executions**:

- **18 complete-domain records**: all declared assignments executed, no early
  stop, one factual model, zero matched-control models;
- **28 strict-subset ChaCha20-R20 executions**: every record ends before full
  residual-domain enumeration, returns the factual assignment, rejects its
  declared control, and confirms all published output blocks through independent
  implementations. A281/A286 use post-model control rejection (`O0`);
  A294--A374 use the same grouped candidate search on factual and control
  relations (`S0`).

The previous 37-record table was internally valid but incomplete. Nine
terminal results were absent from it: five complete-domain records and four
strict-subset records.

## Nine-record publication gap closed by this release

| Record | Standard endpoint | Residual key | Executed domain | Terminal result | Independent confirmation | Control | source archive / compact package / headline |
|---|---|---:|---:|---|---:|---|---|
| B3KR1 | keyed BLAKE3, 7 rounds | 43 / 213 | `2^43` complete | `results/blake3_keyed_metal_recovery_v1.json` | 256 bits plus official `b3sum` root | exact one-bit matched output; 0 models | yes / yes / yes |
| SIPKR1 | SipHash-2-4, complete 2/4 operation | 43 / 85 | `2^43` complete | `results/siphash24_metal_recovery_v1.json` | 128 bits | exact one-bit matched output; 0 models | yes / yes / yes |
| TEAKR1 | TEA, 32 cycles | 43 / 85 | `2^43` complete | `results/tea_metal_recovery_v1.json` | 128 bits | exact one-bit matched output; 0 models | yes / yes / yes |
| XTEAKR1 | XTEA, 32 cycles | 43 / 85 | `2^43` complete | `results/xtea_metal_recovery_v1.json` | 128 bits | exact one-bit matched output; 0 models | yes / yes / yes |
| TF1024KR1 | Threefish-1024, 80 rounds plus final subkey | 39 / 985 | `2^39` complete | `results/threefish1024_metal_record_v1.json` | 1,024 canonical + 1,024 independent bits | exact one-bit matched output; 0 models | yes / yes / yes |
| A322 | ChaCha20, 20 rounds plus feed-forward | 45 / 211 | 12,532,714,569,728 / `2^45` | `results/chacha20_round20_holdout_selected_w45_recovery_a322_v1.json` | 8,192 cross-implementation bits | same grouped search; 0 candidates | yes / yes / yes |
| A325 | ChaCha20, 20 rounds plus feed-forward | 46 / 210 | 1,322,849,927,168 / `2^46` | `results/chacha20_round20_holdout_selected_w46_recovery_a325_v1.json` | 8,192 cross-implementation bits | same grouped search; 0 candidates | yes / yes / yes |
| A350 | ChaCha20, 20 rounds plus feed-forward | 46 / 210 | 7,645,041,786,880 / `2^46` | `results/chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.json` | 8,192 cross-implementation bits | same grouped search; 0 candidates | yes / yes / yes |
| A374 | ChaCha20, 20 rounds plus feed-forward | 48 / 208 | 7,009,386,627,072 / `2^48` | `results/chacha20_round20_w48_target_conditioned_recovery_a374_v1.json` | 8,192 cross-implementation bits | same grouped search; 0 candidates | yes / yes / yes |

The five new complete-domain records preserve frozen protocols, qualification
records, native enumerators, terminal result JSON, AI-native Causal graphs,
reports, reproducers, and tests. A322/A325 preserve the same chain on top of
their already-published pre-result designs. A350/A374 were already included in
the A326--A458 manifest and are now promoted into the headline table.

## Earlier primary breadth ladder

A178, A182, and A183 are fresh, prospectively frozen ChaCha20 targets and remain
terminal verified complete-domain recoveries. They are recorded separately
because A184 is the retained width-40 frontier row for this exact breadth
ladder; they are not erased or described as failures.

| Record | Width | Domain | Confirmation | Result / Causal SHA-256 | Publication |
|---|---:|---:|---:|---|---|
| A178 | 32 | `2^32` | 512 bits | `80fee52a…bea1` / `94c651c6…6995` | F8-Causal, `FULLROUND_TRANSFER_SHA256SUMS` |
| A182 | 36 | `2^36` | 512 bits | `8450a334…08e3` / `aad20851…b110` | F8-Causal, `FULLROUND_TRANSFER_SHA256SUMS` |
| A183 | 38 | `2^38` | 512 bits | `68d4396e…be7d` / `2f82b26e…1688` | F8-Causal, `FULLROUND_TRANSFER_SHA256SUMS` |

Including these gives **49 fresh primary terminal recoveries**: 21 complete
domain and 28 strict subset.

## Same-target implementation replays

| Record | Role | Domain | Result / Causal SHA-256 | Classification |
|---|---|---:|---|---|
| A179 | Vector256 replay of the A178 target | `2^32` | `73874897…fb93` / `ab627294…91a1` | terminal confirmation replay |
| A181 | Metal replay of the A178 target | `2^32` | `f58e24cd…bace` / `b16a7a2f…662e` | terminal confirmation replay |

Both execute the full domain and return 1/0. They strengthen implementation
independence without creating a new target record.

## Alternative target-blind solver recoveries

These terminal full-round ChaCha20 recoveries use solver-returned models and a
post-model flipped-control rejection, the same control class used by A281/A286,
rather than the grouped Metal candidate-search convention used by A294--A374.
Their class is explicit, positive, and separate.

| Record | Residual model | Terminal result | Confirmation | Exact boundary |
|---|---:|---|---:|---|
| R20-A211-TRANSFER-V1 | W20 / K236 | `results/chacha20_round20_global_incremental_transfer_v1.json` | 4,096 bits in each of Numeric and Gray modes | two complete 256-cell plans; one common confirmed model |
| A274 | W20 / K236 | `results/chacha20_round20_selected_channel_target_recovery_v1.json` | 4,096 bits | target-blind selected order; SAT at selected position 90/128 |
| A277 | W20 / K236 | `results/chacha20_round20_replication_residual_two_pass_v1.json` | 4,096 bits | one global retained residual solve; no complete remaining-half enumeration |

## Post-barrier recovery labels

The A223--A235 capacity experiments intentionally obtain ground truth after a
barrier. Their label executions are real full-round recoveries, but they answer
a different scientific question and therefore remain outside the primary
frontier count.

| Record | Executions | Width / domain | Result |
|---|---:|---:|---|
| A224 | 1 | W32, complete `2^32` | `chacha20_round20_a223_w32_metal_label_v1.json` |
| A225 | 1 | W40, complete `2^40` | `chacha20_round20_a223_w40_metal_transfer_v1.json` |
| A228 | 1 | W32, complete `2^32` | `chacha20_round20_a227_postbarrier_label_v1.json` |
| A230 | 7 | W32, complete `2^32` each | `chacha20_round20_a229_postbarrier_labels_v1.json` |
| A233 | 1 | W32, strict `2^30 / 2^32` | `chacha20_round20_w32_h16_top64_v1.json` |
| A234 | 7 | W32, complete `2^32` each | `chacha20_round20_a233_postbarrier_labels_v1.json` |

This class contains 18 executions on 17 unique targets; A233 and A234 target 6
are the one deliberate duplicate.

## Threefish-1024: two different full-round results

The original F8 result and TF1024KR1 are complementary, not interchangeable:

| Evidence | Operation | Full-round endpoint | Recovered key material |
|---|---|---|---|
| original F8 `results/threefish1024.json` | permutation-fixed-point cross-round distinguisher, `Z = 16,537.4` | 80 rounds | none; this artifact is a distinguisher |
| TF1024KR1 `threefish1024_metal_record_v1.json` | exhaustive residual-key recovery | 80 rounds plus final subkey | unique W39 assignment `0x2718170cd1`, complete `2^39`, 1/0 |

TF1024KR1's terminal result SHA-256 is
`a1267651b7cf283a1d3fe94da15e63b1746650d97bc04d047ed7efc881cf3a5d`;
its Causal artifact SHA-256 is
`9608580fef4dd08e59002a4b23e48d12f622a6d5e833afeef4a8416762d32c31`.

## Aggregate inventory

Across every explicitly separated evidence class, the archive contains:

- 46 current primary-frontier executions;
- 49 fresh primary terminal recoveries when A178/A182/A183 are included;
- two same-target implementation replays;
- three alternative target-blind solver targets, with two modes on the R20
  transfer;
- 17 unique post-barrier targets from 18 executions.

The 46 current-frontier executions cover 45 targets because A294/A295 apply two
frozen orders to one target. The complete inventory therefore contains **68
unique recovered targets** and **72 terminal target-level
executions**. The 46-record headline remains the current selected frontier;
the larger inventory is fully retained and classified here.

Qualification-only results, frozen orders, ready schedules, active progress
files, and negative boundaries are valuable mechanism evidence but are not
counted as terminal recoveries. In particular, GIFT-128 remains qualification
only and the W49--W52 items in the audited tree remain schedules or progress
states rather than completed key-recovery outcomes.
