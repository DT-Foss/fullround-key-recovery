# A287--A325 verified recovery release

This release closes the A287--A325 ChaCha20-R20 evidence batch in the compact
recovery archive: one complete-domain W43 record, 21 strict-subset
executions across 20 targets, the exact source chronology, and independent
recomputation of every recovered output block.

Every recovery executes all 20 ChaCha20 rounds plus feed-forward, uses eight
complete public output blocks, rejects the matched one-bit control, and is
confirmed over 8,192 bits by independent word- and byte-oriented references.

## Complete-domain record

CHACHA20KR43 executes all `2^43 = 8,796,093,022,208` assignments in the frozen
43-bit residual domain, without early stopping. It returns the unique factual
assignment `2,800,167,095,032`, no matched-control model, and the complete
reconstructed 256-bit key.

## Strict-subset records

| Record | Width | Executions | Frozen rank(s) / 4,096 | Executed assignment bound |
|---|---:|---:|---|---:|
| A294 | 24 | 1 | 202 | 827,392 / 16,777,216 |
| A295 | 24 | 1 | 2,605 | 10,670,080 / 16,777,216 |
| A296 | 24 / 28 | 8 | 2,750, 2,948, 1,485, 213 / 1,144, 2,113, 520, 3,019 | per-target exact bounds in result JSON |
| A297 | 32 | 4 | 2,867, 2,032, 926, 3,932 | per-target exact bounds in result JSON |
| A303 | 32 | 1 | 3,801 | 3,985,637,376 / 4,294,967,296 |
| A302/A304 | 43 | 1 | 2,473 | 5,310,727,061,504 / 8,796,093,022,208 |
| A305 | 43 | 1 | 2,114 | 4,539,780,431,872 / 8,796,093,022,208 |
| A309 | 43 | 1 | 4,044 | 8,684,423,872,512 / 8,796,093,022,208 |
| A313 | 44 | 1 | 2,753 | 11,824,044,965,888 / 17,592,186,044,416 |
| A322 | 45 | 1 | 1,459 | 12,532,714,569,728 / 35,184,372,088,832 |
| A325 | 46 | 1 | 77 | 1,322,849,927,168 / 70,368,744,177,664 |

A294 and A295 intentionally execute two distinct frozen orders against the same
public target. The batch therefore contains 21 executions across 20 targets.
Together with A281/A286, the archive at A325 contains 26 strict-subset
executions across 25 distinct targets. A350 and A374 extend the selected
frontier to 28 strict-subset executions.

## Source chronology

`chronology/arx-carry-leak/` preserves the portable A287--A325 source and
evidence paths exactly as they appeared in the active research tree. It includes
protocols, designs, runners, reports, tests, Causal files, order objects,
compressed measurements, grouped-engine qualifications, and the selected
attempt-ledger rows. Checkpoints, local builds, raw generated CNF, and active
execution state are excluded.

The chronology also preserves completed non-recovery objects: A287--A293,
A298--A301, the W43/W44/W45/W46 grouped-engine qualifications, A308/A310/A312
orders, the A314 order-only record, completed A315/A317/A319 rank evaluations,
the A321 holdout selection, A316/A318/A320 commitments, and the A323 cross-width
operator audit.

## Closed outcome boundary

A322 recovers W45 assignment `0x091190ecc0e8` at rank 1,459 and A325 recovers
W46 assignment `0x1df3bae9e3a6` at rank 77. Both terminal JSON and AI-native
Causal confirmations are hash-pinned. A321 remains the completed holdout
selection and A324 the target-free W46 engine qualification on which A325 runs.

## Verification

`make verify` pins every chronology byte, independently recomputes all 21
strict-subset executions and CHACHA20KR43, opens all headline and chronology
Causal files through the integrity-checking Reader, and checks the frozen
information boundaries encoded in every retained result.
