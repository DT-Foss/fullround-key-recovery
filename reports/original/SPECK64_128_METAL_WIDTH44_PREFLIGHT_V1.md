# A243/A244 — Speck64/128 full-round W44 Metal preflight

## Decision

**W44 is qualified.** The A243 implementation executes the standard 27-round Speck64/128 cipher with two known plaintext/ciphertext blocks per candidate. The slowest of five end-to-end timed samples projects the complete `2^44` domain in **4,886.434 seconds (81.441 minutes)**, below the hard 7,200-second launch ceiling.

The fresh A244 public challenge and execution plan are frozen. **No A244 production candidate batch has been executed.**

## Measured throughput on Apple M4

Each repeat processed `536,870,912` candidates through both the factual 128-bit filter and its matched one-bit-flipped control.

| Statistic | End-to-end candidates/s | Projected `2^44` time |
|---|---:|---:|
| Minimum of 5 | 3,600,209,640.169 | 4,886.434 s / 81.441 min |
| Median of 5 | 3,996,654,370.115 | 4,401.728 s / 73.362 min |
| Required for two hours | 2,443,359,172.836 | 7,200.000 s / 120.000 min |

The conservative minimum clears the required rate by **47.347%**. W44 is the highest integer width that fits the two-hour ceiling under the slowest observed end-to-end sample; W45 projects to 9,772.868 seconds under that same statistic.

## Semantic gates passed

- Official Speck64/128 KAT: key `1b1a1918131211100b0a090803020100`, plaintext `3b7265747475432d`, ciphertext `8c6fa548454e028b`.
- Native Swift/Metal equals the canonical Python implementation over 256 consecutive keys and all 32,768 compared output bits.
- Exact filter identity holds at the beginning, interior, and end of the full uint32 inner-key interval.
- A244 maps `assignment = (key1_low12 << 32) | key0`; all 32 bits of `K0` and the low 12 bits of `K1` are unknown, while 84 master-key bits are public.
- The factual target and one-bit-flipped matched control are evaluated together for every candidate.
- Exact acceptance is deferred until every one of the `2^44` assignments has executed and both public blocks have been independently confirmed across all 128 output bits.
- Checkpoints retain progress and any filter candidates, but never evaluate success before complete-domain termination.
- The final package emits an authentic AI-native `.causal` artifact with five explicit edges, two materialized inferred edges, two clusters, one next-step gap, and an authoritative `CausalReader` integrity reopen.

## Frozen anchors

| Artifact | SHA-256 |
|---|---|
| A243 qualification | `ea16b7947e8b7fd3e18791e33149e119d60ede8b678df94dbbec7507733ed653` |
| Native Swift/Metal source | `67c0ff467314db77fa24b7715bd9d8bb3672ae91794d35ca8e39b421ef21fdb0` |
| A244 protocol | `b3555d687a44e803663a253b25afeb5fe42142d1e4d4f152be8e3b6d109be324` |
| Frozen public challenge | `59d30ca435a09987421861ff8bf8c390836ff240e99b68a86a3d5df73716dbf9` |

## Reproduction and launch

Preflight analysis and all unit/KAT/Metal/Reader smoke tests, without starting the domain run:

```sh
scripts/reproduce_speck64_128_metal_width44.sh
```

Explicitly start or resume the complete W44 execution:

```sh
scripts/reproduce_speck64_128_metal_width44.sh --run
```

Equivalent direct command:

```sh
PYTHONPATH=src python3 research/experiments/speck64_128_metal_width44_recovery.py \
  --execute-full-domain --resume
```

The runner will materialize the final JSON, `.causal`, Markdown report, and independent confirmation only after complete-domain termination.
