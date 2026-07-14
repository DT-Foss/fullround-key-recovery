# A245/A246 — SIMON64/128 full-round W43 Metal preflight

## Decision

**W43 is the maximum conservatively qualified width.** A245 executes the exact 44-round SIMON64/128 construction with its `z3` key-schedule sequence and two complete plaintext/ciphertext blocks per candidate. The slowest of five end-to-end samples projects the complete `2^43` domain in **4,086.701 seconds (68.112 minutes)**.

W44 is excluded: it projects to **8,173.401 seconds** at the minimum observed throughput and **7,701.854 seconds** at the median, both above the 7,200-second ceiling.

The fresh A246 W43 challenge and execution plan are frozen. **No A246 production candidate batch has executed.**

## Measured throughput on Apple M4

Each repeat processed `536,870,912` candidates through the factual 128-bit relation and the matched one-bit-flipped control.

| Statistic | End-to-end candidates/s | Projected `2^43` time |
|---|---:|---:|
| Minimum of 5 | 2,152,370,242.189 | 4,086.701 s / 68.112 min |
| Median of 5 | 2,284,149,649.675 | 3,850.927 s / 64.182 min |
| Required for two hours | 1,221,679,586.418 | 7,200.000 s / 120.000 min |

The conservative minimum clears the W43 requirement by **76.181%**.

## Semantic gates passed

- Official SIMON64/128 KAT: key `1b1a1918131211100b0a090803020100`, plaintext `656b696c20646e75`, ciphertext `44c8fc20b9dfa07a`.
- Exact 44-round key schedule with four 32-bit key words, round constant `0xfffffffc`, and the SIMON `z3` bit sequence.
- Native Swift/Metal equals the independent Python implementation over 256 consecutive keys and all 32,768 compared output bits.
- Exact filter identity holds at the beginning, interior, and end of the uint32 inner-key interval.
- A246 maps `assignment = (key1_low11 << 32) | key0`: 43 unknown and 85 known master-key bits.
- Factual and one-bit-flipped matched-control relations execute together for every candidate.
- Acceptance is deferred until all `2^43` assignments execute and both public blocks are independently confirmed across all 128 output bits.
- Checkpoints retain progress and filter candidates without evaluating success before complete-domain termination.
- Final output includes an authentic AI-native `.causal` file with five explicit edges, two materialized inferred edges, two clusters, one next-step gap, and authoritative `CausalReader` readback.

## Frozen anchors

| Artifact | SHA-256 |
|---|---|
| A245 qualification | `c7ab55dbc35ffbfc044a58641c5fd46803652d2ad422cda7f019457b70dd036e` |
| Native Swift/Metal source | `e868d0d19dc3962845a4aedb9e3a7cdf8eaf7a14746ee3d69312b37b1f628880` |
| A246 protocol | `302e5cf20598ff3226144dd004fc6ab0ba2e06ebc2ff344e9a4fdd28e949d5b1` |
| Frozen public challenge | `1ff1df4842b9c105a0eba5583112e1144d734ff09bff3973651443a504c8f54e` |

## Reproduction and launch

Preflight analysis and tests without starting the domain run:

```sh
scripts/reproduce_simon64_128_metal_width43.sh
```

Explicitly start or resume the complete W43 execution:

```sh
scripts/reproduce_simon64_128_metal_width43.sh --run
```

Equivalent direct command:

```sh
PYTHONPATH=src python3 research/experiments/simon64_128_metal_width43_recovery.py \
  --execute-full-domain --resume
```
