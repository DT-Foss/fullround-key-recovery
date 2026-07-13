# ChaCha20 Metal Full-Round 40-Bit Partial-Key Recovery v1

## Result

A184 performs a genuinely fresh, prospectively frozen, exhaustive 40-bit
partial-key recovery against the standard ChaCha20 block function. Key word 0
and the low eight bits of key word 1 are unknown; the other 216 key bits,
counter, nonce, and complete 512-bit block output are public.

The native Apple M4 Metal Reader executes every one of the `2^40` assignments
through all 20 rounds plus standard feedforward and returns one exact model:

| Quantity | Result |
|---|---:|
| unknown key bits | 40 |
| known key bits | 216 |
| logical assignments | 1,099,511,627,776 |
| outer key-word-1 low-byte slices | 256 |
| key-word-0 candidates per slice | 4,294,967,296 |
| Metal batches per slice | 16 |
| total Metal batches | 4,096 |
| resumed assignments | 0 |
| combined assignment | **173,754,364,436 (`0x2874913214`)** |
| recovered key word 0 | **1,955,672,596 (`0x74913214`)** |
| recovered key word 1 low byte | **40 (`0x28`)** |
| control matches | 0 |
| independent confirmation | all 512 bits exact |

This is complete exhaustive fullround 40-bit partial-key recovery in the exact
declared scope. It is not a claim of full 256-bit ChaCha20 key recovery.

## Fresh prospective challenge

The A184 protocol was frozen before any candidate execution. Its SHA-256 is:

```text
a6c904e07bc56b08994a9cf4c36c86cd43b468f6c23f9e0d81f3cd52317c6ecf
```

The new public challenge has canonical SHA-256:

```text
682462f9c90202dcaa6c9987b40b200b76ca8d7c16253533c98b8981f4241078
```

It is a new A184 target whose known-material derivation is domain-separated
and anchored to the retained A183 result. The derivation uses SHAKE256 over:

```text
f8-causal:A184:chacha20:known-material:68d4396e8c064baa2385467cfd5dd7d9aee06014d40f87ee6dfdb8c3d253be7d
```

The 44 derived bytes reproduce exactly:

- the upper 24 known bits of key word 1;
- all six key words 2 through 7;
- the 32-bit counter;
- all three nonce words.

Their byte digest is
`ec7a2bc3555f2ea3f15818812b093cbeac117cbb22dd35e786006119e1c8cc73`.

The unknown 40-bit assignment is generated once from operating-system
cryptographic randomness, used only to create the public target, and discarded
before runner construction. The combined assignment, recovered word 0, and
their exact hexadecimal spellings are absent from the protocol, runner, and
unchanged Metal source. The pre-execution grep gate verifies that absence.

The complete factual target digest is:

```text
b6adca76857aca56c98c9c1f0f024f6846600d97792d501d181626c3c4719bae
```

The control flips only bit zero of output word zero and has digest:

```text
d8156d70efb621de2d9f36196f7a6c0c8da2c735e60689fd8c11d4c3396f2170
```

The predeclared prediction is one complete-block assignment and zero control
assignments after exhaustive `2^40` enumeration.

## Exact assignment encoding

A184 decomposes the 40-bit domain into 256 complete 32-bit slices:

```text
combined = (key_word1_low_value << 32) | key_word0
```

For each byte value from 0 through 255, the persistent Metal host is
reconfigured with that value in initial lane 5, while lane 4 traverses every
unsigned 32-bit word. The mapping is bijective over all 1,099,511,627,776
assignments.

The frozen execution plan has SHA-256:

```text
d31360c8d7072eebd29640f221645a4dc7f71c6748663ad8dff3e93f1fe33c96
```

## Unchanged Metal host and mapping qualification

A184 reuses the exact A181--A183 Swift/Metal source without modification,
SHA-256:

```text
ac06b2b6131b9d7edbaf669b4df8fb78298a5920493e10a39cd2d34b1d808816
```

Swift compilation retains optimization, whole-module optimization, and
`-warnings-as-errors`. The host identity gate requires version
`chacha20-metal-native-v1`, device `Apple M4`, Metal execution width 32, and
runtime shader compilation.

Before any public-target candidate execution, the two-word assignment mapping
is tested synthetically at outer values 0, 127, and 255. Each slice evaluates
256 word-0 candidates starting at 184,032 and compares complete 512-bit Metal
blocks with the independent NumPy RFC implementation. The gate covers:

- 768 logical assignments;
- 393,216 complete output bits;
- the first, interior, and final outer-slice regions;
- exact combined-assignment reconstruction;
- empty one-bit-flipped controls.

Every block and assignment mapping agrees exactly.

## Complete `2^40` execution

The persistent Metal process evaluates 268,435,456 candidates per batch. Each
outer low-byte slice therefore contains 16 batches, giving 4,096 batches over
the complete domain. One GPU logical thread executes one standard ChaCha20
block; the first two output words provide the 64-bit factual/control filter.

All 1,099,511,627,776 assignments execute freshly. No assignment is resumed
and there is no early stop. The filter returns exactly combined assignment
173,754,364,436. A separate NumPy implementation reconstructs word 0 and the
word-1 low byte, executes all 20 rounds plus feedforward, and compares all 16
output words. All 512 bits match the public target.

The canonical execution digest is:

```text
66c37279c97109224add21c8ba0c999a52aa25fbcdf128d3f6b5cf5c27454924
```

The canonical factual/control confirmation digest is:

```text
c9515636f73ef00442bfa9f7be5856f966729300928a4193fd635a6866345c66
```

The control target returns no filter or full-block match. The completed
checkpoint is removed after final JSON and Causal validation.

## Causal Reader chain

The retained Causal artifact contains five explicit edges:

1. A183 verified fresh 38-bit recovery anchor;
2. fresh prospectively frozen A184 40-bit public challenge;
3. three-slice 393,216-bit assignment-mapping gate;
4. complete 256-slice, 4,096-batch `2^40` execution;
5. independent 512-bit recovery confirmation.

The edges form one direct provenance chain with no inferred edges.
`CryptoCausalReader` verifies:

- result JSON:
  `d467c06105d4a4afba9efaa7bdf6c4e58754b034d4640907486c778ad17e12a9`;
- Causal artifact:
  `b37bc0234966185e06eb15ae6926502535b0c50271b01f0b6bd8fe5394dabd0f`;
- canonical Causal graph:
  `864fe8a07d9770763110dc037619c91b5ca6fa36b5ee7e1dbd35d673311a3b28`;
- A183 result anchor:
  `68d4396e8c064baa2385467cfd5dd7d9aee06014d40f87ee6dfdb8c3d253be7d`;
- A183 Causal anchor:
  `2f82b26e85595f50895f159db95562fa872d373b10e5f303f73ca2947ba51688`.

## Timing provenance

The observed local end-to-end command wall-clock was 753.87 seconds. It covers
Swift compilation, runtime Metal shader compilation, host gates, all 4,096
complete-domain batches, checkpoint writes, independent 512-bit confirmation,
and final artifact construction and reopen checks.

This is volatile, noncanonical local execution context. It is excluded from
the canonical result and is not a cross-machine benchmark guarantee.

## Reproduction

Fast hash, analyze, public-derivation, secret-absence, Swift warnings-as-errors,
host-identity, synthetic three-slice mapping, retained-result, and Causal gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_metal_width40_partial_key_recovery.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_chacha20_metal_width40_partial_key_recovery.py
```

Fresh checkpointable exhaustive `2^40` execution on the bound Apple M4 host:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_metal_width40_partial_key_recovery.py
```

## Consequence

A184 advances the fresh prospective partial-key frontier from 38 to 40 unknown
bits under standard fullround ChaCha20 semantics. It exhausts
1,099,511,627,776 assignments, recovers one exact two-word partial assignment,
rejects the control, and independently confirms all 512 output bits. The result
is exhaustive 40-bit partial-key recovery with 216 key bits known, not full-key
recovery.
