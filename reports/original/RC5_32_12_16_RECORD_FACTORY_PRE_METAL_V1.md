# A247/A248 — RC5-32/12/16 Record Factory at the Metal gate

## State

The complete CPU/reference, native-source, protocol-factory, recovery-runner, checkpoint, matched-control, independent-confirmation, and AI-native Causal pipeline is ready.

**A247 has not been executed. A248 has not been frozen. No RC5 Metal kernel, Metal benchmark, production challenge, or production candidate batch has executed.** Width selection remains downstream of the retained A247 minimum end-to-end throughput, exactly as required.

## Exact construction

- Cipher: RC5-32/12/16.
- Block: two little-endian 32-bit words.
- Key: four little-endian 32-bit words from 16 key bytes.
- Expansion: 26 P32/Q32 subkeys and 78 mixing iterations.
- Encryption: pre-whitening followed by all 12 standard rounds.
- Candidate map: all 32 bits of `K0`; a later A247-selected number of low `K1` bits forms the outer slices.
- Per-candidate relation: two plaintext/ciphertext blocks, hence 128 filtered output bits.
- Control: the factual target and a final-word one-bit-flipped target execute together.

## CPU and provenance anchors

- All five chained RC5-32/12/16 examples from Rivest's original RC5 paper pass.
- The RFC 2040 16-byte-key/R12 CBC row passes as the raw-block relation `P xor IV = 1122334455667788` to `294ddb46b3278d60`.
- The non-palindromic key `915f4619be41b2516355a50110a9ce91` maps to key words `19465f91 51b241be 01a55563 91cea910` and encrypts `eedba521 6d8f4b15` to `ac13c0f7 52892b5b` in host word order.
- An independent test transcription agrees on 256 seeded random key/block pairs; the canonical decryptor returns every plaintext.

## Pre-Metal safeguards

- The native source uses 26 subkeys, 78 mixing iterations, 12 encryption rounds, four key words, and two complete blocks.
- Native JSON `uint32` parsing rejects booleans, fractions, negative values, non-finite values, and values above `0xffffffff`.
- A single native request is capped at `2^32 - 1`; a complete 32-bit inner domain is streamed in smaller batches.
- W32, W33, W43, and W64 candidate/outer-slice mappings are covered by CPU-only tests.
- A hard clone-residue gate rejects SIMON identifiers, z-sequence residue, 44-round residue, A245/A246 identifiers, and their retained hashes.
- Importing the A248 protocol factory does not generate a secret or freeze a challenge.
- The runner requires both an explicit protocol SHA-256 and an explicit full-domain acknowledgement before native compilation.
- Recovery is evaluated only after complete-domain termination. Checkpoints retain progress and candidate identities without converting an early match into success.
- The final `.causal` design contains five explicit relations, two materialized inferred relations, two embedded rules, two clusters, one next-step gap, and authoritative `CausalReader` integrity readback.

## Current CPU-only verification

```text
20 passed
ruff: all checks passed
py_compile: all four Python implementation files passed
```

## Files prepared

- `src/arx_carry_leak/rc5_reference.py`
- `research/experiments/rc5_32_12_16_metal_native.swift`
- `research/experiments/rc5_32_12_16_metal_qualification.py`
- `research/experiments/rc5_32_12_16_metal_protocol_factory.py`
- `research/experiments/rc5_32_12_16_metal_recovery.py`
- `tests/test_rc5_reference.py`
- `tests/test_rc5_32_12_16_record_factory_pre_metal.py`
- `scripts/reproduce_rc5_32_12_16_metal.sh`

## Later gate sequence

Only after the active Metal workload is clear:

```sh
scripts/reproduce_rc5_32_12_16_metal.sh --qualify
scripts/reproduce_rc5_32_12_16_metal.sh --freeze
```

The factory names the frozen protocol from A247's selected width. Record its SHA-256, then perform a read-only anchor check:

```sh
scripts/reproduce_rc5_32_12_16_metal.sh --analyze PATH_TO_PROTOCOL SHA256
```

The complete-domain run remains a separate explicit action:

```sh
scripts/reproduce_rc5_32_12_16_metal.sh --run PATH_TO_PROTOCOL SHA256
```
