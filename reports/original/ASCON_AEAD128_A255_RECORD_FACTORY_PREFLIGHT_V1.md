# A255 — NIST Ascon-AEAD128 Metal record-factory qualification

## Status

A255 passed on an Apple M4. No A256 production assignment was generated, no public A256 challenge was frozen, and no complete residual-key domain was launched. The retained qualification artifact is `research/results/v1/ascon_aead128_metal_a255_qualification_v1.json` with SHA-256 `e85272303429f91a1b1c54c3a8dfa4d9b44ccce3b756e8a12501182297b401d2`.

## Semantic gates

- Algorithm: NIST SP 800-232 Ascon-AEAD128, with the standardized little-endian byte/word semantics and IV `0x00001000808c0001`.
- Official KAT file: `ascon/ascon-c` commit `446347f21b209f3921c65ece70027c366cbe1693`, KAT SHA-256 `bbbc34692fe05e5fda0a3b025585622ab3e3747495e5e3655b29aae8c2a4bd33`.
- Pinned official KAT counts: 1, 35, 563, and 1074. All passed in the independent Python reference and the Swift/Metal implementation.
- Non-palindromic orientation sentinel: count 1074. Key bytes `000102030405060708090a0b0c0d0e0f` load as little-endian words `0706050403020100` and `0f0e0d0c0b0a0908`; the word-reversed-key relation is rejected.
- Full comparison: every qualification candidate compares all 32 ciphertext bytes and all 16 tag bytes (384 bits).
- Mapping: deterministic CPU/Metal tests cover low-32 zero, 16-bit carry, bit-31, terminal `0xffffffff`, outer zero-to-one, outer bit 31, and full low-64 terminal boundaries.
- Matched control: identical key domain, nonce, associated data, message, kernel invocation, and completion rule; only the final tag byte is XORed by `0x01`.

## Capped benchmark and width selection

- Timed work: three sustained repeats of `2^26` candidates after a `2^20` warm-up.
- End-to-end median: `200,210,941.57245094` candidates/s.
- End-to-end minimum: `200,088,221.24233952` candidates/s.
- Selected residual width: integer W40, comprising all 32 bits of key word 0 plus the low 8 bits of key word 1.
- W40 projection: `5,491.765930175781` s at median throughput and `5,495.134201049805` s at the observed minimum (91.53 to 91.59 minutes).
- W41 projection at the observed minimum: `10,990.26840209961` s (183.17 minutes), so W41 fails the frozen two-hour rule.
- Selected stream size: `2^30` candidates, projected at `5.3663419932127` s per stream at the observed minimum.
- Resource cap: immutable 110-second host deadline; actual host lifetime `1.5458635003305972` s and reported GPU time `1.004085501190275` s.

The width projection is a volatile scheduling qualification, not a recovery result. A256 success is defined only by a complete-domain execution, no early stop, a unique factual model, zero one-bit-control models, and independent CPU confirmation of the full ciphertext and tag after completion.

## Information boundary

The challenge builder is import-side-effect free and requires `--acknowledge-root-review`. It generates the hidden assignment in a dedicated builder process, uses it once to create the public ciphertext/tag relation, serializes no assignment value, removes local references, and exits. The recovery runner is a separate process that consumes only the public, content-hashed protocol. It cannot be constructed by the builder.

## Required actions before any A256 full-domain launch

1. Root reviews this report, the retained A255 JSON, all source hashes, the KAT provenance, the W40 projection, and the full-run cost.
2. Re-run `scripts/reproduce_ascon_aead128_metal_factory.sh` and confirm all 17 tests, `py_compile`, and Ruff pass without changing anchored source content.
3. If approved, run `scripts/reproduce_ascon_aead128_metal_factory.sh --freeze-reviewed` once. This is the first operation permitted to create the real A256 assignment and protocol.
4. Record the emitted protocol SHA-256 out of band; verify that no assignment-bearing field exists and that the qualification/native/reference/factory hashes match the retained manifest.
5. Run the recovery program with `--analyze-only`, the frozen protocol path, and the exact recorded protocol SHA-256. This must not construct a Metal host or execute candidates.
6. Confirm storage, power, thermal, checkpoint path, and an uninterrupted approximately 92-minute worst-observed-minimum window. The W40 estimate is hardware-state dependent.
7. Only then invoke `--execute-full-domain --resume`. Do not change width, stream size, targets, source files, or hashes after freeze.
8. Retain the final JSON, Markdown report, and generated content manifest. Accept recovery only after all `2^40` assignments execute and the independent Python SP 800-232 implementation confirms the complete 32-byte ciphertext plus 16-byte tag.
