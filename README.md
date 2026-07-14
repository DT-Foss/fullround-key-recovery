# Full-Round Key Recovery on Commodity Apple Silicon

[![verification](https://github.com/DT-Foss/fullround-key-recovery/actions/workflows/ci.yml/badge.svg)](https://github.com/DT-Foss/fullround-key-recovery/actions/workflows/ci.yml)

This repository preserves two complementary full-round recovery result classes:

- **twelve complete-domain residual-key recoveries** across twelve primitive
  configurations in nine cipher families; and
- **five target-blind strict-subset ChaCha20-R20 recoveries**: the A281
  cross-material result and the four-target A286 replication panel.

Every complete-domain record enumerated its full declared domain on Apple M4
Metal without early stopping, produced one exact factual model, and produced no
model for the matched one-bit-flipped control.

| Record | Primitive | Full rounds | Unknown / known key bits | Domain | Factual / control | Independent confirmation |
|---|---|---:|---:|---:|---:|---:|
| A184 | ChaCha20 block function with feed-forward | 20 | 40 / 216 | `2^40` | 1 / 0 | 512 bits |
| A237 | Speck32/64 | 22 | 42 / 22 | `2^42` | 1 / 0 | 96 bits |
| A240 | Threefish-256 | 72 | 38 / 218 | `2^38` | 1 / 0 | 256 bits |
| A244 | Speck64/128 | 27 | 44 / 84 | `2^44` | 1 / 0 | 128 bits |
| A246 | SIMON64/128 | 44 | 43 / 85 | `2^43` | 1 / 0 | 128 bits |
| A248 | RC5-32/12/16 | 12 | 40 / 88 | `2^40` | 1 / 0 | 128 bits |
| A253 | PRESENT-80 | 31 | 38 / 42 | `2^38` | 1 / 0 | 128 bits |
| A256 | Ascon-AEAD128 | 12/8/12 permutation schedule | 40 / 88 | `2^40` | 1 / 0 | 384 bits |
| AES-W41 | AES-128 | 10 | 41 / 87 | `2^41` | 1 / 0 | 256 bits |
| A264 | Salsa20/20 block function | 20 | 42 / 214 | `2^42` | 1 / 0 | 512 bits |
| P128R1 | PRESENT-128 | 31 + K32 whitening | 38 / 90 | `2^38` | 1 / 0 | 128 bits |
| AES256R1 | AES-256 | 14 | 41 / 215 | `2^41` | 1 / 0 | 256 bits |

The strict-subset records use frozen target-blind schedules and stop when the
factual model is found. A281 recovered the hidden 20-bit residual at frozen
rank 37 after 36 exact-UNSAT cells: 151,552 of 1,048,576 assignments
(14.453125%). A286 independently confirmed four fresh public-material targets,
recomputed 16,384 output bits with a third RFC-style implementation, and
rejected all four one-bit controls. Its discovery modes were
`fallback / top128 / top128 / global`; applicable frozen-order ranks were
254, 55, and 107. None of the five strict-subset recoveries enumerated the
complete residual domain.

Each unique assignment reconstructs the complete master key in its declared
known-key model. The package then recomputes the complete output with a compact
independent Python implementation. The exact evidence mapping and per-record
scope are in [docs/CLAIM_MATRIX.md](docs/CLAIM_MATRIX.md).

## Exact claim

The artifacts establish twelve complete-domain full-round recovery points and
a common Metal architecture across ARX, Feistel, SP-network, AEAD, and AES
designs. Each input is a frozen public plaintext/ciphertext or AEAD relation
plus the listed known key bits; every assignment in the remaining 38- to
44-bit domain was executed.

A281 and A286 establish the separate strict-subset result class: target-blind
frozen scheduling, exact UNSAT/SAT evidence, recovery before complete-domain
enumeration, full-output recomputation, and matched-control rejection. The
claim boundary is residual-key recovery in the declared known-key models;
full-key recovery with all master-key bits unknown is a separate scope.

## Verify in seconds

Python 3.10 or newer is required. The exact `dotcausal` 0.3.1 Reader revision
used by the AI-native artifacts is vendored with its MIT license and SHA-256
provenance.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
make verify
make test
make lint
```

`make verify`:

1. verifies all 205 immutable files against `provenance/ARTIFACTS.sha256`;
2. checks every frozen protocol/result challenge and every A286 root anchor;
3. reconstructs every recovered key and independently recomputes the complete
   full-round output, including all five strict-subset ChaCha20 targets;
4. opens all 28 `.causal` files with the matching integrity-checking Reader;
5. checks complete-domain gates for the twelve exhaustive records and
   target-blind/no-full-enumeration gates for A281/A286.

## Native replay

Native replay requires macOS, Apple Silicon with Metal, and Swift 6. The
repository retains all twelve native Swift/Metal hosts. The three original
checkpointable package integrations expose direct complete-search commands:

```bash
make native-smoke
./scripts/reproduce_full_search.sh chacha20
./scripts/reproduce_full_search.sh speck32_64
./scripts/reproduce_full_search.sh threefish256
```

The nine subsequent byte-exact protocol factories, qualification programs, and
recovery runners are preserved under `experiments/original/`, alongside their
native hosts under `experiments/native/`. Their immutable configs, qualification
records, results, manifests, original reports, and Causal artifacts are retained
as one provenance chain. Platform-independent independent confirmation of every
record is part of `make verify`.

The commands write only below `build/`; retained evidence is never overwritten.
A completed replay must match the frozen factual assignment and empty control
set exactly. Checkpoints contain no candidate identity and are removed after a
successful completion.

The originating machine was a base Apple M4 Mac mini (`Mac16,10`) with 10 CPU
cores and 16 GB unified memory.

| Record | Logical candidates | Retained GPU time |
|---|---:|---:|
| A184 | 1,099,511,627,776 | 753.87 s end-to-end context |
| A237 | 4,398,046,511,104 | 959.82 s |
| A240 | 274,877,906,944 | 860.74 s |
| A244 | 17,592,186,044,416 | 4,663.66 s |
| A246 | 8,796,093,022,208 | 4,070.05 s |
| A248 | 1,099,511,627,776 | 4,593.60 s |
| A253 | 274,877,906,944 | 4,244.29 s |
| A256 | 1,099,511,627,776 | 4,616.00 s |
| AES-W41 | 2,199,023,255,552 | 2,255.36 s |
| A264 | 4,398,046,511,104 | 3,153.32 s |
| P128R1 | 274,877,906,944 | 4,305.32 s |
| AES256R1 | 2,199,023,255,552 | 3,712.32 s |

A184's time is contextual, non-canonical end-to-end wall-clock provenance. The
other rows retain GPU seconds directly in their result JSON. Correctness is
determined by the complete-domain and independent-confirmation gates.

## Research lineage

This recovery line grew from Causal knowledge-graph analysis of cipher data into
Live-CASI, F8 full-round distinguishers, full-round Causal Readers, and the
prospectively frozen recovery experiments preserved in
[DT-Foss/f8-causal-cryptanalysis](https://github.com/DT-Foss/f8-causal-cryptanalysis).
The original twelve full-round F8 known-key cross-round distinguishers remain in
[DT-Foss/f8](https://github.com/DT-Foss/f8/tree/68ab9a663d5793b40942b4a4580c208d5973106d).

## Repository map

```text
configs/             frozen public protocols
results/             immutable qualification and recovery JSON
causal/              immutable Causal evidence graphs
reports/original/    byte-exact reports from the originating working tree
experiments/native/  byte-exact Swift/Metal enumerators
experiments/original/byte-exact originating factories and runners
src/                  independent verification and reproduction package
tests/                KAT, artifact, Causal, claim, and CLI gates
scripts/              one-command verification and reproduction
provenance/           source record and SHA-256 manifests
```

## Causal Reader provenance

The AI-native files use the binary `CAUSAL\0\1` revision. The matching Reader is
retained at `src/fullround_key_recovery/_dotcausal/io.py` with SHA-256
`e320f77855a713e44c97fbc9d1bbb8c488a5c458f2b5ddecc0254a7dc57e0074`.
`provenance/VENDORED_READER.sha256` pins the complete minimal Reader package and
license. The legacy A184 graph is opened through its format-specific reader.

## Author and citation

David Tom Foss — AI Systems and Causal Knowledge Graphs<br>
Görlitz, Germany<br>
ORCID: [0009-0004-0289-7154](https://orcid.org/0009-0004-0289-7154)<br>
Contact: [d.foss@ieee.org](mailto:d.foss@ieee.org)

Use [CITATION.cff](CITATION.cff) for machine-readable citation metadata.

## License

MIT © 2026 David Tom Foss. See [LICENSE](LICENSE).
