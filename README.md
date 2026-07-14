# Full-Round Key Recovery on Commodity Apple Silicon

[![verification](https://github.com/DT-Foss/fullround-key-recovery/actions/workflows/ci.yml/badge.svg)](https://github.com/DT-Foss/fullround-key-recovery/actions/workflows/ci.yml)

This repository preserves ten executed full-round residual-key recovery records
across ten primitive configurations in nine cipher families. Every retained search executed its complete declared
domain on Apple M4 Metal without early stopping, produced one exact factual model,
and produced no model for the matched one-bit-flipped control.

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

Each unique assignment reconstructs the complete master key in its declared
known-key model. The package then recomputes the complete output with a compact
independent Python implementation. The exact evidence mapping and per-record
scope are in [docs/CLAIM_MATRIX.md](docs/CLAIM_MATRIX.md).

## Exact claim

The artifacts establish ten executed full-round recovery points and a common
complete-domain Metal architecture across ARX, Feistel, SP-network, AEAD, and
AES designs. The input to each recovery is a frozen public plaintext/ciphertext
or AEAD relation plus the listed known key bits. The runner enumerates every
assignment in the remaining 38- to 44-bit domain.

These records are exact recovery demonstrations. Because each retained domain
was completely enumerated, they do not by themselves establish an asymptotic
search reduction. Strict-subset recovery and recovery with every master-key bit
unknown are separate experimental scopes.

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

1. verifies all 94 immutable files against `provenance/ARTIFACTS.sha256`;
2. checks frozen protocol/result challenge identity for all ten records;
3. reconstructs every recovered key and independently recomputes the complete
   full-round output;
4. opens all ten `.causal` files with the matching integrity-checking Reader;
5. checks complete-domain, no-early-stop, unique-model, and control-rejection
   gates.

## Native replay

Native replay requires macOS, Apple Silicon with Metal, and Swift 6. The
repository retains all ten native Swift/Metal hosts. The three original
checkpointable package integrations expose direct complete-search commands:

```bash
make native-smoke
./scripts/reproduce_full_search.sh chacha20
./scripts/reproduce_full_search.sh speck32_64
./scripts/reproduce_full_search.sh threefish256
```

The seven subsequent byte-exact protocol factories, qualification programs, and
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
