# Full-Round Key Recovery on Commodity Apple Silicon

[![verification](https://github.com/DT-Foss/fullround-key-recovery/actions/workflows/ci.yml/badge.svg)](https://github.com/DT-Foss/fullround-key-recovery/actions/workflows/ci.yml)

This repository preserves and reproduces three executed full-round residual-key
recovery anchors across three independent cipher designs:

| Anchor | Primitive | Full rounds | Unknown / known key bits | Complete domain | Exact factual / control models | Independent confirmation |
|---|---|---:|---:|---:|---:|---:|
| A184 | ChaCha20 block function with feed-forward | 20 | 40 / 216 | `2^40` | 1 / 0 | 512 bits |
| A237 | Speck32/64 | 22 | 42 / 22 | `2^42` | 1 / 0 | 96 bits over 3 blocks |
| A240 | Threefish-256 | 72 | 38 / 218 | `2^38` | 1 / 0 | 256 bits |

Every domain was executed completely on Apple M4 Metal without early stopping.
Each unique recovered assignment reconstructs the complete master key in its
declared known-key model and is independently checked with a compact Python
implementation. The same complete search applied to a one-bit-flipped control
returns zero exact models.

## Exact claim

These artifacts establish three full-round recovery points and demonstrate that
the execution architecture transfers across a stream cipher block function, a
lightweight ARX block cipher, and a wide-tweakable ARX block cipher. The defined
input to each recovery is the public plaintext/ciphertext relation plus the
listed known key bits; the runner enumerates every assignment in the remaining
38-, 40-, or 42-bit domain. Strict-subset search and recovery with every master-key
bit unknown are separate experimental scopes.

The complete claim matrix and evidence map are in
[docs/CLAIM_MATRIX.md](docs/CLAIM_MATRIX.md).

## Research lineage

This recovery line grew out of applying causal knowledge-graph methods to
cipher data: `.causal` led to Live-CASI and then F8.  The twelve full-round F8
known-key cross-round distinguishers and their four retained architectural
mechanisms have their own canonical, executable archive at
[DT-Foss/f8](https://github.com/DT-Foss/f8/tree/68ab9a663d5793b40942b4a4580c208d5973106d).
This repository links that exact public commit for provenance while keeping the
F8 runners, result JSON, and figures in their original repository.

The subsequent full-round Causal Reader, SHAKE reconstruction, and ChaCha20
recovery program is preserved independently in
[DT-Foss/f8-causal-cryptanalysis](https://github.com/DT-Foss/f8-causal-cryptanalysis/tree/1697097b836ac25364668540dd63bd30922a4342).
The link pins the exact public predecessor state without copying its larger
artifact history into this focused three-record package.

## Verify in seconds

Python 3.10 or newer is required. The exact `dotcausal` 0.3.1 Reader revision
that generated the AI-native artifacts is vendored with its original MIT
license and SHA-256 provenance.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
make verify
make test
```

`make verify` performs all of the following:

1. verifies all 17 immutable artifacts against `provenance/ARTIFACTS.sha256`;
2. checks that each frozen protocol contains the exact public challenge retained
   in its result;
3. reconstructs every recovered key and independently recomputes the full-round
   ciphertext;
4. opens the A184 legacy cryptographic Causal graph and the A237/A240 AI-native
   Causal graphs with their appropriate integrity-checking readers;
5. checks the exact complete-domain, no-early-stop, unique-model, and matched-control
   result gates.

## Reproduce the native implementation

Native reproduction requires macOS, Apple Silicon with Metal, and Swift 6.
Compile every byte-pinned host and run three independent scalar/Metal mapping
gates:

```bash
make native-smoke
```

Run one full checkpointable search:

```bash
./scripts/reproduce_full_search.sh chacha20
./scripts/reproduce_full_search.sh speck32_64
./scripts/reproduce_full_search.sh threefish256
```

The commands write only below `build/`; the retained evidence is never
overwritten. A completed reproduction must match the retained factual assignment
and empty control set exactly. Checkpoints intentionally contain no candidate
identity and are removed after successful completion.

The originating machine was a base Apple M4 Mac mini (`Mac16,10`) with 10 CPU
cores and 16 GB unified memory. Observed retained execution times were:

| Anchor | Logical candidates | Observed originating run time |
|---|---:|---:|
| A184 | 1,099,511,627,776 | 753.87 s end-to-end |
| A237 | 4,398,046,511,104 | 959.82 GPU s |
| A240 | 274,877,906,944 | 860.74 GPU s |

A184's 753.87-second value is contextual, non-canonical end-to-end wall-clock
provenance from the originating run. A237 and A240 retain GPU seconds in their
result JSON. Correctness is determined by the complete-domain and
independent-confirmation gates.

## Repository map

```text
configs/             prospectively frozen public protocols
results/             immutable qualification and recovery JSON
causal/              immutable Causal evidence graphs
reports/original/    byte-exact reports from the originating working tree
experiments/native/  byte-exact Swift/Metal enumerators
src/                  independent verification and reproduction package
tests/                KAT, artifact, Causal, claim, and CLI gates
scripts/              one-command verification and reproduction
provenance/           source record and SHA-256 manifest
```

The original reports are preserved byte-for-byte for provenance. Current
repository metadata and authored documentation identify the author separately
from those immutable source artifacts.

## Causal Reader provenance

The A237 and A240 files use the binary `CAUSAL\0\1` revision. The exact Reader
used to write and reopen them is retained at
`src/fullround_key_recovery/_dotcausal/io.py` with SHA-256
`e320f77855a713e44c97fbc9d1bbb8c488a5c458f2b5ddecc0254a7dc57e0074`.
`provenance/VENDORED_READER.sha256` pins the complete minimal Reader package and
license.

## Author and citation

David Tom Foss — AI Systems and Causal Knowledge Graphs<br>
Görlitz, Germany<br>
ORCID: [0009-0004-0289-7154](https://orcid.org/0009-0004-0289-7154)<br>
Contact: [d.foss@ieee.org](mailto:d.foss@ieee.org)

Use [CITATION.cff](CITATION.cff) for machine-readable citation metadata.

## License

MIT © 2026 David Tom Foss. See [LICENSE](LICENSE).
