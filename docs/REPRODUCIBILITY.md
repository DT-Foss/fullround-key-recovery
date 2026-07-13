# Reproducibility

## Level 1 — immutable evidence and independent confirmation

Works on macOS and Linux:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
make verify test lint
```

This level verifies artifact bytes, public-protocol identity, complete-domain
execution records, recovered-key reconstruction, full-output confirmations,
matched controls, and Causal integrity.

The source-compatible Causal Reader is vendored because it is part of the
artifact provenance. Its exact files and MIT license are pinned by
`provenance/VENDORED_READER.sha256`.

The original Reader supports two internal content-check modes selected by
optional `xxhash` availability. A237 stores xxHash64; A240 stores the Reader's
documented MD5-prefix fallback. Verification detects the stored mode and reopens
each file through the authoritative Reader with `verify_integrity=True`. The
outer artifact identity is independently fixed by SHA-256 in both cases.

## Level 2 — native host and scalar/Metal equivalence

Requires Apple Silicon, Metal, and Swift 6:

```bash
make native-smoke
```

The exact retained Swift sources are compiled with optimization,
whole-module optimization, and warnings as errors. Each host is tested on 768
candidates spanning the first, middle, and last outer slice. Every complete
Metal output is compared with the independent Python implementation, and the
factual/control filter result is checked.

## Level 3 — complete-domain replay

```bash
./scripts/reproduce_full_search.sh chacha20
./scripts/reproduce_full_search.sh speck32_64
./scripts/reproduce_full_search.sh threefish256
```

Replays are checkpointable and produce `build/reproductions/<cipher>.json`.
The success gate requires:

- every assignment in the frozen residual domain executed;
- no early stop;
- the exact retained unique assignment rediscovered;
- independent full-output confirmation;
- zero exact models for the matched one-bit control.

The checkpoint records only durable progress and accumulated GPU time. Once a
filter match appears, the durable checkpoint remains before that batch, so no
candidate identity is persisted before full-domain completion.

## Platform boundary

The retained native hosts import Apple's Metal framework and therefore compile
only on macOS. Level 1 remains platform-independent. Level 2 and Level 3 are the
native hardware reproductions. The originating platform was a base Apple M4 Mac
mini (`Mac16,10`) with 10 CPU cores and 16 GB unified memory.
