# Reproducibility

## Level 1 — immutable evidence and independent confirmation

Works on macOS and Linux:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
make verify test lint
```

This verifies 94 artifact hashes, ten protocol/result identities, complete-
domain execution records, recovered-key reconstruction, full-output
confirmations, matched controls, and Causal integrity.

The source-compatible Causal Reader is vendored because it is part of the
artifact provenance. Its exact files and MIT license are pinned by
`provenance/VENDORED_READER.sha256`. The Reader supports both internal content-
check modes used by the retained AI-native files; verification detects the
stored mode and reopens each file with integrity checking. The outer artifact
identity is independently fixed by SHA-256.

## Level 2 — native host and mapping validation

Requires Apple Silicon, Metal, and Swift 6:

```bash
make native-smoke
```

The package-integrated A184, A237, and A240 hosts are compiled with optimization,
whole-module optimization, and warnings as errors. Each is tested on 768
candidates spanning the first, middle, and last outer slice. Every complete
Metal output is compared with the independent Python implementation, and the
factual/control filter result is checked.

The later native hosts and their byte-exact originating qualification/recovery
programs are preserved under `experiments/native/` and `experiments/original/`.
Their completed mapping, official-KAT, and qualification evidence is retained in
the corresponding qualification JSON and pinned by the artifact manifest.

## Level 3 — complete-domain replay

```bash
./scripts/reproduce_full_search.sh chacha20
./scripts/reproduce_full_search.sh speck32_64
./scripts/reproduce_full_search.sh threefish256
```

These package-integrated replays are checkpointable and produce
`build/reproductions/<cipher>.json`. The success gate requires:

- every assignment in the frozen residual domain executed;
- no early stop;
- the retained unique assignment rediscovered;
- independent complete-output confirmation;
- zero exact models for the matched one-bit control.

The checkpoint records durable progress and accumulated GPU time but no candidate
identity. Once a filter match appears, durable progress remains before that
batch, so candidate identity is not persisted before full-domain completion.

The later seven records retain their exact originating protocol factories,
qualification programs, recovery programs, and native hosts. Those sources are
provenance-preserving originals rather than rewritten package wrappers.

## Platform boundary

The native hosts import Apple's Metal framework and compile on macOS. Level 1 is
platform independent. Levels 2 and 3 are native hardware reproductions. The
originating platform was a base Apple M4 Mac mini (`Mac16,10`) with 10 CPU cores
and 16 GB unified memory.
