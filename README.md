# Full-Round Key Recovery on Commodity Apple Silicon

[![verification](https://github.com/DT-Foss/fullround-key-recovery/actions/workflows/ci.yml/badge.svg)](https://github.com/DT-Foss/fullround-key-recovery/actions/workflows/ci.yml)

This is the executable public record of **46 verified full-round residual-key
recovery executions** on a base Apple M4 Mac mini with 16 GB unified memory:
eighteen complete-domain records across thirteen primitive families and 28
strict-subset ChaCha20-R20 executions. Every row below
recovers the declared residual key, reconstructs the complete master key in its
known-key model, recomputes the full public relation independently, and rejects
its frozen control.

## Main results: complete full-round recovery record

### Eighteen complete-domain records

Every assignment in every declared domain was executed without early stopping.
Each factual relation returned exactly one model; each one-bit-flipped control
returned none.

| Record | Primitive / standard endpoint | Residual key | Executed domain | Factual / control | Independent confirmation |
|---|---|---:|---:|---:|---:|
| A184 | ChaCha20, 20 rounds + feed-forward | 40 / 216 bits | `2^40` complete | 1 / 0 | 512 bits |
| A237 | Speck32/64, 22 rounds | 42 / 22 bits | `2^42` complete | 1 / 0 | 96 bits |
| A240 | Threefish-256, 72 rounds | 38 / 218 bits | `2^38` complete | 1 / 0 | 256 bits |
| A244 | Speck64/128, 27 rounds | 44 / 84 bits | `2^44` complete | 1 / 0 | 128 bits |
| A246 | SIMON64/128, 44 rounds | 43 / 85 bits | `2^43` complete | 1 / 0 | 128 bits |
| A248 | RC5-32/12/16, 12 rounds | 40 / 88 bits | `2^40` complete | 1 / 0 | 128 bits |
| A253 | PRESENT-80, 31 rounds | 38 / 42 bits | `2^38` complete | 1 / 0 | 128 bits |
| A256 | Ascon-AEAD128, complete 12/8/12 operation | 40 / 88 bits | `2^40` complete | 1 / 0 | 384 bits |
| AES-W41 | AES-128, 10 rounds | 41 / 87 bits | `2^41` complete | 1 / 0 | 256 bits |
| A264 | Salsa20/20, 20 rounds + feed-forward | 42 / 214 bits | `2^42` complete | 1 / 0 | 512 bits |
| P128R1 | PRESENT-128, 31 rounds + K32 whitening | 38 / 90 bits | `2^38` complete | 1 / 0 | 128 bits |
| AES256R1 | AES-256, 14 FIPS 197 rounds | 41 / 215 bits | `2^41` complete | 1 / 0 | 256 bits |
| CHACHA20KR43 | ChaCha20, 20 rounds + feed-forward | 43 / 213 bits | `2^43` complete | 1 / 0 | 8,192 bits |
| B3KR1 | keyed BLAKE3, all 7 standard rounds | 43 / 213 bits | `2^43` complete | 1 / 0 | 256 bits + official `b3sum` confirmation |
| SIPKR1 | SipHash-2-4, complete 2/4 operation | 43 / 85 bits | `2^43` complete | 1 / 0 | 128 bits |
| TEAKR1 | TEA, 32 cycles / 64 Feistel updates | 43 / 85 bits | `2^43` complete | 1 / 0 | 128 bits |
| XTEAKR1 | XTEA, 32 cycles / 64 Feistel updates | 43 / 85 bits | `2^43` complete | 1 / 0 | 128 bits |
| TF1024KR1 | Threefish-1024, 80 rounds + final subkey | 39 / 985 bits | `2^39` complete | 1 / 0 | 2,048 cross-implementation bits |

### Twenty-eight strict-subset ChaCha20-R20 executions

All rows execute the standard 20 rounds plus feed-forward against eight public
output blocks unless noted. Their schedules were frozen before candidate
execution under the declared information boundary; target-blind,
zero-refit-transfer, and prospectively public-output-conditioned protocols are
labeled in their artifacts. Every execution remains below its full residual
domain. A281 and the four A286 targets use post-model one-bit control rejection
(`O0`); A294--A374 execute the same grouped candidate search against the control
and accept zero control candidates (`S0`).

| Record / target | Residual key | Frozen discovery point | Executed assignments | Recovered / control accepted | Confirmation |
|---|---:|---:|---:|---:|---:|
| A281 | 20 / 236 bits | rank 37 / 256 | 151,552 / 1,048,576 | 1 / 0 | 4,096 bits |
| A286/t01 | 20 / 236 bits | fallback, rank 254 | strict subset | 1 / 0 | 4,096 bits |
| A286/t02 | 20 / 236 bits | top-128, rank 55 | strict subset | 1 / 0 | 4,096 bits |
| A286/t03 | 20 / 236 bits | top-128, rank 107 | strict subset | 1 / 0 | 4,096 bits |
| A286/t04 | 20 / 236 bits | global retained solve | strict subset | 1 / 0 | 4,096 bits |
| A294 | 24 / 232 bits | rank 202 / 4,096 | 827,392 / 16,777,216 | 1 / 0 | 8,192 bits |
| A295 | 24 / 232 bits | rank 2,605 / 4,096 | 10,670,080 / 16,777,216 | 1 / 0 | 8,192 bits |
| A296/w24_t00 | 24 / 232 bits | rank 2,750 / 4,096 | 11,264,000 / 16,777,216 | 1 / 0 | 8,192 bits |
| A296/w24_t01 | 24 / 232 bits | rank 2,948 / 4,096 | 12,075,008 / 16,777,216 | 1 / 0 | 8,192 bits |
| A296/w24_t02 | 24 / 232 bits | rank 1,485 / 4,096 | 6,082,560 / 16,777,216 | 1 / 0 | 8,192 bits |
| A296/w24_t03 | 24 / 232 bits | rank 213 / 4,096 | 872,448 / 16,777,216 | 1 / 0 | 8,192 bits |
| A296/w28_t00 | 28 / 228 bits | rank 1,144 / 4,096 | 74,973,184 / 268,435,456 | 1 / 0 | 8,192 bits |
| A296/w28_t01 | 28 / 228 bits | rank 2,113 / 4,096 | 138,477,568 / 268,435,456 | 1 / 0 | 8,192 bits |
| A296/w28_t02 | 28 / 228 bits | rank 520 / 4,096 | 34,078,720 / 268,435,456 | 1 / 0 | 8,192 bits |
| A296/w28_t03 | 28 / 228 bits | rank 3,019 / 4,096 | 197,853,184 / 268,435,456 | 1 / 0 | 8,192 bits |
| A297/w32_t00 | 32 / 224 bits | rank 2,867 / 4,096 | 3,006,267,392 / 4,294,967,296 | 1 / 0 | 8,192 bits |
| A297/w32_t01 | 32 / 224 bits | rank 2,032 / 4,096 | 2,130,706,432 / 4,294,967,296 | 1 / 0 | 8,192 bits |
| A297/w32_t02 | 32 / 224 bits | rank 926 / 4,096 | 970,981,376 / 4,294,967,296 | 1 / 0 | 8,192 bits |
| A297/w32_t03 | 32 / 224 bits | rank 3,932 / 4,096 | 4,123,000,832 / 4,294,967,296 | 1 / 0 | 8,192 bits |
| A303 | 32 / 224 bits | rank 3,801 / 4,096 | 3,985,637,376 / 4,294,967,296 | 1 / 0 | 8,192 bits |
| A302/A304 | 43 / 213 bits | rank 2,473 / 4,096 | 5,310,727,061,504 / 8,796,093,022,208 | 1 / 0 | 8,192 bits |
| A305 | 43 / 213 bits | rank 2,114 / 4,096 | 4,539,780,431,872 / 8,796,093,022,208 | 1 / 0 | 8,192 bits |
| A309 | 43 / 213 bits | rank 4,044 / 4,096 | 8,684,423,872,512 / 8,796,093,022,208 | 1 / 0 | 8,192 bits |
| A313 | 44 / 212 bits | rank 2,753 / 4,096 | 11,824,044,965,888 / 17,592,186,044,416 | 1 / 0 | 8,192 bits |
| A322 | 45 / 211 bits | rank 1,459 / 4,096 | 12,532,714,569,728 / 35,184,372,088,832 | 1 / 0 | 8,192 bits |
| A325 | 46 / 210 bits | rank 77 / 4,096 | 1,322,849,927,168 / 70,368,744,177,664 | 1 / 0 | 8,192 bits |
| A350 | 46 / 210 bits | rank 445 / 4,096 | 7,645,041,786,880 / 70,368,744,177,664 | 1 / 0 | 8,192 bits |
| A374 | 48 / 208 bits | rank 102 / 4,096 | 7,009,386,627,072 / 281,474,976,710,656 | 1 / 0 | 8,192 bits |

The exact per-record protocols, results, Causal graphs, and reports are linked
in the [claim matrix](docs/CLAIM_MATRIX.md). The A287--A325 ranks and execution
bounds are also collected in the [release record](docs/A287_A325_RELEASE.md).
The [recovery completeness audit](docs/RECOVERY_COMPLETENESS_AUDIT.md) separately
classifies the 46-record frontier, the earlier breadth ladder, same-target
replays, alternative solver records, and post-barrier recovery labels.

## A326--A458: complete W52 Reader frontier

The next public line compiles target-blind execution geometry for the complete
`2^52` residual domain. A456 and A458 each evaluate every registered schedule
and emit a complete permutation of all 16,777,216 W52 pair cells.

| Result | Schedule census | Selected schedule | Remaining-96 aggregate gain | Minimum block gain | Pair-stream SHA-256 |
|---|---:|---|---:|---:|---|
| A456 | 878 schedules / 86 cyclic orbits | `BOOOOOOHHHHHH` | `0.489437610231` bit | `0.176347721941` bit | `9a3af1cfb71f96d186815086170127cd5340e7ac102a5fe9dc65414c14df7352` |
| A458 | 405 paired B1/B0 schedules / 18 cyclic orbits | `OOOOOOOOHHHHHHHHHHHHHHHBOOOOOOO` | `0.495787645250` bit | `0.205050504927` bit | `5220aa319ab75f7e5e77717802f248512ecdb04531a5d660ac48302f428a1138` |

Both schedules have positive gain on all eight fixed blocks, zero W52 labels,
zero refits, zero candidate assignments, and exact component bounds over the
entire pair domain. A455 and A457 are the hash-frozen eight-worker recovery
executors with production disabled. The public release contains no live worker
state or recovery outcome.

- [Pinned A326--A458 release record](docs/A326_A458_FRONTIER.md)
- [One-command frontier verifier](https://github.com/DT-Foss/f8-causal-cryptanalysis/blob/676ee0d6523351347b75907b151c5c4b605061ac/scripts/verify_a326_a458_frontier.py)
- [935-file SHA-256 manifest](https://github.com/DT-Foss/f8-causal-cryptanalysis/blob/676ee0d6523351347b75907b151c5c4b605061ac/research/results/v1/A326_A458_FRONTIER_SHA256SUMS)
- [A456 result and AI-native Causal graph](https://github.com/DT-Foss/f8-causal-cryptanalysis/tree/676ee0d6523351347b75907b151c5c4b605061ac/research/results/v1)
- [Integrity-checking Causal Reader](src/fullround_key_recovery/_dotcausal/io.py)

The package independently reconstructs and confirms every recovered key. Its
immutable evidence mapping and exact per-record scope are in
[docs/CLAIM_MATRIX.md](docs/CLAIM_MATRIX.md).

## Exact claim

The artifacts establish eighteen complete-domain full-round recovery points and
a common Metal architecture across ARX, Feistel, SP-network, AEAD, and AES
designs. Each input is a frozen public relation plus the listed known key bits;
every assignment in the declared 38- to 44-bit residual domain was executed.
TF1024KR1 adds complete `2^39` Threefish-1024 recovery through all 80 rounds and
the final subkey, independently confirming 2,048 output bits. CHACHA20KR43 adds
the complete `2^43` ChaCha20-R20 domain and confirms 8,192 output bits across
independent word- and byte-oriented implementations.

A281, A286, and A294--A374 establish the separate strict-subset result class:
frozen scheduling, recovery before complete-domain enumeration, full-output
recomputation, and matched-control rejection. The demonstrated operation is
exact residual-key recovery in each declared known-key model.

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

1. verifies every immutable file against `provenance/ARTIFACTS.sha256`;
2. checks every frozen protocol/result challenge, every A286 root anchor, and
   every retained A287--A325 chronology artifact and the A001--A458 public
   attempt ledgers;
3. reconstructs every recovered key and independently recomputes the complete
   full-round output for all 18 complete-domain and 28 strict-subset executions;
4. opens every headline and chronology `.causal` file with the matching
   integrity-checking Reader;
5. checks complete-domain gates for the eighteen exhaustive records and the
   frozen-order/no-full-enumeration gates for all strict-subset executions.

## Native replay

Native replay requires macOS, Apple Silicon with Metal, and Swift 6. The
repository retains all fifteen native Swift/Metal hosts. The three original
checkpointable package integrations expose direct complete-search commands:

```bash
make native-smoke
./scripts/reproduce_full_search.sh chacha20
./scripts/reproduce_full_search.sh speck32_64
./scripts/reproduce_full_search.sh threefish256
```

The subsequent byte-exact protocol factories, qualification programs, and
recovery runners are preserved under `experiments/original/`, alongside their
native hosts under `experiments/native/`. The complete A287--A325 source and
evidence chain is preserved under `chronology/arx-carry-leak/`. Their immutable
configs, qualification records, results, manifests, reports, source, and Causal
artifacts are retained as one provenance chain. Platform-independent independent
confirmation of every recovery record is part of `make verify`.

The public attempt history through A458 is retained separately in
`chronology/ATTEMPT_LOG_A001_A431.md` and
`chronology/ATTEMPT_LOG_A432_A458.md`. These ledgers bind this compact recovery
package to the completed W52 Reader frontier without copying its five 64 MiB
pair streams into a second repository.

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
| CHACHA20KR43 | 8,796,093,022,208 | 6,406.80 s |
| B3KR1 | 8,796,093,022,208 | 6,313.44 s |
| SIPKR1 | 8,796,093,022,208 | 4,259.91 s |
| TEAKR1 | 8,796,093,022,208 | 5,012.03 s |
| XTEAKR1 | 8,796,093,022,208 | 3,522.48 s |
| TF1024KR1 | 549,755,813,888 | 6,434.77 s |

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
chronology/           A001--A458 ledgers plus byte-exact A287--A325 evidence
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
