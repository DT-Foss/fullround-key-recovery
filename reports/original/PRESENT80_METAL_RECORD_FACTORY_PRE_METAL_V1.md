# PRESENT-80 A252/A253 record factory — pre-Metal state

## Scope

The prepared implementation executes all 31 PRESENT-80 SPN rounds and the
final `K32` whitening operation.  The master key is represented as
`high16 || middle32 || low32`; each ciphertext block is represented as two
big-endian 32-bit words.  Two public plaintext/ciphertext pairs form one exact
128-bit filter.

## CPU and static gates

- The scalar reference passes all four CHES 2007 PRESENT-80 vectors.
- ISO/IEC 29192-2:2012 Annex B.1.1 binds the nonpalindromic key, plaintext,
  ciphertext, and `K1`, `K2`, `K31`, and `K32` round-key orientations.
- Two additional nonpalindromic sentinels exercise byte, nibble, P-layer, and
  key-register orientation.
- Encryption is differentially checked against an independent transcription;
  decryption is checked by randomized roundtrips.
- Static gates bind the Metal 80-bit rotate-left-61 decomposition, top-nibble
  S-box, split round-counter injection, 31-round loop, final whitening, host
  parameter ABI, strict JSON `uint32` parsing, and factual/control filters.
- The Swift host passes a compiler typecheck without constructing a Metal
  device, compiling the runtime shader, or dispatching GPU work.
- A253 maps assignment bits 0..31 to `low32` and bits 32..W-1 to the low
  `W-32` bits of `middle32`.  Widths 32, 33, 43, and 64 are covered explicitly.
- The runner requires the retained protocol hash, executes the complete domain
  without early stopping, persists exact candidate identities in a resumable
  checkpoint, applies the identical search to a one-bit control, independently
  confirms all filtered candidates, and writes a native `.causal` v1 artifact
  that is reopened with the authoritative Causal Reader.

## Deliberately pending

`A252` has not been executed.  Therefore no Metal throughput, selected width,
or completion ETA exists.  `A253` has not been frozen, no production target has
been generated, and no candidate from a production domain has been evaluated.
Metal qualification requires an explicit `--qualify`; freezing and execution
require separate explicit commands after the retained qualification exists.

Run the CPU/static preflight only:

```sh
sh scripts/reproduce_present80_metal.sh
```
