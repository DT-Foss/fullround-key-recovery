# Source provenance

The initial immutable evidence in this repository was extracted on 2026-07-13 from the
local `arx-carry-leak` research working tree maintained by David Tom Foss. The
base Git commit visible during extraction was:

```text
97fa868b96771951d5fb2c26aa1785e9d05c4cde
```

The A184, A237, and A240 research files were uncommitted working-tree artifacts
at extraction time. Their identity is therefore established by the complete
SHA-256 inventory in `ARTIFACTS.sha256`, not by the base commit alone.

The inventory was extended on 2026-07-14 with the completed A278-A281
cross-material chain, the A282-A286 four-target panel, PRESENT-128 W38, and
AES-256 W41. These artifacts were copied without content transformation from
the same source tree. Original reports and experiment sources remain byte-exact
provenance artifacts; package verification code, documentation, and metadata
were authored separately in this repository.

The authoritative source-compatible `dotcausal` Reader revision used by A237
and A240 was copied from the same research environment. Its `io.py` SHA-256 is
`e320f77855a713e44c97fbc9d1bbb8c488a5c458f2b5ddecc0254a7dc57e0074`,
matching the Reader provenance embedded in the authentic result JSON files. The complete
vendored subset and MIT license are pinned separately in
`VENDORED_READER.sha256`.
