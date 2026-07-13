# Source provenance

The immutable evidence in this repository was extracted on 2026-07-13 from the
local `arx-carry-leak` research working tree maintained by David Tom Foss. The
base Git commit visible during extraction was:

```text
97fa868b96771951d5fb2c26aa1785e9d05c4cde
```

The A184, A237, and A240 research files were uncommitted working-tree artifacts
at extraction time. Their identity is therefore established by the complete
SHA-256 inventory in `ARTIFACTS.sha256`, not by the base commit alone.

The 17 listed files were copied without content transformation. Original reports
remain byte-exact provenance artifacts. All new package code, documentation, and
metadata were authored separately in this repository.

The authoritative source-compatible `dotcausal` Reader revision used by A237
and A240 was copied from the same research environment. Its `io.py` SHA-256 is
`e320f77855a713e44c97fbc9d1bbb8c488a5c458f2b5ddecc0254a7dc57e0074`,
matching the Reader provenance embedded in both result JSON files. The complete
vendored subset and MIT license are pinned separately in
`VENDORED_READER.sha256`.
