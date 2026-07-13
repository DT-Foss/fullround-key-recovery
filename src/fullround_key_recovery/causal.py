"""Read and integrity-check both retained Causal encodings."""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path
from typing import Any


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def read_legacy_v3(path: Path) -> dict[str, Any]:
    encoded = path.read_bytes()
    if len(encoded) < 8 or encoded[:6] != b"CAUSAL" or struct.unpack("<H", encoded[6:8])[0] != 3:
        raise ValueError("not a legacy crypto-causal v3 file")
    envelope = json.loads(zlib.decompress(encoded[8:]).decode())
    graph = envelope.get("graph")
    if not isinstance(graph, dict) or graph.get("schema") != "crypto-causal-v1":
        raise ValueError("invalid legacy crypto-causal graph")
    graph_sha = hashlib.sha256(_canonical_bytes(graph)).hexdigest()
    if envelope.get("graph_sha256") != graph_sha:
        raise ValueError("legacy crypto-causal graph integrity mismatch")
    ids = {row["edge_id"] for row in graph["triplets"]}
    provenance_ok = all(
        not row.get("is_inferred") or set(row.get("provenance", ())).issubset(ids)
        for row in graph["triplets"]
    )
    return {
        "format": "crypto-causal-v3",
        "file_sha256": hashlib.sha256(encoded).hexdigest(),
        "graph_sha256": graph_sha,
        "explicit_triplets": sum(not row.get("is_inferred") for row in graph["triplets"]),
        "inferred_triplets": sum(bool(row.get("is_inferred")) for row in graph["triplets"]),
        "provenance_verified": provenance_ok,
    }


def read_dotcausal_v1(path: Path) -> dict[str, Any]:
    from ._dotcausal import io as dotcausal_io

    encoded = path.read_bytes()
    stored_crc = encoded[20:28]
    content = encoded[96:]
    xxhash_crc = dotcausal_io.struct.pack(
        "<Q", dotcausal_io.xxhash.xxh64(content).intdigest()
    )
    md5_crc = hashlib.md5(content).digest()[:8]
    if stored_crc == xxhash_crc:
        integrity_algorithm = "xxhash64"
        has_xxhash = True
    elif stored_crc == md5_crc:
        integrity_algorithm = "md5-fallback"
        has_xxhash = False
    else:
        raise ValueError("dotcausal content integrity mismatch under both supported CRC modes")

    # The retained writer chooses CRC according to optional xxhash availability.
    # Reopen under the same deterministic mode so the authoritative Reader runs
    # its own verify_integrity=True gate for both artifact variants.
    original = dotcausal_io.HAS_XXHASH
    dotcausal_io.HAS_XXHASH = has_xxhash
    try:
        reader = dotcausal_io.CausalReader(str(path), verify_integrity=True)
    finally:
        dotcausal_io.HAS_XXHASH = original
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    return {
        "format": "dotcausal-v1",
        "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "integrity_algorithm": integrity_algorithm,
        "integrity_verified_by_authoritative_reader": True,
        "version": reader.version,
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "inferred_triplets": len(all_rows) - len(explicit),
        "total_triplets": len(all_rows),
        "rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
    }


def read_causal(path: Path) -> dict[str, Any]:
    header = path.read_bytes()[:8]
    if header == b"CAUSAL\x03\x00":
        return read_legacy_v3(path)
    if header == b"CAUSAL\x00\x01":
        return read_dotcausal_v1(path)
    raise ValueError(f"unsupported Causal header: {header!r}")
