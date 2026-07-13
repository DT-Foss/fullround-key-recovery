from __future__ import annotations

from pathlib import Path

from fullround_key_recovery.causal import read_causal

ROOT = Path(__file__).parents[1]


def test_a184_legacy_graph_integrity_and_provenance() -> None:
    value = read_causal(ROOT / "causal" / "chacha20_metal_width40_partial_key_recovery_v1.causal")
    assert value == {
        "format": "crypto-causal-v3",
        "file_sha256": "b37bc0234966185e06eb15ae6926502535b0c50271b01f0b6bd8fe5394dabd0f",
        "graph_sha256": "864fe8a07d9770763110dc037619c91b5ca6fa36b5ee7e1dbd35d673311a3b28",
        "explicit_triplets": 5,
        "inferred_triplets": 0,
        "provenance_verified": True,
    }


def test_a237_authentic_reader_opens_materialized_graph() -> None:
    value = read_causal(ROOT / "causal" / "speck32_64_metal_width42_recovery_v1.causal")
    assert value["format"] == "dotcausal-v1"
    assert value["api_id"] == "a237"
    assert value["explicit_triplets"] == 5
    assert value["inferred_triplets"] == 2
    assert value["integrity_algorithm"] == "xxhash64"
    assert value["integrity_verified_by_authoritative_reader"] is True
    assert value["rules"] == value["clusters"] == 2
    assert value["gaps"] == 1


def test_a240_authentic_reader_opens_materialized_graph() -> None:
    value = read_causal(ROOT / "causal" / "threefish256_metal_width38_recovery_v1.causal")
    assert value["format"] == "dotcausal-v1"
    assert value["api_id"] == "a240"
    assert value["explicit_triplets"] == 5
    assert value["inferred_triplets"] == 2
    assert value["integrity_algorithm"] == "md5-fallback"
    assert value["integrity_verified_by_authoritative_reader"] is True
    assert value["rules"] == value["clusters"] == 2
    assert value["gaps"] == 1
