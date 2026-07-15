from __future__ import annotations

from pathlib import Path

from fullround_key_recovery.artifacts import EXPECTED_SHA256, verify_artifact_hashes

ROOT = Path(__file__).parents[1]


def test_every_immutable_artifact_is_hash_pinned() -> None:
    assert verify_artifact_hashes(ROOT) == EXPECTED_SHA256
    assert len(EXPECTED_SHA256) == 570


def test_checked_in_manifest_exactly_matches_runtime_inventory() -> None:
    rows = {}
    for line in (ROOT / "provenance" / "ARTIFACTS.sha256").read_text().splitlines():
        digest, relative = line.split("  ", 1)
        rows[relative] = digest
    assert rows == EXPECTED_SHA256


def test_original_reports_are_explicitly_separated_from_current_docs() -> None:
    originals = sorted((ROOT / "reports" / "original").glob("*.md"))
    assert len(originals) == 32
    assert all(path.suffix == ".md" for path in originals)


def test_vendored_authoritative_reader_and_license_are_hash_pinned() -> None:
    rows = {}
    for line in (ROOT / "provenance" / "VENDORED_READER.sha256").read_text().splitlines():
        digest, relative = line.split("  ", 1)
        rows[relative] = digest
    assert len(rows) == 5
    for relative, digest in rows.items():
        from fullround_key_recovery.artifacts import sha256_file

        assert sha256_file(ROOT / relative) == digest
    assert rows["src/fullround_key_recovery/_dotcausal/io.py"] == (
        "e320f77855a713e44c97fbc9d1bbb8c488a5c458f2b5ddecc0254a7dc57e0074"
    )
