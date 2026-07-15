#!/usr/bin/env python3
"""Canonicalize A204's immutable reverse-order evidence into AI-native Causal.

The A204 solver measurements are not rerun.  This program binds the exact
legacy result and sidecar hashes, separates the successful global calibration
from the later prefix-partition budget boundary, and materializes the next
testable gap with the authentic ``dotcausal.io.CausalReader`` format.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESULTS = ROOT / "research/results/v1"
REPORTS = ROOT / "research/reports"
SOURCE_RESULT = RESULTS / "chacha20_round10_external_cnf_reverse_v1.json"
SOURCE_LEGACY_CAUSAL = RESULTS / "chacha20_round10_external_cnf_reverse_v1.causal"
OUTPUT_RESULT = RESULTS / "chacha20_round10_external_cnf_reverse_canonical_v1.json"
OUTPUT_CAUSAL = RESULTS / "chacha20_round10_external_cnf_reverse_canonical_v1.causal"
OUTPUT_REPORT = REPORTS / "CHACHA20_ROUND10_EXTERNAL_CNF_REVERSE_CANONICAL_V1.md"
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)

SOURCE_RESULT_SHA256 = "603eaf8a2a6bb85c3c4bb2fdf4b7466205ffd1d8005593d987c8a6461b7c8c22"
SOURCE_LEGACY_CAUSAL_SHA256 = (
    "f1ca39f964640d8aa2a5c6f6dab9bcfb48dfaddf6dda2e399275f77235ca71c3"
)
EXPECTED_GAP = "prospective_fullround_W24_global_reverse_operator"


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def canonical_sha256(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    )


def atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def atomic_json(path: Path, value: Any) -> None:
    atomic_bytes(
        path,
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n",
    )


def relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:
        return str(resolved)


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    digest = file_sha256(path)
    if expected is not None and digest != expected:
        raise RuntimeError(f"A204 canonical anchor differs: {path}")
    return {"path": relative(path), "sha256": digest}


def validate_source() -> dict[str, Any]:
    anchor(SOURCE_RESULT, SOURCE_RESULT_SHA256)
    anchor(SOURCE_LEGACY_CAUSAL, SOURCE_LEGACY_CAUSAL_SHA256)
    payload = json.loads(SOURCE_RESULT.read_bytes())
    calibration = payload.get("calibration", {})
    outcomes = calibration.get("outcomes", [])
    sat = [row for row in outcomes if row.get("status_at_5000ms") == "sat"]
    execution = payload.get("execution", {})
    wave_rows = execution.get("wave_observations", [])
    if (
        payload.get("schema") != "chacha20-round10-external-cnf-reverse-v1"
        or payload.get("attempt_id") != "A204"
        or payload.get("evidence_stage")
        != "ROUND10_EXTERNAL_CNF_COMPLETE_PARTITION_BOUNDARY_RETAINED"
        or calibration.get("tested_configuration_count") != 26
        or len(outcomes) != 26
        or sat != [{"status_at_5000ms": "sat", "variant": "cadical_reverse"}]
        or calibration.get("selected_variant") != "cadical_reverse"
        or "--reverse=true" not in calibration.get("selected_command", [])
        or calibration.get("confirmation", {}).get("all_blocks_match") is not True
        or calibration.get("confirmation", {}).get("output_bits_checked") != 4096
        or calibration.get("confirmation", {}).get("control_first_block_match")
        is not False
        or execution.get("complete_variant_plan_executed") is not True
        or execution.get("returned_model_count") != 0
        or len(execution.get("variant_order", [])) != 32
        or len(wave_rows) != 8
        or any(status != "unknown" for wave in wave_rows for status in wave["statuses"])
    ):
        raise RuntimeError("A204 canonical source semantics differ")
    return payload


def canonicalize() -> dict[str, Any]:
    if OUTPUT_RESULT.exists() or OUTPUT_REPORT.exists():
        raise FileExistsError("A204 canonical outputs already exist")
    # A prior interrupted canonicalization may have completed the binary write
    # before its JSON/report transaction.  It contains no new solver evidence
    # and is deterministically rebuilt from the immutable source anchors.
    OUTPUT_CAUSAL.unlink(missing_ok=True)
    source = validate_source()
    calibration = source["calibration"]
    execution = source["execution"]

    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    reader_source = Path(inspect.getsourcefile(CausalReader) or "")
    writer = CausalWriter(api_id="a204rv")
    writer._rules = []
    writer.add_rule(
        name="unique_global_configuration_plus_confirmation",
        description=(
            "A uniquely successful predeclared global solver configuration followed "
            "by exact 4096-bit confirmation retains that configuration as an operator."
        ),
        pattern=["unique_global_configuration", "4096_bit_confirmation"],
        conclusion="retained_reverse_global_operator",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="partition_boundary_is_representation_conditioned",
        description=(
            "A complete UNKNOWN result after changing the formula into 32 independent "
            "prefix partitions identifies a representation boundary; it does not erase "
            "the separately confirmed unpartitioned global calibration."
        ),
        pattern=["retained_reverse_global_operator", "complete_prefix_UNKNOWN_boundary"],
        conclusion="test_reverse_operator_on_unpartitioned_fullround_formula",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A204:predeclared_26_configuration_global_matrix",
        mechanism="five_second_external_CNF_calibration",
        outcome="A204:unique_cadical_reverse_SAT_model",
        confidence=1.0,
        source=SOURCE_RESULT_SHA256,
        quantification="1 SAT configuration of 26; cadical --reverse=true",
        evidence=json.dumps(calibration["outcomes"], sort_keys=True),
        domain="ChaCha10 global external-CNF solver calibration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A204:unique_cadical_reverse_SAT_model",
        mechanism="independent_eight_block_standard_output_recompute",
        outcome="A204:confirmed_reverse_global_operator",
        confidence=1.0,
        source=source["confirmation_sha256"],
        quantification="8 blocks; 4096 output bits; one-bit control rejected",
        evidence=json.dumps(calibration["confirmation"], sort_keys=True),
        domain="exact model confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A204:confirmed_reverse_global_operator",
        mechanism="transfer_to_32_independent_prefix_CNF_partitions",
        outcome="A204:complete_prefix_UNKNOWN_boundary",
        confidence=1.0,
        source=source["execution_sha256"],
        quantification="32/32 cells UNKNOWN at 10 seconds; zero disclosed models",
        evidence=json.dumps(execution["wave_observations"], sort_keys=True),
        domain="prospective partitioned ChaCha10 transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A204:complete_prefix_UNKNOWN_boundary",
        mechanism="separate_global_operator_from_partition_representation",
        outcome="A204:unpartitioned_reverse_transfer_required",
        confidence=1.0,
        source=SOURCE_RESULT_SHA256,
        quantification="global calibration retained; prefix representation bounded",
        evidence=source["evidence_stage"],
        domain="operator representation boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A204:predeclared_26_configuration_global_matrix",
        mechanism="unique_global_configuration_plus_confirmation",
        outcome="A204:confirmed_reverse_global_operator",
        confidence=1.0,
        source="materialized:A204_unique_reverse_plus_4096_bit_confirmation",
        quantification="exact two-edge closure retained in-file",
        evidence="materialized from the immutable A204 calibration and confirmation",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_triplet(
        trigger="A204:confirmed_reverse_global_operator",
        mechanism="partition_boundary_is_representation_conditioned",
        outcome="A204:unpartitioned_reverse_transfer_required",
        confidence=1.0,
        source="materialized:A204_reverse_operator_plus_partition_boundary",
        quantification="operator/representation distinction retained in-file",
        evidence="materialized from the immutable A204 global and partition results",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A204 retained reverse global operator",
        entities=[
            "A204:predeclared_26_configuration_global_matrix",
            "A204:unique_cadical_reverse_SAT_model",
            "A204:confirmed_reverse_global_operator",
        ],
    )
    writer.add_cluster(
        name="A204 representation-conditioned transfer boundary",
        entities=[
            "A204:confirmed_reverse_global_operator",
            "A204:complete_prefix_UNKNOWN_boundary",
            "A204:unpartitioned_reverse_transfer_required",
        ],
    )
    writer.add_gap(
        subject="A204:unpartitioned_reverse_transfer_required",
        predicate="next_required_object",
        expected_object_type=EXPECTED_GAP,
        confidence=1.0,
        suggested_queries=[
            "Does cadical --reverse=true return a model on the frozen unpartitioned ChaCha20-R20 W24 CNF?",
            "Does the reverse operator behave differently on the native and BFS-far CNF views?",
        ],
    )
    temporary = OUTPUT_CAUSAL.with_name(f".{OUTPUT_CAUSAL.name}.tmp")
    stats = writer.save(str(temporary))
    os.replace(temporary, OUTPUT_CAUSAL)
    reader = CausalReader(str(OUTPUT_CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    gaps = list(reader._gaps)
    if (
        reader.version != 1
        or reader.api_id != "a204rv"
        or len(explicit) != 4
        or len(all_rows) != 6
        or len(inferred) != 2
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(gaps) != 1
        or gaps[0].get("expected_object_type") != EXPECTED_GAP
    ):
        raise RuntimeError("A204 canonical authentic Causal gate failed")
    payload = {
        "schema": "chacha20-round10-external-cnf-reverse-canonical-v1",
        "attempt_id": "A204R",
        "evidence_stage": "AUTHENTIC_CAUSAL_REPRESENTATION_BOUNDARY_CANONICALIZED",
        "solver_evidence_rerun": False,
        "source_result": anchor(SOURCE_RESULT, SOURCE_RESULT_SHA256),
        "source_legacy_sidecar": anchor(
            SOURCE_LEGACY_CAUSAL, SOURCE_LEGACY_CAUSAL_SHA256
        ),
        "canonicalizer": anchor(Path(__file__)),
        "authentic_causal": {
            "path": relative(OUTPUT_CAUSAL),
            "sha256": file_sha256(OUTPUT_CAUSAL),
            "api_id": reader.api_id,
            "explicit_triplets": len(explicit),
            "materialized_inferred_triplets": len(inferred),
            "rules": len(reader._rules),
            "clusters": len(reader._clusters),
            "gaps": gaps,
            "reader_source": anchor(reader_source),
            "writer_stats": stats,
        },
        "personal_semantic_readback": {
            "retained_global_operator": all_rows[1],
            "representation_boundary": all_rows[2],
            "materialized_next_chain": all_rows[-1],
            "next_gap": gaps[0],
        },
    }
    payload["canonical_content_sha256"] = canonical_sha256(payload)
    atomic_json(OUTPUT_RESULT, payload)
    report = f"""# A204R — authentic Causal canonicalization of the reverse-order frontier

The immutable A204 solver evidence was not rerun. Its 26-way calibration retained
`cadical --reverse=true` as the unique five-second global SAT configuration and
confirmed the model over 4096 output bits. The later 32-cell UNKNOWN result is
encoded separately as a prefix-representation boundary.

- Source result SHA-256: `{SOURCE_RESULT_SHA256}`
- Authentic Causal SHA-256: `{file_sha256(OUTPUT_CAUSAL)}`
- Personally read next gap: `{EXPECTED_GAP}`
"""
    atomic_bytes(OUTPUT_REPORT, report.encode("utf-8"))
    return payload


def main() -> None:
    payload = canonicalize()
    print(file_sha256(OUTPUT_RESULT))
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
