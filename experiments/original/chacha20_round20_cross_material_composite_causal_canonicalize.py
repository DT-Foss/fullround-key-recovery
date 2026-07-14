#!/usr/bin/env python3
"""Canonicalize A281's AI-native graph without rerunning its solver evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
ATTEMPT_ID = "A281C"
SOURCE_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_cross_material_composite_recovery_v1.json"
)
SOURCE_CAUSAL = SOURCE_RESULT.with_suffix(".causal")
SOURCE_RESULT_SHA256 = "0083e7e476844086b2ea58d6f490d0ab61cb9a7193371525aeac5252c12f1b05"
SOURCE_CAUSAL_SHA256 = "21376078164db9bad5eb2804c5e9e5a4dab2328876b1589c6e04db785bb49067"
DEFAULT_OUTPUT = (
    ROOT
    / "research/results/v1/chacha20_round20_cross_material_composite_recovery_canonical_v1.json"
)
DEFAULT_CAUSAL = DEFAULT_OUTPUT.with_suffix(".causal")
DEFAULT_REPORT = (
    ROOT
    / "research/reports/CAUSAL_CHACHA20_ROUND20_CROSS_MATERIAL_COMPOSITE_RECOVERY_CANONICAL_V1.md"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_bytes(
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


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(module.CausalReader) or "")
    return module.CausalWriter, module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": _file_sha256(source),
    }


def canonicalize(
    *,
    source_result: Path,
    expected_result_sha256: str,
    source_causal: Path,
    expected_causal_sha256: str,
    output: Path,
    causal_output: Path,
    report_output: Path,
    dotcausal_src: Path,
) -> dict[str, Any]:
    if _file_sha256(source_result) != expected_result_sha256:
        raise RuntimeError("A281C source result hash differs")
    if _file_sha256(source_causal) != expected_causal_sha256:
        raise RuntimeError("A281C source Causal hash differs")
    result = json.loads(source_result.read_bytes())
    confirmation = result.get("confirmation")
    top = result.get("top_execution_summary", {})
    sat_row = result.get("top_execution", {}).get("sat_row", {})
    if (
        result.get("schema")
        != "chacha20-round20-cross-material-composite-recovery-result-v1"
        or result.get("attempt_id") != "A281"
        or result.get("evidence_stage")
        != "FULLROUND_R20_CROSS_MATERIAL_TARGET_BLIND_TOP128_RECOVERY_CONFIRMED"
        or top.get("attempted_cells") != 37
        or top.get("unsat") != 36
        or top.get("unknown") != 0
        or top.get("sat") != 1
        or sat_row.get("cell_index") != 36
        or sat_row.get("prefix8") != "10111111"
        or confirmation is None
        or confirmation.get("recovered_unknown_low20") != 0xBF9F3
        or confirmation.get("all_blocks_match") is not True
        or confirmation.get("all_cross_implementation_blocks_match") is not True
        or confirmation.get("output_bits_checked") != 4096
        or confirmation.get("control_first_block_match") is not False
        or result.get("residual_execution") is not None
        or result.get("information_boundary", {}).get("complete_full_domain_enumeration_used")
        is not False
    ):
        raise RuntimeError("A281C retained recovery evidence gate failed")

    CausalWriter, CausalReader, reader_source = _load_dotcausal(dotcausal_src)
    original = CausalReader(str(source_causal), verify_integrity=True)
    original_explicit = original.get_all_triplets(include_inferred=False)
    self_loops = [
        row
        for row in original_explicit
        if row.get("trigger") == row.get("outcome")
    ]
    duplicate_cluster_indices = any(
        len(cluster.get("entity_indices", []))
        != len(set(cluster.get("entity_indices", [])))
        for cluster in original._clusters
    )
    if len(self_loops) != 1 or duplicate_cluster_indices is not True:
        raise RuntimeError("A281C expected source-graph representation issue differs")

    writer = CausalWriter(api_id="a281c")
    writer._rules = []
    writer.add_rule(
        name="frozen_cross_material_order_yields_rank37_model",
        description="The prospectively frozen A280 order enters one retained CaDiCaL state; 36 exact UNSAT cells precede the first SAT model in cell 37.",
        pattern=["A280_hash_frozen_cross_material_order", "A281_rank37_solver_model"],
        conclusion="A281_strict_subset_cross_material_recovery",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="solver_model_requires_dual_full_output_confirmation",
        description="The rank-37 solver model becomes recovery evidence only after two independent standard ChaCha20 implementations match eight blocks and the flipped control rejects.",
        pattern=["A281_rank37_solver_model", "A281_dual_4096_bit_confirmation"],
        conclusion="A281_confirmed_cross_material_R20_recovery",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A280:hash_frozen_cross_material_candidate_order",
        mechanism="one_retained_CaDiCaL_state_proves_36_prefixes_UNSAT_then_returns_SAT",
        outcome="A281:rank37_solver_model",
        confidence=1.0,
        source=result["measurement_sha256"],
        quantification=(
            "37/256 prefix cells; 151552/1048576 logical assignments in visited cells; "
            "465.439099 solver seconds"
        ),
        evidence=json.dumps(top, sort_keys=True),
        domain="full-round ChaCha20-R20 prospective cross-material recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A281:rank37_solver_model",
        mechanism="decode_low20_bf9f3_then_recompute_eight_standard_R20_blocks_twice",
        outcome="A281:dual_4096_bit_confirmation",
        confidence=1.0,
        source=expected_result_sha256,
        quantification="8 blocks; 4096 output bits; RFC8439 KAT; one flipped-output control",
        evidence=json.dumps(
            {
                "recovered_unknown_low20_hex": confirmation[
                    "recovered_unknown_low20_hex"
                ],
                "all_blocks_match": confirmation["all_blocks_match"],
                "control_first_block_match": confirmation["control_first_block_match"],
            },
            sort_keys=True,
        ),
        domain="dual-independent standard-output confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A281:dual_4096_bit_confirmation",
        mechanism="bind_prospective_order_model_and_control_rejection",
        outcome="A281:confirmed_cross_material_R20_recovery",
        confidence=1.0,
        source=expected_result_sha256,
        quantification="rank 37; 14.453125 percent of the declared prefix-cell domain visited",
        evidence=result["evidence_stage"],
        domain="confirmed strict-subset full-round residual-key recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A280:hash_frozen_cross_material_candidate_order",
        mechanism="materialized_order_model_confirmation_chain_without_self_loop",
        outcome="A281:confirmed_cross_material_R20_recovery",
        confidence=1.0,
        source="materialized:A280_order_plus_A281_rank37_model_plus_dual_confirmation",
        quantification="canonical three-edge AI-native closure",
        evidence=result["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A281 canonical cross-material strict-subset recovery",
        entities=[
            "A280:hash_frozen_cross_material_candidate_order",
            "A281:rank37_solver_model",
            "A281:dual_4096_bit_confirmation",
            "A281:confirmed_cross_material_R20_recovery",
        ],
    )
    writer.add_gap(
        subject="A281:confirmed_cross_material_R20_recovery",
        predicate="next_required_object",
        expected_object_type="multi_target_cross_material_replication_or_wider_unknown_domain",
        confidence=1.0,
        suggested_queries=[
            "Freeze the same end-to-end reader and solver schedule across multiple independently derived public targets.",
            "Transfer the confirmed cross-material mechanism to a wider unknown-key domain.",
        ],
    )
    causal_output.parent.mkdir(parents=True, exist_ok=True)
    temporary = causal_output.with_name(f".{causal_output.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, causal_output)

    reader = CausalReader(str(causal_output), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a281c"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or any(row.get("trigger") == row.get("outcome") for row in explicit)
        or len(reader._clusters[0]["entity_indices"])
        != len(set(reader._clusters[0]["entity_indices"]))
        or all_rows[-1]["outcome"]
        != "A281:confirmed_cross_material_R20_recovery"
    ):
        raise RuntimeError("A281C canonical Causal Reader reopen gate failed")

    payload = {
        "schema": "chacha20-round20-cross-material-composite-recovery-canonical-causal-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": result["evidence_stage"],
        "source_result": {
            "path": str(source_result.relative_to(ROOT)),
            "sha256": expected_result_sha256,
        },
        "source_causal": {
            "path": str(source_causal.relative_to(ROOT)),
            "sha256": expected_causal_sha256,
            "retained_as_immutable_original": True,
        },
        "correction": {
            "solver_or_measurement_reexecuted": False,
            "scientific_result_changed": False,
            "removed_explicit_self_loops": len(self_loops),
            "removed_duplicate_cluster_entity_indices": duplicate_cluster_indices,
            "canonical_chain": [
                "A280:hash_frozen_cross_material_candidate_order",
                "A281:rank37_solver_model",
                "A281:dual_4096_bit_confirmation",
                "A281:confirmed_cross_material_R20_recovery",
            ],
        },
        "causal": {
            "format": "authentic_dotcausal_v1_AI_native",
            "path": str(causal_output.relative_to(ROOT)),
            "sha256": _file_sha256(causal_output),
            "bytes": causal_output.stat().st_size,
            "api_id": reader.api_id,
            "explicit_triplets": len(explicit),
            "materialized_inferred_triplets": len(inferred),
            "embedded_rules": len(reader._rules),
            "clusters": len(reader._clusters),
            "gaps": len(reader._gaps),
            "integrity_verified_by_authoritative_reader": True,
            "reader_source": reader_source,
            "writer_stats": stats,
            "personal_semantic_readback": {
                "terminal_chain": all_rows[-1],
                "next_gap": reader._gaps[0],
            },
        },
    }
    _atomic_json(output, payload)
    report = "\n".join(
        [
            "# A281C — canonical AI-native recovery graph",
            "",
            "The immutable A281 solver result is unchanged. This artifact replaces one representational self-loop and one duplicate cluster entry in its first Causal graph with the exact prospective order → rank-37 solver model → dual confirmation chain.",
            "",
            f"- Source result SHA-256: `{expected_result_sha256}`",
            f"- Canonical Causal SHA-256: `{payload['causal']['sha256']}`",
            "- Solver re-executed: **False**",
            f"- Next gap: **{reader._gaps[0]['expected_object_type']}**",
            "",
        ]
    )
    _atomic_bytes(report_output, report.encode("utf-8"))
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-result", type=Path, default=SOURCE_RESULT)
    parser.add_argument("--expected-result-sha256", default=SOURCE_RESULT_SHA256)
    parser.add_argument("--source-causal", type=Path, default=SOURCE_CAUSAL)
    parser.add_argument("--expected-causal-sha256", default=SOURCE_CAUSAL_SHA256)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--causal-output", type=Path, default=DEFAULT_CAUSAL)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    payload = canonicalize(
        source_result=args.source_result,
        expected_result_sha256=args.expected_result_sha256,
        source_causal=args.source_causal,
        expected_causal_sha256=args.expected_causal_sha256,
        output=args.output,
        causal_output=args.causal_output,
        report_output=args.report_output,
        dotcausal_src=args.dotcausal_src,
    )
    print(
        json.dumps(
            {
                "evidence_stage": payload["evidence_stage"],
                "source_result_sha256": payload["source_result"]["sha256"],
                "canonical_causal": payload["causal"]["path"],
                "canonical_causal_sha256": payload["causal"]["sha256"],
                "result": str(args.output),
                "result_sha256": _file_sha256(args.output),
                "next_gap": payload["causal"]["personal_semantic_readback"][
                    "next_gap"
                ]["expected_object_type"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
