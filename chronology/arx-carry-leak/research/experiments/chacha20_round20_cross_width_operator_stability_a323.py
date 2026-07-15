#!/usr/bin/env python3
"""A323: audit target-blind cross-width stability of the eight A321 operators."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import statistics
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_cross_width_operator_stability_a323_design_v1.json"
RESULT = RESULTS / "chacha20_round20_cross_width_operator_stability_a323_v1.json"
CAUSAL = RESULTS / "chacha20_round20_cross_width_operator_stability_a323_v1.causal"
REPORT = RESULTS / "chacha20_round20_cross_width_operator_stability_a323_v1.md"

A321_RUNNER = RESEARCH / "experiments/chacha20_round20_holdout_selected_w45_operator_a321.py"
A323_TEST = ROOT / "tests/test_chacha20_round20_cross_width_operator_stability_a323.py"
A323_REPRO = ROOT / "scripts/reproduce_chacha20_round20_cross_width_operator_stability_a323.sh"

ATTEMPT_ID = "A323"
DESIGN_SHA256 = "459826534bdc106796df6cb56e8ef8d6421c347bf2b944d7fd59ef9ae1f3890f"
A321_DESIGN_SHA256 = "3db5966ca254f8a5342399445d992db672fd0e9e5d40bc8ad401b0ae8cbd1e92"
A321_RUNNER_SHA256 = "61fd8e3c9635eab8cb166d8c9008df08b0cc067764f9c64da5042fa18726ef52"
CELLS = 1 << 12


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A323 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A321 = load_module(A321_RUNNER, "a323_a321_common")
file_sha256 = A321.file_sha256
canonical_sha256 = A321.canonical_sha256
atomic_json = A321.atomic_json
atomic_bytes = A321.atomic_bytes
relative = A321.relative
path_from_ref = A321.path_from_ref
anchor = A321.anchor
DOTCAUSAL_SRC = A321.DOTCAUSAL_SRC


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A323 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    analysis = design.get("analysis_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-cross-width-operator-stability-a323-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_and_executed_while_A313_recovery_is_running_before_any_A313_or_A314_result_candidate_or_prefix_rank_exists"
        or analysis.get("candidate_execution") is not False
        or analysis.get("operator_refit") is not False
        or analysis.get("target_label_use") != 0
        or boundary.get("A313_result_available") is not False
        or boundary.get("A313_candidate_available") is not False
        or boundary.get("A314_result_available") is not False
        or boundary.get("A314_candidate_available") is not False
        or boundary.get("target_labels_used") != 0
    ):
        raise RuntimeError("A323 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(value),
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def rank_vector(order: Sequence[int]) -> list[int]:
    exact = A321._exact_order(order, "A323 rank vector")  # noqa: SLF001
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact, 1):
        ranks[cell] = rank
    return ranks


def spearman(left: Sequence[int], right: Sequence[int]) -> float:
    x = rank_vector(left)
    y = rank_vector(right)
    mean = (CELLS + 1) / 2.0
    numerator = sum(
        (a - mean) * (b - mean) for a, b in zip(x, y, strict=True)
    )
    denominator = math.sqrt(
        sum((a - mean) ** 2 for a in x) * sum((b - mean) ** 2 for b in y)
    )
    return numerator / denominator


def nearest_index_quantile(values: Sequence[int], probability: float) -> dict[str, Any]:
    ordered = sorted(int(value) for value in values)
    index = round((len(ordered) - 1) * probability)
    return {"probability": probability, "zero_based_index": index, "value": ordered[index]}


def analyze_operators() -> dict[str, Any]:
    load_design()
    pairs = A321.candidate_pairs()
    w44_ranks = {row["name"]: rank_vector(row["W44_order"]) for row in pairs}
    correlations = {
        row["name"]: spearman(row["W44_order"], row["W45_order"]) for row in pairs
    }
    most_stable_index = max(
        range(len(pairs)), key=lambda index: (correlations[pairs[index]["name"]], -index)
    )
    winner_counts = {row["name"]: 0 for row in pairs}
    best_ranks: list[int] = []
    for cell in range(CELLS):
        ranks = [w44_ranks[row["name"]][cell] for row in pairs]
        winner = min(range(len(pairs)), key=lambda index: (ranks[index], index))
        winner_counts[pairs[winner]["name"]] += 1
        best_ranks.append(ranks[winner])
    quantiles = [
        nearest_index_quantile(best_ranks, probability)
        for probability in (0.25, 0.5, 0.75, 0.9)
    ]
    return {
        "operator_sequence": [row["name"] for row in pairs],
        "paired_order_hashes": {
            row["name"]: {
                "W44_uint16be_sha256": row["W44_order_uint16be_sha256"],
                "W45_uint16be_sha256": row["W45_order_uint16be_sha256"],
            }
            for row in pairs
        },
        "cross_width_spearman": correlations,
        "most_stable_operator": pairs[most_stable_index]["name"],
        "most_stable_operator_index": most_stable_index,
        "most_stable_spearman": correlations[pairs[most_stable_index]["name"]],
        "best_of_eight_W44_oracle_coverage": {
            "interpretation": "target_blind_family_complementarity_only_not_an_executable_single_order",
            "winner_cell_counts": winner_counts,
            "minimum_rank": min(best_ranks),
            "maximum_rank": max(best_ranks),
            "mean_rank": statistics.mean(best_ranks),
            "quantile_method": "nearest_index_round_of_n_minus_one_times_probability",
            "quantiles": quantiles,
            "covered_cells": len(best_ranks),
        },
        "target_labels_used": 0,
        "candidate_execution": False,
        "operator_refits": 0,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A323:target_blind_cross_width_operator_stability_map"
    writer = CausalWriter(api_id="a323xw")
    writer._rules = []
    writer.add_rule(
        name="paired_complete_orders_to_cross_width_stability",
        description="Exact W44 and W45 cell-rank vectors are compared by Spearman correlation before either recovery target is revealed.",
        pattern=["eight_hash_pinned_W44_orders", "eight_corresponding_hash_pinned_W45_orders"],
        conclusion="A323_cross_width_stability_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_W44_family_to_complementarity_map",
        description="Every W44 cell is assigned its smallest rank and frozen-index winning operator across the complete precommitted family.",
        pattern=["eight_hash_pinned_W44_orders", "frozen_A321_candidate_index"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A315_A317_A319:complete_target_blind_W44_operator_family",
        mechanism="paired_complete_rank_vector_Spearman_against_A316_A318_A320",
        outcome="A323:cross_width_stability_panel",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["analysis"]["cross_width_spearman"], sort_keys=True),
        evidence=json.dumps(
            {
                "most_stable_operator": payload["analysis"]["most_stable_operator"],
                "most_stable_spearman": payload["analysis"]["most_stable_spearman"],
            },
            sort_keys=True,
        ),
        domain="AI-native cross-width operator stability",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A323:cross_width_stability_panel",
        mechanism="complete_best_of_eight_W44_rank_and_winner_count_audit",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(
            payload["analysis"]["best_of_eight_W44_oracle_coverage"], sort_keys=True
        ),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="target-blind operator-family complementarity",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A315_A317_A319:complete_target_blind_W44_operator_family",
        mechanism="materialized_stability_and_complementarity_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A323_cross_width_stability_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A323 target-blind cross-width stability map",
        entities=[
            "A315_A317_A319:complete_target_blind_W44_operator_family",
            "A323:cross_width_stability_panel",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="A322_holdout_selection_versus_structural_stability_comparison",
        confidence=1.0,
        suggested_queries=[
            "On the independently confirmed W45 target, does A321 holdout-rank selection or A323's target-blind cross-width stability prior identify the earlier frozen operator?"
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a323xw"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A323 authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(CAUSAL),
        "sha256": file_sha256(CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def materialize() -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A323 artifacts already exist")
    if A321.A313.RESULT.exists() or A321.A314_RESULT.exists():
        raise RuntimeError("A323 must execute before A313 and A314 results exist")
    design = load_design()
    analysis = analyze_operators()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-cross-width-operator-stability-a323-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "TARGET_BLIND_COMPLETE_W44_W45_OPERATOR_STABILITY_AND_COMPLEMENTARITY_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "analysis": analysis,
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "A321_design": {
                "path": relative(A321.DESIGN),
                "sha256": A321_DESIGN_SHA256,
            },
            "A321_runner": {
                "path": relative(A321_RUNNER),
                "sha256": A321_RUNNER_SHA256,
            },
            "runner": {"path": relative(Path(__file__)), "sha256": file_sha256(Path(__file__))},
            "test": {"path": relative(A323_TEST), "sha256": file_sha256(A323_TEST)},
            "reproducer": {"path": relative(A323_REPRO), "sha256": file_sha256(A323_REPRO)},
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "analysis": analysis,
            "information_boundary": payload["information_boundary"],
            "source_order_sha256": analysis["paired_order_hashes"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    coverage = analysis["best_of_eight_W44_oracle_coverage"]
    quantiles = {row["probability"]: row["value"] for row in coverage["quantiles"]}
    atomic_bytes(
        REPORT,
        (
            "# A323 — target-blind cross-width operator stability\n\n"
            f"- Most stable W44→W45 operator: **{analysis['most_stable_operator']}**\n"
            f"- Complete-rank Spearman: **{analysis['most_stable_spearman']:.6f}**\n"
            f"- Best-of-8 W44 median rank: **{quantiles[0.5]} / 4,096**\n"
            f"- Best-of-8 W44 mean rank: **{coverage['mean_rank']:.6f} / 4,096**\n"
            f"- Best-of-8 W44 maximum rank: **{coverage['maximum_rank']} / 4,096**\n"
            "- Complete cells audited: **4,096**\n"
            "- Target labels and candidate executions: **zero**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    response = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "A313_result_complete": A321.A313.RESULT.exists(),
        "A314_result_complete": A321.A314_RESULT.exists(),
        "result_complete": RESULT.exists(),
    }
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        response["result_sha256"] = file_sha256(RESULT)
        response["analysis"] = value["analysis"]
        response["causal"] = value["causal"]
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--materialize", action="store_true")
    action.add_argument("--analyze", action="store_true")
    args = parser.parse_args()
    payload = materialize() if args.materialize else analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
