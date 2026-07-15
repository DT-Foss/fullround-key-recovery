#!/usr/bin/env python3
"""A321: let independent W44 holdout rank select an unchanged W45 order."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_holdout_selected_w45_operator_a321_design_v1.json"
COMMITMENT = CONFIGS / "chacha20_round20_holdout_selected_w45_operator_a321_commitment_v1.json"
ORDER = RESULTS / "chacha20_round20_holdout_selected_w45_operator_a321_order_v1.json"
CAUSAL = RESULTS / "chacha20_round20_holdout_selected_w45_operator_a321_order_v1.causal"
REPORT = RESULTS / "chacha20_round20_holdout_selected_w45_operator_a321_order_v1.md"

A313_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_width_conditioned_fine_portfolio_a313.py"
A315_ORDER = RESULTS / "chacha20_round20_w44_online_multicenter_counterfactual_a315_order_v1.json"
A316_ORDER = RESULTS / "chacha20_round20_w45_online_multicenter_counterfactual_a316_order_v1.json"
A317_ORDER = RESULTS / "chacha20_round20_w44_multiview_operator_atlas_a317_order_v1.json"
A318_ORDER = RESULTS / "chacha20_round20_w45_multiview_operator_atlas_a318_order_v1.json"
A319_ORDER = RESULTS / "chacha20_round20_w44_covariance_whitened_atlas_a319_order_v1.json"
A320_ORDER = RESULTS / "chacha20_round20_w45_covariance_whitened_atlas_a320_order_v1.json"
A314_ORDER = RESULTS / "chacha20_round20_w45_fine_band_recovery_a314_order_v1.json"
A314_RESULT = RESULTS / "chacha20_round20_w45_fine_band_recovery_a314_v1.json"
A321_TEST = ROOT / "tests/test_chacha20_round20_holdout_selected_w45_operator_a321.py"
A321_REPRO = ROOT / "scripts/reproduce_chacha20_round20_holdout_selected_w45_operator_a321.sh"

ATTEMPT_ID = "A321"
DESIGN_SHA256 = "3db5966ca254f8a5342399445d992db672fd0e9e5d40bc8ad401b0ae8cbd1e92"
CELLS = 1 << 12
CANDIDATE_NAMES = (
    "online_four_center_band",
    "online_weighted_dovetail_2_to_1",
    "raw_nearest_prototype_L1",
    "raw_nearest_prototype_Linf",
    "raw_nearest_prototype_squared_L2",
    "whitened_shrinkage_mahalanobis",
    "whitened_diagonal_variance_L2",
    "whitened_pairwise_median_scaled_L1",
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A321 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A313 = load_module(A313_RUNNER, "a321_a313_common")
file_sha256 = A313.file_sha256
canonical_sha256 = A313.canonical_sha256
sha256 = A313.sha256
atomic_json = A313.atomic_json
atomic_bytes = A313.atomic_bytes
relative = A313.relative
path_from_ref = A313.path_from_ref
anchor = A313.anchor
DOTCAUSAL_SRC = A313.DOTCAUSAL_SRC


def _exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A321 {label} is not an exact 4,096-cell cover")
    return order


def _order_sha(values: Sequence[int]) -> str:
    return sha256(b"".join(int(value).to_bytes(2, "big") for value in values))


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A321 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    selection = design.get("selection_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-holdout-selected-w45-operator-a321-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A313_recovery_is_running_after_A314_target_blind_order_but_before_any_A313_or_A314_result_candidate_or_prefix_rank_exists"
        or tuple(selection.get("candidate_sequence_and_tie_break", []))
        != CANDIDATE_NAMES
        or selection.get("A314_target_label_or_candidate_used_for_selection") is not False
        or selection.get("candidate_execution_by_A321") is not False
        or boundary.get("A313_result_available_at_design_freeze") is not False
        or boundary.get("A313_candidate_available_at_design_freeze") is not False
        or boundary.get("A314_result_available_at_design_freeze") is not False
        or boundary.get("A314_candidate_available_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A314") != 0
        or boundary.get("manual_operator_choice_after_A313_reveal") is not False
    ):
        raise RuntimeError("A321 frozen design semantics differ")
    anchors = design["source_anchors"]
    for key, value in anchors.items():
        if key.endswith("_path"):
            anchor(path_from_ref(value), anchors[key.removesuffix("_path") + "_sha256"])
    return design


def candidate_pairs() -> list[dict[str, Any]]:
    design = load_design()
    a315 = json.loads(A315_ORDER.read_bytes())
    a316 = json.loads(A316_ORDER.read_bytes())
    a317 = json.loads(A317_ORDER.read_bytes())
    a318 = json.loads(A318_ORDER.read_bytes())
    a319 = json.loads(A319_ORDER.read_bytes())
    a320 = json.loads(A320_ORDER.read_bytes())
    if any(
        value.get("public_challenge_sha256") != a315["public_challenge_sha256"]
        for value in (a317, a319)
    ):
        raise RuntimeError("A321 W44 candidate orders do not share A313 challenge")
    if any(
        value.get("public_challenge_sha256") != a316["public_challenge_sha256"]
        for value in (a318, a320)
    ):
        raise RuntimeError("A321 W45 deployment orders do not share A314 challenge")
    if a315["public_challenge_sha256"] == a316["public_challenge_sha256"]:
        raise RuntimeError("A321 calibration and deployment challenges are not disjoint")
    raw_rows = [
        (
            CANDIDATE_NAMES[0],
            "online_multicenter",
            a315["component_orders"]["four_center_nearest_rank_band"],
            a316["component_orders"]["four_center_nearest_rank_band"],
            a315["component_order_sha256"]["four_center_band_uint16be_sha256"],
            a316["component_order_sha256"]["four_center_band_uint16be_sha256"],
        ),
        (
            CANDIDATE_NAMES[1],
            "online_multicenter",
            a315["weighted_dovetail_2_to_1"],
            a316["weighted_dovetail_2_to_1"],
            a315["component_order_sha256"]["weighted_dovetail_2_to_1_uint16be_sha256"],
            a316["component_order_sha256"]["weighted_dovetail_2_to_1_uint16be_sha256"],
        ),
        (
            CANDIDATE_NAMES[2],
            "raw_multiview",
            a317["atlas_orders"]["nearest_prototype_L1"],
            a318["atlas_orders"]["nearest_prototype_L1"],
            a317["order_uint16be_sha256"]["nearest_prototype_L1"],
            a318["order_uint16be_sha256"]["nearest_prototype_L1"],
        ),
        (
            CANDIDATE_NAMES[3],
            "raw_multiview",
            a317["atlas_orders"]["nearest_prototype_Linf"],
            a318["atlas_orders"]["nearest_prototype_Linf"],
            a317["order_uint16be_sha256"]["nearest_prototype_Linf"],
            a318["order_uint16be_sha256"]["nearest_prototype_Linf"],
        ),
        (
            CANDIDATE_NAMES[4],
            "raw_multiview",
            a317["atlas_orders"]["nearest_prototype_squared_L2"],
            a318["atlas_orders"]["nearest_prototype_squared_L2"],
            a317["order_uint16be_sha256"]["nearest_prototype_squared_L2"],
            a318["order_uint16be_sha256"]["nearest_prototype_squared_L2"],
        ),
        (
            CANDIDATE_NAMES[5],
            "covariance_whitened",
            a319["whitened_orders"]["nearest_exact_shrinkage_mahalanobis"],
            a320["whitened_orders"]["nearest_exact_shrinkage_mahalanobis"],
            a319["order_uint16be_sha256"]["nearest_exact_shrinkage_mahalanobis"],
            a320["order_uint16be_sha256"]["nearest_exact_shrinkage_mahalanobis"],
        ),
        (
            CANDIDATE_NAMES[6],
            "covariance_whitened",
            a319["whitened_orders"]["nearest_exact_diagonal_variance_L2"],
            a320["whitened_orders"]["nearest_exact_diagonal_variance_L2"],
            a319["order_uint16be_sha256"]["nearest_exact_diagonal_variance_L2"],
            a320["order_uint16be_sha256"]["nearest_exact_diagonal_variance_L2"],
        ),
        (
            CANDIDATE_NAMES[7],
            "covariance_whitened",
            a319["whitened_orders"]["nearest_exact_pairwise_median_scaled_L1"],
            a320["whitened_orders"]["nearest_exact_pairwise_median_scaled_L1"],
            a319["order_uint16be_sha256"]["nearest_exact_pairwise_median_scaled_L1"],
            a320["order_uint16be_sha256"]["nearest_exact_pairwise_median_scaled_L1"],
        ),
    ]
    rows: list[dict[str, Any]] = []
    for index, (name, family, w44_raw, w45_raw, expected_w44, expected_w45) in enumerate(
        raw_rows
    ):
        w44 = _exact_order(w44_raw, f"{name} W44")
        w45 = _exact_order(w45_raw, f"{name} W45")
        if _order_sha(w44) != expected_w44 or _order_sha(w45) != expected_w45:
            raise RuntimeError(f"A321 {name} order hash differs")
        rows.append(
            {
                "candidate_index": index,
                "name": name,
                "family": family,
                "W44_order": w44,
                "W45_order": w45,
                "W44_order_uint16be_sha256": expected_w44,
                "W45_order_uint16be_sha256": expected_w45,
            }
        )
    if [row["name"] for row in rows] != list(CANDIDATE_NAMES):
        raise RuntimeError("A321 candidate sequence differs")
    if design["selection_contract"]["candidate_sequence_and_tie_break"] != list(
        CANDIDATE_NAMES
    ):
        raise RuntimeError("A321 candidate tie-break differs")
    return rows


def selection_for_prefix(prefix: int) -> dict[str, Any]:
    if not 0 <= prefix < CELLS:
        raise ValueError("A321 prefix is outside the 12-bit cell domain")
    pairs = candidate_pairs()
    ranks = [row["W44_order"].index(prefix) + 1 for row in pairs]
    selected_index = min(range(len(pairs)), key=lambda index: (ranks[index], index))
    selected = pairs[selected_index]
    return {
        "calibration_prefix12": prefix,
        "calibration_prefix12_hex": f"{prefix:03x}",
        "candidate_ranks_one_based": {
            row["name"]: ranks[index] for index, row in enumerate(pairs)
        },
        "selected_candidate_index": selected_index,
        "selected_operator": selected["name"],
        "selected_family": selected["family"],
        "selected_calibration_rank_one_based": ranks[selected_index],
        "selected_W44_order_uint16be_sha256": selected[
            "W44_order_uint16be_sha256"
        ],
        "selected_W45_order_uint16be_sha256": selected[
            "W45_order_uint16be_sha256"
        ],
        "selected_W45_order": selected["W45_order"],
        "selection_rule": "minimum_A313_rank_then_frozen_candidate_index",
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A321:frozen_holdout_selected_W45_execution_order"
    writer = CausalWriter(api_id="a321sel")
    writer._rules = []
    writer.add_rule(
        name="independent_W44_holdout_to_frozen_operator_selection",
        description="The independently confirmed A313 prefix is ranked in eight pre-reveal W44 orders; the minimum rank with frozen index tie-break selects one operator.",
        pattern=["A313_independently_confirmed_W44_prefix", "eight_pre_reveal_W44_candidate_orders"],
        conclusion="A321_selected_operator_identity",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selected_operator_identity_to_unchanged_W45_order",
        description="The exact corresponding A316, A318 or A320 W45 order is copied without refit, merge or access to the A314 candidate.",
        pattern=["A321_selected_operator_identity", "precommitted_corresponding_W45_order"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A313:independently_confirmed_W44_prefix",
        mechanism="minimum_rank_across_eight_precommitted_operators_with_frozen_tie_break",
        outcome="A321:selected_operator_identity",
        confidence=1.0,
        source=payload["A313_result_sha256"],
        quantification=json.dumps(payload["selection"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="AI-native holdout operator selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A321:selected_operator_identity",
        mechanism="exact_cross_width_order_copy_without_W45_refit",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["selected_order_commitment"], sort_keys=True),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="prospective ChaCha20-R20 W45 search-order deployment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A313:independently_confirmed_W44_prefix",
        mechanism="materialized_holdout_selection_and_cross_width_deployment_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A321_holdout_selection_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A321 holdout-selected W45 execution order",
        entities=[
            "A313:independently_confirmed_W44_prefix",
            "A321:selected_operator_identity",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="A322_complete_W45_grouped_execution_and_dual_confirmation",
        confidence=1.0,
        suggested_queries=[
            "Does the operator selected solely by the independent W44 holdout recover the unseen W45 target in a strict subset of its complete residual domain?"
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
        reader.api_id != "a321sel"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A321 authentic Causal reopen gate failed")
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


def materialize(*, expected_a313_result_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (ORDER, COMMITMENT, CAUSAL, REPORT)):
        raise FileExistsError("A321 artifacts already exist")
    if A314_RESULT.exists():
        raise RuntimeError("A321 must select before any A314 result exists")
    design = load_design()
    if file_sha256(A313.RESULT) != expected_a313_result_sha256:
        raise RuntimeError("A321 A313 result hash differs")
    a313 = json.loads(A313.RESULT.read_bytes())
    if (
        a313.get("confirmation", {}).get("all_blocks_match") is not True
        or a313.get("discovery", {}).get("matched_control_candidates") != 0
        or a313.get("public_challenge_sha256")
        != json.loads(A315_ORDER.read_bytes())["public_challenge_sha256"]
    ):
        raise RuntimeError("A321 requires independently confirmed A313 holdout")
    selection = selection_for_prefix(int(a313["discovery"]["prefix12"]))
    selected_order = selection.pop("selected_W45_order")
    selected_commitment = {
        "selected_operator": selection["selected_operator"],
        "selected_family": selection["selected_family"],
        "selected_W45_order_uint16be_sha256": selection[
            "selected_W45_order_uint16be_sha256"
        ],
        "selected_W45_prefix_cells": len(selected_order),
        "deployment_target_public_challenge_sha256": json.loads(A314_ORDER.read_bytes())[
            "public_challenge_sha256"
        ],
        "parameter_refit_or_manual_override": False,
    }
    information_boundary = {
        **design["information_boundary"],
        "A313_result_used_only_as_independent_calibration_label": True,
        "A314_result_available_at_materialization": False,
        "A314_candidate_or_prefix_rank_available_at_materialization": False,
        "A314_filter_outcome_available_at_materialization": False,
        "target_labels_used_from_A314": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-holdout-selected-w45-operator-a321-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "INDEPENDENT_W44_HOLDOUT_SELECTED_EXACT_W45_ORDER_BEFORE_A314_RECOVERY",
        "design_sha256": DESIGN_SHA256,
        "A313_result_sha256": expected_a313_result_sha256,
        "A314_order_sha256": design["source_anchors"]["A314_order_sha256"],
        "selection": selection,
        "selected_order_commitment": selected_commitment,
        "selected_W45_order": selected_order,
        "information_boundary": information_boundary,
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "A313_result_sha256": expected_a313_result_sha256,
            "A314_order_sha256": payload["A314_order_sha256"],
            "selection": selection,
            "selected_order_commitment": selected_commitment,
            "information_boundary": information_boundary,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    order_sha = file_sha256(ORDER)
    commitment = {
        "schema": "chacha20-round20-holdout-selected-w45-operator-a321-commitment-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_after_independent_A313_confirmation_before_any_A314_recovery_result",
        "design_sha256": DESIGN_SHA256,
        "order_sha256": order_sha,
        "A313_result_sha256": expected_a313_result_sha256,
        "A314_order_sha256": payload["A314_order_sha256"],
        "selection": selection,
        "selected_order_commitment": selected_commitment,
        "A314_result_available_at_commitment": False,
        "A314_candidate_or_rank_available_at_commitment": False,
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "order": {"path": relative(ORDER), "sha256": order_sha},
            "causal": {"path": relative(CAUSAL), "sha256": payload["causal"]["sha256"]},
            "A313_result": {
                "path": relative(A313.RESULT),
                "sha256": expected_a313_result_sha256,
            },
            "A314_order": {
                "path": relative(A314_ORDER),
                "sha256": payload["A314_order_sha256"],
            },
            "runner": {"path": relative(Path(__file__)), "sha256": file_sha256(Path(__file__))},
            "test": {"path": relative(A321_TEST), "sha256": file_sha256(A321_TEST)},
            "reproducer": {"path": relative(A321_REPRO), "sha256": file_sha256(A321_REPRO)},
        },
    }
    atomic_json(COMMITMENT, commitment)
    atomic_bytes(
        REPORT,
        (
            "# A321 — independent-holdout-selected W45 operator\n\n"
            f"- Selected operator: **{selection['selected_operator']}**\n"
            f"- A313 calibration rank: **{selection['selected_calibration_rank_one_based']} / 4,096**\n"
            f"- Selected W45 order SHA-256: **{selection['selected_W45_order_uint16be_sha256']}**\n"
            "- A314 target labels used: **zero**\n"
            "- Manual override or W45 refit: **none**\n"
            "- Next execution object: **A322 complete grouped W45 recovery**\n"
        ).encode(),
    )
    return {
        "order": relative(ORDER),
        "order_sha256": order_sha,
        "commitment": relative(COMMITMENT),
        "commitment_sha256": file_sha256(COMMITMENT),
        "selection": selection,
        "selected_order_commitment": selected_commitment,
        "causal": payload["causal"],
    }


def load_frozen(expected_commitment_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(COMMITMENT) != expected_commitment_sha256:
        raise RuntimeError("A321 commitment hash differs")
    commitment = json.loads(COMMITMENT.read_bytes())
    if (
        commitment.get("schema")
        != "chacha20-round20-holdout-selected-w45-operator-a321-commitment-v1"
        or commitment.get("commitment_state")
        != "frozen_after_independent_A313_confirmation_before_any_A314_recovery_result"
        or commitment.get("A314_candidate_or_rank_available_at_commitment") is not False
    ):
        raise RuntimeError("A321 commitment semantics differ")
    for row in commitment["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    order = json.loads(ORDER.read_bytes())
    a313 = json.loads(A313.RESULT.read_bytes())
    reconstructed = selection_for_prefix(int(a313["discovery"]["prefix12"]))
    selected_order = reconstructed.pop("selected_W45_order")
    if (
        order.get("selection") != reconstructed
        or order.get("selected_W45_order") != selected_order
        or _order_sha(selected_order)
        != order["selected_order_commitment"]["selected_W45_order_uint16be_sha256"]
    ):
        raise RuntimeError("A321 exact selection reconstruction differs")
    return commitment, order


def analyze() -> dict[str, Any]:
    pairs = candidate_pairs()
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "candidate_sequence": [row["name"] for row in pairs],
        "candidate_W44_order_sha256": {
            row["name"]: row["W44_order_uint16be_sha256"] for row in pairs
        },
        "candidate_W45_order_sha256": {
            row["name"]: row["W45_order_uint16be_sha256"] for row in pairs
        },
        "A313_result_complete": A313.RESULT.exists(),
        "A314_result_complete": A314_RESULT.exists(),
        "selection_materialized": ORDER.exists(),
        "commitment_frozen": COMMITMENT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--materialize", action="store_true")
    parser.add_argument("--expected-a313-result-sha256")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    else:
        if not args.expected_a313_result_sha256:
            parser.error("--materialize requires --expected-a313-result-sha256")
        payload = materialize(expected_a313_result_sha256=args.expected_a313_result_sha256)
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
