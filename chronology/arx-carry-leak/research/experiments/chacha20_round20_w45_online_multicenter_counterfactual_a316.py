#!/usr/bin/env python3
"""A316: precommit A315's online rank memory on the unseen A314 W45 target."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w45_online_multicenter_counterfactual_a316_design_v1.json"
COMMITMENT = CONFIGS / "chacha20_round20_w45_online_multicenter_counterfactual_a316_commitment_v1.json"
ORDER = RESULTS / "chacha20_round20_w45_online_multicenter_counterfactual_a316_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w45_online_multicenter_counterfactual_a316_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w45_online_multicenter_counterfactual_a316_v1.causal"
REPORT = RESULTS / "chacha20_round20_w45_online_multicenter_counterfactual_a316_v1.md"

A314_RUNNER = RESEARCH / "experiments/chacha20_round20_w45_fine_band_recovery_a314.py"
A315_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_online_multicenter_counterfactual_a315.py"
A316_TEST = ROOT / "tests/test_chacha20_round20_w45_online_multicenter_counterfactual_a316.py"
A316_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w45_online_multicenter_counterfactual_a316.sh"

ATTEMPT_ID = "A316"
DESIGN_SHA256 = "e7a3b185c12f2767946f256298839798be366dc69e3017c9778c7cb409c8c8ba"
A314_RUNNER_SHA256 = "f85ed4e7ae7acbd71f06aeca54609e278a1d26e16f9fbddf94e154a3b5f005f0"
A314_PROTOCOL_SHA256 = "17877a15624f7ab6fec1333c57260fa447d71d1112b9df5aa8219f8403968574"
A314_PREFLIGHT_SHA256 = "cfb5bacd6e6e17479260d8a2cacd2f9808afc632d82e31f80e8dc6ed2d4159a4"
A315_COMMITMENT_SHA256 = "c6fae402a992da304c21fa17fef48360a166bb47a9e2bc223fa608b1649cdc4c"
A315_ORDER_SHA256 = "7f3765084afcf9015a60b1561c4a3d6dc327eee7ee4ef6395794599a499ea3ff"
CENTERS = [2114, 2366, 2605, 3829]
CELLS = 1 << 12


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A316 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A314 = load_module(A314_RUNNER, "a316_a314_common")
A315 = load_module(A315_RUNNER, "a316_a315_common")
file_sha256 = A314.file_sha256
canonical_sha256 = A314.canonical_sha256
sha256 = A314.sha256
atomic_json = A314.atomic_json
atomic_bytes = A314.atomic_bytes
relative = A314.relative
path_from_ref = A314.path_from_ref
anchor = A314.anchor
DOTCAUSAL_SRC = A314.DOTCAUSAL_SRC


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A316 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    branch = design.get("conditional_branch_contract", {})
    operator = design.get("operator_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-w45-online-multicenter-counterfactual-a316-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A314_measurement_is_running_before_any_A314_order_model_candidate_or_prefix_rank_exists"
        or branch.get("branch_selected_only_by_A314_public_measurement_outcome") is not True
        or branch.get("branch_logic_frozen_before_A314_order_exists") is not True
        or operator.get("confirmed_fine_rank_centers_one_based") != CENTERS
        or operator.get("selection_or_refit_after_A314_reveal") is not False
        or operator.get("candidate_execution_by_A316") is not False
        or boundary.get("A314_order_available_at_design_freeze") is not False
        or boundary.get("A314_result_available_at_design_freeze") is not False
        or boundary.get("A314_candidate_available_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A314") != 0
    ):
        raise RuntimeError("A316 frozen design semantics differ")
    for key, expected in design["source_anchors"].items():
        if key.endswith("_path"):
            sha_key = key.removesuffix("_path") + "_sha256"
            anchor(path_from_ref(expected), design["source_anchors"][sha_key])
    return design


def derive_model_free_orders(order_value: Mapping[str, Any]) -> dict[str, Any]:
    components = order_value.get("component_orders")
    if not isinstance(components, Mapping):
        raise ValueError("A316 requires the A314 model-free component orders")
    fine = A315._exact_order(components["fine_selected_channel"], "A314 fine")  # noqa: SLF001
    baseline = A315._exact_order(  # noqa: SLF001
        components["coarse_numeric_baseline"], "A314 baseline"
    )
    original = A315._exact_order(order_value["portfolio_order"], "A314 portfolio")  # noqa: SLF001
    band = A315.multicenter_band(fine=fine, centers=CENTERS)
    weighted = A315.weighted_dovetail(band=band, baseline=baseline)
    guarantee = A315.guarantee(portfolio=weighted, band=band, baseline=baseline)
    hashes = {
        "four_center_band_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in band)
        ),
        "weighted_dovetail_2_to_1_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in weighted)
        ),
        "A314_baseline_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in baseline)
        ),
        "A314_portfolio_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in original)
        ),
    }
    return {
        "fine": fine,
        "band": band,
        "baseline": baseline,
        "weighted": weighted,
        "A314_portfolio": original,
        "guarantee": guarantee,
        "hashes": hashes,
    }


def authentic_order_readback(order_value: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(A314.ORDER_CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a314w45o"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or order_value.get("causal", {}).get("sha256") != file_sha256(A314.ORDER_CAUSAL)
    ):
        raise RuntimeError("A316 authentic A314 order Causal readback differs")
    return {
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "terminal_chain": all_rows[-1],
        "next_gap": reader._gaps[0],
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
    }


def load_a314_order(expected_a314_order_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    _protocol, _preflight, order_value = A314.load_order(
        A314_PROTOCOL_SHA256,
        A314_PREFLIGHT_SHA256,
        expected_a314_order_sha256,
    )
    return order_value, authentic_order_readback(order_value)


def materialize(*, expected_a314_order_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (ORDER, COMMITMENT, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A316 artifacts already exist")
    if A314.RESULT.exists() or A314.CAUSAL.exists():
        raise RuntimeError("A316 must freeze before any A314 result exists")
    design = load_design()
    order_value, readback = load_a314_order(expected_a314_order_sha256)
    direct = order_value.get("direct_symbolic_winner") is not None
    derived = None if direct else derive_model_free_orders(order_value)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w45-online-multicenter-counterfactual-a316-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "A316_DIRECT_A314_SYMBOLIC_BRANCH_RETAINED_WITHOUT_DUPLICATE_SEARCH"
            if direct
            else "A316_TARGET_BLIND_ONLINE_MULTICENTER_ORDER_FROZEN_BEFORE_A314_RECOVERY"
        ),
        "execution_branch": (
            "A314_direct_symbolic_model_no_rank_counterfactual_required"
            if direct
            else "A314_complete_model_free_field_to_online_multicenter_rank_panel"
        ),
        "design_sha256": DESIGN_SHA256,
        "A314_order_sha256": expected_a314_order_sha256,
        "public_challenge_sha256": order_value["public_challenge_sha256"],
        "confirmed_fine_rank_centers_one_based": CENTERS,
        "authentic_A314_order_causal_readback": readback,
        "direct_symbolic_winner": order_value.get("direct_symbolic_winner"),
        "direct_symbolic_confirmation": order_value.get("confirmation"),
        "component_orders": (
            None
            if direct
            else {
                "four_center_nearest_rank_band": derived["band"],
                "A314_coarse_numeric_baseline": derived["baseline"],
                "A314_three_arm_portfolio": derived["A314_portfolio"],
            }
        ),
        "weighted_dovetail_2_to_1": None if direct else derived["weighted"],
        "component_order_sha256": None if direct else derived["hashes"],
        "weighted_portfolio_guarantee": None if direct else derived["guarantee"],
        "information_boundary": {
            **design["information_boundary"],
            "A314_outcome_used_only_to_select_predeclared_conditional_branch": True,
            "A314_result_available_at_materialization": False,
            "A314_candidate_or_prefix_rank_available_at_materialization": False,
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "A314_order_sha256": expected_a314_order_sha256,
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "execution_branch": payload["execution_branch"],
            "component_order_sha256": payload["component_order_sha256"],
            "weighted_portfolio_guarantee": payload["weighted_portfolio_guarantee"],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(ORDER, payload)
    order_sha = file_sha256(ORDER)
    commitment = {
        "schema": "chacha20-round20-w45-online-multicenter-counterfactual-a316-commitment-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_after_target_blind_A314_measurement_before_A314_recovery",
        "design_sha256": DESIGN_SHA256,
        "order_sha256": order_sha,
        "A314_order_sha256": expected_a314_order_sha256,
        "public_challenge_sha256": payload["public_challenge_sha256"],
        "execution_branch": payload["execution_branch"],
        "component_order_sha256": payload["component_order_sha256"],
        "weighted_portfolio_guarantee": payload["weighted_portfolio_guarantee"],
        "A314_result_available_at_commitment": False,
        "candidate_or_rank_available_at_commitment": False,
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "order": {"path": relative(ORDER), "sha256": order_sha},
            "A314_protocol": {"path": relative(A314.PROTOCOL), "sha256": A314_PROTOCOL_SHA256},
            "A314_preflight": {"path": relative(A314.PREFLIGHT), "sha256": A314_PREFLIGHT_SHA256},
            "A314_order": {"path": relative(A314.ORDER), "sha256": expected_a314_order_sha256},
            "A314_order_causal": {
                "path": relative(A314.ORDER_CAUSAL),
                "sha256": order_value["causal"]["sha256"],
            },
            "A315_commitment": {
                "path": relative(A315.COMMITMENT),
                "sha256": A315_COMMITMENT_SHA256,
            },
            "A315_order": {"path": relative(A315.ORDER), "sha256": A315_ORDER_SHA256},
            "runner": {"path": relative(Path(__file__)), "sha256": file_sha256(Path(__file__))},
            "test": {"path": relative(A316_TEST), "sha256": file_sha256(A316_TEST)},
            "reproducer": {"path": relative(A316_REPRO), "sha256": file_sha256(A316_REPRO)},
        },
    }
    atomic_json(COMMITMENT, commitment)
    return {
        "order": relative(ORDER),
        "order_sha256": order_sha,
        "commitment": relative(COMMITMENT),
        "commitment_sha256": file_sha256(COMMITMENT),
        "execution_branch": payload["execution_branch"],
        "component_order_sha256": payload["component_order_sha256"],
        "weighted_portfolio_guarantee": payload["weighted_portfolio_guarantee"],
    }


def load_frozen(expected_commitment_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(COMMITMENT) != expected_commitment_sha256:
        raise RuntimeError("A316 commitment hash differs")
    commitment = json.loads(COMMITMENT.read_bytes())
    if (
        commitment.get("schema")
        != "chacha20-round20-w45-online-multicenter-counterfactual-a316-commitment-v1"
        or commitment.get("commitment_state")
        != "frozen_after_target_blind_A314_measurement_before_A314_recovery"
        or commitment.get("candidate_or_rank_available_at_commitment") is not False
    ):
        raise RuntimeError("A316 commitment semantics differ")
    for row in commitment["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    order = json.loads(ORDER.read_bytes())
    a314_order, _readback = load_a314_order(commitment["A314_order_sha256"])
    direct = a314_order.get("direct_symbolic_winner") is not None
    if direct != (order["component_orders"] is None):
        raise RuntimeError("A316 conditional branch differs")
    if not direct:
        derived = derive_model_free_orders(a314_order)
        if (
            order["component_order_sha256"] != derived["hashes"]
            or order["component_orders"]["four_center_nearest_rank_band"] != derived["band"]
            or order["weighted_dovetail_2_to_1"] != derived["weighted"]
        ):
            raise RuntimeError("A316 exact rank-panel reconstruction differs")
    return commitment, order


def rank_analysis(prefix: int, order: Mapping[str, Any]) -> dict[str, Any]:
    components = order.get("component_orders")
    if not isinstance(components, Mapping):
        raise ValueError("A316 direct branch has no rank counterfactual")
    orders = {
        "A316_four_center_nearest_rank_band": components["four_center_nearest_rank_band"],
        "A316_weighted_dovetail_2_to_1": order["weighted_dovetail_2_to_1"],
        "A314_coarse_numeric_baseline": components["A314_coarse_numeric_baseline"],
        "A314_three_arm_portfolio": components["A314_three_arm_portfolio"],
    }
    ranks = {
        name: A315._exact_order(values, name).index(prefix) + 1  # noqa: SLF001
        for name, values in orders.items()
    }
    best = min(ranks.values())
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "best_frozen_order": min(ranks, key=ranks.get),
        "best_frozen_rank_one_based": best,
        "gain_bits_vs_complete_prefix_domain": {
            name: math.log2(CELLS / rank) for name, rank in ranks.items()
        },
        "counterfactual_only_no_duplicate_candidate_execution": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    direct = payload["rank_analysis"] is None
    terminal = "A316:prospective_online_multicenter_W45_evaluated"
    writer = CausalWriter(api_id="a316w45")
    writer._rules = []
    writer.add_rule(
        name="A315_rank_memory_to_unseen_W45_conditional_branch",
        description="The exact four-center memory and branch logic are frozen while A314 is still measuring its target-blind public-relation field.",
        pattern=["A315_frozen_online_rank_memory", "A314_future_public_measurement"],
        conclusion="A316_frozen_W45_counterfactual_object",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="A316_object_to_post_confirmation_evaluation",
        description="A direct symbolic model is retained without duplicate work, or the independently confirmed A314 prefix is located in unchanged direct, weighted and baseline orders.",
        pattern=["A316_frozen_W45_counterfactual_object", "A314_confirmed_W45_model"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A315:confirmed_rank_memory_and_update_rule",
        mechanism="pre_reveal_conditional_transfer_to_A314_W45_field",
        outcome="A316:frozen_W45_counterfactual_object",
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(payload["order_commitment"], sort_keys=True),
        evidence=json.dumps(payload.get("weighted_portfolio_guarantee"), sort_keys=True),
        domain="AI-native online ChaCha20-R20 W45 search operator",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A316:frozen_W45_counterfactual_object",
        mechanism=(
            "direct_symbolic_branch_retained_without_duplicate_execution"
            if direct
            else "post_confirmation_rank_only_evaluation_without_duplicate_search"
        ),
        outcome=terminal,
        confidence=1.0,
        source=payload["A314_result_sha256"],
        quantification=json.dumps(
            payload["direct_symbolic_retention"] if direct else payload["rank_analysis"],
            sort_keys=True,
        ),
        evidence=payload["evidence_stage"],
        domain="prospective online operator width transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A315:confirmed_rank_memory_and_update_rule",
        mechanism="materialized_conditional_transfer_evaluation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A316_online_multicenter_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A316 prospective online multicenter W45 counterfactual",
        entities=[
            "A315:confirmed_rank_memory_and_update_rule",
            "A316:frozen_W45_counterfactual_object",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_direct_execution_of_selected_online_operator_or_wider_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the same frozen online operator deserve direct execution on the next fresh W45 or wider target?"
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
        reader.api_id != "a316w45"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A316 authentic Causal reopen gate failed")
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


def evaluate(*, expected_commitment_sha256: str, expected_a314_result_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A316 evaluation artifacts already exist")
    commitment, order = load_frozen(expected_commitment_sha256)
    if file_sha256(A314.RESULT) != expected_a314_result_sha256:
        raise RuntimeError("A316 A314 result hash differs")
    a314 = json.loads(A314.RESULT.read_bytes())
    if (
        a314.get("confirmation", {}).get("all_blocks_match") is not True
        or a314.get("public_challenge_sha256") != order["public_challenge_sha256"]
    ):
        raise RuntimeError("A316 requires the independently confirmed A314 target")
    direct = order["component_orders"] is None
    ranks = None if direct else rank_analysis(int(a314["discovery"]["prefix12"]), order)
    direct_retention = (
        {
            "A314_direct_symbolic_model_retained": True,
            "duplicate_grouped_candidate_execution": False,
            "candidate": int(a314["discovery"]["candidate"]),
            "confirmation_all_blocks_match": True,
        }
        if direct
        else None
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w45-online-multicenter-counterfactual-a316-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "PRE_REVEAL_CONDITIONAL_DIRECT_SYMBOLIC_BRANCH_RETAINED"
            if direct
            else "PRE_REVEAL_COMMITTED_ONLINE_MULTICENTER_W45_COUNTERFACTUAL_EVALUATED"
        ),
        "design_sha256": DESIGN_SHA256,
        "commitment_sha256": expected_commitment_sha256,
        "order_sha256": commitment["order_sha256"],
        "A314_result_sha256": expected_a314_result_sha256,
        "public_challenge_sha256": order["public_challenge_sha256"],
        "order_commitment": commitment,
        "rank_analysis": ranks,
        "direct_symbolic_retention": direct_retention,
        "weighted_portfolio_guarantee": order["weighted_portfolio_guarantee"],
        "candidate_execution": {
            "performed_by_A316": False,
            "duplicate_candidate_execution": False,
            "confirmed_model_source": "A314_dual_independent_confirmation",
        },
        "information_boundary": order["information_boundary"],
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "commitment": {"path": relative(COMMITMENT), "sha256": expected_commitment_sha256},
            "order": {"path": relative(ORDER), "sha256": commitment["order_sha256"]},
            "A314_result": {"path": relative(A314.RESULT), "sha256": expected_a314_result_sha256},
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "order_commitment": commitment,
            "rank_analysis": ranks,
            "direct_symbolic_retention": direct_retention,
            "weighted_portfolio_guarantee": payload["weighted_portfolio_guarantee"],
            "candidate_execution": payload["candidate_execution"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    if direct:
        body = (
            "- Frozen direct-symbolic branch: **retained**\n"
            "- Duplicate grouped candidate execution: **none**\n"
        )
    else:
        rank_rows = ranks["prefix_ranks_one_based"]
        body = (
            f"- Direct four-center rank: **{rank_rows['A316_four_center_nearest_rank_band']} / 4,096**\n"
            f"- Weighted 2:1 rank: **{rank_rows['A316_weighted_dovetail_2_to_1']} / 4,096**\n"
            f"- A314 executed-order rank: **{rank_rows['A314_three_arm_portfolio']} / 4,096**\n"
            f"- A314 baseline rank: **{rank_rows['A314_coarse_numeric_baseline']} / 4,096**\n"
        )
    atomic_bytes(
        REPORT,
        (
            "# A316 — online multicenter W45 counterfactual\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            + body
            + "- Conditional logic frozen before A314 measurement completed: **yes**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "A314_order_complete": A314.ORDER.exists(),
        "order_materialized": ORDER.exists(),
        "commitment_frozen": COMMITMENT.exists(),
        "A314_result_complete": A314.RESULT.exists(),
        "evaluation_complete": RESULT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--materialize", action="store_true")
    action.add_argument("--evaluate", action="store_true")
    parser.add_argument("--expected-a314-order-sha256")
    parser.add_argument("--expected-commitment-sha256")
    parser.add_argument("--expected-a314-result-sha256")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.materialize:
        if not args.expected_a314_order_sha256:
            parser.error("--materialize requires --expected-a314-order-sha256")
        payload = materialize(expected_a314_order_sha256=args.expected_a314_order_sha256)
    else:
        if not args.expected_commitment_sha256 or not args.expected_a314_result_sha256:
            parser.error(
                "--evaluate requires --expected-commitment-sha256 and --expected-a314-result-sha256"
            )
        payload = evaluate(
            expected_commitment_sha256=args.expected_commitment_sha256,
            expected_a314_result_sha256=args.expected_a314_result_sha256,
        )
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
