#!/usr/bin/env python3
"""A315: freeze and evaluate an online multicenter W44 rank operator."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w44_online_multicenter_counterfactual_a315_design_v1.json"
COMMITMENT = CONFIGS / "chacha20_round20_w44_online_multicenter_counterfactual_a315_commitment_v1.json"
ORDER = RESULTS / "chacha20_round20_w44_online_multicenter_counterfactual_a315_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w44_online_multicenter_counterfactual_a315_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w44_online_multicenter_counterfactual_a315_v1.causal"
REPORT = RESULTS / "chacha20_round20_w44_online_multicenter_counterfactual_a315_v1.md"

A309_RESULT = RESULTS / "chacha20_round20_w43_width_conditioned_band_portfolio_a309_v1.json"
A310_RESULT = RESULTS / "chacha20_round20_w43_empirical_multicenter_band_counterfactual_a310_v1.json"
A312_ORDER = RESULTS / "chacha20_round20_w44_fine_selected_channel_transfer_a312_order_v1.json"
A313_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_width_conditioned_fine_portfolio_a313.py"
A315_TEST = ROOT / "tests/test_chacha20_round20_w44_online_multicenter_counterfactual_a315.py"
A315_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w44_online_multicenter_counterfactual_a315.sh"

ATTEMPT_ID = "A315"
DESIGN_SHA256 = "7cc62d63ea2a7f0987dd24e6e55071487b796ffbffbba7f39c1d43663bc4d696"
A309_RESULT_SHA256 = "73edd2514cb644330c481d9fe01293e3a0242aad5157ba7a598ac776fbfb8abd"
A310_RESULT_SHA256 = "19d9a341e103345600470adfa3a8feae1c99a66a38de241a60b42c4c8bdd13bc"
A312_ORDER_SHA256 = "698641af20a9f9ef7071f7a46d239a9cb9124cc82e10ab1b4bdb00f4a98f39fc"
A313_PROTOCOL_SHA256 = "dd5d59c52b8d5247d4a51b5a078f640577a2b8e3506fd2c7a46a8ca2a34c2f3c"
A313_ORDER_SHA256 = "2772df2531cc150d04002816661fb755c272f1afd5d699d5b802a2ff96eb42e3"
CENTERS = [2114, 2366, 2605, 3829]
CELLS = 1 << 12


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A315 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A313 = load_module(A313_RUNNER, "a315_a313_common")
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
        raise ValueError(f"A315 {label} is not an exact 4,096-cell cover")
    return order


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A315 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    operator = design.get("operator_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-w44-online-multicenter-counterfactual-a315-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A313_recovery_is_running_before_any_A313_result_candidate_or_prefix_rank_exists"
        or operator.get("confirmed_fine_rank_centers_one_based") != CENTERS
        or operator.get("selection_or_refit_after_A313_reveal") is not False
        or operator.get("candidate_execution_by_A315") is not False
        or boundary.get("A313_result_available_at_design_freeze") is not False
        or boundary.get("A313_candidate_available_at_design_freeze") is not False
        or boundary.get("A313_prefix_rank_available_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A313") != 0
    ):
        raise RuntimeError("A315 frozen design semantics differ")
    for key, expected in design["source_anchors"].items():
        if key.endswith("_path"):
            sha_key = key.removesuffix("_path") + "_sha256"
            anchor(path_from_ref(expected), design["source_anchors"][sha_key])
    a309 = json.loads(A309_RESULT.read_bytes())
    a310 = json.loads(A310_RESULT.read_bytes())
    if (
        a309.get("confirmation", {}).get("all_blocks_match") is not True
        or a309.get("rank_analysis", {})
        .get("prefix_ranks_one_based", {})
        .get("A295_fine_selected_channel")
        != 3829
        or a310.get("rank_analysis", {})
        .get("prefix_ranks_one_based", {})
        .get("empirical_multicenter_band")
        != 2940
        or a310.get("candidate_execution", {}).get("duplicate_candidate_execution")
        is not False
    ):
        raise RuntimeError("A315 A309/A310 retained breadcrumb differs")
    return design


def multicenter_band(*, fine: Sequence[int], centers: Sequence[int] = CENTERS) -> list[int]:
    fine_order = _exact_order(fine, "fine source order")
    center_values = [int(value) for value in centers]
    if (
        not center_values
        or len(center_values) != len(set(center_values))
        or any(not 1 <= value <= CELLS for value in center_values)
    ):
        raise ValueError("A315 centers are not distinct one-based ranks")
    ranks = {cell: rank for rank, cell in enumerate(fine_order, 1)}

    def key(cell: int) -> tuple[int, int, int]:
        rank = ranks[cell]
        distances = [abs(rank - center) for center in center_values]
        minimum = min(distances)
        return minimum, distances.index(minimum), rank

    return _exact_order(sorted(fine_order, key=key), "multicenter band")


def weighted_dovetail(
    *, band: Sequence[int], baseline: Sequence[int], band_weight: int = 2, baseline_weight: int = 1
) -> list[int]:
    band_order = _exact_order(band, "band arm")
    baseline_order = _exact_order(baseline, "baseline arm")
    if band_weight <= 0 or baseline_weight <= 0:
        raise ValueError("A315 weights must be positive")
    pointers = [0, 0]
    output: list[int] = []
    seen: set[int] = set()
    while len(output) < CELLS:
        before = len(output)
        for arm_index, (arm, weight) in enumerate(
            ((band_order, band_weight), (baseline_order, baseline_weight))
        ):
            for _ in range(weight):
                if pointers[arm_index] >= CELLS:
                    continue
                cell = arm[pointers[arm_index]]
                pointers[arm_index] += 1
                if cell not in seen:
                    seen.add(cell)
                    output.append(cell)
        if len(output) == before and pointers == [CELLS, CELLS]:
            raise RuntimeError("A315 dovetail exhausted before complete cover")
    return _exact_order(output, "weighted dovetail")


def guarantee(
    *, portfolio: Sequence[int], band: Sequence[int], baseline: Sequence[int]
) -> dict[str, Any]:
    orders = {
        "portfolio": _exact_order(portfolio, "portfolio"),
        "band": _exact_order(band, "band"),
        "baseline": _exact_order(baseline, "baseline"),
    }
    ranks = {
        name: {cell: rank for rank, cell in enumerate(order, 1)}
        for name, order in orders.items()
    }
    band_factors = [ranks["portfolio"][cell] / ranks["band"][cell] for cell in range(CELLS)]
    baseline_factors = [
        ranks["portfolio"][cell] / ranks["baseline"][cell] for cell in range(CELLS)
    ]
    best_factors = [
        ranks["portfolio"][cell]
        / min(ranks["band"][cell], ranks["baseline"][cell])
        for cell in range(CELLS)
    ]
    maximum_band = max(band_factors)
    maximum_baseline = max(baseline_factors)
    maximum_best = max(best_factors)
    if maximum_band > 1.5 or maximum_baseline > 3.0 or maximum_best > 3.0:
        raise RuntimeError("A315 weighted rank guarantee differs")
    return {
        "checked_prefix_cells": CELLS,
        "violations": 0,
        "maximum_factor_vs_four_center_band": maximum_band,
        "maximum_factor_vs_A308_baseline": maximum_baseline,
        "maximum_factor_vs_best_arm": maximum_best,
        "maximum_regret_bits_vs_best_arm": math.log2(maximum_best),
        "statement": "R_A315_weighted <= 1.5 R_four_center_band and <= 3 R_A308_baseline over every exact W44 prefix cell",
    }


def reconstruct() -> dict[str, Any]:
    design = load_design()
    a313 = json.loads(A313.ORDER.read_bytes())
    if (
        file_sha256(A313.ORDER) != A313_ORDER_SHA256
        or file_sha256(A313.PROTOCOL) != A313_PROTOCOL_SHA256
        or a313.get("schema")
        != "chacha20-round20-w44-width-conditioned-fine-portfolio-a313-order-v1"
        or a313.get("public_challenge_sha256")
        != json.loads(A313.PROTOCOL.read_bytes())["public_challenge_sha256"]
    ):
        raise RuntimeError("A315 A313 frozen search object differs")
    components = a313["component_orders"]
    fine = _exact_order(components["A312_fine_selected_channel"], "A312 fine")
    baseline = _exact_order(components["A308_two_operator_baseline"], "A308 baseline")
    a313_portfolio = _exact_order(a313["portfolio_order"], "A313 portfolio")
    band = multicenter_band(fine=fine)
    weighted = weighted_dovetail(band=band, baseline=baseline)
    hashes = {
        "four_center_band_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in band)
        ),
        "weighted_dovetail_2_to_1_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in weighted)
        ),
        "A308_baseline_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in baseline)
        ),
        "A313_portfolio_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in a313_portfolio)
        ),
    }
    return {
        "design": design,
        "public_challenge_sha256": a313["public_challenge_sha256"],
        "fine": fine,
        "band": band,
        "baseline": baseline,
        "weighted": weighted,
        "A313_portfolio": a313_portfolio,
        "hashes": hashes,
        "guarantee": guarantee(portfolio=weighted, band=band, baseline=baseline),
    }


def materialize() -> dict[str, Any]:
    if any(path.exists() for path in (ORDER, COMMITMENT, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A315 artifacts already exist")
    if A313.RESULT.exists() or A313.CAUSAL.exists():
        raise RuntimeError("A315 must freeze before any A313 result exists")
    value = reconstruct()
    order: dict[str, Any] = {
        "schema": "chacha20-round20-w44-online-multicenter-counterfactual-a315-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "A315_TARGET_BLIND_ONLINE_MULTICENTER_ORDER_FROZEN_BEFORE_A313_REVEAL",
        "design_sha256": DESIGN_SHA256,
        "public_challenge_sha256": value["public_challenge_sha256"],
        "confirmed_fine_rank_centers_one_based": CENTERS,
        "component_orders": {
            "four_center_nearest_rank_band": value["band"],
            "A308_two_operator_baseline": value["baseline"],
            "A313_three_arm_portfolio": value["A313_portfolio"],
        },
        "weighted_dovetail_2_to_1": value["weighted"],
        "component_order_sha256": value["hashes"],
        "weighted_portfolio_guarantee": value["guarantee"],
        "information_boundary": {
            **value["design"]["information_boundary"],
            "A313_result_available_at_materialization": False,
            "A313_candidate_or_prefix_rank_available_at_materialization": False,
        },
    }
    order["measurement_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "public_challenge_sha256": order["public_challenge_sha256"],
            "confirmed_fine_rank_centers_one_based": CENTERS,
            "component_order_sha256": order["component_order_sha256"],
            "weighted_portfolio_guarantee": order["weighted_portfolio_guarantee"],
            "information_boundary": order["information_boundary"],
        }
    )
    atomic_json(ORDER, order)
    order_sha = file_sha256(ORDER)
    commitment = {
        "schema": "chacha20-round20-w44-online-multicenter-counterfactual-a315-commitment-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A313_result_candidate_or_rank_exists",
        "design_sha256": DESIGN_SHA256,
        "order_sha256": order_sha,
        "public_challenge_sha256": order["public_challenge_sha256"],
        "component_order_sha256": order["component_order_sha256"],
        "weighted_portfolio_guarantee": order["weighted_portfolio_guarantee"],
        "A313_result_available_at_commitment": False,
        "candidate_or_rank_available_at_commitment": False,
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "order": {"path": relative(ORDER), "sha256": order_sha},
            "A309_result": {"path": relative(A309_RESULT), "sha256": A309_RESULT_SHA256},
            "A310_result": {"path": relative(A310_RESULT), "sha256": A310_RESULT_SHA256},
            "A312_order": {"path": relative(A312_ORDER), "sha256": A312_ORDER_SHA256},
            "A313_protocol": {"path": relative(A313.PROTOCOL), "sha256": A313_PROTOCOL_SHA256},
            "A313_order": {"path": relative(A313.ORDER), "sha256": A313_ORDER_SHA256},
            "runner": {"path": relative(Path(__file__)), "sha256": file_sha256(Path(__file__))},
            "test": {"path": relative(A315_TEST), "sha256": file_sha256(A315_TEST)},
            "reproducer": {"path": relative(A315_REPRO), "sha256": file_sha256(A315_REPRO)},
        },
    }
    atomic_json(COMMITMENT, commitment)
    return {
        "order": relative(ORDER),
        "order_sha256": order_sha,
        "commitment": relative(COMMITMENT),
        "commitment_sha256": file_sha256(COMMITMENT),
        "component_order_sha256": order["component_order_sha256"],
        "weighted_portfolio_guarantee": order["weighted_portfolio_guarantee"],
    }


def load_frozen(expected_commitment_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(COMMITMENT) != expected_commitment_sha256:
        raise RuntimeError("A315 commitment hash differs")
    commitment = json.loads(COMMITMENT.read_bytes())
    if (
        commitment.get("schema")
        != "chacha20-round20-w44-online-multicenter-counterfactual-a315-commitment-v1"
        or commitment.get("commitment_state")
        != "frozen_before_A313_result_candidate_or_rank_exists"
        or commitment.get("candidate_or_rank_available_at_commitment") is not False
    ):
        raise RuntimeError("A315 commitment semantics differ")
    for row in commitment["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    order = json.loads(ORDER.read_bytes())
    reconstructed = reconstruct()
    if (
        order.get("component_order_sha256") != reconstructed["hashes"]
        or order.get("component_orders", {}).get("four_center_nearest_rank_band")
        != reconstructed["band"]
        or order.get("weighted_dovetail_2_to_1") != reconstructed["weighted"]
    ):
        raise RuntimeError("A315 exact order reconstruction differs")
    return commitment, order


def rank_analysis(prefix: int, order: Mapping[str, Any]) -> dict[str, Any]:
    component = order["component_orders"]
    orders = {
        "A315_four_center_nearest_rank_band": component["four_center_nearest_rank_band"],
        "A315_weighted_dovetail_2_to_1": order["weighted_dovetail_2_to_1"],
        "A308_two_operator_baseline": component["A308_two_operator_baseline"],
        "A313_three_arm_portfolio": component["A313_three_arm_portfolio"],
    }
    ranks = {
        name: _exact_order(values, name).index(prefix) + 1
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

    terminal = "A315:prospective_online_multicenter_W44_evaluated"
    writer = CausalWriter(api_id="a315w44")
    writer._rules = []
    writer.add_rule(
        name="confirmed_fine_rank_to_online_multicenter_update",
        description="Each independently confirmed fresh-target fine rank is appended once to the unchanged target-blind rank map before the next target is revealed.",
        pattern=["A295_A303_A305_A309_confirmed_fine_ranks", "A312_target_blind_fine_order"],
        conclusion="A315_frozen_four_center_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_A315_order_to_counterfactual_W44_rank",
        description="After A313 independently confirms the target, its prefix is located in the unchanged direct and weighted A315 orders without candidate re-execution.",
        pattern=["A315_frozen_four_center_order", "A313_confirmed_prefix"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A295_A303_A305_A309:confirmed_fine_rank_memory",
        mechanism="target_blind_online_multicenter_update_plus_2_to_1_dovetail",
        outcome="A315:frozen_W44_order_panel",
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(payload["order_commitment"], sort_keys=True),
        evidence=json.dumps(payload["weighted_portfolio_guarantee"], sort_keys=True),
        domain="AI-native online ChaCha20-R20 search operator",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A315:frozen_W44_order_panel",
        mechanism="post_confirmation_rank_only_evaluation_without_duplicate_search",
        outcome=terminal,
        confidence=1.0,
        source=payload["A313_result_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="prospective online operator transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A295_A303_A305_A309:confirmed_fine_rank_memory",
        mechanism="materialized_online_update_commitment_evaluation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A315_online_multicenter_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A315 prospective online multicenter W44 counterfactual",
        entities=[
            "A295_A303_A305_A309:confirmed_fine_rank_memory",
            "A315:frozen_W44_order_panel",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="online_rank_memory_update_or_direct_execution_on_fresh_width",
        confidence=1.0,
        suggested_queries=[
            "Did the appended A309 center improve unseen W44 concentration, and which direct or weighted schedule should be executed next?"
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
        reader.api_id != "a315w44"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A315 authentic Causal reopen gate failed")
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


def evaluate(*, expected_commitment_sha256: str, expected_a313_result_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A315 evaluation artifacts already exist")
    commitment, order = load_frozen(expected_commitment_sha256)
    if file_sha256(A313.RESULT) != expected_a313_result_sha256:
        raise RuntimeError("A315 A313 result hash differs")
    a313 = json.loads(A313.RESULT.read_bytes())
    if (
        a313.get("confirmation", {}).get("all_blocks_match") is not True
        or a313.get("public_challenge_sha256") != order["public_challenge_sha256"]
        or a313.get("discovery", {}).get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A315 requires the independently confirmed A313 target")
    prefix = int(a313["discovery"]["prefix12"])
    ranks = rank_analysis(prefix, order)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w44-online-multicenter-counterfactual-a315-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_REVEAL_COMMITTED_ONLINE_MULTICENTER_W44_COUNTERFACTUAL_EVALUATED",
        "design_sha256": DESIGN_SHA256,
        "commitment_sha256": expected_commitment_sha256,
        "order_sha256": commitment["order_sha256"],
        "A313_result_sha256": expected_a313_result_sha256,
        "public_challenge_sha256": order["public_challenge_sha256"],
        "order_commitment": commitment,
        "rank_analysis": ranks,
        "weighted_portfolio_guarantee": order["weighted_portfolio_guarantee"],
        "candidate_execution": {
            "performed_by_A315": False,
            "duplicate_candidate_execution": False,
            "confirmed_prefix_source": "A313_dual_independent_confirmation",
        },
        "information_boundary": order["information_boundary"],
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "commitment": {"path": relative(COMMITMENT), "sha256": expected_commitment_sha256},
            "order": {"path": relative(ORDER), "sha256": commitment["order_sha256"]},
            "A313_result": {"path": relative(A313.RESULT), "sha256": expected_a313_result_sha256},
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "order_commitment": commitment,
            "rank_analysis": ranks,
            "weighted_portfolio_guarantee": payload["weighted_portfolio_guarantee"],
            "candidate_execution": payload["candidate_execution"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    rank_rows = ranks["prefix_ranks_one_based"]
    atomic_bytes(
        REPORT,
        (
            "# A315 — online multicenter W44 counterfactual\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Direct four-center rank: **{rank_rows['A315_four_center_nearest_rank_band']} / 4,096**\n"
            f"- Weighted 2:1 rank: **{rank_rows['A315_weighted_dovetail_2_to_1']} / 4,096**\n"
            f"- A313 executed-order rank: **{rank_rows['A313_three_arm_portfolio']} / 4,096**\n"
            f"- A308 baseline rank: **{rank_rows['A308_two_operator_baseline']} / 4,096**\n"
            "- Exact order bytes frozen before A313 reveal: **yes**\n"
            "- Duplicate candidate execution: **none**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "order_materialized": ORDER.exists(),
        "commitment_frozen": COMMITMENT.exists(),
        "A313_result_complete": A313.RESULT.exists(),
        "evaluation_complete": RESULT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--materialize", action="store_true")
    action.add_argument("--evaluate", action="store_true")
    parser.add_argument("--expected-commitment-sha256")
    parser.add_argument("--expected-a313-result-sha256")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.materialize:
        payload = materialize()
    else:
        if not args.expected_commitment_sha256 or not args.expected_a313_result_sha256:
            parser.error(
                "--evaluate requires --expected-commitment-sha256 and --expected-a313-result-sha256"
            )
        payload = evaluate(
            expected_commitment_sha256=args.expected_commitment_sha256,
            expected_a313_result_sha256=args.expected_a313_result_sha256,
        )
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
