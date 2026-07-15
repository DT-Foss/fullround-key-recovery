#!/usr/bin/env python3
"""A301: calibrated two-operator recovery for the sealed A300 W43 target."""

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

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"

DESIGN = CONFIGS / "chacha20_round20_w43_dominance_pruned_portfolio_a301_design_v1.json"
A300_RUNNER = RESEARCH / "experiments/chacha20_round20_w43_three_operator_portfolio_a300.py"
A301_TEST = ROOT / "tests/test_chacha20_round20_w43_dominance_pruned_portfolio_a301.py"

CALIBRATION = RESULTS / "chacha20_round20_w43_dominance_pruned_portfolio_a301_calibration_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w43_dominance_pruned_portfolio_a301_v1.json"
ORDER = RESULTS / "chacha20_round20_w43_dominance_pruned_portfolio_a301_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w43_dominance_pruned_portfolio_a301_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_W43_DOMINANCE_PRUNED_PORTFOLIO_A301_V1.md"
BUILD = RESEARCH / "build/chacha20_round20_w43_dominance_pruned_portfolio_a301"

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A301"
DESIGN_SHA256 = "0a9acb05e5b68f3eb8ec1acb0778e6a6a1ba3e9f29dcab058bec638d7cc4ffa1"
WIDTH = 43
PREFIX_BITS = 12
CELLS = 1 << PREFIX_BITS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A301 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A300 = load_module(A300_RUNNER, "a301_a300_common")
sha256 = A300.sha256
file_sha256 = A300.file_sha256
canonical_sha256 = A300.canonical_sha256
atomic_bytes = A300.atomic_bytes
atomic_json = A300.atomic_json
relative = A300.relative
path_from_ref = A300.path_from_ref
anchor = A300.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A301 prospective design hash differs")
    value = json.loads(DESIGN.read_bytes())
    operator = value.get("operator_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w43-dominance-pruned-portfolio-a301-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A299_order_readback_and_before_A300_measurement_order_candidate_or_assignment_reveal"
        or operator.get("candidate_execution_orders")
        != [
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        ]
        or operator.get("audit_only_order") != "A295_fine_selected_channel"
        or operator.get("merge_component_precedence")
        != [
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        ]
        or boundary.get("A300_measurement_or_order_available_at_freeze") is not False
        or boundary.get(
            "A300_production_assignment_model_candidate_filter_outcome_or_rank_available_at_freeze"
        )
        is not False
    ):
        raise RuntimeError("A301 prospective design semantics differ")
    return value


def two_operator_portfolio(
    *, coarse: Sequence[int], numeric: Sequence[int]
) -> list[int]:
    orders = [[int(value) for value in coarse], [int(value) for value in numeric]]
    if any(len(order) != CELLS or set(order) != set(range(CELLS)) for order in orders):
        raise ValueError("A301 component order is not an exact prefix cover")
    result: list[int] = []
    seen: set[int] = set()
    for rank in range(CELLS):
        for order in orders:
            value = order[rank]
            if value not in seen:
                seen.add(value)
                result.append(value)
    if len(result) != CELLS or set(result) != set(range(CELLS)):
        raise RuntimeError("A301 portfolio merge is not an exact prefix cover")
    return result


def portfolio_guarantee(
    *, portfolio: Sequence[int], coarse: Sequence[int], numeric: Sequence[int]
) -> dict[str, Any]:
    ranks = {
        "portfolio": {int(value): rank for rank, value in enumerate(portfolio, 1)},
        "coarse": {int(value): rank for rank, value in enumerate(coarse, 1)},
        "numeric": {int(value): rank for rank, value in enumerate(numeric, 1)},
    }
    worst_factor = 0.0
    worst_cell = 0
    for cell in range(CELLS):
        best = min(ranks["coarse"][cell], ranks["numeric"][cell])
        observed = ranks["portfolio"][cell]
        if observed > 2 * best:
            raise RuntimeError("A301 portfolio rank guarantee failed")
        factor = observed / best
        if factor > worst_factor:
            worst_factor = factor
            worst_cell = cell
    return {
        "statement": "R_A301 <= 2 * min(R_coarse, R_numeric)",
        "checked_prefix_cells": CELLS,
        "violations": 0,
        "maximum_observed_regret_factor": worst_factor,
        "maximum_observed_regret_bits": math.log2(worst_factor),
        "maximum_observed_regret_cell": worst_cell,
        "frozen_worst_case_bound_factor": 2,
        "frozen_worst_case_bound_bits": 1.0,
    }


def _hash_gated_json(path: Path, expected_sha256: str) -> dict[str, Any]:
    if file_sha256(path) != expected_sha256:
        raise RuntimeError(f"A301 calibration anchor differs: {path}")
    return json.loads(path.read_bytes())


def _rank_row(
    *,
    target_id: str,
    width: int,
    prefix: int,
    coarse: Sequence[int],
    numeric: Sequence[int],
    fine_rank: int | None = None,
) -> dict[str, Any]:
    portfolio = two_operator_portfolio(coarse=coarse, numeric=numeric)
    ranks: dict[str, int] = {
        "coarse": list(coarse).index(prefix) + 1,
        "numeric": list(numeric).index(prefix) + 1,
        "two_operator_portfolio": portfolio.index(prefix) + 1,
    }
    if fine_rank is not None:
        ranks["fine"] = int(fine_rank)
    portfolio_rank = ranks["two_operator_portfolio"]
    return {
        "target_id": target_id,
        "unknown_key_bits": width,
        "prefix12": prefix,
        "prefix_ranks_one_based": ranks,
        "strict_subset": portfolio_rank < CELLS,
        "complete_domain_reduction": CELLS / portfolio_rank,
        "search_gain_bits": math.log2(CELLS / portfolio_rank),
        "rank_bound_holds": portfolio_rank
        <= 2 * min(ranks["coarse"], ranks["numeric"]),
    }


def calibration_payload() -> dict[str, Any]:
    design = load_design()
    sources = design["source_anchors"]
    a291 = _hash_gated_json(
        path_from_ref(sources["A291_result_path"]), sources["A291_result_sha256"]
    )
    a295 = _hash_gated_json(
        path_from_ref(sources["A295_result_path"]), sources["A295_result_sha256"]
    )
    a296 = _hash_gated_json(
        path_from_ref(sources["A296_result_path"]), sources["A296_result_sha256"]
    )
    a297 = _hash_gated_json(
        path_from_ref(sources["A297_result_path"]), sources["A297_result_sha256"]
    )
    a299 = _hash_gated_json(
        path_from_ref(sources["A299_order_path"]), sources["A299_order_sha256"]
    )
    w43 = _hash_gated_json(
        path_from_ref(sources["CHACHA20KR43_result_path"]),
        sources["CHACHA20KR43_result_sha256"],
    )
    numeric = list(range(CELLS))
    rows: list[dict[str, Any]] = []
    for panel in (a296, a297):
        for target in panel["targets"]:
            order_ref = target["order_artifact"]
            order_path = path_from_ref(order_ref["path"])
            order = _hash_gated_json(order_path, order_ref["sha256"])
            coarse = A300.A299.A297.A296.fine_order(
                [int(value) for value in order["complete_coarse_order"]]
            )
            rows.append(
                _rank_row(
                    target_id=target["target_id"],
                    width=int(target["unknown_key_bits"]),
                    prefix=int(target["rank_analysis"]["prefix12"]),
                    coarse=coarse,
                    numeric=numeric,
                )
            )
    a295_coarse = A300.A299.A297.A296.fine_order(
        [int(value) for value in a291["analysis"]["complete_cell_order"]]
    )
    a295_ranks = a295["rank_analysis"]["prefix_ranks_one_based"]
    rows.append(
        _rank_row(
            target_id="A295",
            width=24,
            prefix=int(a295["rank_analysis"]["prefix12"]),
            coarse=a295_coarse,
            numeric=numeric,
            fine_rank=int(a295_ranks["A295_fine_selected_channel"]),
        )
    )
    a299_coarse = A300.A299.A297.A296.fine_order(
        [int(value) for value in a299["coarse_readout"]["complete_coarse_order"]]
    )
    a299_assignment = int(w43["confirmation"]["assignment"])
    a299_prefix = (a299_assignment & 0xFFFFFFFF) >> 20
    a299_fine = [int(value) for value in a299["fine_readout"]["complete_order"]]
    rows.append(
        _rank_row(
            target_id="A299",
            width=43,
            prefix=a299_prefix,
            coarse=a299_coarse,
            numeric=numeric,
            fine_rank=a299_fine.index(a299_prefix) + 1,
        )
    )
    if (
        len(rows) != 14
        or not all(row["rank_bound_holds"] for row in rows)
        or not all(row["strict_subset"] for row in rows)
    ):
        raise RuntimeError("A301 retained calibration panel differs")
    fine_rows = [row for row in rows if "fine" in row["prefix_ranks_one_based"]]
    if len(fine_rows) != 2 or not all(
        row["prefix_ranks_one_based"]["fine"]
        > min(
            row["prefix_ranks_one_based"]["coarse"],
            row["prefix_ranks_one_based"]["numeric"],
        )
        for row in fine_rows
    ):
        raise RuntimeError("A301 fine-operator dominance observation differs")
    mean_gain = sum(row["search_gain_bits"] for row in rows) / len(rows)
    gm_reduction = 2**mean_gain
    payload = {
        "schema": "chacha20-round20-w43-dominance-pruned-portfolio-a301-calibration-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FOURTEEN_TARGET_TWO_OPERATOR_CALIBRATION_FROZEN",
        "rows": rows,
        "aggregate": {
            "targets": len(rows),
            "strict_subset_targets": sum(row["strict_subset"] for row in rows),
            "fine_operator_direct_calibrations": len(fine_rows),
            "fine_operator_dominated_calibrations": sum(
                row["prefix_ranks_one_based"]["fine"]
                > min(
                    row["prefix_ranks_one_based"]["coarse"],
                    row["prefix_ranks_one_based"]["numeric"],
                )
                for row in fine_rows
            ),
            "geometric_mean_complete_domain_reduction": gm_reduction,
            "mean_search_gain_bits": mean_gain,
            "maximum_portfolio_rank": max(
                row["prefix_ranks_one_based"]["two_operator_portfolio"]
                for row in rows
            ),
        },
        "information_boundary": {
            "completed_postconfirmation_calibration_labels_used": True,
            "A300_measurement_order_candidate_assignment_or_label_used": False,
            "calibration_selects_only_the_future_operator_allocation": True,
        },
        "source_sha256": {
            key: value
            for key, value in sources.items()
            if key.endswith("_sha256")
            and key
            in {
                "A291_result_sha256",
                "A295_result_sha256",
                "A296_result_sha256",
                "A297_result_sha256",
                "A299_order_sha256",
                "CHACHA20KR43_result_sha256",
            }
        },
    }
    if not math.isclose(
        gm_reduction,
        float(
            design["calibration_contract"][
                "retrospective_geometric_mean_complete_domain_reduction"
            ]
        ),
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise RuntimeError("A301 frozen calibration aggregate differs")
    return payload


def execution_contract() -> dict[str, Any]:
    return {
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward_included": True,
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "public_output_blocks": 8,
        "prefix_cells": CELLS,
        "candidate_group_size": GROUP_SIZE,
        "complete_residual_domain": DOMAIN_SIZE,
        "candidate_execution_orders": [
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        ],
        "audit_only_order": "A295_fine_selected_channel",
        "merge": "rank_round_robin_then_first_occurrence_deduplication",
        "rank_guarantee": "R_A301 <= 2 * min(R_coarse, R_numeric)",
        "reader_refits": 0,
        "target_labels_used": 0,
        "recovery": (
            "portfolio_ordered_word0_prefix12_groups_x_complete_word1_low11_"
            "slices_then_dual_independent_eight_block_confirmation"
        ),
    }


def freeze(
    *, expected_a300_protocol_sha256: str, expected_a300_preflight_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (CALIBRATION, PROTOCOL, ORDER, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A301 artifacts already exist")
    design = load_design()
    sources = design["source_anchors"]
    if (
        expected_a300_protocol_sha256 != sources["A300_protocol_sha256"]
        or expected_a300_preflight_sha256 != sources["A300_preflight_sha256"]
        or file_sha256(A300_RUNNER) != sources["A300_runner_sha256"]
    ):
        raise RuntimeError("A301 sealed A300 source frontier differs")
    a300_protocol, _ = A300.load_preflight(
        expected_a300_protocol_sha256, expected_a300_preflight_sha256
    )
    if A300.ORDER.exists() or A300.RESULT.exists():
        raise RuntimeError("A301 must freeze before A300 order or result exists")
    if not A301_TEST.exists():
        raise FileNotFoundError("A301 tests must exist before protocol freeze")
    calibration = calibration_payload()
    atomic_json(CALIBRATION, calibration)
    plan = execution_contract()
    runner_source = Path(__file__)
    payload = {
        "schema": "chacha20-round20-w43-dominance-pruned-portfolio-a301-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A301_operator_allocation_frozen_before_A300_measurement_order_or_candidate_discovery",
        "design": design,
        "execution_contract": plan,
        "execution_contract_sha256": canonical_sha256(plan),
        "public_challenge_sha256": a300_protocol["public_challenge_sha256"],
        "reader_challenge_sha256": a300_protocol["reader_challenge_sha256"],
        "calibration": anchor(CALIBRATION),
        "calibration_aggregate": calibration["aggregate"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "runner": anchor(runner_source),
            "test": anchor(A301_TEST),
            "A300_runner": anchor(A300_RUNNER, sources["A300_runner_sha256"]),
            "A300_design": anchor(A300.DESIGN, sources["A300_design_sha256"]),
            "A300_protocol": anchor(A300.PROTOCOL, expected_a300_protocol_sha256),
            "A300_preflight": anchor(A300.PREFLIGHT, expected_a300_preflight_sha256),
        },
        "information_boundary": {
            "sealed_A300_public_challenge_exists": True,
            "A300_measurement_or_order_available_at_freeze": False,
            "A300_assignment_model_candidate_filter_outcome_or_rank_available_at_freeze": False,
            "calibration_labels_are_disjoint_completed_targets": True,
            "operator_allocation_merge_and_precedence_frozen": True,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "execution_contract": plan,
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "calibration_sha256": payload["calibration"]["sha256"],
            "information_boundary": payload["information_boundary"],
            "anchors": payload["anchors"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A301 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-dominance-pruned-portfolio-a301-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("execution_contract") != execution_contract()
        or value.get("anchors", {}).get("runner", {}).get("sha256")
        != file_sha256(Path(__file__))
        or value.get("anchors", {}).get("test", {}).get("sha256")
        != file_sha256(A301_TEST)
        or value.get("information_boundary", {}).get(
            "A300_measurement_or_order_available_at_freeze"
        )
        is not False
    ):
        raise RuntimeError("A301 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(CALIBRATION, value["calibration"]["sha256"])
    A300.load_preflight(
        value["anchors"]["A300_protocol"]["sha256"],
        value["anchors"]["A300_preflight"]["sha256"],
    )
    return value


def derive_order(
    *, expected_protocol_sha256: str, expected_a300_order_sha256: str
) -> dict[str, Any]:
    if ORDER.exists():
        raise FileExistsError("A301 order already exists")
    protocol = load_protocol(expected_protocol_sha256)
    a300_protocol_sha = protocol["anchors"]["A300_protocol"]["sha256"]
    a300_preflight_sha = protocol["anchors"]["A300_preflight"]["sha256"]
    _, _, a300_order = A300.load_order(
        a300_protocol_sha,
        a300_preflight_sha,
        expected_a300_order_sha256,
    )
    components = a300_order["component_orders"]
    coarse = [
        int(value)
        for value in components["A297_coarse_high8_then_reflected_Gray4"]
    ]
    numeric = [int(value) for value in components["numeric_word0_prefix12"]]
    fine = [int(value) for value in components["A295_fine_selected_channel"]]
    portfolio = two_operator_portfolio(coarse=coarse, numeric=numeric)
    guarantee = portfolio_guarantee(
        portfolio=portfolio, coarse=coarse, numeric=numeric
    )
    payload = {
        "schema": "chacha20-round20-w43-dominance-pruned-portfolio-a301-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "SEALED_W43_TARGET_BLIND_TWO_OPERATOR_ORDER_FROZEN",
        "protocol_sha256": expected_protocol_sha256,
        "A300_order": anchor(A300.ORDER, expected_a300_order_sha256),
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "candidate_execution_orders": {
            "A297_coarse_high8_then_reflected_Gray4": coarse,
            "numeric_word0_prefix12": numeric,
        },
        "audit_only_order": {
            "name": "A295_fine_selected_channel",
            "order_uint16be_sha256": sha256(
                b"".join(value.to_bytes(2, "big") for value in fine)
            ),
        },
        "portfolio_order": portfolio,
        "portfolio_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in portfolio)
        ),
        "portfolio_guarantee": guarantee,
        "information_boundary": {
            "A300_target_key_label_available": False,
            "A300_target_model_used_for_order": False,
            "candidate_filter_outcome_used_for_order": False,
            "A300_result_available": False,
            "calibration_rule_changed_after_A300_measurement": False,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "A300_order_sha256": expected_a300_order_sha256,
            "candidate_execution_orders": payload["candidate_execution_orders"],
            "audit_only_order": payload["audit_only_order"],
            "portfolio_order_uint16be_sha256": payload[
                "portfolio_order_uint16be_sha256"
            ],
            "portfolio_guarantee": guarantee,
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(ORDER, payload)
    return payload


def load_order(
    expected_protocol_sha256: str, expected_order_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = load_protocol(expected_protocol_sha256)
    if file_sha256(ORDER) != expected_order_sha256:
        raise RuntimeError("A301 order hash differs")
    value = json.loads(ORDER.read_bytes())
    components = value.get("candidate_execution_orders", {})
    if (
        value.get("schema")
        != "chacha20-round20-w43-dominance-pruned-portfolio-a301-order-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("public_challenge_sha256")
        != protocol["public_challenge_sha256"]
        or set(components)
        != {
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        }
        or value.get("portfolio_guarantee", {}).get("violations") != 0
        or value.get("information_boundary", {}).get("A300_result_available")
        is not False
    ):
        raise RuntimeError("A301 order semantics differ")
    recomputed = two_operator_portfolio(
        coarse=components["A297_coarse_high8_then_reflected_Gray4"],
        numeric=components["numeric_word0_prefix12"],
    )
    if recomputed != value.get("portfolio_order"):
        raise RuntimeError("A301 portfolio order reconstruction differs")
    anchor(A300.ORDER, value["A300_order"]["sha256"])
    return protocol, value


def rank_analysis(
    *, prefix: int, order_value: Mapping[str, Any], challenge_sha: str
) -> dict[str, Any]:
    components = order_value["candidate_execution_orders"]
    portfolio = [int(value) for value in order_value["portfolio_order"]]
    coarse = [
        int(value)
        for value in components["A297_coarse_high8_then_reflected_Gray4"]
    ]
    numeric = [int(value) for value in components["numeric_word0_prefix12"]]
    a300_order = json.loads(A300.ORDER.read_bytes())
    fine = [
        int(value)
        for value in a300_order["component_orders"]["A295_fine_selected_channel"]
    ]
    ranks = {
        "A301_two_operator_portfolio": portfolio.index(prefix) + 1,
        "A297_coarse_high8_then_reflected_Gray4": coarse.index(prefix) + 1,
        "numeric_word0_prefix12": numeric.index(prefix) + 1,
        "A295_fine_selected_channel_audit_only": fine.index(prefix) + 1,
        "A300_three_operator_portfolio_counterfactual": [
            int(value) for value in a300_order["portfolio_order"]
        ].index(prefix)
        + 1,
        "public_hash_control": A300.A299.public_hash_order(challenge_sha).index(prefix)
        + 1,
    }
    best_allocated = min(
        ranks["A297_coarse_high8_then_reflected_Gray4"],
        ranks["numeric_word0_prefix12"],
    )
    portfolio_rank = ranks["A301_two_operator_portfolio"]
    if portfolio_rank > 2 * best_allocated:
        raise RuntimeError("A301 target rank violates the frozen portfolio guarantee")
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "best_allocated_component_rank_one_based": best_allocated,
        "portfolio_regret_factor_vs_best_allocated": portfolio_rank
        / best_allocated,
        "portfolio_regret_bits_vs_best_allocated": math.log2(
            portfolio_rank / best_allocated
        ),
        "portfolio_gain_bits_vs_complete_domain": math.log2(
            CELLS / portfolio_rank
        ),
        "portfolio_speedup_vs_public_hash_rank": ranks["public_hash_control"]
        / portfolio_rank,
        "portfolio_speedup_vs_A300_counterfactual": ranks[
            "A300_three_operator_portfolio_counterfactual"
        ]
        / portfolio_rank,
        "assignment_upper_bounds": {
            name: rank * GROUP_SIZE for name, rank in ranks.items()
        },
        "rank_guarantee_holds": True,
        "counterfactual_component_ranks_computed_only_after_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A301:confirmed_two_operator_W43_recovery"
    writer = CausalWriter(api_id="a301w43")
    writer._rules = []
    writer.add_rule(
        name="dominance_pruned_two_operator_rank_bound",
        description=(
            "Round-robin first-occurrence merging visits both allocated operator "
            "prefixes of rank r by portfolio position at most 2r."
        ),
        pattern=["calibration_pruned_operator_set", "two_operator_round_robin"],
        conclusion="A301_bounded_regret_portfolio_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="bounded_regret_order_to_confirmed_recovery",
        description=(
            "Each frozen prefix expands over every 2^31 residual assignment "
            "before dual eight-block confirmation."
        ),
        pattern=["A301_bounded_regret_portfolio_order", "dual_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A301:fourteen_target_calibration",
        mechanism="prune_twice_dominated_fine_execution_allocation",
        outcome="A301:frozen_two_operator_rank_bound",
        confidence=1.0,
        source=payload["calibration_sha256"],
        quantification=json.dumps(payload["calibration_aggregate"], sort_keys=True),
        evidence=json.dumps(payload["portfolio_guarantee"], sort_keys=True),
        domain="AI-native calibrated ChaCha20-R20 W43 operator allocation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A301:frozen_two_operator_rank_bound",
        mechanism="complete_2^31_candidate_groups_plus_dual_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="confirmed full-round ChaCha20 W43 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A301:fourteen_target_calibration",
        mechanism="materialized_pruning_order_discovery_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A301_calibrated_portfolio_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A301 calibrated W43 recovery",
        entities=[
            "A301:fourteen_target_calibration",
            "A301:frozen_two_operator_rank_bound",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="replicated_calibrated_portfolio_gain_or_wider_residual_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the frozen two-operator allocation retain gain on another sealed W43 or wider target?"
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
        reader.api_id != "a301w43"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A301 authentic Causal reopen gate failed")
    source = Path(inspect.getsourcefile(CausalReader) or "")
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
        "reader_source": anchor(source),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def recover(
    *, expected_protocol_sha256: str, expected_order_sha256: str, swiftc: str
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A301 final artifacts already exist")
    protocol, order_value = load_order(
        expected_protocol_sha256, expected_order_sha256
    )
    a300_protocol = A300.load_protocol(
        protocol["anchors"]["A300_protocol"]["sha256"]
    )
    challenge = a300_protocol["public_challenge"]
    executable, build = A300.A299.W43.A184._A181._compile_native(  # noqa: SLF001
        BUILD, swiftc
    )
    host = A300.A299.W43.A184.SliceMetalHost(
        executable,
        A300.A299.W43._initial(  # noqa: SLF001
            challenge["known_zeroed_key_words"],
            int(challenge["counter_start"]),
            challenge["nonce_words"],
            0,
        ),
        np.asarray(challenge["target_words"][0], dtype=np.uint32),
        np.asarray(challenge["control_target_words"], dtype=np.uint32),
    )
    try:
        mapping = A300.A299.W43._mapping_gate(  # noqa: SLF001
            host,
            known_zeroed_key_words=challenge["known_zeroed_key_words"],
            counter=int(challenge["counter_start"]),
            nonce_words=challenge["nonce_words"],
        )
        discovery = A300.A299.ordered_discovery(
            host=host,
            challenge=challenge,
            order=[int(value) for value in order_value["portfolio_order"]],
        )
        identity = host.identity
    finally:
        host.close()
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A301 matched one-bit control produced a filter candidate")
    confirmation = A300.A299.W43._confirm(  # noqa: SLF001
        {"challenge": challenge}, int(discovery["candidate"])
    )
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A301 dual independent confirmation failed")
    prefix = int(discovery["fine_prefix12"])
    ranks = rank_analysis(
        prefix=prefix,
        order_value=order_value,
        challenge_sha=protocol["public_challenge_sha256"],
    )
    portfolio_rank = ranks["prefix_ranks_one_based"][
        "A301_two_operator_portfolio"
    ]
    if portfolio_rank != discovery["executed_prefix_groups"]:
        raise RuntimeError("A301 discovery and portfolio ranks differ")
    strict_subset = portfolio_rank < CELLS
    evidence_stage = (
        "FULLROUND_R20_W43_CALIBRATED_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_W43_CALIBRATED_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w43-dominance-pruned-portfolio-a301-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "order_sha256": expected_order_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "calibration_sha256": protocol["calibration"]["sha256"],
        "calibration_aggregate": protocol["calibration_aggregate"],
        "native_build": build,
        "metal_identity": identity,
        "mapping_gate": mapping,
        "portfolio_guarantee": order_value["portfolio_guarantee"],
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "strict_subset_of_complete_domain": strict_subset,
        "information_boundary": order_value["information_boundary"],
        "anchors": protocol["anchors"],
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "mapping_gate": mapping,
            "discovery": {
                key: value
                for key, value in discovery.items()
                if not key.startswith("volatile_")
            },
            "metal_identity": identity,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": {
                key: value
                for key, value in discovery.items()
                if not key.startswith("volatile_")
            },
            "rank_analysis": ranks,
            "confirmation": confirmation,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A301 — calibrated two-operator ChaCha20-R20 W43 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Portfolio prefix rank: **{portfolio_rank} / 4,096**\n"
            f"- Search gain: **{ranks['portfolio_gain_bits_vs_complete_domain']:.6f} bits**\n"
            f"- Executed assignments: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W43 assignment: **0x{int(discovery['candidate']):011x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Calibration targets / strict subsets: **14 / 14**\n"
            "- Reader refits / target labels: **0 / 0**\n"
            "- Frozen guarantee: **R <= 2 min(R_coarse, R_numeric)**\n"
        ).encode()
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "calibration_complete": CALIBRATION.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "A300_order_complete": A300.ORDER.exists(),
        "A301_order_complete": ORDER.exists(),
        "result_complete": RESULT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--derive-order", action="store_true")
    mode.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-a300-protocol-sha256")
    parser.add_argument("--expected-a300-preflight-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-a300-order-sha256")
    parser.add_argument("--expected-order-sha256")
    parser.add_argument("--swiftc", default="/usr/bin/swiftc")
    args = parser.parse_args()
    if args.analyze:
        output = analyze()
    elif args.freeze:
        if not args.expected_a300_protocol_sha256 or not args.expected_a300_preflight_sha256:
            parser.error("--freeze requires both A300 protocol and preflight hashes")
        value = freeze(
            expected_a300_protocol_sha256=args.expected_a300_protocol_sha256,
            expected_a300_preflight_sha256=args.expected_a300_preflight_sha256,
        )
        output = {
            "calibration": relative(CALIBRATION),
            "calibration_sha256": value["calibration"]["sha256"],
            "protocol": relative(PROTOCOL),
            "protocol_sha256": file_sha256(PROTOCOL),
            "public_challenge_sha256": value["public_challenge_sha256"],
        }
    else:
        if not args.expected_protocol_sha256:
            parser.error("this mode requires --expected-protocol-sha256")
        if args.derive_order:
            if not args.expected_a300_order_sha256:
                parser.error("--derive-order requires --expected-a300-order-sha256")
            value = derive_order(
                expected_protocol_sha256=args.expected_protocol_sha256,
                expected_a300_order_sha256=args.expected_a300_order_sha256,
            )
            output = {
                "order": relative(ORDER),
                "order_sha256": file_sha256(ORDER),
                "evidence_stage": value["evidence_stage"],
                "portfolio_guarantee": value["portfolio_guarantee"],
            }
        else:
            if not args.expected_order_sha256:
                parser.error("--recover requires --expected-order-sha256")
            value = recover(
                expected_protocol_sha256=args.expected_protocol_sha256,
                expected_order_sha256=args.expected_order_sha256,
                swiftc=args.swiftc,
            )
            output = {
                "result": relative(RESULT),
                "result_sha256": file_sha256(RESULT),
                "causal_sha256": value["causal"]["sha256"],
                "evidence_stage": value["evidence_stage"],
                "rank_analysis": value["rank_analysis"],
            }
    print(json.dumps(output, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
