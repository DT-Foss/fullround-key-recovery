#!/usr/bin/env python3
"""Prospective three-operator ChaCha20-R20 W43 portfolio recovery."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import secrets
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"
ARTIFACTS = RESEARCH / "artifacts/a300_chacha20_r20_w43_three_operator_portfolio"

DESIGN = CONFIGS / "chacha20_round20_w43_three_operator_portfolio_a300_design_v1.json"
A299_RUNNER = RESEARCH / "experiments/chacha20_round20_w43_fine_selected_channel_transfer_a299.py"
A300_TEST = ROOT / "tests/test_chacha20_round20_w43_three_operator_portfolio_a300.py"

PROTOCOL = CONFIGS / "chacha20_round20_w43_three_operator_portfolio_a300_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_w43_three_operator_portfolio_a300_preflight_v1.json"
COARSE = RESULTS / "chacha20_round20_w43_three_operator_portfolio_a300_coarse_v1.json.zst"
ORDER = RESULTS / "chacha20_round20_w43_three_operator_portfolio_a300_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w43_three_operator_portfolio_a300_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_W43_THREE_OPERATOR_PORTFOLIO_A300_V1.md"
BUILD = RESEARCH / "build/chacha20_round20_w43_three_operator_portfolio_a300"
W43_HELPER_DERIVED = BUILD / "cadical_ranked_variable_prefix_reverse_w43_derived.cpp"
W43_HELPER_BINARY = BUILD / "cadical_ranked_variable_prefix_reverse_w43"

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A300"
DESIGN_SHA256 = "640dea44142309870faec5f4699283e84b8b30212803745c32f3ab04dd39170a"
WIDTH = 43
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
WORD1_LOW_BITS = 11
CELLS = 1 << PREFIX_BITS
LANES = 8
CELLS_PER_LANE = CELLS // LANES
INNER_GROUP_SIZE = 1 << WORD0_SUFFIX_BITS
OUTER_SLICES = 1 << WORD1_LOW_BITS
GROUP_SIZE = INNER_GROUP_SIZE * OUTER_SLICES
DOMAIN_SIZE = 1 << WIDTH
SECONDS_PER_CELL = 5.0
ZSTD_LEVEL = 10


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A300 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A299 = load_module(A299_RUNNER, "a300_a299_common")
sha256 = A299.sha256
file_sha256 = A299.file_sha256
canonical_bytes = A299.canonical_bytes
canonical_sha256 = A299.canonical_sha256
atomic_bytes = A299.atomic_bytes
atomic_json = A299.atomic_json
relative = A299.relative
path_from_ref = A299.path_from_ref
anchor = A299.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A300 prospective design hash differs")
    value = json.loads(DESIGN.read_bytes())
    operator = value.get("operator_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w43-three-operator-portfolio-a300-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_before_A299_order_result_candidate_rank_or_confirmation_and_before_the_fresh_A300_target_exists"
        or operator.get("component_orders")
        != [
            "numeric_word0_prefix12",
            "A297_coarse_high8_then_reflected_Gray4",
            "A295_fine_selected_channel",
        ]
        or operator.get("merge")
        != "round_robin_by_component_rank_then_first_occurrence_deduplication"
        or operator.get("merge_component_precedence")
        != [
            "A295_fine_selected_channel",
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        ]
        or boundary.get("A299_candidate_prefix_rank_or_result_available_at_freeze")
        is not False
        or boundary.get("A300_production_assignment_or_target_available_at_freeze")
        is not False
    ):
        raise RuntimeError("A300 prospective design semantics differ")
    return value


def _reader(path: Path) -> Any:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    return CausalReader(str(path), verify_integrity=True)


def _source_gates(
    expected_a293_result_sha256: str, expected_a295_result_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    design = load_design()
    if (
        expected_a295_result_sha256
        != design["source_anchors"]["A295_result_sha256"]
        or file_sha256(A299.A297_RESULT)
        != design["source_anchors"]["A297_result_sha256"]
        or file_sha256(A299.A295_RUNNER)
        != design["source_anchors"]["A295_runner_sha256"]
        or file_sha256(A299.A297_RUNNER)
        != design["source_anchors"]["A297_runner_sha256"]
    ):
        raise RuntimeError("A300 frozen source frontier differs")
    return A299._source_gates(  # noqa: SLF001
        expected_a293_result_sha256, expected_a295_result_sha256
    )


def execution_contract() -> dict[str, Any]:
    return {
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward_included": True,
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "public_output_blocks": 8,
        "fine_prefix_coordinates_high_to_low": list(range(31, 19, -1)),
        "prefix_cells": CELLS,
        "parallel_retained_state_lanes": LANES,
        "cells_per_lane": CELLS_PER_LANE,
        "seconds_per_cell": SECONDS_PER_CELL,
        "candidate_group_size": GROUP_SIZE,
        "complete_residual_domain": DOMAIN_SIZE,
        "component_orders": [
            "A295_fine_selected_channel",
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        ],
        "merge": "rank_round_robin_then_first_occurrence_deduplication",
        "rank_guarantee": "R_portfolio <= 3 * min(R_fine, R_coarse, R_numeric)",
        "reader_refits": 0,
        "target_labels_used": 0,
        "recovery": (
            "portfolio_ordered_word0_prefix12_groups_x_complete_word1_low11_"
            "slices_then_dual_independent_eight_block_confirmation"
        ),
    }


def reader_challenge(
    challenge: Mapping[str, Any], public_challenge_sha256: str
) -> dict[str, Any]:
    value = A299.reader_challenge(challenge)
    value["challenge_id"] = "a300-reader-view-of-chacha20-r20-w43-fresh-v1"
    value["source_public_challenge_sha256"] = public_challenge_sha256
    return value


def fresh_challenge() -> dict[str, Any]:
    label = f"A300|fresh|{secrets.token_hex(32)}"
    assignment = secrets.randbits(WIDTH)
    challenge = A299.W43._challenge_from_assignment(  # noqa: SLF001
        label=label, assignment=assignment
    )
    del assignment
    A299.W43._validate_challenge(challenge)  # noqa: SLF001
    return challenge


def freeze(
    *, expected_a293_result_sha256: str, expected_a295_result_sha256: str
) -> dict[str, Any]:
    if any(
        path.exists()
        for path in (PROTOCOL, PREFLIGHT, COARSE, ORDER, RESULT, CAUSAL, REPORT)
    ) or ARTIFACTS.exists():
        raise FileExistsError("A300 artifacts already exist")
    design = load_design()
    a293, a295 = _source_gates(
        expected_a293_result_sha256, expected_a295_result_sha256
    )
    if not A300_TEST.exists():
        raise FileNotFoundError("A300 tests must exist before target generation")
    runner_sha = file_sha256(Path(__file__))
    test_sha = file_sha256(A300_TEST)
    challenge = fresh_challenge()
    public_sha = canonical_sha256(challenge)
    adapted = reader_challenge(challenge, public_sha)
    plan = execution_contract()
    reader_source = Path(inspect.getsourcefile(type(_reader(A299.A297_CAUSAL))) or "")
    payload = {
        "schema": "chacha20-round20-w43-three-operator-portfolio-a300-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": (
            "fresh_W43_target_and_three_operator_contract_frozen_before_CNF_"
            "export_measurement_order_or_candidate_discovery"
        ),
        "design": design,
        "execution_contract": plan,
        "execution_contract_sha256": canonical_sha256(plan),
        "public_challenge": challenge,
        "public_challenge_sha256": public_sha,
        "reader_challenge": adapted,
        "reader_challenge_sha256": canonical_sha256(adapted),
        "source_results": {
            "A293_result_sha256": expected_a293_result_sha256,
            "A295_result_sha256": expected_a295_result_sha256,
            "A293_coverage": a293["coverage"],
            "A295_rank_analysis": a295["rank_analysis"],
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "runner": anchor(Path(__file__), runner_sha),
            "test": anchor(A300_TEST, test_sha),
            "A299_runner": anchor(A299_RUNNER),
            "A293_result": anchor(A299.A293_RESULT, expected_a293_result_sha256),
            "A293_causal": anchor(A299.A293_CAUSAL),
            "A295_result": anchor(A299.A295_RESULT, expected_a295_result_sha256),
            "A295_causal": anchor(A299.A295_CAUSAL),
            "A295_runner": anchor(A299.A295_RUNNER),
            "A297_result": anchor(A299.A297_RESULT),
            "A297_causal": anchor(A299.A297_CAUSAL),
            "A297_runner": anchor(A299.A297_RUNNER),
            "A296_runner": anchor(A299.A297.A296_RUNNER),
            "A223_source": anchor(A299.A297.A223_SOURCE),
            "A223_config": anchor(A299.A297.A223_CONFIG),
            "A251_wrapper": anchor(A299.A297.A251_WRAPPER),
            "W43_runner": anchor(A299.W43_RUNNER),
            "W43_qualification": anchor(A299.W43_QUALIFICATION),
            "Metal_anchor": anchor(A299.A297.METAL_ANCHOR),
            "CausalReader": anchor(reader_source),
        },
        "information_boundary": {
            "runner_and_tests_hashed_before_fresh_target_generation": True,
            "fresh_assignment_generated_only_to_materialize_public_outputs": True,
            "fresh_assignment_stored": False,
            "full_key_stored": False,
            "A299_order_result_candidate_or_rank_used": False,
            "target_measurement_order_model_or_filter_outcome_available_at_freeze": False,
            "operator_family_merge_rule_and_precedence_frozen": True,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "execution_contract": plan,
            "public_challenge_sha256": public_sha,
            "reader_challenge_sha256": payload["reader_challenge_sha256"],
            "information_boundary": payload["information_boundary"],
            "anchors": payload["anchors"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A300 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-three-operator-portfolio-a300-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("execution_contract") != execution_contract()
        or canonical_sha256(value.get("public_challenge"))
        != value.get("public_challenge_sha256")
        or canonical_sha256(value.get("reader_challenge"))
        != value.get("reader_challenge_sha256")
        or value.get("anchors", {}).get("runner", {}).get("sha256")
        != file_sha256(Path(__file__))
        or value.get("anchors", {}).get("test", {}).get("sha256")
        != file_sha256(A300_TEST)
        or value.get("information_boundary", {}).get("fresh_assignment_stored")
        is not False
        or value.get("information_boundary", {}).get(
            "A299_order_result_candidate_or_rank_used"
        )
        is not False
    ):
        raise RuntimeError("A300 protocol semantics differ")
    A299.W43._validate_challenge(value["public_challenge"])  # noqa: SLF001
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    return value


def preflight(expected_protocol_sha256: str) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A300 preflight artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    a223 = load_module(A299.A297.A223_SOURCE, "a300_a223_preflight")
    config = json.loads(A299.A297.A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    original = A299.A297.A296.ARTIFACTS
    try:
        A299.A297.A296.ARTIFACTS = ARTIFACTS / "preflight"
        row = A299.export_reader_cnf_w43(
            a223=a223,
            config=config,
            challenge=protocol["reader_challenge"],
        )
    finally:
        A299.A297.A296.ARTIFACTS = original
    mapping = [int(value) for value in row["source_one_literals_bit0_upward"]]
    if len(mapping) != WIDTH or len({abs(value) for value in mapping}) != WIDTH:
        raise RuntimeError("A300 W43 source literal mapping differs")
    coarse_view = [*mapping[:12], *mapping[24:32]]
    row["synthetic_reader_mapping"] = coarse_view
    row["synthetic_reader_mapping_sha256"] = canonical_sha256(coarse_view)
    row["partition_coordinates_high_to_low"] = list(range(31, 19, -1))
    row["coarse_partition_coordinates_high_to_low"] = list(range(31, 23, -1))
    row["diagnostic_model_view_coordinates"] = [*range(12), *range(24, 32)]
    payload = {
        "schema": "chacha20-round20-w43-three-operator-portfolio-a300-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FRESH_W43_TARGET_CNF_AND_WORD0_LITERAL_MAP_FROZEN_BEFORE_ANY_A300_MEASUREMENT"
        ),
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "target": row,
        "measurement_started_before_preflight": False,
        "A299_order_result_candidate_or_rank_used": False,
        "preflight_sha256": canonical_sha256(row),
    }
    atomic_json(PREFLIGHT, payload)
    return payload


def load_preflight(
    expected_protocol_sha256: str, expected_preflight_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = load_protocol(expected_protocol_sha256)
    if file_sha256(PREFLIGHT) != expected_preflight_sha256:
        raise RuntimeError("A300 preflight hash differs")
    value = json.loads(PREFLIGHT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-three-operator-portfolio-a300-preflight-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("public_challenge_sha256")
        != protocol["public_challenge_sha256"]
        or value.get("A299_order_result_candidate_or_rank_used") is not False
    ):
        raise RuntimeError("A300 preflight semantics differ")
    anchor(
        path_from_ref(value["target"]["CNF"]["path"]),
        value["target"]["CNF"]["sha256"],
    )
    return protocol, value


def coarse_measurement(
    protocol: Mapping[str, Any], preflight_value: Mapping[str, Any]
) -> dict[str, Any]:
    a275, model, _a291, indices, helper = A299.A297.A296._reader_stack()  # noqa: SLF001
    wrapper = load_module(A299.A297.A251_WRAPPER, "a300_clause_wrapper")
    row = preflight_value["target"]
    started = time.perf_counter()
    raw_run = wrapper.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["CNF"]["path"]),
        mode="A300_W43_word0_high8_numeric_unlabeled",
        order=[f"{value:08b}" for value in range(256)],
        key_one_literals_bit0_through_bit19=row["synthetic_reader_mapping"],
        conflict_horizons=A299.A297.HORIZONS,
        watchdog_seconds=A299.A297.WATCHDOG_SECONDS,
        external_timeout_seconds=1800.0,
    )
    stable = {
        key: value
        for key, value in raw_run.items()
        if key not in {"command", "process_elapsed_seconds"}
    }
    measurement = {
        "schema": "chacha20-round20-w43-three-operator-portfolio-a300-coarse-measurement-v1",
        "attempt_id": ATTEMPT_ID,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "unknown_key_bits": WIDTH,
        "order_name": "numeric",
        "partition_scope": "key_word0",
        "partition_coordinates_high_to_low": list(range(31, 23, -1)),
        "free_bits_per_cell": WIDTH - 8,
        "run": stable,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "target_label_available_to_measurement": False,
        "label_used_for_feature_construction_or_scoring": False,
        "complete_candidate_cover": len(raw_run["cells"]) == 256,
    }
    matrix = a275._target_feature_matrix(measurement)  # noqa: SLF001
    contributions = a275.standardized_contributions(
        matrix,
        means=model.means,
        scales=model.scales,
        coefficients=model.coefficients,
    )
    scores = contributions[:, indices].sum(axis=1)
    order = a275._candidate_order(scores)  # noqa: SLF001
    if len(order) != 256 or set(order) != set(range(256)):
        raise RuntimeError("A300 coarse order is not an exact cover")
    raw = canonical_bytes(measurement)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    atomic_bytes(COARSE, compressed)
    return {
        "measurement": {
            "path": relative(COARSE),
            "raw_bytes": len(raw),
            "raw_sha256": sha256(raw),
            "compressed_bytes": len(compressed),
            "compressed_sha256": sha256(compressed),
        },
        "score_field": np.asarray(scores, dtype=np.float64).tolist(),
        "score_field_sha256": canonical_sha256(
            np.asarray(scores, dtype=np.float64).tolist()
        ),
        "complete_coarse_order": order,
        "complete_coarse_order_uint8_sha256": sha256(bytes(order)),
        "selected_feature_indices": list(indices),
        "model_refits": 0,
        "target_labels_used": 0,
        "model_free_UNKNOWN_stages": len(stable["stages"]),
    }


def fine_lane_plan(
    coarse_order: Sequence[int], preflight_value: Mapping[str, Any]
) -> dict[str, Any]:
    plan = A299.fine_lane_plan(coarse_order, preflight_value)
    for lane, arm in enumerate(plan["arms"]):
        arm["arm"] = f"a300_fine12_lane{lane}"
    return plan


def trace_rows(directory: Path) -> list[dict[str, Any]]:
    return A299._trace_rows(directory)  # noqa: SLF001


def round_robin_portfolio(
    *, fine: Sequence[int], coarse: Sequence[int], numeric: Sequence[int]
) -> list[int]:
    orders = [
        [int(value) for value in fine],
        [int(value) for value in coarse],
        [int(value) for value in numeric],
    ]
    if any(len(order) != CELLS or set(order) != set(range(CELLS)) for order in orders):
        raise ValueError("A300 component order is not an exact prefix cover")
    result: list[int] = []
    seen: set[int] = set()
    for rank in range(CELLS):
        for order in orders:
            value = order[rank]
            if value not in seen:
                seen.add(value)
                result.append(value)
    if len(result) != CELLS or set(result) != set(range(CELLS)):
        raise RuntimeError("A300 portfolio merge is not an exact prefix cover")
    return result


def portfolio_guarantee(
    *, portfolio: Sequence[int], fine: Sequence[int], coarse: Sequence[int], numeric: Sequence[int]
) -> dict[str, Any]:
    ranks = {
        "portfolio": {value: rank for rank, value in enumerate(portfolio, 1)},
        "fine": {value: rank for rank, value in enumerate(fine, 1)},
        "coarse": {value: rank for rank, value in enumerate(coarse, 1)},
        "numeric": {value: rank for rank, value in enumerate(numeric, 1)},
    }
    worst_factor = 0.0
    worst_cell = 0
    for cell in range(CELLS):
        best = min(ranks[name][cell] for name in ("fine", "coarse", "numeric"))
        observed = ranks["portfolio"][cell]
        if observed > 3 * best:
            raise RuntimeError("A300 portfolio rank guarantee failed")
        factor = observed / best
        if factor > worst_factor:
            worst_factor = factor
            worst_cell = cell
    return {
        "statement": "R_portfolio <= 3 * min(R_fine, R_coarse, R_numeric)",
        "checked_prefix_cells": CELLS,
        "violations": 0,
        "maximum_observed_regret_factor": worst_factor,
        "maximum_observed_regret_bits": math.log2(worst_factor),
        "maximum_observed_regret_cell": worst_cell,
        "frozen_worst_case_bound_factor": 3,
        "frozen_worst_case_bound_bits": math.log2(3),
    }


def measure(
    *, expected_protocol_sha256: str, expected_preflight_sha256: str
) -> dict[str, Any]:
    if COARSE.exists() or ORDER.exists() or (ARTIFACTS / "fine").exists():
        raise FileExistsError("A300 measurement artifacts already exist")
    protocol, preflight_value = load_preflight(
        expected_protocol_sha256, expected_preflight_sha256
    )
    coarse_readout = coarse_measurement(protocol, preflight_value)
    plan = fine_lane_plan(coarse_readout["complete_coarse_order"], preflight_value)
    helper_build = A299.compile_w43_helper(
        output=W43_HELPER_BINARY,
        derived_source=W43_HELPER_DERIVED,
    )
    a293 = load_module(A299.A293_RUNNER, "a300_a293_fine_runner")
    original = (
        a293.WIDTH,
        a293.SUFFIX_BITS,
        a293.ARTIFACTS,
        a293.HELPER_BINARY,
    )
    try:
        a293.WIDTH = WIDTH
        a293.SUFFIX_BITS = WIDTH - PREFIX_BITS
        a293.ARTIFACTS = ARTIFACTS / "fine"
        a293.HELPER_BINARY = W43_HELPER_BINARY
        solver_rows, raw_winner = a293.run_partition(
            {"execution_plan": {"arms": plan["arms"]}}
        )
    finally:
        (
            a293.WIDTH,
            a293.SUFFIX_BITS,
            a293.ARTIFACTS,
            a293.HELPER_BINARY,
        ) = original
    if raw_winner is not None:
        raise RuntimeError(
            "A300 symbolic model appeared before complete field closure; preserve it as a direct-recovery boundary"
        )
    traces = trace_rows(ARTIFACTS / "fine")
    attempted = [str(row["prefix"]) for row in traces]
    if (
        len(traces) != CELLS
        or len(attempted) != len(set(attempted))
        or set(attempted) != {f"{value:012b}" for value in range(CELLS)}
        or any(
            row.get("status") != "unknown"
            or row.get("model_bits_bit0_upward") != []
            or row.get("failed_assumptions") != []
            or row.get("returncode") != 0
            for row in traces
        )
    ):
        raise RuntimeError("A300 requires a complete clean model-free fine field")
    a295 = load_module(A299.A295_RUNNER, "a300_a295_reader")
    fine_readout = a295.frozen_order(traces)
    fine = [int(value) for value in fine_readout["complete_order"]]
    coarse = A299.A297.A296.fine_order(
        [int(value) for value in coarse_readout["complete_coarse_order"]]
    )
    numeric = list(range(CELLS))
    portfolio = round_robin_portfolio(fine=fine, coarse=coarse, numeric=numeric)
    guarantee = portfolio_guarantee(
        portfolio=portfolio, fine=fine, coarse=coarse, numeric=numeric
    )
    trace_anchors = [
        anchor(path)
        for path in sorted((ARTIFACTS / "fine").glob("*"))
        if path.is_file()
    ]
    components = {
        "A295_fine_selected_channel": fine,
        "A297_coarse_high8_then_reflected_Gray4": coarse,
        "numeric_word0_prefix12": numeric,
    }
    payload = {
        "schema": "chacha20-round20-w43-three-operator-portfolio-a300-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FRESH_W43_COMPLETE_MODEL_FREE_THREE_OPERATOR_PORTFOLIO_ORDER_FROZEN",
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "coarse_readout": coarse_readout,
        "fine_readout": fine_readout,
        "w43_helper_build": helper_build,
        "fine_lane_plan": {
            "fine_seed_order_uint16be_sha256": plan["fine_seed_order_uint16be_sha256"],
            "model_index_to_assignment_coordinate": plan[
                "model_index_to_assignment_coordinate"
            ],
            "model_permutation_sha256": plan["model_permutation_sha256"],
            "arms": plan["arms"],
        },
        "solver_arms": solver_rows,
        "attempted_prefix_cells": len(attempted),
        "component_orders": components,
        "component_order_sha256": {
            name: sha256(b"".join(value.to_bytes(2, "big") for value in order))
            for name, order in components.items()
        },
        "portfolio_order": portfolio,
        "portfolio_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in portfolio)
        ),
        "portfolio_guarantee": guarantee,
        "trace_artifacts": trace_anchors,
        "information_boundary": {
            "target_key_label_available": False,
            "target_model_used_for_order": False,
            "candidate_filter_outcome_used_for_order": False,
            "A299_order_result_candidate_or_rank_used": False,
            "reader_refits": 0,
            "target_labels_used": 0,
            "all_component_and_portfolio_orders_frozen_before_Metal_candidate_discovery": True,
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "coarse_readout": coarse_readout,
            "fine_readout": fine_readout,
            "w43_helper_build": helper_build,
            "solver_arms": solver_rows,
            "component_order_sha256": payload["component_order_sha256"],
            "portfolio_order_uint16be_sha256": payload[
                "portfolio_order_uint16be_sha256"
            ],
            "portfolio_guarantee": guarantee,
            "trace_artifacts": trace_anchors,
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(ORDER, payload)
    return payload


def load_order(
    expected_protocol_sha256: str,
    expected_preflight_sha256: str,
    expected_order_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    protocol, preflight_value = load_preflight(
        expected_protocol_sha256, expected_preflight_sha256
    )
    if file_sha256(ORDER) != expected_order_sha256:
        raise RuntimeError("A300 order hash differs")
    value = json.loads(ORDER.read_bytes())
    components = value.get("component_orders", {})
    if (
        value.get("schema")
        != "chacha20-round20-w43-three-operator-portfolio-a300-order-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("preflight_sha256") != expected_preflight_sha256
        or value.get("public_challenge_sha256")
        != protocol["public_challenge_sha256"]
        or len(value.get("portfolio_order", [])) != CELLS
        or set(value.get("portfolio_order", [])) != set(range(CELLS))
        or set(components)
        != {
            "A295_fine_selected_channel",
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        }
        or value.get("portfolio_guarantee", {}).get("violations") != 0
        or value.get("information_boundary", {}).get(
            "A299_order_result_candidate_or_rank_used"
        )
        is not False
    ):
        raise RuntimeError("A300 order semantics differ")
    recomputed = round_robin_portfolio(
        fine=components["A295_fine_selected_channel"],
        coarse=components["A297_coarse_high8_then_reflected_Gray4"],
        numeric=components["numeric_word0_prefix12"],
    )
    if recomputed != value["portfolio_order"]:
        raise RuntimeError("A300 portfolio order reconstruction differs")
    for row in value["trace_artifacts"]:
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(COARSE, value["coarse_readout"]["measurement"]["compressed_sha256"])
    helper = value["w43_helper_build"]
    anchor(Path(helper["binary_path"]), helper["binary_sha256"])
    anchor(Path(helper["derived_source_path"]), helper["derived_source_sha256"])
    return protocol, preflight_value, value


def rank_analysis(
    *, prefix: int, order_value: Mapping[str, Any], challenge_sha: str
) -> dict[str, Any]:
    components = order_value["component_orders"]
    portfolio = [int(value) for value in order_value["portfolio_order"]]
    ranks = {
        "A300_three_operator_portfolio": portfolio.index(prefix) + 1,
        "A295_fine_selected_channel": [
            int(value) for value in components["A295_fine_selected_channel"]
        ].index(prefix)
        + 1,
        "A297_coarse_high8_then_reflected_Gray4": [
            int(value)
            for value in components["A297_coarse_high8_then_reflected_Gray4"]
        ].index(prefix)
        + 1,
        "numeric_word0_prefix12": [
            int(value) for value in components["numeric_word0_prefix12"]
        ].index(prefix)
        + 1,
        "public_hash_control": A299.public_hash_order(challenge_sha).index(prefix)
        + 1,
    }
    best = min(
        ranks[name]
        for name in (
            "A295_fine_selected_channel",
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        )
    )
    portfolio_rank = ranks["A300_three_operator_portfolio"]
    if portfolio_rank > 3 * best:
        raise RuntimeError("A300 target rank violates the frozen portfolio guarantee")
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "best_component_rank_one_based": best,
        "portfolio_regret_factor_vs_best_component": portfolio_rank / best,
        "portfolio_regret_bits_vs_best_component": math.log2(portfolio_rank / best),
        "portfolio_gain_bits_vs_complete_domain": math.log2(CELLS / portfolio_rank),
        "portfolio_speedup_vs_public_hash_rank": (
            ranks["public_hash_control"] / portfolio_rank
        ),
        "assignment_upper_bounds": {
            name: rank * GROUP_SIZE for name, rank in ranks.items()
        },
        "rank_guarantee_holds": True,
        "counterfactual_component_ranks_computed_only_after_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A300:confirmed_three_operator_W43_recovery"
    writer = CausalWriter(api_id="a300w43")
    writer._rules = []
    writer.add_rule(
        name="three_operator_round_robin_rank_bound",
        description="Round-robin first-occurrence merging visits every operator prefix of rank r by portfolio position at most 3r.",
        pattern=["three_frozen_component_orders", "round_robin_deduplication"],
        conclusion="A300_bounded_regret_portfolio_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="bounded_regret_order_to_confirmed_recovery",
        description="Each frozen prefix expands over every 2^31 residual assignment before dual eight-block confirmation.",
        pattern=["A300_bounded_regret_portfolio_order", "dual_eight_block_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A300:fresh_W43_public_relation",
        mechanism="A295_fine_plus_A297_coarse_plus_numeric_round_robin",
        outcome="A300:frozen_bounded_regret_prefix_order",
        confidence=1.0,
        source=payload["order_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=json.dumps(payload["portfolio_guarantee"], sort_keys=True),
        domain="AI-native multi-operator ChaCha20-R20 W43 readout",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A300:frozen_bounded_regret_prefix_order",
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
        trigger="A300:fresh_W43_public_relation",
        mechanism="materialized_portfolio_order_discovery_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A300_three_operator_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A300 bounded-regret W43 recovery",
        entities=[
            "A300:fresh_W43_public_relation",
            "A300:frozen_bounded_regret_prefix_order",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="replicated_W43_portfolio_gain_or_wider_residual_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the frozen portfolio retain strict-subset gain across more W43 targets or wider residual domains?"
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
        reader.api_id != "a300w43"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A300 authentic Causal reopen gate failed")
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
    *,
    expected_protocol_sha256: str,
    expected_preflight_sha256: str,
    expected_order_sha256: str,
    swiftc: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A300 final artifacts already exist")
    protocol, _preflight, order_value = load_order(
        expected_protocol_sha256,
        expected_preflight_sha256,
        expected_order_sha256,
    )
    challenge = protocol["public_challenge"]
    executable, build = A299.W43.A184._A181._compile_native(BUILD, swiftc)  # noqa: SLF001
    host = A299.W43.A184.SliceMetalHost(
        executable,
        A299.W43._initial(  # noqa: SLF001
            challenge["known_zeroed_key_words"],
            int(challenge["counter_start"]),
            challenge["nonce_words"],
            0,
        ),
        np.asarray(challenge["target_words"][0], dtype=np.uint32),
        np.asarray(challenge["control_target_words"], dtype=np.uint32),
    )
    try:
        mapping = A299.W43._mapping_gate(  # noqa: SLF001
            host,
            known_zeroed_key_words=challenge["known_zeroed_key_words"],
            counter=int(challenge["counter_start"]),
            nonce_words=challenge["nonce_words"],
        )
        order = [int(value) for value in order_value["portfolio_order"]]
        discovery = A299.ordered_discovery(
            host=host, challenge=challenge, order=order
        )
        identity = host.identity
    finally:
        host.close()
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A300 matched one-bit control produced a filter candidate")
    confirmation = A299.W43._confirm(  # noqa: SLF001
        {"challenge": challenge}, int(discovery["candidate"])
    )
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A300 dual independent confirmation failed")
    prefix = int(discovery["fine_prefix12"])
    ranks = rank_analysis(
        prefix=prefix,
        order_value=order_value,
        challenge_sha=protocol["public_challenge_sha256"],
    )
    if (
        ranks["prefix_ranks_one_based"]["A300_three_operator_portfolio"]
        != discovery["executed_prefix_groups"]
    ):
        raise RuntimeError("A300 discovery and portfolio ranks differ")
    evidence_stage = "FULLROUND_R20_W43_THREE_OPERATOR_STRICT_SUBSET_RECOVERY_CONFIRMED"
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w43-three-operator-portfolio-a300-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "order_sha256": expected_order_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "native_build": build,
        "metal_identity": identity,
        "mapping_gate": mapping,
        "portfolio_guarantee": order_value["portfolio_guarantee"],
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
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
    portfolio_rank = ranks["prefix_ranks_one_based"][
        "A300_three_operator_portfolio"
    ]
    atomic_bytes(
        REPORT,
        (
            "# A300 — three-operator ChaCha20-R20 W43 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Portfolio prefix rank: **{portfolio_rank} / 4,096**\n"
            f"- Search gain: **{ranks['portfolio_gain_bits_vs_complete_domain']:.6f} bits**\n"
            f"- Executed assignments: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W43 assignment: **0x{int(discovery['candidate']):011x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Reader refits / target labels: **0 / 0**\n"
            "- Frozen portfolio guarantee: **R <= 3 min(R_fine, R_coarse, R_numeric)**\n"
        ).encode()
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "protocol_frozen": PROTOCOL.exists(),
        "preflight_complete": PREFLIGHT.exists(),
        "order_complete": ORDER.exists(),
        "result_complete": RESULT.exists(),
        "A299_outcome_used": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--measure", action="store_true")
    mode.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-a293-result-sha256")
    parser.add_argument("--expected-a295-result-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-preflight-sha256")
    parser.add_argument("--expected-order-sha256")
    parser.add_argument("--swiftc", default="/usr/bin/swiftc")
    args = parser.parse_args()
    if args.analyze:
        output = analyze()
    elif args.freeze:
        if not args.expected_a293_result_sha256 or not args.expected_a295_result_sha256:
            parser.error("--freeze requires both source result hashes")
        value = freeze(
            expected_a293_result_sha256=args.expected_a293_result_sha256,
            expected_a295_result_sha256=args.expected_a295_result_sha256,
        )
        output = {
            "protocol": relative(PROTOCOL),
            "protocol_sha256": file_sha256(PROTOCOL),
            "public_challenge_sha256": value["public_challenge_sha256"],
        }
    else:
        if not args.expected_protocol_sha256:
            parser.error("this mode requires --expected-protocol-sha256")
        if args.preflight:
            value = preflight(args.expected_protocol_sha256)
            output = {
                "preflight": relative(PREFLIGHT),
                "preflight_sha256": file_sha256(PREFLIGHT),
                "evidence_stage": value["evidence_stage"],
            }
        else:
            if not args.expected_preflight_sha256:
                parser.error("--measure/--recover requires --expected-preflight-sha256")
            if args.measure:
                value = measure(
                    expected_protocol_sha256=args.expected_protocol_sha256,
                    expected_preflight_sha256=args.expected_preflight_sha256,
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
                    expected_preflight_sha256=args.expected_preflight_sha256,
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
