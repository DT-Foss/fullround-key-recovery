#!/usr/bin/env python3
"""A302: fresh W43 replication with calibrated coarse/numeric Causal order."""

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
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"
ARTIFACTS = RESEARCH / "artifacts/a302_chacha20_r20_w43_coarse_numeric_replication"

DESIGN = CONFIGS / "chacha20_round20_w43_calibrated_coarse_numeric_replication_a302_design_v1.json"
A301_RUNNER = RESEARCH / "experiments/chacha20_round20_w43_dominance_pruned_portfolio_a301.py"
A302_TEST = ROOT / "tests/test_chacha20_round20_w43_calibrated_coarse_numeric_replication_a302.py"

PROTOCOL = CONFIGS / "chacha20_round20_w43_calibrated_coarse_numeric_replication_a302_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_w43_calibrated_coarse_numeric_replication_a302_preflight_v1.json"
COARSE = RESULTS / "chacha20_round20_w43_calibrated_coarse_numeric_replication_a302_coarse_v1.json.zst"
ORDER = RESULTS / "chacha20_round20_w43_calibrated_coarse_numeric_replication_a302_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w43_calibrated_coarse_numeric_replication_a302_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_W43_CALIBRATED_COARSE_NUMERIC_REPLICATION_A302_V1.md"
BUILD = RESEARCH / "build/chacha20_round20_w43_calibrated_coarse_numeric_replication_a302"

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A302"
DESIGN_SHA256 = "d5792178976e49de1b7c768f72e68ef1c809237e41dd954ff32c215f3d5f2b91"
WIDTH = 43
PREFIX_BITS = 12
CELLS = 1 << PREFIX_BITS
COARSE_CELLS = 1 << 8
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
ZSTD_LEVEL = 10


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A302 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A301 = load_module(A301_RUNNER, "a302_a301_common")
A300 = A301.A300
sha256 = A301.sha256
file_sha256 = A301.file_sha256
canonical_bytes = A300.canonical_bytes
canonical_sha256 = A301.canonical_sha256
atomic_bytes = A301.atomic_bytes
atomic_json = A301.atomic_json
relative = A301.relative
path_from_ref = A301.path_from_ref
anchor = A301.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A302 prospective design hash differs")
    value = json.loads(DESIGN.read_bytes())
    measurement = value.get("measurement_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w43-calibrated-coarse-numeric-replication-a302-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A301_calibration_and_before_A302_runner_protocol_target_measurement_order_or_candidate_exists"
        or measurement.get("coarse_cells") != COARSE_CELLS
        or measurement.get("fine_cells") != 0
        or measurement.get("expected_model_free_stages") != 1024
        or boundary.get("A300_result_available_at_freeze") is not False
        or boundary.get("A301_result_available_at_freeze") is not False
        or boundary.get(
            "A302_production_assignment_target_measurement_order_model_candidate_filter_outcome_or_rank_available_at_freeze"
        )
        is not False
    ):
        raise RuntimeError("A302 prospective design semantics differ")
    return value


def execution_contract() -> dict[str, Any]:
    return {
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward_included": True,
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "public_output_blocks": 8,
        "coarse_partition_coordinates_high_to_low": list(range(31, 23, -1)),
        "coarse_cells": COARSE_CELLS,
        "conflict_horizons_per_cell": len(A300.A299.A297.HORIZONS),
        "fine_cells": 0,
        "prefix_cells": CELLS,
        "candidate_group_size": GROUP_SIZE,
        "complete_residual_domain": DOMAIN_SIZE,
        "candidate_execution_orders": [
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        ],
        "merge": "rank_round_robin_then_first_occurrence_deduplication",
        "rank_guarantee": "R_A302 <= 2 * min(R_coarse, R_numeric)",
        "reader_refits": 0,
        "target_labels_used": 0,
        "recovery": (
            "portfolio_ordered_word0_prefix12_groups_x_complete_word1_low11_"
            "slices_then_dual_independent_eight_block_confirmation"
        ),
    }


def fresh_challenge() -> dict[str, Any]:
    label = f"A302|fresh|{secrets.token_hex(32)}"
    assignment = secrets.randbits(WIDTH)
    challenge = A300.A299.W43._challenge_from_assignment(  # noqa: SLF001
        label=label, assignment=assignment
    )
    del assignment
    A300.A299.W43._validate_challenge(challenge)  # noqa: SLF001
    return challenge


def reader_challenge(
    challenge: Mapping[str, Any], public_challenge_sha256: str
) -> dict[str, Any]:
    value = A300.A299.reader_challenge(challenge)
    value["challenge_id"] = "a302-reader-view-of-chacha20-r20-w43-fresh-v1"
    value["source_public_challenge_sha256"] = public_challenge_sha256
    return value


def freeze() -> dict[str, Any]:
    if any(
        path.exists()
        for path in (PROTOCOL, PREFLIGHT, COARSE, ORDER, RESULT, CAUSAL, REPORT)
    ) or ARTIFACTS.exists():
        raise FileExistsError("A302 artifacts already exist")
    design = load_design()
    sources = design["source_anchors"]
    for path_key, sha_key in (
        ("A301_design_path", "A301_design_sha256"),
        ("A301_calibration_path", "A301_calibration_sha256"),
        ("A301_protocol_path", "A301_protocol_sha256"),
        ("A301_runner_path", "A301_runner_sha256"),
        ("A301_test_path", "A301_test_sha256"),
        ("A297_runner_path", "A297_runner_sha256"),
        ("A297_result_path", "A297_result_sha256"),
        ("A297_causal_path", "A297_causal_sha256"),
    ):
        anchor(path_from_ref(sources[path_key]), sources[sha_key])
    a301_protocol = A301.load_protocol(sources["A301_protocol_sha256"])
    calibration = json.loads(
        path_from_ref(sources["A301_calibration_path"]).read_bytes()
    )
    aggregate = calibration["aggregate"]
    if (
        aggregate.get("targets") != 14
        or aggregate.get("strict_subset_targets") != 14
        or aggregate.get("fine_operator_dominated_calibrations") != 2
        or A300.RESULT.exists()
        or A301.RESULT.exists()
    ):
        raise RuntimeError("A302 frozen learning frontier differs")
    if not A302_TEST.exists():
        raise FileNotFoundError("A302 tests must exist before target generation")
    challenge = fresh_challenge()
    public_sha = canonical_sha256(challenge)
    adapted = reader_challenge(challenge, public_sha)
    plan = execution_contract()
    reader_source = Path(
        inspect.getsourcefile(type(A300._reader(A300.A299.A297_CAUSAL))) or ""
    )
    payload = {
        "schema": "chacha20-round20-w43-calibrated-coarse-numeric-replication-a302-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "fresh_W43_target_and_calibrated_coarse_numeric_contract_frozen_before_CNF_measurement_order_or_candidate_discovery",
        "design": design,
        "execution_contract": plan,
        "execution_contract_sha256": canonical_sha256(plan),
        "public_challenge": challenge,
        "public_challenge_sha256": public_sha,
        "reader_challenge": adapted,
        "reader_challenge_sha256": canonical_sha256(adapted),
        "calibration_aggregate": aggregate,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A302_TEST),
            "A301_design": anchor(A301.DESIGN, sources["A301_design_sha256"]),
            "A301_calibration": anchor(
                A301.CALIBRATION, sources["A301_calibration_sha256"]
            ),
            "A301_protocol": anchor(
                A301.PROTOCOL, sources["A301_protocol_sha256"]
            ),
            "A301_runner": anchor(A301_RUNNER, sources["A301_runner_sha256"]),
            "A297_runner": anchor(
                A300.A299.A297_RUNNER, sources["A297_runner_sha256"]
            ),
            "A297_result": anchor(
                A300.A299.A297_RESULT, sources["A297_result_sha256"]
            ),
            "A297_causal": anchor(
                A300.A299.A297_CAUSAL, sources["A297_causal_sha256"]
            ),
            "A223_source": anchor(A300.A299.A297.A223_SOURCE),
            "A223_config": anchor(A300.A299.A297.A223_CONFIG),
            "A251_wrapper": anchor(A300.A299.A297.A251_WRAPPER),
            "W43_runner": anchor(A300.A299.W43_RUNNER),
            "W43_qualification": anchor(A300.A299.W43_QUALIFICATION),
            "Metal_anchor": anchor(A300.A299.A297.METAL_ANCHOR),
            "CausalReader": anchor(reader_source),
        },
        "information_boundary": {
            "runner_and_tests_hashed_before_fresh_target_generation": True,
            "fresh_assignment_generated_only_to_materialize_public_outputs": True,
            "fresh_assignment_stored": False,
            "full_key_stored": False,
            "A300_result_used": False,
            "A301_result_used": False,
            "A302_measurement_order_model_candidate_or_filter_outcome_available_at_freeze": False,
            "operator_measurement_merge_rule_and_precedence_frozen": True,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
        "source_protocol_scientific_design_sha256": a301_protocol[
            "scientific_design_sha256"
        ],
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "execution_contract": plan,
            "public_challenge_sha256": public_sha,
            "reader_challenge_sha256": payload["reader_challenge_sha256"],
            "calibration_sha256": sources["A301_calibration_sha256"],
            "information_boundary": payload["information_boundary"],
            "anchors": payload["anchors"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A302 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-calibrated-coarse-numeric-replication-a302-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("execution_contract") != execution_contract()
        or canonical_sha256(value.get("public_challenge"))
        != value.get("public_challenge_sha256")
        or canonical_sha256(value.get("reader_challenge"))
        != value.get("reader_challenge_sha256")
        or value.get("anchors", {}).get("runner", {}).get("sha256")
        != file_sha256(Path(__file__))
        or value.get("anchors", {}).get("test", {}).get("sha256")
        != file_sha256(A302_TEST)
        or value.get("information_boundary", {}).get("fresh_assignment_stored")
        is not False
        or value.get("information_boundary", {}).get("A301_result_used") is not False
    ):
        raise RuntimeError("A302 protocol semantics differ")
    A300.A299.W43._validate_challenge(value["public_challenge"])  # noqa: SLF001
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    return value


def preflight(expected_protocol_sha256: str) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A302 preflight artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    a223 = load_module(A300.A299.A297.A223_SOURCE, "a302_a223_preflight")
    config = json.loads(A300.A299.A297.A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    original = A300.A299.A297.A296.ARTIFACTS
    try:
        A300.A299.A297.A296.ARTIFACTS = ARTIFACTS / "preflight"
        row = A300.A299.export_reader_cnf_w43(
            a223=a223,
            config=config,
            challenge=protocol["reader_challenge"],
        )
    finally:
        A300.A299.A297.A296.ARTIFACTS = original
    mapping = [int(value) for value in row["source_one_literals_bit0_upward"]]
    if len(mapping) != WIDTH or len({abs(value) for value in mapping}) != WIDTH:
        raise RuntimeError("A302 W43 source literal mapping differs")
    coarse_view = [*mapping[:12], *mapping[24:32]]
    row["synthetic_reader_mapping"] = coarse_view
    row["synthetic_reader_mapping_sha256"] = canonical_sha256(coarse_view)
    row["coarse_partition_coordinates_high_to_low"] = list(range(31, 23, -1))
    row["diagnostic_model_view_coordinates"] = [*range(12), *range(24, 32)]
    payload = {
        "schema": "chacha20-round20-w43-calibrated-coarse-numeric-replication-a302-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FRESH_W43_TARGET_CNF_AND_COARSE_MAPPING_FROZEN_BEFORE_ANY_A302_MEASUREMENT",
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "target": row,
        "measurement_started_before_preflight": False,
        "A300_or_A301_result_used": False,
        "preflight_sha256": canonical_sha256(row),
    }
    atomic_json(PREFLIGHT, payload)
    return payload


def load_preflight(
    expected_protocol_sha256: str, expected_preflight_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = load_protocol(expected_protocol_sha256)
    if file_sha256(PREFLIGHT) != expected_preflight_sha256:
        raise RuntimeError("A302 preflight hash differs")
    value = json.loads(PREFLIGHT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-calibrated-coarse-numeric-replication-a302-preflight-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("public_challenge_sha256")
        != protocol["public_challenge_sha256"]
        or value.get("A300_or_A301_result_used") is not False
    ):
        raise RuntimeError("A302 preflight semantics differ")
    anchor(
        path_from_ref(value["target"]["CNF"]["path"]),
        value["target"]["CNF"]["sha256"],
    )
    return protocol, value


def coarse_measurement(
    protocol: Mapping[str, Any], preflight_value: Mapping[str, Any]
) -> dict[str, Any]:
    a275, model, _a291, indices, helper = A300.A299.A297.A296._reader_stack()  # noqa: SLF001
    wrapper = load_module(A300.A299.A297.A251_WRAPPER, "a302_clause_wrapper")
    row = preflight_value["target"]
    started = time.perf_counter()
    raw_run = wrapper.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["CNF"]["path"]),
        mode="A302_W43_word0_high8_numeric_unlabeled",
        order=[f"{value:08b}" for value in range(COARSE_CELLS)],
        key_one_literals_bit0_through_bit19=row["synthetic_reader_mapping"],
        conflict_horizons=A300.A299.A297.HORIZONS,
        watchdog_seconds=A300.A299.A297.WATCHDOG_SECONDS,
        external_timeout_seconds=1800.0,
    )
    stable = {
        key: value
        for key, value in raw_run.items()
        if key not in {"command", "process_elapsed_seconds"}
    }
    measurement = {
        "schema": "chacha20-round20-w43-calibrated-coarse-numeric-replication-a302-measurement-v1",
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
        "complete_candidate_cover": len(raw_run["cells"]) == COARSE_CELLS,
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
    if len(order) != COARSE_CELLS or set(order) != set(range(COARSE_CELLS)):
        raise RuntimeError("A302 coarse order is not an exact cover")
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


def measure(
    *, expected_protocol_sha256: str, expected_preflight_sha256: str
) -> dict[str, Any]:
    if COARSE.exists() or ORDER.exists():
        raise FileExistsError("A302 measurement artifacts already exist")
    protocol, preflight_value = load_preflight(
        expected_protocol_sha256, expected_preflight_sha256
    )
    coarse_readout = coarse_measurement(protocol, preflight_value)
    if coarse_readout["model_free_UNKNOWN_stages"] != 1024:
        raise RuntimeError("A302 requires exactly 1024 model-free coarse stages")
    coarse = A300.A299.A297.A296.fine_order(
        [int(value) for value in coarse_readout["complete_coarse_order"]]
    )
    numeric = list(range(CELLS))
    portfolio = A301.two_operator_portfolio(coarse=coarse, numeric=numeric)
    guarantee = A301.portfolio_guarantee(
        portfolio=portfolio, coarse=coarse, numeric=numeric
    )
    components = {
        "A297_coarse_high8_then_reflected_Gray4": coarse,
        "numeric_word0_prefix12": numeric,
    }
    payload = {
        "schema": "chacha20-round20-w43-calibrated-coarse-numeric-replication-a302-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FRESH_W43_COMPLETE_MODEL_FREE_COARSE_NUMERIC_PORTFOLIO_ORDER_FROZEN",
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "coarse_readout": coarse_readout,
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
        "measurement_efficiency": {
            "coarse_cells": COARSE_CELLS,
            "coarse_stages": 1024,
            "fine_cells": 0,
            "fine_stages": 0,
            "cells_avoided_vs_A300": 4096,
        },
        "information_boundary": {
            "target_key_label_available": False,
            "target_model_used_for_order": False,
            "candidate_filter_outcome_used_for_order": False,
            "A300_result_used": False,
            "A301_result_used": False,
            "reader_refits": 0,
            "target_labels_used": 0,
            "all_component_and_portfolio_orders_frozen_before_Metal_candidate_discovery": True,
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "coarse_readout": coarse_readout,
            "component_order_sha256": payload["component_order_sha256"],
            "portfolio_order_uint16be_sha256": payload[
                "portfolio_order_uint16be_sha256"
            ],
            "portfolio_guarantee": guarantee,
            "measurement_efficiency": payload["measurement_efficiency"],
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
        raise RuntimeError("A302 order hash differs")
    value = json.loads(ORDER.read_bytes())
    components = value.get("component_orders", {})
    if (
        value.get("schema")
        != "chacha20-round20-w43-calibrated-coarse-numeric-replication-a302-order-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("preflight_sha256") != expected_preflight_sha256
        or value.get("public_challenge_sha256")
        != protocol["public_challenge_sha256"]
        or set(components)
        != {
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        }
        or value.get("measurement_efficiency", {}).get("fine_cells") != 0
        or value.get("portfolio_guarantee", {}).get("violations") != 0
    ):
        raise RuntimeError("A302 order semantics differ")
    recomputed = A301.two_operator_portfolio(
        coarse=components["A297_coarse_high8_then_reflected_Gray4"],
        numeric=components["numeric_word0_prefix12"],
    )
    if recomputed != value["portfolio_order"]:
        raise RuntimeError("A302 portfolio order reconstruction differs")
    anchor(COARSE, value["coarse_readout"]["measurement"]["compressed_sha256"])
    return protocol, preflight_value, value


def rank_analysis(
    *, prefix: int, order_value: Mapping[str, Any], challenge_sha: str
) -> dict[str, Any]:
    components = order_value["component_orders"]
    portfolio = [int(value) for value in order_value["portfolio_order"]]
    coarse = [
        int(value)
        for value in components["A297_coarse_high8_then_reflected_Gray4"]
    ]
    numeric = [int(value) for value in components["numeric_word0_prefix12"]]
    ranks = {
        "A302_two_operator_portfolio": portfolio.index(prefix) + 1,
        "A297_coarse_high8_then_reflected_Gray4": coarse.index(prefix) + 1,
        "numeric_word0_prefix12": numeric.index(prefix) + 1,
        "public_hash_control": A300.A299.public_hash_order(challenge_sha).index(prefix)
        + 1,
    }
    best = min(
        ranks["A297_coarse_high8_then_reflected_Gray4"],
        ranks["numeric_word0_prefix12"],
    )
    portfolio_rank = ranks["A302_two_operator_portfolio"]
    if portfolio_rank > 2 * best:
        raise RuntimeError("A302 target rank violates the frozen portfolio guarantee")
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "best_component_rank_one_based": best,
        "portfolio_regret_factor_vs_best_component": portfolio_rank / best,
        "portfolio_regret_bits_vs_best_component": math.log2(portfolio_rank / best),
        "portfolio_gain_bits_vs_complete_domain": math.log2(CELLS / portfolio_rank),
        "portfolio_speedup_vs_public_hash_rank": ranks["public_hash_control"]
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

    terminal = "A302:confirmed_calibrated_coarse_numeric_W43_recovery"
    writer = CausalWriter(api_id="a302w43")
    writer._rules = []
    writer.add_rule(
        name="calibration_to_measurement_pruning",
        description=(
            "Fourteen retained targets select the coarse/numeric allocation and "
            "remove the dominated fine field from prospective measurement."
        ),
        pattern=["A301_calibration", "fresh_256_cell_coarse_field"],
        conclusion="A302_two_operator_prefix_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="two_operator_order_to_confirmed_recovery",
        description=(
            "Each frozen prefix expands over every 2^31 residual assignment "
            "before dual eight-block confirmation."
        ),
        pattern=["A302_two_operator_prefix_order", "dual_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A302:fresh_W43_public_relation",
        mechanism="A301_calibrated_256_cell_coarse_reader_plus_numeric_portfolio",
        outcome="A302:frozen_factor_two_prefix_order",
        confidence=1.0,
        source=payload["order_sha256"],
        quantification=json.dumps(payload["measurement_efficiency"], sort_keys=True),
        evidence=json.dumps(payload["portfolio_guarantee"], sort_keys=True),
        domain="AI-native calibrated low-overhead ChaCha20-R20 W43 readout",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A302:frozen_factor_two_prefix_order",
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
        trigger="A302:fresh_W43_public_relation",
        mechanism="materialized_calibration_measurement_order_recovery_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A302_low_overhead_portfolio_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A302 low-overhead calibrated W43 recovery",
        entities=[
            "A302:fresh_W43_public_relation",
            "A302:frozen_factor_two_prefix_order",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="additional_W43_replication_or_hierarchical_wider_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the 256-cell calibrated Reader replicate again or extend hierarchically beyond W43?"
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
        reader.api_id != "a302w43"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A302 authentic Causal reopen gate failed")
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
        raise FileExistsError("A302 final artifacts already exist")
    protocol, _preflight, order_value = load_order(
        expected_protocol_sha256,
        expected_preflight_sha256,
        expected_order_sha256,
    )
    challenge = protocol["public_challenge"]
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
        raise RuntimeError("A302 matched one-bit control produced a filter candidate")
    confirmation = A300.A299.W43._confirm(  # noqa: SLF001
        {"challenge": challenge}, int(discovery["candidate"])
    )
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A302 dual independent confirmation failed")
    prefix = int(discovery["fine_prefix12"])
    ranks = rank_analysis(
        prefix=prefix,
        order_value=order_value,
        challenge_sha=protocol["public_challenge_sha256"],
    )
    portfolio_rank = ranks["prefix_ranks_one_based"][
        "A302_two_operator_portfolio"
    ]
    if portfolio_rank != discovery["executed_prefix_groups"]:
        raise RuntimeError("A302 discovery and portfolio ranks differ")
    strict_subset = portfolio_rank < CELLS
    evidence_stage = (
        "FULLROUND_R20_W43_LOW_OVERHEAD_CALIBRATED_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_W43_LOW_OVERHEAD_CALIBRATED_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w43-calibrated-coarse-numeric-replication-a302-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "order_sha256": expected_order_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "calibration_aggregate": protocol["calibration_aggregate"],
        "native_build": build,
        "metal_identity": identity,
        "mapping_gate": mapping,
        "measurement_efficiency": order_value["measurement_efficiency"],
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
            "measurement_efficiency": payload["measurement_efficiency"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A302 — low-overhead calibrated ChaCha20-R20 W43 replication\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Portfolio prefix rank: **{portfolio_rank} / 4,096**\n"
            f"- Search gain: **{ranks['portfolio_gain_bits_vs_complete_domain']:.6f} bits**\n"
            f"- Executed assignments: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W43 assignment: **0x{int(discovery['candidate']):011x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Reader measurement: **256 coarse cells / 1,024 model-free stages / zero fine cells**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Frozen guarantee: **R <= 2 min(R_coarse, R_numeric)**\n"
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
        "fine_measurement_cells": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--measure", action="store_true")
    mode.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-preflight-sha256")
    parser.add_argument("--expected-order-sha256")
    parser.add_argument("--swiftc", default="/usr/bin/swiftc")
    args = parser.parse_args()
    if args.analyze:
        output = analyze()
    elif args.freeze:
        value = freeze()
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
