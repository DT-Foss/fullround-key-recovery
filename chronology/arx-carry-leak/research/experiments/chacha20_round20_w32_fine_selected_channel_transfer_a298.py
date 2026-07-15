#!/usr/bin/env python3
"""Prospective A295 fine-reader transfer to one fresh ChaCha20-R20 W32 target."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
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
ARTIFACTS = RESEARCH / "artifacts/a298_chacha20_r20_w32_fine_transfer"

DESIGN = (
    CONFIGS / "chacha20_round20_w32_fine_selected_channel_transfer_a298_design_v1.json"
)
A293_RESULT = RESULTS / "chacha20_round20_w24_causal_refinement_a293_v1.json"
A293_CAUSAL = RESULTS / "chacha20_round20_w24_causal_refinement_a293_v1.causal"
A293_RUNNER = RESEARCH / "experiments/chacha20_round20_w24_causal_refinement_a293.py"
A295_RESULT = RESULTS / "chacha20_round20_w24_fine_selected_channel_a295_v1.json"
A295_CAUSAL = RESULTS / "chacha20_round20_w24_fine_selected_channel_a295_v1.causal"
A295_RUNNER = RESEARCH / "experiments/chacha20_round20_w24_fine_selected_channel_a295.py"
A297_RESULT = RESULTS / "chacha20_round20_w32_causal_search_gain_panel_a297_v1.json"
A297_CAUSAL = RESULTS / "chacha20_round20_w32_causal_search_gain_panel_a297_v1.causal"
A297_RUNNER = RESEARCH / "experiments/chacha20_round20_w32_causal_search_gain_panel_a297.py"

PROTOCOL = CONFIGS / "chacha20_round20_w32_fine_selected_channel_transfer_a298_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_w32_fine_selected_channel_transfer_a298_preflight_v1.json"
COARSE = RESULTS / "chacha20_round20_w32_fine_selected_channel_transfer_a298_coarse_v1.json.zst"
ORDER = RESULTS / "chacha20_round20_w32_fine_selected_channel_transfer_a298_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w32_fine_selected_channel_transfer_a298_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_W32_FINE_SELECTED_CHANNEL_A298_V1.md"
BUILD = RESEARCH / "build/chacha20_round20_w32_fine_selected_channel_a298"

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A298"
DESIGN_SHA256 = "118bb29b7494ced14256b120a36ce5b206eb347fdd0c10b261c1793300720189"
WIDTH = 32
PREFIX_BITS = 12
SUFFIX_BITS = WIDTH - PREFIX_BITS
CELLS = 1 << PREFIX_BITS
LANES = 8
CELLS_PER_LANE = CELLS // LANES
GROUP_SIZE = 1 << SUFFIX_BITS
DOMAIN_SIZE = 1 << WIDTH
SECONDS_PER_CELL = 5.0
ZSTD_LEVEL = 10


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A298 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A297 = load_module(A297_RUNNER, "a298_a297_common")
sha256 = A297.sha256
file_sha256 = A297.file_sha256
canonical_bytes = A297.canonical_bytes
canonical_sha256 = A297.canonical_sha256
atomic_bytes = A297.atomic_bytes
atomic_json = A297.atomic_json
relative = A297.relative
path_from_ref = A297.path_from_ref
anchor = A297.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A298 prospective design hash differs")
    value = json.loads(DESIGN.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w32-fine-selected-channel-transfer-a298-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("information_boundary", {}).get(
            "A298_target_exists_at_design_freeze"
        )
        is not False
        or value.get("fine_measurement_contract", {}).get("prefix_cells") != CELLS
        or value.get("reader_contract", {}).get("model_refits") not in {None, 0}
    ):
        raise RuntimeError("A298 prospective design semantics differ")
    return value


def _reader(path: Path) -> Any:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    return CausalReader(str(path), verify_integrity=True)


def _source_gates(
    expected_a293_result_sha256: str, expected_a295_result_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(A293_RESULT) != expected_a293_result_sha256:
        raise RuntimeError("A298 A293 result hash differs")
    if file_sha256(A295_RESULT) != expected_a295_result_sha256:
        raise RuntimeError("A298 A295 result hash differs")
    a293 = json.loads(A293_RESULT.read_bytes())
    a295 = json.loads(A295_RESULT.read_bytes())
    if (
        a293.get("evidence_stage")
        != "FULLROUND_R20_W24_COMPLETE_CAUSAL_REFINED_BUDGET_BOUNDARY"
        or a293.get("winner") is not None
        or a293.get("coverage", {}).get("executed_prefix_cells") != CELLS
        or a293.get("coverage", {}).get("complete_prefix_cover_if_no_recovery")
        is not True
        or file_sha256(A293_CAUSAL) != a293.get("causal", {}).get("sha256")
    ):
        raise RuntimeError("A298 requires the complete A293 model-free boundary")
    if (
        a295.get("evidence_stage")
        != "FULLROUND_R20_W24_FINE_SELECTED_CHANNEL_ORDERED_RECOVERY_CONFIRMED"
        or a295.get("confirmation") is None
        or a295.get("information_boundary", {}).get("reader_refits") != 0
        or a295.get("information_boundary", {}).get("target_labels_used") != 0
        or file_sha256(A295_CAUSAL) != a295.get("causal", {}).get("sha256")
    ):
        raise RuntimeError("A298 requires the confirmed zero-refit A295 result")
    orbit = a295.get("anchors", {}).get("orbit_source", {})
    expected_orbit_sha = load_design()["source_frontier"][
        "A295_orbit_source_sha256"
    ]
    if orbit.get("sha256") != expected_orbit_sha:
        raise RuntimeError("A298 A295 fine-operator source identity differs")
    anchor(path_from_ref(str(orbit["path"])), expected_orbit_sha)
    a293_reader = _reader(A293_CAUSAL)
    a295_reader = _reader(A295_CAUSAL)
    a297_reader = _reader(A297_CAUSAL)
    if (
        a293_reader.api_id != "a293w24"
        or a295_reader.api_id != "a295w24"
        or a297_reader.api_id != "a297w32"
        or a297_reader._gaps[0].get("expected_object_type")
        != "fine_subprefix_reader_or_prospective_W36_transfer"
    ):
        raise RuntimeError("A298 authentic source Reader chain differs")
    return a293, a295


def execution_contract() -> dict[str, Any]:
    return {
        "primitive": "standard_ChaCha20_block_function",
        "rounds": 20,
        "feedforward_included": True,
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "public_output_blocks": 8,
        "coarse_seed": "unchanged_A297_high8_reader",
        "fine_prefix_bits": PREFIX_BITS,
        "fine_prefix_cells": CELLS,
        "parallel_retained_state_lanes": LANES,
        "cells_per_lane": CELLS_PER_LANE,
        "seconds_per_cell": SECONDS_PER_CELL,
        "suffix_bits_per_candidate_group": SUFFIX_BITS,
        "candidate_group_size": GROUP_SIZE,
        "complete_residual_domain": DOMAIN_SIZE,
        "reader": "unchanged_A295_frozen_fine_selected_channel",
        "reader_refits": 0,
        "target_labels_used": 0,
        "recovery": "ordered_Metal_then_dual_independent_eight_block_confirmation",
    }


def freeze(
    *, expected_a293_result_sha256: str, expected_a295_result_sha256: str
) -> dict[str, Any]:
    if any(
        path.exists()
        for path in (PROTOCOL, PREFLIGHT, COARSE, ORDER, RESULT, CAUSAL, REPORT)
    ) or ARTIFACTS.exists():
        raise FileExistsError("A298 artifacts already exist")
    design = load_design()
    a293, a295 = _source_gates(
        expected_a293_result_sha256, expected_a295_result_sha256
    )
    root_reference = load_module(A297.ROOT_REFERENCE, "a298_root_freeze")
    a223 = load_module(A297.A223_SOURCE, "a298_a223_freeze")
    challenge = A297.challenge_from_ephemeral_secret(root_reference)
    a223._validate_challenge(challenge, width=WIDTH)  # noqa: SLF001
    public_sha = canonical_sha256(challenge)
    reader_source = Path(inspect.getsourcefile(type(_reader(A297_CAUSAL))) or "")
    byte_reference_source = Path(
        inspect.getsourcefile(A297.A296.byte_reference_block) or ""
    )
    a293_runner = load_module(A293_RUNNER, "a298_a293_freeze")
    plan = execution_contract()
    payload = {
        "schema": "chacha20-round20-w32-fine-selected-channel-transfer-a298-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "fresh_W32_target_and_unchanged_two_stage_reader_contract_frozen_before_CNF_export_measurement_order_or_candidate_discovery",
        "design": design,
        "execution_contract": plan,
        "execution_contract_sha256": canonical_sha256(plan),
        "public_challenge": challenge,
        "public_challenge_sha256": public_sha,
        "source_results": {
            "A293_result_sha256": expected_a293_result_sha256,
            "A295_result_sha256": expected_a295_result_sha256,
            "A295_rank_analysis": a295["rank_analysis"],
            "A293_coverage": a293["coverage"],
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A293_result": anchor(A293_RESULT, expected_a293_result_sha256),
            "A293_causal": anchor(A293_CAUSAL),
            "A293_runner": anchor(A293_RUNNER),
            "A293_helper_wrapper": anchor(a293_runner.HELPER_WRAPPER),
            "A293_helper_derived_source": anchor(a293_runner.HELPER_DERIVED),
            "A293_helper_binary": anchor(a293_runner.HELPER_BINARY),
            "A295_result": anchor(A295_RESULT, expected_a295_result_sha256),
            "A295_causal": anchor(A295_CAUSAL),
            "A295_runner": anchor(A295_RUNNER),
            "A297_result": anchor(
                A297_RESULT, design["source_frontier"]["A297_result_sha256"]
            ),
            "A297_causal": anchor(
                A297_CAUSAL, design["source_frontier"]["A297_causal_sha256"]
            ),
            "A297_runner": anchor(A297_RUNNER),
            "A296_runner": anchor(A297.A296_RUNNER),
            "A223_source": anchor(A297.A223_SOURCE),
            "A223_config": anchor(A297.A223_CONFIG),
            "A251_wrapper": anchor(A297.A251_WRAPPER),
            "Metal_anchor": anchor(A297.METAL_ANCHOR),
            "root_reference": anchor(A297.ROOT_REFERENCE),
            "byte_reference": anchor(byte_reference_source),
            "CausalReader": anchor(reader_source),
            "runner": anchor(Path(__file__)),
        },
        "information_boundary": {
            "generation_assignment_absent": True,
            "full_key_absent": True,
            "target_frozen_before_CNF_export": True,
            "target_measurement_or_order_available_at_freeze": False,
            "target_prefix_model_or_filter_outcome_available_at_freeze": False,
            "reader_formula_features_coefficients_and_tiebreak_frozen": True,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "execution_contract": plan,
            "public_challenge_sha256": public_sha,
            "information_boundary": payload["information_boundary"],
            "anchors": payload["anchors"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A298 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w32-fine-selected-channel-transfer-a298-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("execution_contract") != execution_contract()
        or canonical_sha256(value.get("public_challenge"))
        != value.get("public_challenge_sha256")
        or value.get("anchors", {}).get("runner", {}).get("sha256")
        != file_sha256(Path(__file__))
    ):
        raise RuntimeError("A298 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    return value


def preflight(expected_protocol_sha256: str) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A298 preflight artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    a223 = load_module(A297.A223_SOURCE, "a298_a223_preflight")
    config = json.loads(A297.A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    original = A297.ARTIFACTS
    try:
        A297.ARTIFACTS = ARTIFACTS
        row = A297.export_reader_cnf(
            a223=a223,
            config=config,
            identifier="target",
            challenge=protocol["public_challenge"],
        )
    finally:
        A297.ARTIFACTS = original
    payload = {
        "schema": "chacha20-round20-w32-fine-selected-channel-transfer-a298-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FRESH_W32_TARGET_CNF_AND_LITERAL_MAP_FROZEN_BEFORE_ANY_MEASUREMENT",
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "target": row,
        "measurement_started_before_preflight": False,
        "preflight_sha256": canonical_sha256(row),
    }
    atomic_json(PREFLIGHT, payload)
    return payload


def load_preflight(
    expected_protocol_sha256: str, expected_preflight_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = load_protocol(expected_protocol_sha256)
    if file_sha256(PREFLIGHT) != expected_preflight_sha256:
        raise RuntimeError("A298 preflight hash differs")
    value = json.loads(PREFLIGHT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w32-fine-selected-channel-transfer-a298-preflight-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("public_challenge_sha256")
        != protocol["public_challenge_sha256"]
    ):
        raise RuntimeError("A298 preflight semantics differ")
    anchor(
        path_from_ref(value["target"]["CNF"]["path"]),
        value["target"]["CNF"]["sha256"],
    )
    return protocol, value


def coarse_measurement(
    protocol: Mapping[str, Any], preflight_value: Mapping[str, Any]
) -> dict[str, Any]:
    a275, model, _a291, indices, helper = A297.A296._reader_stack()  # noqa: SLF001
    wrapper = load_module(A297.A251_WRAPPER, "a298_clause_wrapper")
    row = preflight_value["target"]
    started = time.perf_counter()
    raw_run = wrapper.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["CNF"]["path"]),
        mode="A298_W32_high8_numeric_unlabeled",
        order=[f"{value:08b}" for value in range(256)],
        key_one_literals_bit0_through_bit19=row["synthetic_reader_mapping"],
        conflict_horizons=A297.HORIZONS,
        watchdog_seconds=A297.WATCHDOG_SECONDS,
        external_timeout_seconds=1800.0,
    )
    stable = {
        key: value
        for key, value in raw_run.items()
        if key not in {"command", "process_elapsed_seconds"}
    }
    measurement = {
        "schema": "chacha20-round20-w32-fine-selected-channel-transfer-a298-coarse-measurement-v1",
        "attempt_id": ATTEMPT_ID,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "unknown_key_bits": WIDTH,
        "order_name": "numeric",
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
        raise RuntimeError("A298 coarse order is not an exact cover")
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
    fine = A297.A296.fine_order([int(value) for value in coarse_order])
    if len(fine) != CELLS or set(fine) != set(range(CELLS)):
        raise RuntimeError("A298 coarse-plus-Gray fine seed is not an exact cover")
    source = preflight_value["target"]
    arms = []
    active = []
    for lane in range(LANES):
        front = fine[lane::LANES]
        front_set = set(front)
        full = [*front, *[value for value in fine if value not in front_set]]
        prefixes = [f"{value:012b}" for value in full]
        active.extend(front)
        arms.append(
            {
                "arm": f"a298_fine12_lane{lane}",
                "lane": lane,
                "cadical_configuration": "default",
                "cell_order": prefixes,
                "active_prefixes": prefixes[:CELLS_PER_LANE],
                "active_prefixes_uint16be_sha256": sha256(
                    b"".join(value.to_bytes(2, "big") for value in front)
                ),
                "seconds_per_cell": SECONDS_PER_CELL,
                "max_cells": CELLS_PER_LANE,
                "cnf": source["CNF"],
                "model_one_literals_bit0_upward": source[
                    "source_one_literals_bit0_upward"
                ],
            }
        )
    if len(active) != CELLS or set(active) != set(range(CELLS)):
        raise RuntimeError("A298 active lane fronts are not an exact cover")
    return {
        "fine_seed_order": fine,
        "fine_seed_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in fine)
        ),
        "arms": arms,
    }


def _trace_rows(directory: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(directory.glob("*.stdout")):
        for line in path.read_text(encoding="ascii").splitlines():
            if line.startswith("PARTITION_RESULT "):
                rows.append(json.loads(line.removeprefix("PARTITION_RESULT ")))
    return rows


def measure(
    *, expected_protocol_sha256: str, expected_preflight_sha256: str
) -> dict[str, Any]:
    if COARSE.exists() or ORDER.exists() or (ARTIFACTS / "fine").exists():
        raise FileExistsError("A298 measurement artifacts already exist")
    protocol, preflight_value = load_preflight(
        expected_protocol_sha256, expected_preflight_sha256
    )
    coarse = coarse_measurement(protocol, preflight_value)
    plan = fine_lane_plan(coarse["complete_coarse_order"], preflight_value)
    a293 = load_module(A293_RUNNER, "a298_a293_fine_runner")
    a293.WIDTH = WIDTH
    a293.SUFFIX_BITS = SUFFIX_BITS
    a293.ARTIFACTS = ARTIFACTS / "fine"
    solver_rows, raw_winner = a293.run_partition(
        {"execution_plan": {"arms": plan["arms"]}}
    )
    winner = None
    if raw_winner is not None:
        candidate = int(raw_winner["candidate_low24"])
        winner = {
            "arm": raw_winner["arm"],
            "candidate": candidate,
            "candidate_hex": f"{candidate:08x}",
            "prefix12": raw_winner["prefix12"],
            "lane_cell_index": raw_winner["lane_cell_index"],
        }
    traces = _trace_rows(ARTIFACTS / "fine")
    attempted = [str(row["prefix"]) for row in traces]
    if len(attempted) != len(set(attempted)):
        raise RuntimeError("A298 fine trace prefixes overlap")
    fine_readout = None
    if winner is None:
        if (
            len(traces) != CELLS
            or set(attempted) != {f"{value:012b}" for value in range(CELLS)}
            or any(
                row.get("status") != "unknown"
                or row.get("model_bits_bit0_upward") != []
                for row in traces
            )
        ):
            raise RuntimeError("A298 requires a complete model-free fine trace field")
        a295 = load_module(A295_RUNNER, "a298_a295_reader")
        fine_readout = a295.frozen_order(traces)
    trace_anchors = [
        anchor(path)
        for path in sorted((ARTIFACTS / "fine").glob("*"))
        if path.is_file()
    ]
    payload = {
        "schema": "chacha20-round20-w32-fine-selected-channel-transfer-a298-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "W32_DIRECT_FINE_SYMBOLIC_MODEL_DISCOVERED"
            if winner is not None
            else "W32_COMPLETE_MODEL_FREE_FINE_FIELD_AND_ORDER_FROZEN"
        ),
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "coarse_readout": coarse,
        "fine_lane_plan": {
            "fine_seed_order_uint16be_sha256": plan[
                "fine_seed_order_uint16be_sha256"
            ],
            "arms": plan["arms"],
        },
        "solver_arms": solver_rows,
        "attempted_prefix_cells": len(attempted),
        "direct_symbolic_winner": winner,
        "fine_readout": fine_readout,
        "trace_artifacts": trace_anchors,
        "information_boundary": {
            "target_key_label_available": False,
            "target_model_used_for_order": False,
            "candidate_filter_outcome_used_for_order": False,
            "reader_refits": 0,
            "target_labels_used": 0,
            "order_frozen_before_Metal_candidate_discovery": True,
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "coarse_readout": coarse,
            "solver_arms": solver_rows,
            "direct_symbolic_winner": winner,
            "fine_readout": fine_readout,
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
        raise RuntimeError("A298 order hash differs")
    value = json.loads(ORDER.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w32-fine-selected-channel-transfer-a298-order-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("preflight_sha256") != expected_preflight_sha256
        or value.get("public_challenge_sha256")
        != protocol["public_challenge_sha256"]
        or (
            value.get("direct_symbolic_winner") is None
            and len(value.get("fine_readout", {}).get("complete_order", [])) != CELLS
        )
    ):
        raise RuntimeError("A298 order semantics differ")
    for row in value["trace_artifacts"]:
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(COARSE, value["coarse_readout"]["measurement"]["compressed_sha256"])
    return protocol, preflight_value, value


def public_hash_order(public_challenge_sha256: str) -> list[int]:
    return A297.public_hash_order(public_challenge_sha256)


def rank_analysis(
    *, discovery: Mapping[str, Any], order_value: Mapping[str, Any], challenge_sha: str
) -> dict[str, Any]:
    prefix = int(discovery["fine_prefix12"])
    primary = (
        [prefix]
        if order_value["direct_symbolic_winner"] is not None
        else [int(value) for value in order_value["fine_readout"]["complete_order"]]
    )
    coarse = A297.A296.fine_order(
        [int(value) for value in order_value["coarse_readout"]["complete_coarse_order"]]
    )
    numeric = list(range(CELLS))
    hashed = public_hash_order(challenge_sha)
    ranks = {
        "A298_fine_selected_channel": primary.index(prefix) + 1,
        "A297_coarse_seed": coarse.index(prefix) + 1,
        "numeric": numeric.index(prefix) + 1,
        "public_hash_control": hashed.index(prefix) + 1,
    }
    return {
        "prefix12": prefix,
        "prefix_ranks_one_based": ranks,
        "assignment_upper_bounds": {
            name: rank * GROUP_SIZE for name, rank in ranks.items()
        },
        "A298_gain_bits_vs_complete_domain": math.log2(
            CELLS / ranks["A298_fine_selected_channel"]
        ),
        "A298_speedup_vs_coarse_seed_rank": (
            ranks["A297_coarse_seed"] / ranks["A298_fine_selected_channel"]
        ),
        "A298_speedup_vs_numeric_rank": (
            ranks["numeric"] / ranks["A298_fine_selected_channel"]
        ),
        "A298_speedup_vs_public_hash_rank": (
            ranks["public_hash_control"] / ranks["A298_fine_selected_channel"]
        ),
        "counterfactual_ranks_computed_after_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A298:confirmed_fine_reader_W32_recovery"
    writer = CausalWriter(api_id="a298w32")
    writer._rules = []
    writer.add_rule(
        name="coarse_seed_plus_fine_trace_to_W32_order",
        description="The frozen A297 seed and unchanged A295 fine operator convert a complete model-free W32 trace field into one target-label-free order.",
        pattern=["A297_coarse_seed", "A295_fine_operator"],
        conclusion="A298_frozen_W32_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_order_to_confirmed_W32_recovery",
        description="Ordered candidate evaluation plus two independent eight-block recomputations establishes the recovered full key word.",
        pattern=["A298_frozen_W32_order", "dual_eight_block_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A297:coarse_W32_reader_boundary",
        mechanism="A297_high8_seed_then_A295_fine_selected_channel_closure",
        outcome="A298:frozen_fine_W32_order",
        confidence=1.0,
        source=payload["order_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=payload["order_sha256"],
        domain="AI-native fine-subprefix ChaCha20-R20 readout",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A298:frozen_fine_W32_order",
        mechanism="ordered_Metal_search_plus_dual_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="confirmed full-round ChaCha20 W32 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A297:coarse_W32_reader_boundary",
        mechanism="materialized_coarse_fine_discovery_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A297_A295_A298_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A298 fine-reader W32 recovery",
        entities=[
            "A297:coarse_W32_reader_boundary",
            "A298:frozen_fine_W32_order",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_W32_replication_or_W36_fine_reader_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the frozen coarse-to-fine operator replicate or widen beyond one full key word?"
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
        reader.api_id != "a298w32"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A298 authentic Causal reopen gate failed")
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
        raise FileExistsError("A298 final artifacts already exist")
    protocol, _preflight, order_value = load_order(
        expected_protocol_sha256,
        expected_preflight_sha256,
        expected_order_sha256,
    )
    challenge = protocol["public_challenge"]
    metal = load_module(A297.METAL_ANCHOR, "a298_metal_recover")
    root_reference = load_module(A297.ROOT_REFERENCE, "a298_root_recover")
    executable, build = metal.A184._A181._compile_native(BUILD, swiftc)
    host = metal.A184.SliceMetalHost(
        executable,
        A297.A296.initial_state(challenge, metal.A119.CONSTANTS, WIDTH),
        np.asarray(challenge["target_words"][0], dtype=np.uint32),
        np.asarray(challenge["control_target_words"], dtype=np.uint32),
    )
    try:
        mapping = A297.A296.mapping_gate(
            host=host,
            challenge=challenge,
            width=WIDTH,
            metal=metal,
            root_reference=root_reference,
        )
        direct = order_value["direct_symbolic_winner"]
        order = (
            [int(direct["prefix12"], 2)]
            if direct is not None
            else [int(value) for value in order_value["fine_readout"]["complete_order"]]
        )
        discovery = A297.A296.discover(
            host=host,
            challenge=challenge,
            width=WIDTH,
            order=order,
            metal=metal,
        )
        if direct is not None and int(discovery["candidate"]) != int(direct["candidate"]):
            raise RuntimeError("A298 symbolic and Metal candidates differ")
        identity = host.identity
    finally:
        host.close()
    confirmation = A297.A296.confirm(
        discovery=discovery,
        challenge=challenge,
        root_reference=root_reference,
    )
    ranks = rank_analysis(
        discovery=discovery,
        order_value=order_value,
        challenge_sha=protocol["public_challenge_sha256"],
    )
    evidence_stage = (
        "FULLROUND_R20_W32_FINE_READER_SYMBOLIC_PLUS_METAL_RECOVERY_CONFIRMED"
        if order_value["direct_symbolic_winner"] is not None
        else "FULLROUND_R20_W32_FINE_SELECTED_CHANNEL_ORDERED_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w32-fine-selected-channel-transfer-a298-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "order_sha256": expected_order_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "native_build": build,
        "metal_identity": identity,
        "mapping_gate": mapping,
        "direct_symbolic_winner": order_value["direct_symbolic_winner"],
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "information_boundary": order_value["information_boundary"],
        "anchors": protocol["anchors"],
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "mapping_gate": mapping,
            "discovery": discovery,
            "metal_identity": identity,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": discovery,
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
            "# A298 — fine-reader ChaCha20-R20 W32 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Fine prefix rank: **{ranks['prefix_ranks_one_based']['A298_fine_selected_channel']} / 4,096**\n"
            f"- Search gain: **{ranks['A298_gain_bits_vs_complete_domain']:.6f} bits**\n"
            f"- Recovered full key word: **0x{int(discovery['candidate']):08x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Reader refits / target labels: **0 / 0**\n"
        ).encode()
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "A293_complete": A293_RESULT.exists(),
        "A295_complete": A295_RESULT.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "preflight_complete": PREFLIGHT.exists(),
        "order_complete": ORDER.exists(),
        "result_complete": RESULT.exists(),
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
                    "direct_symbolic_winner": value["direct_symbolic_winner"],
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
