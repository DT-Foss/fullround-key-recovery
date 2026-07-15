#!/usr/bin/env python3
"""A312: transfer the frozen Causal fine reader to the unrevealed A308 W44 target."""

from __future__ import annotations

import argparse
import inspect
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w44_fine_selected_channel_transfer_a312_design_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w44_fine_selected_channel_transfer_a312_v1.json"
ORDER = RESULTS / "chacha20_round20_w44_fine_selected_channel_transfer_a312_order_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w44_fine_selected_channel_transfer_a312_order_v1.causal"
REPORT = RESULTS / "chacha20_round20_w44_fine_selected_channel_transfer_a312_order_v1.md"
ARTIFACTS = RESEARCH / "artifacts/a312_chacha20_r20_w44_fine_transfer"
BUILD = RESEARCH / "build/chacha20_round20_w44_fine_selected_channel_a312"
W44_HELPER_DERIVED = BUILD / "cadical_ranked_variable_prefix_reverse_w44_derived.cpp"
W44_HELPER_BINARY = BUILD / "cadical_ranked_variable_prefix_reverse_w44"

A293_RUNNER = RESEARCH / "experiments/chacha20_round20_w24_causal_refinement_a293.py"
A295_RESULT = RESULTS / "chacha20_round20_w24_fine_selected_channel_a295_v1.json"
A295_CAUSAL = RESULTS / "chacha20_round20_w24_fine_selected_channel_a295_v1.causal"
A295_RUNNER = RESEARCH / "experiments/chacha20_round20_w24_fine_selected_channel_a295.py"
A299_ORDER = RESULTS / "chacha20_round20_w43_fine_selected_channel_transfer_a299_order_v1.json"
A299_RUNNER = RESEARCH / "experiments/chacha20_round20_w43_fine_selected_channel_transfer_a299.py"
A305_RESULT = RESULTS / "chacha20_round20_w43_a299_grouped_replay_a305_v1.json"
A305_CAUSAL = RESULTS / "chacha20_round20_w43_a299_grouped_replay_a305_v1.causal"
A308_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_calibrated_coarse_numeric_a308.py"
A312_TEST = ROOT / "tests/test_chacha20_round20_w44_fine_selected_channel_transfer_a312.py"
A312_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w44_fine_selected_channel_transfer_a312.sh"

ATTEMPT_ID = "A312"
DESIGN_SHA256 = "40da3c04819ecba94300d5306edd8fcfe21b65174623ceb725ae9c4d9edff272"
A293_RUNNER_SHA256 = "2b5a7c2b22ff35604315af465be58cea6e5abea52b807b2c6cb7dec5f6144a46"
A295_RESULT_SHA256 = "93a591d75ab882345091c813f4ace877dc85ae37d748ed8f70c91e7323effc03"
A295_CAUSAL_SHA256 = "673f0470cd02826ffdd939e36247b3885a55e6d24affd509e7946d24e7d6aac1"
A295_RUNNER_SHA256 = "0ecbffc2e5f0a036ef84bd4c10f17068580592be73f0b59ec03beb0fa29af14e"
A299_ORDER_SHA256 = "8369e7b4b421c68b344a3ea4588de350796cdc97216d71d43fc2f960df26af07"
A299_RUNNER_SHA256 = "1487dd6360523076e60d203aeaff75fa29d15a5c3f3e6c35b79f73279dce42b9"
A305_RESULT_SHA256 = "adbc8b879f09e03896699188d8141ac0164296eaf2ad688b6fb1036f2b1ac40e"
A305_CAUSAL_SHA256 = "c3460e10dedca9027609d16c4686ad56d1576f05edeea5c368cd56e4ae34f888"
A308_PROTOCOL_SHA256 = "06fcdf7e79f07408292ced64eb19c7c973ba202061d47f8c9499bd23fe679dbd"
A308_PREFLIGHT_SHA256 = "7afda29f1cf4f12d4ab09348d2393a80c30b7689d2e6623fffb9351f966cd5fd"
A308_ORDER_SHA256 = "d69b594a5c7a8ce17d7e5e8d5736006f76a3757a532aa6e4e84f2ca5d6ab2f0b"
A308_RUNNER_SHA256 = "c719062aa94500f43d6acae0ad329a06f0dbdd3972875530ee6256b2a98d5aae"
PUBLIC_CHALLENGE_SHA256 = "c3897f3f8499c9afa01628b7f5e8de0ea5910a9559ca6bfb22fafe71d1fb26d6"

WIDTH = 44
PREFIX_BITS = 12
SUFFIX_BITS = WIDTH - PREFIX_BITS
WORD0_SUFFIX_BITS = 20
CELLS = 1 << PREFIX_BITS
LANES = 8
CELLS_PER_LANE = CELLS // LANES
SECONDS_PER_CELL = 5.0


def load_module(path: Path, name: str) -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A312 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A299 = load_module(A299_RUNNER, "a312_a299_common")
A308 = load_module(A308_RUNNER, "a312_a308_common")
file_sha256 = A308.file_sha256
canonical_sha256 = A308.canonical_sha256
atomic_json = A308.atomic_json
relative = A308.relative
path_from_ref = A308.path_from_ref
anchor = A308.anchor
DOTCAUSAL_SRC = A299.DOTCAUSAL_SRC


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A312 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    measurement = value.get("fine_measurement_contract", {})
    boundary = value.get("information_boundary", {})
    target = value.get("target_contract", {})
    if (
        value.get("schema")
        != "chacha20-round20-w44-fine-selected-channel-transfer-a312-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A308_model_free_coarse_order_and_before_any_A308_candidate_result_or_prefix_rank_exists"
        or target.get("unknown_key_bits") != WIDTH
        or target.get("public_challenge_sha256") != PUBLIC_CHALLENGE_SHA256
        or measurement.get("prefix_cells") != CELLS
        or measurement.get("parallel_retained_state_lanes") != LANES
        or measurement.get("cells_per_lane") != CELLS_PER_LANE
        or measurement.get("seconds_per_cell") != SECONDS_PER_CELL
        or measurement.get("reader_refits") != 0
        or measurement.get("target_labels_used") != 0
        or boundary.get("A308_result_available_at_design_freeze") is not False
        or boundary.get("A308_target_assignment_available_at_design_freeze") is not False
        or boundary.get("A308_filter_outcome_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A312 design semantics differ")
    sources = value["source_anchors"]
    for path_key, sha_key in (
        ("A293_runner_path", "A293_runner_sha256"),
        ("A295_result_path", "A295_result_sha256"),
        ("A295_causal_path", "A295_causal_sha256"),
        ("A295_runner_path", "A295_runner_sha256"),
        ("A299_order_path", "A299_order_sha256"),
        ("A299_runner_path", "A299_runner_sha256"),
        ("A305_result_path", "A305_result_sha256"),
        ("A305_causal_path", "A305_causal_sha256"),
        ("A308_protocol_path", "A308_protocol_sha256"),
        ("A308_preflight_path", "A308_preflight_sha256"),
        ("A308_order_path", "A308_order_sha256"),
        ("A308_runner_path", "A308_runner_sha256"),
    ):
        anchor(path_from_ref(sources[path_key]), sources[sha_key])
    return value


def authentic_source_readback() -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    readers = {
        "A295": CausalReader(str(A295_CAUSAL), verify_integrity=True),
        "A305": CausalReader(str(A305_CAUSAL), verify_integrity=True),
    }
    expected = {"A295": "a295w24", "A305": "a305w43"}
    output: dict[str, Any] = {}
    for name, reader in readers.items():
        all_rows = reader.get_all_triplets(include_inferred=True)
        inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
        if (
            reader.api_id != expected[name]
            or len(all_rows) != 3
            or len(inferred) != 1
            or len(reader._rules) != 2
            or len(reader._clusters) != 1
            or len(reader._gaps) != 1
        ):
            raise RuntimeError(f"A312 authentic {name} Causal readback differs")
        output[name] = {
            "api_id": reader.api_id,
            "triplets_including_materialized_inference": len(all_rows),
            "materialized_inferred_triplets": len(inferred),
            "rules": len(reader._rules),
            "clusters": len(reader._clusters),
            "gaps": len(reader._gaps),
            "next_gap": reader._gaps[0],
        }
    output["reader_source"] = anchor(
        Path(inspect.getsourcefile(CausalReader) or "")
    )
    return output


def load_a308() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if A308.RESULT.exists() or A308.CAUSAL.exists():
        raise RuntimeError("A308 result exists before A312 fine-order measurement")
    protocol, preflight, order = A308.load_order(
        A308_PROTOCOL_SHA256,
        A308_PREFLIGHT_SHA256,
        A308_ORDER_SHA256,
    )
    if (
        protocol["public_challenge_sha256"] != PUBLIC_CHALLENGE_SHA256
        or preflight["public_challenge_sha256"] != PUBLIC_CHALLENGE_SHA256
        or order["public_challenge_sha256"] != PUBLIC_CHALLENGE_SHA256
        or order.get("information_boundary", {}).get("target_key_label_available")
        is not False
        or order.get("information_boundary", {}).get("target_labels_used") != 0
    ):
        raise RuntimeError("A312 A308 target-blind source boundary differs")
    return protocol, preflight, order


def solver_model_permutation() -> list[int]:
    permutation = [*range(20), *range(32, 44), *range(20, 32)]
    if (
        len(permutation) != WIDTH
        or set(permutation) != set(range(WIDTH))
        or permutation[-PREFIX_BITS:] != list(range(20, 32))
        or list(reversed(permutation[-PREFIX_BITS:])) != list(range(31, 19, -1))
    ):
        raise RuntimeError("A312 W44 solver model permutation differs")
    return permutation


def decode_permuted_candidate(candidate: int) -> int:
    if not 0 <= candidate < 1 << WIDTH:
        raise ValueError("A312 permuted candidate lies outside W44")
    result = 0
    for permuted_index, original_coordinate in enumerate(solver_model_permutation()):
        result |= ((candidate >> permuted_index) & 1) << original_coordinate
    return result


def fine_lane_plan(
    *, preflight: Mapping[str, Any], order: Mapping[str, Any]
) -> dict[str, Any]:
    fine = [
        int(value)
        for value in order["component_orders"][
            "A297_coarse_high8_then_reflected_Gray4"
        ]
    ]
    if len(fine) != CELLS or set(fine) != set(range(CELLS)):
        raise RuntimeError("A312 A308 coarse-plus-Gray fine seed is not an exact cover")
    source = preflight["target"]
    original_mapping = [
        int(value) for value in source["source_one_literals_bit0_upward"]
    ]
    if len(original_mapping) != WIDTH or len({abs(value) for value in original_mapping}) != WIDTH:
        raise RuntimeError("A312 W44 source literal mapping differs")
    permutation = solver_model_permutation()
    permuted_mapping = [original_mapping[coordinate] for coordinate in permutation]
    arms: list[dict[str, Any]] = []
    active: list[int] = []
    for lane in range(LANES):
        front = fine[lane::LANES]
        front_set = set(front)
        full = [*front, *[value for value in fine if value not in front_set]]
        prefixes = [f"{value:012b}" for value in full]
        active.extend(front)
        arms.append(
            {
                "arm": f"a312_w44_fine12_lane{lane}",
                "lane": lane,
                "cadical_configuration": "default",
                "cell_order": prefixes,
                "active_prefixes": prefixes[:CELLS_PER_LANE],
                "active_prefixes_uint16be_sha256": A308.sha256(
                    b"".join(value.to_bytes(2, "big") for value in front)
                ),
                "seconds_per_cell": SECONDS_PER_CELL,
                "max_cells": CELLS_PER_LANE,
                "cnf": source["CNF"],
                "model_one_literals_bit0_upward": permuted_mapping,
                "model_index_to_assignment_coordinate": permutation,
            }
        )
    if len(active) != CELLS or set(active) != set(range(CELLS)):
        raise RuntimeError("A312 active lane fronts are not an exact cover")
    return {
        "fine_seed_order": fine,
        "fine_seed_order_uint16be_sha256": A308.sha256(
            b"".join(value.to_bytes(2, "big") for value in fine)
        ),
        "model_index_to_assignment_coordinate": permutation,
        "model_permutation_sha256": canonical_sha256(permutation),
        "arms": arms,
    }


def freeze() -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, ORDER, CAUSAL, REPORT)) or ARTIFACTS.exists():
        raise FileExistsError("A312 protocol or measurement artifacts already exist")
    design = load_design()
    a308_protocol, preflight, order = load_a308()
    plan = fine_lane_plan(preflight=preflight, order=order)
    readback = authentic_source_readback()
    payload = {
        "schema": "chacha20-round20-w44-fine-selected-channel-transfer-a312-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "complete_W44_fine_reader_execution_frozen_before_any_A308_candidate_result_or_rank",
        "design_sha256": DESIGN_SHA256,
        "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
        "execution_contract": {
            "unknown_key_bits": WIDTH,
            "fine_prefix_bits": PREFIX_BITS,
            "suffix_bits_per_cell": SUFFIX_BITS,
            "prefix_cells": CELLS,
            "parallel_retained_state_lanes": LANES,
            "cells_per_lane": CELLS_PER_LANE,
            "seconds_per_cell": SECONDS_PER_CELL,
            "reader": "unchanged_A295_frozen_positive_selected_channel",
            "reader_refits": 0,
            "target_labels_used": 0,
        },
        "fine_seed_order_uint16be_sha256": plan["fine_seed_order_uint16be_sha256"],
        "model_permutation_sha256": plan["model_permutation_sha256"],
        "authentic_source_causal_readback": readback,
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "A293_runner": {"path": relative(A293_RUNNER), "sha256": A293_RUNNER_SHA256},
            "A295_result": {"path": relative(A295_RESULT), "sha256": A295_RESULT_SHA256},
            "A295_causal": {"path": relative(A295_CAUSAL), "sha256": A295_CAUSAL_SHA256},
            "A295_runner": {"path": relative(A295_RUNNER), "sha256": A295_RUNNER_SHA256},
            "A299_order": {"path": relative(A299_ORDER), "sha256": A299_ORDER_SHA256},
            "A299_runner": {"path": relative(A299_RUNNER), "sha256": A299_RUNNER_SHA256},
            "A305_result": {"path": relative(A305_RESULT), "sha256": A305_RESULT_SHA256},
            "A305_causal": {"path": relative(A305_CAUSAL), "sha256": A305_CAUSAL_SHA256},
            "A308_protocol": {"path": relative(A308.PROTOCOL), "sha256": A308_PROTOCOL_SHA256},
            "A308_preflight": {"path": relative(A308.PREFLIGHT), "sha256": A308_PREFLIGHT_SHA256},
            "A308_order": {"path": relative(A308.ORDER), "sha256": A308_ORDER_SHA256},
            "A308_runner": {"path": relative(A308_RUNNER), "sha256": A308_RUNNER_SHA256},
            "A312_runner": {"path": relative(Path(__file__)), "sha256": file_sha256(Path(__file__))},
            "A312_test": {"path": relative(A312_TEST), "sha256": file_sha256(A312_TEST)},
            "A312_reproducer": {"path": relative(A312_REPRO), "sha256": file_sha256(A312_REPRO)},
            "CausalReader": readback["reader_source"],
            "target_CNF": preflight["target"]["CNF"],
        },
        "A308_result_available_at_protocol_freeze": False,
        "A308_candidate_or_prefix_rank_available_at_protocol_freeze": False,
        "A312_measurement_started_at_protocol_freeze": False,
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "execution_contract": payload["execution_contract"],
            "fine_seed_order_uint16be_sha256": payload[
                "fine_seed_order_uint16be_sha256"
            ],
            "model_permutation_sha256": payload["model_permutation_sha256"],
            "authentic_source_causal_readback": readback,
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_protocol_sha256: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A312 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w44-fine-selected-channel-transfer-a312-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "complete_W44_fine_reader_execution_frozen_before_any_A308_candidate_result_or_rank"
        or value.get("public_challenge_sha256") != PUBLIC_CHALLENGE_SHA256
        or value.get("A308_result_available_at_protocol_freeze") is not False
        or value.get("A308_candidate_or_prefix_rank_available_at_protocol_freeze")
        is not False
        or value.get("A312_measurement_started_at_protocol_freeze") is not False
    ):
        raise RuntimeError("A312 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    design = load_design()
    a308_protocol, preflight, order = load_a308()
    plan = fine_lane_plan(preflight=preflight, order=order)
    if (
        plan["fine_seed_order_uint16be_sha256"]
        != value["fine_seed_order_uint16be_sha256"]
        or plan["model_permutation_sha256"] != value["model_permutation_sha256"]
    ):
        raise RuntimeError("A312 reconstructed execution plan differs")
    return value, design, a308_protocol, plan


def _trace_rows(directory: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.stdout")):
        for line in path.read_text(encoding="ascii").splitlines():
            if line.startswith("PARTITION_RESULT "):
                rows.append(json.loads(line.removeprefix("PARTITION_RESULT ")))
    return rows


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    recovered = payload.get("confirmation") is not None
    terminal = (
        "A312:direct_symbolic_W44_recovery"
        if recovered
        else "A312:complete_model_free_W44_fine_field"
    )
    writer = CausalWriter(api_id="a312w44")
    writer._rules = []
    writer.add_rule(
        name="frozen_fine_reader_to_W44_trace_field",
        description="The unchanged A295 selected channel reads eight disjoint retained-state lanes over the complete A308 W44 prefix cover without a target label or refit.",
        pattern=["A295_frozen_selected_channel", "A308_unrevealed_W44_relation"],
        conclusion="A312_W44_fine_field_or_direct_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_trace_field_to_W44_search_object",
        description="A direct SAT model is independently confirmed; otherwise all 4,096 UNKNOWN traces are converted into one frozen complete fine-prefix order.",
        pattern=["A312_complete_prefix_cover", "A295_frozen_readout"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A295_A305:confirmed_fine_reader_transfer_chain",
        mechanism="unchanged_selected_channel_over_complete_A308_W44_fine_trace_cover",
        outcome="A312:frozen_W44_fine_search_object",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification=json.dumps(payload["coverage"], sort_keys=True),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="AI-native fine-prefix full-round ChaCha20 W44 readout",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A312:frozen_W44_fine_search_object",
        mechanism=(
            "direct_symbolic_model_plus_dual_eight_block_confirmation"
            if recovered
            else "complete_model_free_field_plus_frozen_A295_selected_channel"
        ),
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(
            payload.get("confirmation") or payload["fine_readout"], sort_keys=True
        ),
        evidence=payload["evidence_stage"],
        domain=(
            "confirmed full-round ChaCha20 W44 recovery"
            if recovered
            else "complete target-label-free W44 search order"
        ),
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A295_A305:confirmed_fine_reader_transfer_chain",
        mechanism="materialized_W44_fine_trace_readout_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A312_W44_fine_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A312 W44 fine selected-channel transfer",
        entities=[
            "A295_A305:confirmed_fine_reader_transfer_chain",
            "A312:frozen_W44_fine_search_object",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "fresh_W44_direct_symbolic_replication_or_W45_transfer"
            if recovered
            else "grouped_W44_execution_of_A312_fine_order"
        ),
        confidence=1.0,
        suggested_queries=[
            (
                "Does the direct W44 model replicate or widen to W45?"
                if recovered
                else "Does the A312 order place the A308 W44 target in a strict subset under complete grouped execution?"
            )
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
        reader.api_id != "a312w44"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A312 authentic Causal reopen gate failed")
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


def measure(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (ORDER, CAUSAL, REPORT)) or ARTIFACTS.exists():
        raise FileExistsError("A312 measurement artifacts already exist")
    protocol, design, a308_protocol, plan = load_protocol(expected_protocol_sha256)
    helper_build = A299.compile_w43_helper(
        output=W44_HELPER_BINARY,
        derived_source=W44_HELPER_DERIVED,
    )
    a293 = load_module(A293_RUNNER, "a312_a293_fine_runner")
    original = (a293.WIDTH, a293.SUFFIX_BITS, a293.ARTIFACTS, a293.HELPER_BINARY)
    try:
        a293.WIDTH = WIDTH
        a293.SUFFIX_BITS = SUFFIX_BITS
        a293.ARTIFACTS = ARTIFACTS / "fine"
        a293.HELPER_BINARY = W44_HELPER_BINARY
        solver_rows, raw_winner = a293.run_partition(
            {"execution_plan": {"arms": plan["arms"]}}
        )
    finally:
        (a293.WIDTH, a293.SUFFIX_BITS, a293.ARTIFACTS, a293.HELPER_BINARY) = original

    traces = _trace_rows(ARTIFACTS / "fine")
    attempted = [str(row["prefix"]) for row in traces]
    if len(attempted) != len(set(attempted)):
        raise RuntimeError("A312 fine trace prefixes overlap")
    winner = None
    confirmation = None
    fine_readout = None
    if raw_winner is not None:
        permuted_candidate = int(raw_winner["candidate_low24"])
        candidate = decode_permuted_candidate(permuted_candidate)
        prefix = int(raw_winner["prefix12"], 2)
        if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
            raise RuntimeError("A312 decoded symbolic model prefix differs")
        confirmation = A308.confirm(a308_protocol["public_challenge"], candidate)
        if confirmation.get("all_blocks_match") is not True:
            raise RuntimeError("A312 direct symbolic candidate failed dual confirmation")
        winner = {
            "arm": raw_winner["arm"],
            "candidate": candidate,
            "candidate_hex": f"{candidate:011x}",
            "permuted_candidate": permuted_candidate,
            "prefix12": raw_winner["prefix12"],
            "lane_cell_index": raw_winner["lane_cell_index"],
        }
    else:
        if (
            len(traces) != CELLS
            or set(attempted) != {f"{value:012b}" for value in range(CELLS)}
            or any(
                row.get("status") != "unknown"
                or row.get("model_bits_bit0_upward") != []
                for row in traces
            )
        ):
            raise RuntimeError("A312 requires a complete model-free W44 fine trace field")
        a295 = load_module(A295_RUNNER, "a312_a295_reader")
        fine_readout = a295.frozen_order(traces)
        complete = [int(value) for value in fine_readout["complete_order"]]
        if len(complete) != CELLS or set(complete) != set(range(CELLS)):
            raise RuntimeError("A312 frozen fine order is not an exact cover")

    trace_anchors = [
        anchor(path)
        for path in sorted((ARTIFACTS / "fine").glob("*"))
        if path.is_file()
    ]
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w44-fine-selected-channel-transfer-a312-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FULLROUND_R20_W44_DIRECT_SYMBOLIC_RECOVERY_CONFIRMED"
            if winner is not None
            else "FULLROUND_R20_W44_COMPLETE_MODEL_FREE_FINE_FIELD_AND_ORDER_FROZEN"
        ),
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
        "helper_build": helper_build,
        "fine_lane_plan": {
            "fine_seed_order_uint16be_sha256": plan[
                "fine_seed_order_uint16be_sha256"
            ],
            "model_index_to_assignment_coordinate": plan[
                "model_index_to_assignment_coordinate"
            ],
            "model_permutation_sha256": plan["model_permutation_sha256"],
            "arms": plan["arms"],
        },
        "solver_arms": solver_rows,
        "attempted_prefix_cells": len(attempted),
        "direct_symbolic_winner": winner,
        "confirmation": confirmation,
        "fine_readout": fine_readout,
        "trace_artifacts": trace_anchors,
        "coverage": {
            "fine_prefix_cells": CELLS,
            "attempted_prefix_cells": len(attempted),
            "complete_model_free_cover": winner is None and len(attempted) == CELLS,
            "direct_symbolic_model": winner is not None,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
        "information_boundary": {
            **design["information_boundary"],
            "A308_result_read": False,
            "A308_candidate_filter_outcome_read": False,
            "order_frozen_before_A308_Metal_candidate_discovery": True,
        },
        "anchors": {
            "protocol": {"path": relative(PROTOCOL), "sha256": expected_protocol_sha256},
            "A308_protocol": {"path": relative(A308.PROTOCOL), "sha256": A308_PROTOCOL_SHA256},
            "A308_preflight": {"path": relative(A308.PREFLIGHT), "sha256": A308_PREFLIGHT_SHA256},
            "A308_order": {"path": relative(A308.ORDER), "sha256": A308_ORDER_SHA256},
            "A295_result": {"path": relative(A295_RESULT), "sha256": A295_RESULT_SHA256},
            "A295_causal": {"path": relative(A295_CAUSAL), "sha256": A295_CAUSAL_SHA256},
            "A305_result": {"path": relative(A305_RESULT), "sha256": A305_RESULT_SHA256},
            "A305_causal": {"path": relative(A305_CAUSAL), "sha256": A305_CAUSAL_SHA256},
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "protocol_sha256": expected_protocol_sha256,
            "helper_build": helper_build,
            "solver_arms": solver_rows,
            "attempted_prefix_cells": len(attempted),
            "direct_symbolic_winner": winner,
            "confirmation": confirmation,
            "fine_readout": fine_readout,
            "trace_artifacts": trace_anchors,
            "coverage": payload["coverage"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    REPORT.write_text(
        (
            "# A312 — W44 fine selected-channel transfer\n\n"
            f"- Evidence: **{payload['evidence_stage']}**\n"
            f"- Attempted fine-prefix cells: **{len(attempted)} / 4,096**\n"
            f"- Direct symbolic model: **{'yes' if winner is not None else 'no'}**\n"
            f"- Complete model-free fine order: **{'yes' if fine_readout is not None else 'no'}**\n"
            "- Reader refits: **0**\n"
            "- Target labels used: **0**\n"
            f"- Causal artifact: **{payload['causal']['sha256']}**\n"
        ),
        encoding="utf-8",
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "protocol_frozen": PROTOCOL.exists(),
        "measurement_complete": ORDER.exists(),
        "unknown_key_bits": WIDTH,
        "fine_prefix_cells": CELLS,
        "parallel_lanes": LANES,
        "seconds_per_cell": SECONDS_PER_CELL,
        "A308_result_available": A308.RESULT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze", action="store_true")
    action.add_argument("--measure", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.freeze:
        payload = freeze()
    else:
        if not args.expected_protocol_sha256:
            parser.error("--measure requires --expected-protocol-sha256")
        payload = measure(expected_protocol_sha256=args.expected_protocol_sha256)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
