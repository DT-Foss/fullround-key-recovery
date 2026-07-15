#!/usr/bin/env python3
"""Refine an A288 boundary into an exact Causal-ranked 12+12 W24 cover."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"
ARTIFACTS = RESEARCH / "artifacts/a293_chacha20_r20_w24_causal_refinement"

COMMON_SOURCE = RESEARCH / "experiments/chacha20_round20_w24_causal_ranked_recovery_a292.py"
DESIGN = CONFIGS / "chacha20_round20_w24_causal_refinement_a293_design_v1.json"
A291_RESULT = RESULTS / "chacha20_round20_w24_selected_channel_transfer_a291_v1.json"
A291_CAUSAL = RESULTS / "chacha20_round20_w24_selected_channel_transfer_a291_v1.causal"
A287_PREFLIGHT = RESULTS / "chacha20_round20_w24_global_portfolio_a287_preflight_v1.json"
A288_RESULT = RESULTS / "chacha20_round20_w24_partition_portfolio_a288_v1.json"
A288_CAUSAL = RESULTS / "chacha20_round20_w24_partition_portfolio_a288_v1.causal"
A292_RESULT = RESULTS / "chacha20_round20_w24_causal_ranked_recovery_a292_v1.json"
HELPER_WRAPPER = RESEARCH / "experiments/cadical_ranked_variable_prefix_reverse.py"
HELPER_DERIVED = RESEARCH / "native/build/cadical_ranked_variable_prefix_reverse_derived.cpp"
HELPER_BINARY = RESEARCH / "native/build/cadical_ranked_variable_prefix_reverse"

PROTOCOL = CONFIGS / "chacha20_round20_w24_causal_refinement_a293_v1.json"
RESULT = RESULTS / "chacha20_round20_w24_causal_refinement_a293_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w24_causal_refinement_a293_v1.causal"
REPORT = REPORTS / "CHACHA20_ROUND20_W24_CAUSAL_REFINEMENT_A293_V1.md"

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A293"
WIDTH = 24
PREFIX_BITS = 12
SUFFIX_BITS = 12
CELLS = 1 << PREFIX_BITS
LANES = 8
CELLS_PER_LANE = CELLS // LANES
SECONDS_PER_CELL = 5.0
POLL_SECONDS = 0.25


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


COMMON = load_module(COMMON_SOURCE, "a293_a292_common")
sha256 = COMMON.sha256
file_sha256 = COMMON.file_sha256
canonical_sha256 = COMMON.canonical_sha256
atomic_bytes = COMMON.atomic_bytes
atomic_json = COMMON.atomic_json
relative = COMMON.relative
anchored_path = COMMON.anchored_path
anchor = COMMON.anchor


def gray4() -> list[int]:
    return [value ^ (value >> 1) for value in range(16)]


def fine_values(a291: Mapping[str, Any]) -> list[int]:
    coarse = [int(value) for value in a291["analysis"]["complete_cell_order"]]
    values = [(prefix << 4) | suffix for prefix in coarse for suffix in gray4()]
    if len(values) != CELLS or set(values) != set(range(CELLS)):
        raise RuntimeError("A293 fine Causal/Gray order is not an exact cover")
    return values


def lane_orders(a291: Mapping[str, Any]) -> list[list[str]]:
    values = fine_values(a291)
    result = []
    for lane in range(LANES):
        front = values[lane::LANES]
        front_set = set(front)
        tail = [value for value in values if value not in front_set]
        result.append([f"{value:012b}" for value in [*front, *tail]])
    active = [value for order in result for value in order[:CELLS_PER_LANE]]
    if len(active) != CELLS or len(set(active)) != CELLS:
        raise RuntimeError("A293 lane fronts are not an exact disjoint cover")
    return result


def _load_boundary(
    expected_design_sha256: str,
    expected_a288_result_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if file_sha256(DESIGN) != expected_design_sha256:
        raise RuntimeError("A293 prospective design hash differs")
    design = json.loads(DESIGN.read_bytes())
    if (
        design.get("schema")
        != "chacha20-round20-w24-causal-refinement-a293-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "prospectively_frozen_before_any_A288_or_A292_outcome"
        or design.get("launch_gate")
        != "execute_if_A288_returns_a_complete_budget_boundary_and_no_confirmed_A292_model_exists_at_launch"
    ):
        raise RuntimeError("A293 prospective design semantics differ")
    if file_sha256(A288_RESULT) != expected_a288_result_sha256:
        raise RuntimeError("A293 A288 result hash differs")
    a288 = json.loads(A288_RESULT.read_bytes())
    coverage = a288.get("coverage", {})
    if (
        a288.get("schema")
        != "chacha20-round20-w24-partition-portfolio-a288-result-v1"
        or a288.get("attempt_id") != "A288"
        or a288.get("evidence_stage")
        != "FULLROUND_R20_W24_COMPLETE_PARTITION_BUDGET_BOUNDARY"
        or a288.get("winner") is not None
        or a288.get("confirmation") is not None
        or coverage.get("executed_prefix_cells") != 256
        or coverage.get("complete_prefix_cover_if_no_recovery") is not True
        or coverage.get("complete_candidate_domain_enumeration_used") is not False
        or file_sha256(A288_CAUSAL) != a288.get("causal", {}).get("sha256")
    ):
        raise RuntimeError("A293 requires the exact complete A288 budget boundary")
    if A292_RESULT.exists():
        a292 = json.loads(A292_RESULT.read_bytes())
        if a292.get("confirmation") is not None:
            raise RuntimeError("A293 launch gate closes after confirmed A292 recovery")

    if file_sha256(A291_RESULT) != design["frozen_inputs"]["A291_result_sha256"]:
        raise RuntimeError("A293 A291 result hash differs")
    a291 = json.loads(A291_RESULT.read_bytes())
    if (
        a291.get("evidence_stage")
        != "FULLROUND_R20_W24_ZERO_REFIT_SELECTED_CHANNEL_ORDER_FROZEN"
        or a291.get("analysis", {}).get("complete_cell_order_uint8_sha256")
        != design["frozen_inputs"]["A291_complete_order_uint8_sha256"]
        or file_sha256(A291_CAUSAL)
        != design["frozen_inputs"]["A291_Causal_sha256"]
    ):
        raise RuntimeError("A293 A291 Causal order differs")
    if file_sha256(A287_PREFLIGHT) == "":
        raise RuntimeError("A293 missing A287 preflight")
    preflight = json.loads(A287_PREFLIGHT.read_bytes())
    source = preflight["arms"]["base_default"]
    if (
        preflight.get("public_challenge_sha256")
        != design["frozen_inputs"]["public_challenge_sha256"]
        or source["cnf"]["sha256"] != design["frozen_inputs"]["base_CNF_sha256"]
        or file_sha256(anchored_path(source["cnf"]["path"]))
        != source["cnf"]["sha256"]
    ):
        raise RuntimeError("A293 challenge or base CNF differs")

    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(A288_CAUSAL), verify_integrity=True)
    if (
        reader.api_id != "a288w24"
        or len(reader._gaps) != 1
        or reader._gaps[0].get("expected_object_type")
        != "retained_clause_budget_or_prefix_granularity_intervention"
    ):
        raise RuntimeError("A293 authentic A288 Causal gap differs")
    return design, a288, a291, preflight


def execution_plan(a291: Mapping[str, Any], preflight: Mapping[str, Any]) -> dict[str, Any]:
    orders = lane_orders(a291)
    source = preflight["arms"]["base_default"]
    arms = []
    for lane, order in enumerate(orders):
        front = order[:CELLS_PER_LANE]
        arms.append(
            {
                "arm": f"causal_gray12_lane{lane}",
                "lane": lane,
                "cadical_configuration": "default",
                "cell_order": order,
                "active_prefixes": front,
                "active_prefixes_uint16be_sha256": sha256(
                    b"".join(int(value, 2).to_bytes(2, "big") for value in front)
                ),
                "seconds_per_cell": SECONDS_PER_CELL,
                "max_cells": CELLS_PER_LANE,
                "cnf": source["cnf"],
                "model_one_literals_bit0_upward": source[
                    "model_one_literals_bit0_upward"
                ],
            }
        )
    return {
        "primitive": "standard_ChaCha20_block_function",
        "rounds": 20,
        "feedforward_included": True,
        "unknown_key_bits": WIDTH,
        "public_input_output_blocks": 8,
        "constrained_output_bits": 4096,
        "partition_prefix_bits": PREFIX_BITS,
        "suffix_bits_per_cell": SUFFIX_BITS,
        "prefix_cells": CELLS,
        "parallel_retained_state_lanes": LANES,
        "cells_per_lane": CELLS_PER_LANE,
        "fine_order": "A291_coarse_Causal_order_then_4bit_Gray",
        "lane_construction": "fine_order_index_modulo_eight_exact_cover",
        "reverse_operator_enabled": True,
        "arms": arms,
        "first_exact_SAT_terminates_unfinished_siblings": True,
        "UNKNOWN_is_not_UNSAT_or_elimination": True,
        "complete_candidate_domain_enumeration_used": False,
        "confirmation": "frozen_third_RFC_operation_reference_all_eight_blocks",
    }


def freeze(
    expected_design_sha256: str,
    expected_a288_result_sha256: str,
) -> dict[str, Any]:
    if PROTOCOL.exists():
        raise FileExistsError(PROTOCOL)
    design, a288, a291, preflight = _load_boundary(
        expected_design_sha256, expected_a288_result_sha256
    )
    helper = load_module(HELPER_WRAPPER, "a293_helper_compile")
    build = helper.compile_helper(output=HELPER_BINARY, derived_source=HELPER_DERIVED)
    if (
        build["binary_sha256"]
        != design["frozen_inputs"]["variable_prefix_binary_sha256"]
        or build["derived_source_sha256"]
        != design["frozen_inputs"]["variable_prefix_derived_source_sha256"]
    ):
        raise RuntimeError("A293 predeclared variable-prefix build differs")
    plan = execution_plan(a291, preflight)
    protocol = {
        "schema": "chacha20-round20-w24-causal-refinement-a293-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "eight_exact_disjoint_Causal_12bit_lanes_frozen_before_any_A293_solver_execution",
        "execution_plan": plan,
        "execution_plan_sha256": canonical_sha256(plan),
        "public_challenge_sha256": design["frozen_inputs"]["public_challenge_sha256"],
        "anchors": {
            "prospective_design": anchor(DESIGN, expected_design_sha256),
            "A288_result": anchor(A288_RESULT, expected_a288_result_sha256),
            "A288_causal": anchor(A288_CAUSAL, a288["causal"]["sha256"]),
            "A291_result": anchor(A291_RESULT, design["frozen_inputs"]["A291_result_sha256"]),
            "A291_causal": anchor(A291_CAUSAL, design["frozen_inputs"]["A291_Causal_sha256"]),
            "A287_preflight": anchor(A287_PREFLIGHT),
            "helper_wrapper": anchor(HELPER_WRAPPER),
            "helper_derived_source": anchor(HELPER_DERIVED, build["derived_source_sha256"]),
            "helper_binary": anchor(HELPER_BINARY, build["binary_sha256"]),
            "common_confirmation_runner": anchor(COMMON_SOURCE),
            "runner": anchor(Path(__file__)),
        },
        "information_boundary": {
            "A293_design_precedes_A288_and_A292_outcomes": True,
            "A288_boundary_selects_only_the_predeclared_launch_gate": True,
            "target_prefix_or_model_available_to_order": False,
            "all_lanes_orders_and_budgets_frozen": True,
            "any_A293_solver_execution_started": False,
            "UNKNOWN_will_not_be_treated_as_UNSAT": True,
        },
    }
    protocol["scientific_design_sha256"] = canonical_sha256(
        {
            "execution_plan": plan,
            "public_challenge_sha256": protocol["public_challenge_sha256"],
            "information_boundary": protocol["information_boundary"],
            "anchors": protocol["anchors"],
        }
    )
    atomic_json(PROTOCOL, protocol)
    return protocol


def load_protocol(
    expected_protocol_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A293 protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    if (
        protocol.get("schema")
        != "chacha20-round20-w24-causal-refinement-a293-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "eight_exact_disjoint_Causal_12bit_lanes_frozen_before_any_A293_solver_execution"
        or protocol.get("execution_plan_sha256")
        != canonical_sha256(protocol.get("execution_plan"))
    ):
        raise RuntimeError("A293 protocol semantics differ")
    for row in protocol["anchors"].values():
        anchor(anchored_path(row["path"]), row["sha256"])
    _, a288, a291, preflight = _load_boundary(
        protocol["anchors"]["prospective_design"]["sha256"],
        protocol["anchors"]["A288_result"]["sha256"],
    )
    if execution_plan(a291, preflight) != protocol["execution_plan"]:
        raise RuntimeError("A293 recomputed execution plan differs")
    return protocol, a288


def _command(arm: Mapping[str, Any]) -> list[str]:
    mapping = [int(value) for value in arm["model_one_literals_bit0_upward"]]
    assumptions = [mapping[bit] for bit in range(WIDTH - 1, SUFFIX_BITS - 1, -1)]
    return [
        str(HELPER_BINARY),
        "--cnf",
        str(anchored_path(arm["cnf"]["path"])),
        "--mode",
        str(arm["arm"]),
        "--configuration",
        str(arm["cadical_configuration"]),
        "--assumption-one-literals",
        ",".join(str(value) for value in assumptions),
        "--model-one-literals",
        ",".join(str(value) for value in mapping),
        "--cell-order",
        ",".join(arm["cell_order"]),
        "--seconds",
        str(arm["seconds_per_cell"]),
        "--max-cells",
        str(arm["max_cells"]),
    ]


def _raw_rows(raw: str) -> list[dict[str, Any]]:
    return [
        json.loads(line.removeprefix("PARTITION_RESULT "))
        for line in raw.splitlines()
        if line.startswith("PARTITION_RESULT ")
    ]


def run_partition(
    protocol: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    helper = load_module(HELPER_WRAPPER, "a293_helper_run")
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    processes: dict[str, subprocess.Popen[bytes]] = {}
    handles: dict[str, tuple[Any, Any]] = {}
    metadata: dict[str, dict[str, Any]] = {}
    arm_by_name = {row["arm"]: row for row in protocol["execution_plan"]["arms"]}
    for arm in protocol["execution_plan"]["arms"]:
        name = arm["arm"]
        stdout_path = ARTIFACTS / f"{name}.stdout"
        stderr_path = ARTIFACTS / f"{name}.stderr"
        stdout_path.unlink(missing_ok=True)
        stderr_path.unlink(missing_ok=True)
        command = _command(arm)
        stdout_handle = stdout_path.open("wb")
        stderr_handle = stderr_path.open("wb")
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=stdout_handle,
            stderr=stderr_handle,
            start_new_session=True,
        )
        processes[name] = process
        handles[name] = (stdout_handle, stderr_handle)
        metadata[name] = {
            "command_sha256": canonical_sha256(command),
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "started": time.monotonic(),
            "parsed": None,
            "terminated_after_sibling_sat": False,
        }
    winner_name: str | None = None
    while True:
        for name, process in processes.items():
            meta = metadata[name]
            if process.poll() is None or meta["parsed"] is not None:
                continue
            if process.returncode != 0:
                raise RuntimeError(f"A293 {name} helper returned {process.returncode}")
            handles[name][0].flush()
            handles[name][1].flush()
            raw = Path(meta["stdout_path"]).read_text(encoding="ascii")
            arm = arm_by_name[name]
            parsed = helper.parse_ranked_output(
                stdout=raw,
                returncode=process.returncode,
                mode=name,
                configuration=arm["cadical_configuration"],
                order=arm["cell_order"],
                model_one_literals_bit0_upward=arm[
                    "model_one_literals_bit0_upward"
                ],
                prefix_bits=PREFIX_BITS,
                seconds=float(arm["seconds_per_cell"]),
                max_cells=int(arm["max_cells"]),
            )
            meta["parsed"] = parsed
            if parsed["sat_found"]:
                winner_name = name
                break
        if winner_name is not None or all(
            process.poll() is not None for process in processes.values()
        ):
            break
        time.sleep(POLL_SECONDS)
    if winner_name is not None:
        for name, process in processes.items():
            if name == winner_name or process.poll() is not None:
                continue
            metadata[name]["terminated_after_sibling_sat"] = True
            os.killpg(process.pid, signal.SIGTERM)
    for process in processes.values():
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=15)
    for stdout_handle, stderr_handle in handles.values():
        stdout_handle.close()
        stderr_handle.close()

    rows = []
    winner: dict[str, Any] | None = None
    seen: set[str] = set()
    for name, process in processes.items():
        arm = arm_by_name[name]
        meta = metadata[name]
        stdout_path = Path(meta["stdout_path"])
        stderr_path = Path(meta["stderr_path"])
        raw = stdout_path.read_text(encoding="ascii")
        raw_rows = _raw_rows(raw)
        observed = [row.get("prefix") for row in raw_rows]
        expected = arm["active_prefixes"]
        if observed != expected[: len(observed)]:
            raise RuntimeError(f"A293 {name} partial prefix order differs")
        if seen.intersection(observed):
            raise RuntimeError("A293 executed lane prefixes overlap")
        seen.update(observed)
        parsed = meta["parsed"]
        if parsed is None and not meta["terminated_after_sibling_sat"]:
            if process.returncode != 0:
                raise RuntimeError(f"A293 {name} incomplete without sibling SAT")
            parsed = helper.parse_ranked_output(
                stdout=raw,
                returncode=process.returncode,
                mode=name,
                configuration=arm["cadical_configuration"],
                order=arm["cell_order"],
                model_one_literals_bit0_upward=arm[
                    "model_one_literals_bit0_upward"
                ],
                prefix_bits=PREFIX_BITS,
                seconds=float(arm["seconds_per_cell"]),
                max_cells=int(arm["max_cells"]),
            )
        rows.append(
            {
                "arm": name,
                "lane": arm["lane"],
                "returncode": process.returncode,
                "elapsed_seconds": time.monotonic() - float(meta["started"]),
                "terminated_after_sibling_sat": meta[
                    "terminated_after_sibling_sat"
                ],
                "command_sha256": meta["command_sha256"],
                "stdout_sha256": file_sha256(stdout_path),
                "stderr_sha256": file_sha256(stderr_path),
                "attempted_prefixes": observed,
                "attempted_prefix_count": len(observed),
                "status_counts": {
                    status: sum(item.get("status") == status for item in raw_rows)
                    for status in ("sat", "unsat", "unknown")
                },
                "retained_state_continuity_verified": (
                    None
                    if parsed is None
                    else parsed["retained_state_continuity_verified"]
                ),
                "completed_lane": parsed is not None,
            }
        )
        if parsed is None or not parsed["sat_found"]:
            continue
        sat_row = parsed["sat_row"]
        bits = sat_row["model_bits_bit0_upward"]
        candidate = sum(int(bit) << index for index, bit in enumerate(bits))
        if candidate >> SUFFIX_BITS != int(sat_row["prefix"], 2):
            raise RuntimeError("A293 SAT model fine prefix differs")
        winner = {
            "arm": name,
            "candidate_low24": candidate,
            "candidate_low24_hex": f"{candidate:06x}",
            "prefix12": sat_row["prefix"],
            "lane_cell_index": sat_row["cell_index"],
        }
    rows.sort(key=lambda row: row["lane"])
    if winner_name is not None and (winner is None or winner["arm"] != winner_name):
        raise RuntimeError("A293 winner parsing differs")
    if winner is None and seen != {f"{value:012b}" for value in range(CELLS)}:
        raise RuntimeError("A293 boundary lacks a complete fine prefix cover")
    return rows, winner


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    reader_source = Path(inspect.getsourcefile(CausalReader) or "")
    recovered = payload.get("confirmation") is not None
    terminal = (
        "A293:confirmed_Causal_refined_fullround_W24_recovery"
        if recovered
        else "A293:complete_Causal_refined_budget_boundary"
    )
    writer = CausalWriter(api_id="a293w24")
    writer._rules = []
    writer.add_rule(
        name="coarse_Causal_order_to_exact_fine_cover",
        description="The frozen A291 Reader order is refined by a four-bit Gray subprefix into 4,096 exact cells distributed across eight retained reverse states.",
        pattern=["A291_coarse_order", "Gray4_subprefix", "eight_disjoint_lanes"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="fine_partition_to_confirmation",
        description="Only a SAT model independently matching all eight standard output blocks is accepted; timed cells remain UNKNOWN.",
        pattern=["fine_partition_SAT", "4096_bit_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A288:complete_partition_budget_boundary",
        mechanism="refine_A291_Causal_order_from_8_to_12_prefix_bits",
        outcome="A293:frozen_exact_12bit_partition",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification="4096 exact cells; eight disjoint lanes; 12 free bits per cell",
        evidence=payload["evidence_stage"],
        domain="AI-native selected full-round ChaCha20 refinement",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A293:frozen_exact_12bit_partition",
        mechanism="parallel_reverse_retained_state_fine_cells",
        outcome=("A293:fine_partition_SAT" if recovered else terminal),
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["coverage"], sort_keys=True),
        evidence=json.dumps(payload["solver_arms"], sort_keys=True),
        domain="fine partitioned symbolic full-round search",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=("A293:fine_partition_SAT" if recovered else terminal),
        mechanism=(
            "standalone_RFC_operation_recompute_all_eight_blocks"
            if recovered
            else "retain_complete_fine_UNKNOWN_boundary"
        ),
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=(
            "4096 exact output bits; one-bit control rejected"
            if recovered
            else "all 4096 fine cells attempted under frozen budgets"
        ),
        evidence=payload["evidence_stage"],
        domain="independent confirmation or exact solver boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A288:complete_partition_budget_boundary",
        mechanism="materialized_Causal_fine_refinement_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A288_gap_plus_A293_refinement",
        quantification="AI-native exact continuation retained in-file",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A293 Causal-refined ChaCha20-R20 W24 recovery",
        entities=[
            "A288:complete_partition_budget_boundary",
            "A293:frozen_exact_12bit_partition",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospectively_frozen_W28_fine_partition_transfer"
            if recovered
            else "retained_state_depth_or_16plus8_refinement"
        ),
        confidence=1.0,
        suggested_queries=(
            ["Does the confirmed 12+12 mechanism widen to W28?"]
            if recovered
            else ["Which finer split or longer retained budget crosses W24?" ]
        ),
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
        reader.version != 1
        or reader.api_id != "a293w24"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A293 authentic Causal gate failed")
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
        "reader_source": anchor(reader_source),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def execute(expected_protocol_sha256: str) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A293 result already exists")
    protocol, _ = load_protocol(expected_protocol_sha256)
    root_reference = load_module(COMMON.ROOT_REFERENCE_SOURCE, "a293_root_reference")
    a287_protocol = json.loads(COMMON.A287_PROTOCOL.read_bytes())
    solver_rows, winner = run_partition(protocol)
    confirmation = (
        None
        if winner is None
        else COMMON.confirm_candidate(
            int(winner["candidate_low24"]), a287_protocol, root_reference
        )
    )
    attempted = [
        prefix for row in solver_rows for prefix in row["attempted_prefixes"]
    ]
    if len(attempted) != len(set(attempted)):
        raise RuntimeError("A293 executed fine prefix cover overlaps")
    coverage = {
        "executed_prefix_cells": len(attempted),
        "total_prefix_cells": CELLS,
        "executed_prefix_fraction": len(attempted) / CELLS,
        "prefix_domain_upper_bound_assignments": len(attempted) * (1 << SUFFIX_BITS),
        "full_W24_assignment_domain": 1 << WIDTH,
        "strict_prefix_subset_before_recovery": (
            confirmation is not None and len(attempted) < CELLS
        ),
        "complete_prefix_cover_if_no_recovery": (
            confirmation is None and len(attempted) == CELLS
        ),
        "complete_candidate_domain_enumeration_used": False,
    }
    evidence_stage = (
        "FULLROUND_R20_W24_CAUSAL_REFINED_SYMBOLIC_RECOVERY_CONFIRMED"
        if confirmation is not None
        else "FULLROUND_R20_W24_COMPLETE_CAUSAL_REFINED_BUDGET_BOUNDARY"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w24-causal-refinement-a293-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "solver_arms": solver_rows,
        "winner": winner,
        "confirmation": confirmation,
        "coverage": coverage,
        "information_boundary": {
            "prospective_design_precedes_A288_and_A292_outcomes": True,
            "target_prefix_or_model_available_to_order": False,
            "unknown_treated_as_UNSAT": False,
            "complete_candidate_domain_enumeration_used": False,
        },
        "rfc8439_gate": root_reference.rfc8439_kat(),
        "runner": anchor(Path(__file__)),
    }
    payload["execution_sha256"] = canonical_sha256(solver_rows)
    payload["measurement_sha256"] = canonical_sha256(
        {
            "solver_arms": solver_rows,
            "winner": winner,
            "confirmation": confirmation,
            "coverage": coverage,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    lines = [
        "# A293 — ChaCha20-R20 W24 Causal 12+12 refinement",
        "",
        f"Evidence stage: **{evidence_stage}**",
        "",
        "- Standard rounds plus feed-forward: **20**",
        "- Unknown key bits: **24**",
        "- Public standard-output blocks: **8 / 4,096 bits**",
        "- Exact fine partition: **8 lanes × 512 cells; 12 free bits/cell**",
        f"- Fine prefix cells attempted: **{len(attempted)} / 4,096**",
        f"- Independently confirmed recovery: **{confirmation is not None}**",
        "- Complete candidate-domain enumeration: **False**",
        "",
        "## Authentic AI-native Causal readback",
        "",
        f"- Terminal: **{payload['causal']['personal_semantic_readback']['terminal_chain']['outcome']}**",
        f"- Next gap: **{payload['causal']['personal_semantic_readback']['next_gap']['expected_object_type']}**",
        "",
    ]
    atomic_bytes(REPORT, ("\n".join(lines) + "\n").encode("utf-8"))
    return payload


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze", action="store_true")
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--run", action="store_true")
    parser.add_argument("--expected-design-sha256")
    parser.add_argument("--expected-a288-result-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args(argv)
    if args.freeze:
        if not args.expected_design_sha256 or not args.expected_a288_result_sha256:
            parser.error(
                "--freeze requires --expected-design-sha256 and --expected-a288-result-sha256"
            )
        payload = freeze(
            args.expected_design_sha256,
            args.expected_a288_result_sha256,
        )
        output = {
            "protocol": str(PROTOCOL),
            "protocol_sha256": file_sha256(PROTOCOL),
            "execution_plan_sha256": payload["execution_plan_sha256"],
            "A293_solver_execution_started": False,
        }
    else:
        if not args.expected_protocol_sha256:
            parser.error("--analyze/--run requires --expected-protocol-sha256")
        protocol, _ = load_protocol(args.expected_protocol_sha256)
        if args.analyze:
            output = {
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": args.expected_protocol_sha256,
                "prefix_cells": protocol["execution_plan"]["prefix_cells"],
                "parallel_lanes": protocol["execution_plan"][
                    "parallel_retained_state_lanes"
                ],
                "A293_solver_execution_started": False,
            }
        else:
            payload = execute(args.expected_protocol_sha256)
            output = {
                "result": str(RESULT),
                "result_sha256": file_sha256(RESULT),
                "causal_sha256": payload["causal"]["sha256"],
                "evidence_stage": payload["evidence_stage"],
                "confirmation": payload["confirmation"],
                "coverage": payload["coverage"],
            }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
