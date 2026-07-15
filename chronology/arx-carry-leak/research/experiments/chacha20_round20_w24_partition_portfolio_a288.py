#!/usr/bin/env python3
"""Continue an A287 boundary with an exact four-lane W24 prefix partition."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
ARTIFACTS = RESEARCH / "artifacts/a288_chacha20_r20_w24_partition"
REPORTS = RESEARCH / "reports"

A287_SOURCE = RESEARCH / "experiments/chacha20_round20_w24_global_portfolio_a287.py"
A287_PROTOCOL = CONFIGS / "chacha20_round20_w24_global_portfolio_a287_v1.json"
A287_PREFLIGHT = RESULTS / "chacha20_round20_w24_global_portfolio_a287_preflight_v1.json"
A287_RESULT = RESULTS / "chacha20_round20_w24_global_portfolio_a287_v1.json"
A287_CAUSAL = RESULTS / "chacha20_round20_w24_global_portfolio_a287_v1.causal"
PARTITION_WRAPPER = RESEARCH / "experiments/cadical_ranked_partition.py"
PARTITION_NATIVE = RESEARCH / "native/cadical_ranked_partition_until_sat.cpp"
PARTITION_BINARY = RESEARCH / "native/build/cadical_ranked_partition_a288"
ROOT_REFERENCE_SOURCE = (
    RESEARCH / "experiments/chacha20_round20_multitarget_root_confirm.py"
)
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)

PROTOCOL = CONFIGS / "chacha20_round20_w24_partition_portfolio_a288_v1.json"
RESULT = RESULTS / "chacha20_round20_w24_partition_portfolio_a288_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w24_partition_portfolio_a288_v1.causal"
REPORT = REPORTS / "CHACHA20_ROUND20_W24_PARTITION_PORTFOLIO_A288_V1.md"

ATTEMPT_ID = "A288"
WIDTH = 24
PREFIX_BITS = 8
SUFFIX_BITS = WIDTH - PREFIX_BITS
LANES = 4
CELLS_PER_LANE = 64
SECONDS_PER_CELL = 60.0
BLOCKS = 8
OUTPUT_BITS = 4096
POLL_SECONDS = 0.25
MASK32 = (1 << 32) - 1


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_sha256(value: Any) -> str:
    return sha256(canonical_bytes(value))


def atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def atomic_json(path: Path, value: Any) -> None:
    atomic_bytes(
        path,
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n",
    )


def relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:
        return str(resolved)


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    digest = file_sha256(path)
    if expected is not None and digest != expected:
        raise RuntimeError(f"A288 anchor differs: {path}")
    return {"path": relative(path), "sha256": digest}


def anchored_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def gray_values() -> list[int]:
    return [index ^ (index >> 1) for index in range(256)]


def partition_orders() -> list[list[str]]:
    gray = gray_values()
    orders: list[list[str]] = []
    for lane in range(LANES):
        front = gray[lane::LANES]
        front_set = set(front)
        tail = [value for value in gray if value not in front_set]
        orders.append([f"{value:08b}" for value in [*front, *tail]])
    return orders


def execution_plan() -> dict[str, Any]:
    orders = partition_orders()
    definitions = [
        ("base_default_lane0", "base_default", "default", 0),
        ("bfs_sat_lane1", "bfs_far_sat", "sat", 1),
        ("base_sat_lane2", "base_default", "sat", 2),
        ("bfs_default_lane3", "bfs_far_sat", "default", 3),
    ]
    arms = []
    for name, source_arm, configuration, lane in definitions:
        front = orders[lane][:CELLS_PER_LANE]
        arms.append(
            {
                "arm": name,
                "source_A287_CNF_arm": source_arm,
                "cadical_configuration": configuration,
                "lane": lane,
                "cell_order": orders[lane],
                "active_prefixes": front,
                "active_prefixes_uint8_sha256": sha256(
                    bytes(int(value, 2) for value in front)
                ),
                "seconds_per_cell": SECONDS_PER_CELL,
                "max_cells": CELLS_PER_LANE,
            }
        )
    active = [prefix for arm in arms for prefix in arm["active_prefixes"]]
    if len(active) != 256 or len(set(active)) != 256:
        raise RuntimeError("A288 active prefix lanes are not an exact partition")
    return {
        "primitive": "standard_ChaCha20_block_function",
        "rounds": 20,
        "feedforward_included": True,
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "public_input_output_blocks": BLOCKS,
        "constrained_output_bits": OUTPUT_BITS,
        "partition_prefix_bits": PREFIX_BITS,
        "suffix_bits_per_cell": SUFFIX_BITS,
        "prefix_cells": 256,
        "parallel_retained_state_lanes": LANES,
        "cells_per_lane": CELLS_PER_LANE,
        "lane_construction": "Gray_sequence_modulo_four_exact_disjoint_cover",
        "arms": arms,
        "first_exact_SAT_terminates_unfinished_siblings": True,
        "UNKNOWN_is_not_UNSAT_or_elimination": True,
        "no_complete_candidate_enumeration": True,
        "confirmation": "frozen_third_RFC_operation_reference_all_eight_blocks",
        "control": "one_bit_flipped_first_standard_output_block",
    }


def _load_a287_boundary(expected_result_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(A287_RESULT) != expected_result_sha256:
        raise RuntimeError("A288 A287 result hash differs")
    result = json.loads(A287_RESULT.read_bytes())
    preflight_sha = str(result.get("preflight", {}).get("sha256", ""))
    if (
        result.get("schema")
        != "chacha20-round20-w24-global-portfolio-a287-result-v1"
        or result.get("attempt_id") != "A287"
        or result.get("evidence_stage")
        != "FULLROUND_R20_W24_DIVERSE_GLOBAL_BUDGET_BOUNDARY"
        or result.get("winner") is not None
        or result.get("confirmation") is not None
        or len(result.get("solver_arms", [])) != 2
        or any(row.get("status") != "unknown" for row in result["solver_arms"])
        or result.get("information_boundary", {}).get(
            "complete_candidate_domain_enumeration_used"
        )
        is not False
        or file_sha256(A287_PREFLIGHT) != preflight_sha
        or file_sha256(A287_CAUSAL) != result.get("causal", {}).get("sha256")
    ):
        raise RuntimeError("A288 requires the exact A287 diverse global boundary")
    preflight = json.loads(A287_PREFLIGHT.read_bytes())
    if (
        preflight.get("schema")
        != "chacha20-round20-w24-global-portfolio-a287-preflight-v1"
        or preflight.get("public_challenge_sha256")
        != result.get("public_challenge_sha256")
    ):
        raise RuntimeError("A288 A287 preflight semantics differ")
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(A287_CAUSAL), verify_integrity=True)
    gaps = list(reader._gaps)
    if (
        reader.api_id != "a287w24"
        or len(gaps) != 1
        or gaps[0].get("expected_object_type")
        != "exact_disjoint_partitioned_W24_transfer"
    ):
        raise RuntimeError("A288 A287 authentic Causal gap differs")
    return result, preflight


def freeze(expected_a287_result_sha256: str) -> dict[str, Any]:
    if PROTOCOL.exists():
        raise FileExistsError(PROTOCOL)
    result, preflight = _load_a287_boundary(expected_a287_result_sha256)
    wrapper = load_module(PARTITION_WRAPPER, "a288_partition_compile")
    build = wrapper.compile_helper(output=PARTITION_BINARY)
    plan = execution_plan()
    arms = []
    for row in plan["arms"]:
        source = preflight["arms"][row["source_A287_CNF_arm"]]
        mapping = [int(value) for value in source["model_one_literals_bit0_upward"]]
        if len(mapping) != WIDTH or len({abs(value) for value in mapping}) != WIDTH:
            raise RuntimeError("A288 W24 model mapping differs")
        cnf = anchored_path(source["cnf"]["path"])
        arms.append(
            {
                **row,
                "cnf": anchor(cnf, source["cnf"]["sha256"]),
                "model_one_literals_bit0_upward": mapping,
                "model_mapping_sha256": canonical_sha256(mapping),
            }
        )
    plan = {**plan, "arms": arms}
    protocol = {
        "schema": "chacha20-round20-w24-partition-portfolio-a288-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "four_exact_disjoint_prefix_lanes_frozen_before_any_partition_solver_execution",
        "execution_plan": plan,
        "execution_plan_sha256": canonical_sha256(plan),
        "public_challenge_sha256": result["public_challenge_sha256"],
        "anchors": {
            "A287_source": anchor(A287_SOURCE),
            "A287_protocol": anchor(
                A287_PROTOCOL, preflight["protocol"]["sha256"]
            ),
            "A287_preflight": anchor(
                A287_PREFLIGHT, result["preflight"]["sha256"]
            ),
            "A287_result": anchor(A287_RESULT, expected_a287_result_sha256),
            "A287_causal": anchor(A287_CAUSAL, result["causal"]["sha256"]),
            "partition_wrapper": anchor(PARTITION_WRAPPER),
            "partition_native": anchor(PARTITION_NATIVE, build["source_sha256"]),
            "partition_binary": anchor(PARTITION_BINARY, build["binary_sha256"]),
            "standalone_RFC_reference": anchor(ROOT_REFERENCE_SOURCE),
        },
        "information_boundary": {
            "A287_global_boundary_precedes_A288_design": True,
            "A287_authentic_Causal_gap_read_before_A288_freeze": True,
            "secret_assignment_target_prefix_or_model_available": False,
            "all_four_orders_CNF_views_configurations_and_budgets_frozen": True,
            "any_partition_solver_execution_started": False,
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


def load_protocol(expected_sha256: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A288 protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    if (
        protocol.get("schema")
        != "chacha20-round20-w24-partition-portfolio-a288-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "four_exact_disjoint_prefix_lanes_frozen_before_any_partition_solver_execution"
        or protocol.get("execution_plan_sha256")
        != canonical_sha256(protocol.get("execution_plan"))
    ):
        raise RuntimeError("A288 protocol semantics differ")
    for row in protocol["anchors"].values():
        anchor(anchored_path(row["path"]), row["sha256"])
    a287, preflight = _load_a287_boundary(
        protocol["anchors"]["A287_result"]["sha256"]
    )
    if a287["public_challenge_sha256"] != protocol["public_challenge_sha256"]:
        raise RuntimeError("A288 public challenge differs")
    return protocol, a287, preflight


def _command(arm: dict[str, Any]) -> list[str]:
    width = len(arm["model_one_literals_bit0_upward"])
    mapping = arm["model_one_literals_bit0_upward"]
    assumptions = [mapping[bit] for bit in range(width - 1, width - 9, -1)]
    return [
        str(PARTITION_BINARY),
        "--cnf",
        str(anchored_path(arm["cnf"]["path"])),
        "--mode",
        arm["arm"],
        "--configuration",
        arm["cadical_configuration"],
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


def run_partition(protocol: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    wrapper = load_module(PARTITION_WRAPPER, "a288_partition_run")
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
            "command": command,
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
                raise RuntimeError(f"A288 {name} helper returned {process.returncode}")
            stdout_handle, stderr_handle = handles[name]
            stdout_handle.flush()
            stderr_handle.flush()
            raw = Path(meta["stdout_path"]).read_text(encoding="ascii")
            arm = arm_by_name[name]
            parsed = wrapper.parse_ranked_output(
                stdout=raw,
                returncode=process.returncode,
                mode=name,
                configuration=arm["cadical_configuration"],
                order=arm["cell_order"],
                model_one_literals_bit0_upward=arm[
                    "model_one_literals_bit0_upward"
                ],
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

    rows: list[dict[str, Any]] = []
    winner: dict[str, Any] | None = None
    seen_prefixes: set[str] = set()
    for name, process in processes.items():
        arm = arm_by_name[name]
        meta = metadata[name]
        stdout_path = Path(meta["stdout_path"])
        stderr_path = Path(meta["stderr_path"])
        raw = stdout_path.read_text(encoding="ascii")
        parsed_rows = _raw_rows(raw)
        expected_front = arm["active_prefixes"]
        observed_prefixes = [row.get("prefix8") for row in parsed_rows]
        if observed_prefixes != expected_front[: len(observed_prefixes)]:
            raise RuntimeError(f"A288 {name} partial prefix order differs")
        if seen_prefixes.intersection(observed_prefixes):
            raise RuntimeError("A288 executed prefix lanes overlap")
        seen_prefixes.update(observed_prefixes)
        parsed = meta["parsed"]
        if parsed is None and not meta["terminated_after_sibling_sat"]:
            if process.returncode != 0:
                raise RuntimeError(f"A288 {name} incomplete without sibling SAT")
            parsed = wrapper.parse_ranked_output(
                stdout=raw,
                returncode=process.returncode,
                mode=name,
                configuration=arm["cadical_configuration"],
                order=arm["cell_order"],
                model_one_literals_bit0_upward=arm[
                    "model_one_literals_bit0_upward"
                ],
                seconds=float(arm["seconds_per_cell"]),
                max_cells=int(arm["max_cells"]),
            )
        row = {
            "arm": name,
            "source_A287_CNF_arm": arm["source_A287_CNF_arm"],
            "cadical_configuration": arm["cadical_configuration"],
            "returncode": process.returncode,
            "elapsed_seconds": time.monotonic() - float(meta["started"]),
            "terminated_after_sibling_sat": meta["terminated_after_sibling_sat"],
            "command_sha256": meta["command_sha256"],
            "stdout_sha256": file_sha256(stdout_path),
            "stderr_sha256": file_sha256(stderr_path),
            "attempted_prefixes": observed_prefixes,
            "attempted_prefix_count": len(observed_prefixes),
            "status_counts": {
                status: sum(item.get("status") == status for item in parsed_rows)
                for status in ("sat", "unsat", "unknown")
            },
            "retained_state_continuity_verified": (
                None if parsed is None else parsed["retained_state_continuity_verified"]
            ),
            "completed_lane": parsed is not None,
        }
        rows.append(row)
        if parsed is None or not parsed["sat_found"]:
            continue
        sat_row = parsed["sat_row"]
        bits = sat_row["model_bits_bit0_upward"]
        candidate = sum(int(bit) << index for index, bit in enumerate(bits))
        if candidate >> SUFFIX_BITS != int(sat_row["prefix8"], 2):
            raise RuntimeError("A288 SAT model prefix differs")
        winner = {
            "arm": name,
            "candidate_low24": candidate,
            "candidate_low24_hex": f"{candidate:06x}",
            "prefix8": sat_row["prefix8"],
            "lane_cell_index": sat_row["cell_index"],
        }
    rows.sort(key=lambda row: row["arm"])
    if winner_name is not None and (winner is None or winner["arm"] != winner_name):
        raise RuntimeError("A288 winner parsing differs")
    if winner is None and seen_prefixes != {f"{value:08b}" for value in range(256)}:
        raise RuntimeError("A288 boundary lacks a complete prefix cover")
    return rows, winner


def confirm_winner(
    winner: dict[str, Any], a287: dict[str, Any], root_reference: Any
) -> dict[str, Any]:
    protocol = json.loads(A287_PROTOCOL.read_bytes())
    challenge = protocol["public_challenge"]
    if challenge["target_block_sha256"] != [
        sha256(root_reference._word_bytes(block))  # noqa: SLF001
        for block in challenge["target_words"]
    ]:
        raise RuntimeError("A288 frozen target block hashes differ")
    candidate = int(winner["candidate_low24"])
    key_words = [
        int(challenge["known_key_value_words"][0]) | candidate,
        *[int(word) for word in challenge["known_key_value_words"][1:]],
    ]
    observed = [
        root_reference.chacha20_block(
            key_words,
            (int(challenge["counter_start"]) + block) & MASK32,
            challenge["nonce_words"],
        )
        for block in range(BLOCKS)
    ]
    hashes = [
        sha256(root_reference._word_bytes(block))  # noqa: SLF001
        for block in observed
    ]
    if (
        observed != challenge["target_words"]
        or hashes != challenge["target_block_sha256"]
        or observed[0] == challenge["control_target_words"]
        or a287["public_challenge_sha256"]
        != canonical_sha256(challenge)
    ):
        raise RuntimeError("A288 standalone full-output confirmation failed")
    return {
        "recovered_unknown_low24": candidate,
        "recovered_unknown_low24_hex": f"{candidate:06x}",
        "standalone_direct_RFC_operation_all_eight_blocks_match": True,
        "output_bits_checked": OUTPUT_BITS,
        "block_sha256": hashes,
        "one_bit_control_rejected": True,
        "complete_candidate_domain_enumeration_used": False,
    }


def build_causal(payload: dict[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    reader_source = Path(inspect.getsourcefile(CausalReader) or "")
    retained = payload.get("confirmation") is not None
    terminal = (
        "A288:confirmed_partitioned_fullround_W24_recovery"
        if retained
        else "A288:complete_partition_budget_boundary"
    )
    writer = CausalWriter(api_id="a288w24")
    writer._rules = []
    writer.add_rule(
        name="exact_disjoint_partition_to_confirmation",
        description="Four hash-frozen disjoint prefix lanes retain solver state and accept only a model independently confirmed over all 4096 output bits.",
        pattern=["exact_four_lane_partition", "partition_SAT_model", "4096_bit_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_partition_boundary_retention",
        description="A complete 256-prefix budget cover with UNKNOWN preserved as UNKNOWN becomes the next exact solver boundary.",
        pattern=["complete_prefix_cover", "UNKNOWN_not_elimination"],
        conclusion="partition_budget_boundary",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A287:measured_W24_global_budget_boundary",
        mechanism="freeze_exact_disjoint_four_lane_Gray_partition",
        outcome="A288:frozen_W24_partition_portfolio",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification="256 prefixes; four disjoint lanes; 16 residual bits per cell",
        evidence=payload["evidence_stage"],
        domain="AI-native selected full-round ChaCha20 continuation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A288:frozen_W24_partition_portfolio",
        mechanism="parallel_retained_state_prefix_cells",
        outcome=("A288:partition_SAT_model" if retained else "A288:complete_prefix_budget_cover"),
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["coverage"], sort_keys=True),
        evidence=json.dumps(payload["solver_arms"], sort_keys=True),
        domain="partitioned symbolic full-round search",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=("A288:partition_SAT_model" if retained else "A288:complete_prefix_budget_cover"),
        mechanism=(
            "standalone_RFC_operation_recompute_all_eight_blocks"
            if retained
            else "retain_UNKNOWN_as_exact_cell_budget_boundary"
        ),
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=(
            "4096 exact bits; one-bit control rejected"
            if retained
            else "all 256 prefixes attempted under frozen budgets"
        ),
        evidence=payload["evidence_stage"],
        domain="independent confirmation or exact solver boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A288:frozen_W24_partition_portfolio",
        mechanism="materialized_partition_execution_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A288_partition_execution",
        quantification="AI-native exact closure retained in-file",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A288 ChaCha20-R20 W24 partition continuation",
        entities=[
            "A287:measured_W24_global_budget_boundary",
            "A288:frozen_W24_partition_portfolio",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospectively_frozen_W28_transfer"
            if retained
            else "retained_clause_budget_or_prefix_granularity_intervention"
        ),
        confidence=1.0,
        suggested_queries=(
            ["Can the confirmed partition mechanism widen to W28?"]
            if retained
            else [
                "Which UNKNOWN cells retain the strongest reusable clause-state gain?",
                "Does a 12+12 split cross the measured W24 boundary?",
            ]
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
        or reader.api_id != "a288w24"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A288 authentic Causal gate failed")
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
        raise FileExistsError("A288 result already exists")
    protocol, a287, _ = load_protocol(expected_protocol_sha256)
    root_reference = load_module(ROOT_REFERENCE_SOURCE, "a288_root_reference")
    solver_rows, winner = run_partition(protocol)
    confirmation = (
        None if winner is None else confirm_winner(winner, a287, root_reference)
    )
    attempted = [
        prefix for row in solver_rows for prefix in row["attempted_prefixes"]
    ]
    if len(attempted) != len(set(attempted)):
        raise RuntimeError("A288 executed prefix cover overlaps")
    coverage = {
        "executed_prefix_cells": len(attempted),
        "total_prefix_cells": 256,
        "executed_prefix_fraction": len(attempted) / 256.0,
        "prefix_domain_upper_bound_assignments": len(attempted) * (1 << SUFFIX_BITS),
        "full_W24_assignment_domain": 1 << WIDTH,
        "strict_prefix_subset_before_recovery": (
            confirmation is not None and len(attempted) < 256
        ),
        "complete_prefix_cover_if_no_recovery": (
            confirmation is None and len(attempted) == 256
        ),
        "complete_candidate_domain_enumeration_used": False,
    }
    evidence_stage = (
        "FULLROUND_R20_W24_PARTITIONED_SYMBOLIC_RECOVERY_CONFIRMED"
        if confirmation is not None
        else "FULLROUND_R20_W24_COMPLETE_PARTITION_BUDGET_BOUNDARY"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w24-partition-portfolio-a288-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "solver_arms": solver_rows,
        "winner": winner,
        "confirmation": confirmation,
        "coverage": coverage,
        "information_boundary": {
            "secret_assignment_target_prefix_or_model_available_before_solver": False,
            "all_four_partitions_and_budgets_frozen_before_solver": True,
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
        "# A288 — ChaCha20-R20 W24 partition portfolio",
        "",
        f"Evidence stage: **{evidence_stage}**",
        "",
        "- Standard rounds plus feed-forward: **20**",
        "- Unknown key bits: **24**",
        "- Public standard-output blocks: **8 / 4,096 bits**",
        "- Frozen exact prefix partition: **4 lanes × 64 cells**",
        f"- Prefix cells attempted: **{coverage['executed_prefix_cells']} / 256**",
        f"- Independent recovery confirmation: **{confirmation is not None}**",
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
    parser.add_argument("--expected-a287-result-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args(argv)
    if args.freeze:
        if not args.expected_a287_result_sha256:
            parser.error("--freeze requires --expected-a287-result-sha256")
        payload = freeze(args.expected_a287_result_sha256)
        output = {
            "protocol": str(PROTOCOL),
            "protocol_sha256": file_sha256(PROTOCOL),
            "execution_plan_sha256": payload["execution_plan_sha256"],
            "partition_solver_execution_started": False,
        }
    else:
        if not args.expected_protocol_sha256:
            parser.error("--analyze/--run requires --expected-protocol-sha256")
        protocol, _, _ = load_protocol(args.expected_protocol_sha256)
        if args.analyze:
            output = {
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": args.expected_protocol_sha256,
                "public_challenge_sha256": protocol["public_challenge_sha256"],
                "prefix_cells": protocol["execution_plan"]["prefix_cells"],
                "parallel_lanes": protocol["execution_plan"][
                    "parallel_retained_state_lanes"
                ],
                "partition_solver_execution_started": False,
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
