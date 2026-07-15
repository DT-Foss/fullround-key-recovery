from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SOURCE = (
    ROOT / "research/experiments/chacha20_round20_w24_causal_refinement_a293.py"
)
DESIGN_SHA256 = "3328b9410c657bf9a3735e1262cf7bde0b50137b3dca606675982a5279a8612a"


def load_runner():
    spec = importlib.util.spec_from_file_location("a293_test_runner", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a293_prospective_design_and_helper_are_hash_frozen() -> None:
    runner = load_runner()
    design = json.loads(runner.DESIGN.read_bytes())
    assert runner.file_sha256(runner.DESIGN) == DESIGN_SHA256
    assert design["design_state"] == (
        "prospectively_frozen_before_any_A288_or_A292_outcome"
    )
    assert runner.file_sha256(runner.HELPER_BINARY) == (
        design["frozen_inputs"]["variable_prefix_binary_sha256"]
    )
    assert runner.file_sha256(runner.HELPER_DERIVED) == (
        design["frozen_inputs"]["variable_prefix_derived_source_sha256"]
    )


def test_a293_causal_gray12_lanes_are_an_exact_w24_cover() -> None:
    runner = load_runner()
    a291 = json.loads(runner.A291_RESULT.read_bytes())
    preflight = json.loads(runner.A287_PREFLIGHT.read_bytes())
    values = runner.fine_values(a291)
    assert values[:16] == [
        (124 << 4) | value for value in [0, 1, 3, 2, 6, 7, 5, 4, 12, 13, 15, 14, 10, 11, 9, 8]
    ]
    assert len(values) == len(set(values)) == 4096
    orders = runner.lane_orders(a291)
    assert len(orders) == 8
    assert all(len(order) == 4096 for order in orders)
    active = [prefix for order in orders for prefix in order[:512]]
    assert len(active) == len(set(active)) == 4096
    plan = runner.execution_plan(a291, preflight)
    assert plan["partition_prefix_bits"] == 12
    assert plan["suffix_bits_per_cell"] == 12
    assert plan["parallel_retained_state_lanes"] == 8
    assert plan["complete_candidate_domain_enumeration_used"] is False
    command = runner._command(plan["arms"][0])
    assumptions = command[command.index("--assumption-one-literals") + 1].split(",")
    assert len(assumptions) == 12


def test_a293_eight_lane_runner_stops_on_exact_synthetic_model(
    tmp_path: Path, monkeypatch
) -> None:
    runner = load_runner()
    helper = runner.load_module(runner.HELPER_WRAPPER, "a293_test_helper_build")
    binary = tmp_path / "variable-prefix"
    derived = tmp_path / "variable-prefix.cpp"
    helper.compile_helper(output=binary, derived_source=derived)
    monkeypatch.setattr(runner, "HELPER_BINARY", binary)
    monkeypatch.setattr(runner, "ARTIFACTS", tmp_path / "artifacts")

    a291 = json.loads(runner.A291_RESULT.read_bytes())
    orders = runner.lane_orders(a291)
    true_prefix = int(orders[3][0], 2)
    assignment = (true_prefix << 12) | 0xABC
    cnf = tmp_path / "fixed.cnf"
    lines = ["p cnf 24 24"]
    for bit in range(24):
        literal = bit + 1 if (assignment >> bit) & 1 else -(bit + 1)
        lines.append(f"{literal} 0")
    cnf.write_text("\n".join(lines) + "\n", encoding="ascii")
    cnf_anchor = {"path": str(cnf), "sha256": runner.file_sha256(cnf)}
    arms = []
    for lane, order in enumerate(orders):
        arms.append(
            {
                "arm": f"synthetic_lane{lane}",
                "lane": lane,
                "cadical_configuration": "default",
                "cell_order": order,
                "active_prefixes": order[:512],
                "seconds_per_cell": 1.0,
                "max_cells": 512,
                "cnf": cnf_anchor,
                "model_one_literals_bit0_upward": list(range(1, 25)),
            }
        )
    rows, winner = runner.run_partition({"execution_plan": {"arms": arms}})
    assert winner is not None
    assert winner["arm"] == "synthetic_lane3"
    assert winner["candidate_low24"] == assignment
    assert winner["prefix12"] == f"{true_prefix:012b}"
    assert len(rows) == 8
