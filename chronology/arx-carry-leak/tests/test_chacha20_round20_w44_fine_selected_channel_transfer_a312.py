from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_w44_fine_selected_channel_transfer_a312.py"


@pytest.fixture(scope="module")
def a312() -> Any:
    spec = importlib.util.spec_from_file_location("test_a312_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_freezes_complete_target_blind_w44_transfer(a312: Any) -> None:
    design = a312.load_design()
    assert design["attempt_id"] == "A312"
    target = design["target_contract"]
    assert target["unknown_key_bits"] == 44
    assert target["full_rounds"] == 20
    assert target["feedforward_included"] is True
    measurement = design["fine_measurement_contract"]
    assert measurement["prefix_cells"] == 4096
    assert measurement["parallel_retained_state_lanes"] == 8
    assert measurement["cells_per_lane"] == 512
    assert measurement["reader_refits"] == 0
    assert measurement["target_labels_used"] == 0
    boundary = design["information_boundary"]
    assert boundary["A308_result_available_at_design_freeze"] is False
    assert boundary["A308_target_assignment_available_at_design_freeze"] is False
    assert boundary["A308_filter_outcome_available_at_design_freeze"] is False


def test_authentic_source_graphs_close_reader_and_request_wider_transfer(a312: Any) -> None:
    readback = a312.authentic_source_readback()
    assert readback["A295"]["api_id"] == "a295w24"
    assert readback["A305"]["api_id"] == "a305w43"
    assert readback["A295"]["materialized_inferred_triplets"] == 1
    assert readback["A305"]["materialized_inferred_triplets"] == 1
    assert readback["A305"]["next_gap"]["expected_object_type"] == (
        "fresh_grouped_W43_replication_or_wider_residual_transfer"
    )


def test_w44_model_permutation_places_word0_high12_in_prefix(a312: Any) -> None:
    permutation = a312.solver_model_permutation()
    assert permutation == [*range(20), *range(32, 44), *range(20, 32)]
    assert permutation[-12:] == list(range(20, 32))
    for candidate in (0, 1, (1 << 44) - 1, 0xABCDEF01234):
        permuted = 0
        for permuted_index, original_coordinate in enumerate(permutation):
            permuted |= ((candidate >> original_coordinate) & 1) << permuted_index
        assert a312.decode_permuted_candidate(permuted) == candidate


def test_lane_fronts_are_disjoint_complete_cover(a312: Any) -> None:
    _protocol, preflight, order = a312.load_a308()
    plan = a312.fine_lane_plan(preflight=preflight, order=order)
    assert len(plan["arms"]) == 8
    active = [
        prefix
        for arm in plan["arms"]
        for prefix in arm["active_prefixes"]
    ]
    assert len(active) == 4096
    assert len(set(active)) == 4096
    assert set(active) == {f"{value:012b}" for value in range(4096)}
    assert all(len(arm["active_prefixes"]) == 512 for arm in plan["arms"])
    assert all(len(arm["cell_order"]) == 4096 for arm in plan["arms"])
    assert all(len(arm["model_one_literals_bit0_upward"]) == 44 for arm in plan["arms"])
    assert all(
        arm["cnf"]["sha256"]
        == "9c1a67674a0600feab564733d2e0374a2c2fe017a40babae5a87e8078cf89720"
        for arm in plan["arms"]
    )


def test_frozen_reader_reproduces_existing_w43_order(a312: Any) -> None:
    trace_dir = ROOT / "research/artifacts/a299_chacha20_r20_w43_fine_transfer/fine"
    traces = a312._trace_rows(trace_dir)  # noqa: SLF001
    assert len(traces) == 4096
    a295 = a312.load_module(a312.A295_RUNNER, "test_a312_a295_replay")
    observed = a295.frozen_order(traces)
    source = json.loads(a312.A299_ORDER.read_bytes())["fine_readout"]
    assert observed["complete_order"] == source["complete_order"]
    assert observed["complete_order_uint16be_sha256"] == (
        source["complete_order_uint16be_sha256"]
    )


def test_decode_rejects_outside_w44(a312: Any) -> None:
    with pytest.raises(ValueError, match="outside W44"):
        a312.decode_permuted_candidate(1 << 44)
