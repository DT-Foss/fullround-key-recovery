from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_holdout_selected_w45_recovery_a322.py"
)


def load_runner():
    spec = importlib.util.spec_from_file_location("test_a322_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_freezes_complete_group_execution_before_selection_and_recovery() -> None:
    runner = load_runner()
    design = runner.load_design()
    execution = design["execution_contract"]
    boundary = design["information_boundary"]
    assert execution["candidates_per_prefix_group"] == 1 << 33
    assert execution["slabs_per_prefix_group"] == 4
    assert execution["candidates_per_slab"] == 1 << 31
    assert execution["host_refresh_interval_prefix_groups"] == 128
    assert execution["manual_order_override_after_A321_selection"] is False
    assert boundary["A313_result_available_at_design_freeze"] is False
    assert boundary["A321_selected_operator_available_at_design_freeze"] is False
    assert boundary["A314_result_available_at_design_freeze"] is False
    assert boundary["A314_candidate_available_at_design_freeze"] is False
    assert boundary["target_labels_used_from_A314_for_order_selection"] == 0


def test_rank_panel_contains_every_frozen_candidate_and_baseline() -> None:
    runner = load_runner()
    for prefix in (0, 1337, 4095):
        for selected in runner.A321.CANDIDATE_NAMES:
            panel = runner.rank_panel(prefix=prefix, selected_operator=selected)
            ranks = panel["prefix_ranks_one_based"]
            assert set(ranks) == {
                *runner.A321.CANDIDATE_NAMES,
                "A314_three_arm_portfolio",
            }
            assert panel["selected_rank_one_based"] == ranks[selected]
            assert panel["A314_baseline_rank_one_based"] == ranks[
                "A314_three_arm_portfolio"
            ]
            assert 1 <= panel["selected_rank_one_based"] <= runner.CELLS


def test_all_deployment_orders_are_exact_complete_covers() -> None:
    runner = load_runner()
    orders = runner.all_w45_orders()
    assert set(orders) == {
        *runner.A321.CANDIDATE_NAMES,
        "A314_three_arm_portfolio",
    }
    for order in orders.values():
        assert len(order) == runner.CELLS
        assert set(order) == set(range(runner.CELLS))


def test_invalid_selected_operator_is_rejected() -> None:
    runner = load_runner()
    try:
        runner.rank_panel(prefix=0, selected_operator="not_frozen")
    except ValueError as error:
        assert "outside frozen" in str(error)
    else:
        raise AssertionError("A322 accepted an operator outside A321 candidates")
