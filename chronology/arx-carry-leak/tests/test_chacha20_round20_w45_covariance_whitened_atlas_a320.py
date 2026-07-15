from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w45_covariance_whitened_atlas_a320.py"
)


def load_runner():
    spec = importlib.util.spec_from_file_location("test_a320_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def synthetic_model_free_order(runner):
    cells = runner.CELLS
    return {
        "component_orders": {
            "fine_selected_channel": list(range(cells)),
            "coarse_high8_then_reflected_Gray4": list(reversed(range(cells))),
            "numeric_word0_prefix12": [value ^ (value >> 1) for value in range(cells)],
        },
        "portfolio_order": list(range(1, cells)) + [0],
    }


def test_design_fixes_unchanged_geometry_before_a314_order() -> None:
    runner = load_runner()
    design = runner.load_design()
    boundary = design["information_boundary"]
    operator = design["operator_contract"]
    assert boundary["A314_order_available_at_design_freeze"] is False
    assert boundary["A314_result_available_at_design_freeze"] is False
    assert boundary["A314_candidate_available_at_design_freeze"] is False
    assert boundary["target_labels_used_from_A314"] == 0
    assert operator["parameter_refit_at_W45"] is False
    assert tuple(operator["frozen_views"]) == runner.A319.METRICS


def test_model_free_branch_builds_three_exact_deterministic_w45_views() -> None:
    runner = load_runner()
    source = synthetic_model_free_order(runner)
    first = runner.derive_model_free_atlas(source)
    second = runner.derive_model_free_atlas(source)
    assert first["geometry"] == runner.A319.geometry_json(runner.A319.exact_geometry())
    assert first["atlas"] == second["atlas"]
    assert first["hashes"] == second["hashes"]
    assert first["diversity"]["target_labels_used"] == 0
    for metric in runner.A319.METRICS:
        order = first["atlas"][metric]
        assert len(order) == runner.CELLS
        assert set(order) == set(range(runner.CELLS))


def test_rank_analysis_uses_only_frozen_orders() -> None:
    runner = load_runner()
    derived = runner.derive_model_free_atlas(synthetic_model_free_order(runner))
    order = {
        "whitened_orders": derived["atlas"],
        "coordinate_source_orders": derived["source"],
    }
    ranks = runner.rank_analysis(1337, order)
    assert ranks["prefix12"] == 1337
    assert ranks["counterfactual_only_no_duplicate_candidate_execution"] is True
    assert set(ranks["prefix_ranks_one_based"]) == {
        *runner.A319.METRICS,
        "A314_three_arm_portfolio",
        "fine",
        "coarse",
        "numeric",
    }
