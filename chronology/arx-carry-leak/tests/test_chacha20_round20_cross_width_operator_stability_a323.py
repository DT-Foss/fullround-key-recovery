from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_cross_width_operator_stability_a323.py"
)


def load_runner():
    spec = importlib.util.spec_from_file_location("test_a323_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_retains_target_blind_analysis_boundary() -> None:
    runner = load_runner()
    design = runner.load_design()
    boundary = design["information_boundary"]
    contract = design["analysis_contract"]
    assert boundary["A313_result_available"] is False
    assert boundary["A313_candidate_available"] is False
    assert boundary["A314_result_available"] is False
    assert boundary["A314_candidate_available"] is False
    assert boundary["target_labels_used"] == 0
    assert contract["candidate_execution"] is False
    assert contract["operator_refit"] is False


def test_complete_cross_width_panel_matches_frozen_orders() -> None:
    runner = load_runner()
    value = runner.analyze_operators()
    assert value["operator_sequence"] == list(runner.A321.CANDIDATE_NAMES)
    assert value["target_labels_used"] == 0
    assert value["candidate_execution"] is False
    assert value["operator_refits"] == 0
    assert value["most_stable_operator"] == "raw_nearest_prototype_Linf"
    assert abs(value["most_stable_spearman"] - 0.3498032707836566) < 1e-15


def test_best_of_eight_complementarity_is_complete_and_exact() -> None:
    runner = load_runner()
    coverage = runner.analyze_operators()["best_of_eight_W44_oracle_coverage"]
    assert coverage["covered_cells"] == runner.CELLS
    assert sum(coverage["winner_cell_counts"].values()) == runner.CELLS
    assert coverage["minimum_rank"] == 1
    assert coverage["maximum_rank"] == 3778
    assert coverage["mean_rank"] == 1249.98681640625
    quantiles = {row["probability"]: row["value"] for row in coverage["quantiles"]}
    assert quantiles == {0.25: 442, 0.5: 1019, 0.75: 1974, 0.9: 2728}


def test_all_eight_operators_win_at_least_one_complete_cell() -> None:
    runner = load_runner()
    counts = runner.analyze_operators()["best_of_eight_W44_oracle_coverage"][
        "winner_cell_counts"
    ]
    assert set(counts) == set(runner.A321.CANDIDATE_NAMES)
    assert all(value > 0 for value in counts.values())
