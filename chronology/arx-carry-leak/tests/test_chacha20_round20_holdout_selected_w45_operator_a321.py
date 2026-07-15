from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_holdout_selected_w45_operator_a321.py"
)


def load_runner():
    spec = importlib.util.spec_from_file_location("test_a321_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_freezes_selection_before_both_results() -> None:
    runner = load_runner()
    design = runner.load_design()
    boundary = design["information_boundary"]
    selection = design["selection_contract"]
    assert boundary["A313_result_available_at_design_freeze"] is False
    assert boundary["A313_candidate_available_at_design_freeze"] is False
    assert boundary["A314_result_available_at_design_freeze"] is False
    assert boundary["A314_candidate_available_at_design_freeze"] is False
    assert boundary["target_labels_used_from_A314"] == 0
    assert selection["A314_target_label_or_candidate_used_for_selection"] is False
    assert tuple(selection["candidate_sequence_and_tie_break"]) == runner.CANDIDATE_NAMES


def test_all_eight_cross_width_pairs_are_exact_and_hash_pinned() -> None:
    runner = load_runner()
    pairs = runner.candidate_pairs()
    assert [row["name"] for row in pairs] == list(runner.CANDIDATE_NAMES)
    assert len(pairs) == 8
    for index, row in enumerate(pairs):
        assert row["candidate_index"] == index
        assert len(row["W44_order"]) == runner.CELLS
        assert len(row["W45_order"]) == runner.CELLS
        assert set(row["W44_order"]) == set(range(runner.CELLS))
        assert set(row["W45_order"]) == set(range(runner.CELLS))
        assert runner._order_sha(row["W44_order"]) == row["W44_order_uint16be_sha256"]
        assert runner._order_sha(row["W45_order"]) == row["W45_order_uint16be_sha256"]


def test_selection_is_exact_minimum_rank_with_frozen_index_tie_break() -> None:
    runner = load_runner()
    pairs = runner.candidate_pairs()
    for prefix in (0, 1, 1337, 4095):
        result = runner.selection_for_prefix(prefix)
        ranks = [row["W44_order"].index(prefix) + 1 for row in pairs]
        expected = min(range(len(pairs)), key=lambda index: (ranks[index], index))
        assert result["selected_candidate_index"] == expected
        assert result["selected_operator"] == runner.CANDIDATE_NAMES[expected]
        assert result["selected_calibration_rank_one_based"] == ranks[expected]
        assert runner._order_sha(result["selected_W45_order"]) == result[
            "selected_W45_order_uint16be_sha256"
        ]


def test_calibration_and_deployment_challenges_are_disjoint() -> None:
    runner = load_runner()
    w44 = runner.json.loads(runner.A315_ORDER.read_bytes())["public_challenge_sha256"]
    w45 = runner.json.loads(runner.A316_ORDER.read_bytes())["public_challenge_sha256"]
    assert w44 != w45
