from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_w45_fine_band_recovery_a314.py"


@pytest.fixture(scope="module")
def a314() -> Any:
    spec = importlib.util.spec_from_file_location("test_a314_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_freezes_target_free_end_to_end_w45_pipeline(a314: Any) -> None:
    design = a314.load_design()
    assert design["attempt_id"] == "A314"
    contract = design["execution_contract"]
    assert contract["unknown_key_bits"] == 45
    assert contract["full_rounds"] == 20
    assert contract["feedforward_included"] is True
    assert contract["candidate_group_size"] == 1 << 33
    fine = design["fine_reader_contract"]
    assert fine["prefix_cells"] == 4096
    assert fine["parallel_retained_state_lanes"] == 8
    assert fine["reader_refits"] == 0
    assert fine["target_labels_used"] == 0
    boundary = design["information_boundary"]
    assert boundary["A311_qualification_available_at_design_freeze"] is False
    assert boundary["W45_challenge_available_at_design_freeze"] is False
    assert boundary["W45_secret_or_assignment_available_at_design_freeze"] is False


def test_exact_width_fit_reconstructs_precommitted_w45_center(a314: Any) -> None:
    fit = a314.exact_width_fit(a314.load_design())
    assert fit["slope"] == {"numerator": -4671, "denominator": 182}
    assert fit["intercept"] == {"numerator": 1751899, "denominator": 546}
    assert fit["predicted_W45_rank"] == {
        "numerator": 560657,
        "denominator": 273,
        "decimal": 560657 / 273,
        "nearest_integer": 2054,
    }


def test_w45_public_challenge_excludes_assignment_and_dual_confirms(a314: Any) -> None:
    assignment = 0x1ABCDEF01234
    challenge = a314.challenge_from_assignment(
        label="A314 deterministic public-challenge test", assignment=assignment
    )
    a314.validate_challenge(challenge)
    assert challenge["unknown_assignment_included"] is False
    assert "unknown_assignment" not in challenge
    assert challenge["known_zeroed_key_words"][0] == 0
    assert challenge["known_zeroed_key_words"][1] & 0x1FFF == 0
    confirmation = a314.confirm(challenge, assignment)
    assert confirmation["all_blocks_match"] is True
    assert confirmation["total_cross_implementation_output_bits_checked"] == 8192


def test_w45_model_permutation_places_word0_high12_in_prefix(a314: Any) -> None:
    permutation = a314.solver_model_permutation()
    assert permutation == [*range(20), *range(32, 45), *range(20, 32)]
    assert permutation[-12:] == list(range(20, 32))
    for candidate in (0, 1, (1 << 45) - 1, 0x1ABCDEF01234):
        permuted = 0
        for permuted_index, original_coordinate in enumerate(permutation):
            permuted |= ((candidate >> original_coordinate) & 1) << permuted_index
        assert a314.decode_permuted_candidate(permuted) == candidate
    with pytest.raises(ValueError, match="outside W45"):
        a314.decode_permuted_candidate(1 << 45)


def test_w45_lane_fronts_are_disjoint_complete_cover(a314: Any) -> None:
    preflight = {
        "target": {
            "source_one_literals_bit0_upward": list(range(1, 46)),
            "CNF": {"path": "synthetic.cnf", "sha256": "0" * 64},
        }
    }
    coarse = {"complete_coarse_order": list(range(256))}
    plan = a314.fine_lane_plan(
        preflight_value=preflight, coarse_readout=coarse
    )
    active = [
        prefix for arm in plan["arms"] for prefix in arm["active_prefixes"]
    ]
    assert len(plan["arms"]) == 8
    assert len(active) == 4096
    assert len(set(active)) == 4096
    assert set(active) == {f"{value:012b}" for value in range(4096)}
    assert all(len(arm["active_prefixes"]) == 512 for arm in plan["arms"])
    assert all(len(arm["cell_order"]) == 4096 for arm in plan["arms"])
    assert all(len(arm["model_one_literals_bit0_upward"]) == 45 for arm in plan["arms"])


def test_precommitted_band_portfolio_is_exact_and_factor_three(a314: Any) -> None:
    fine = list(reversed(range(4096)))
    baseline = list(range(4096))
    band = a314.A313.band_order(fine=fine, center=a314.CENTER)
    portfolio = a314.A313.three_arm_portfolio(
        band=band, fine=fine, baseline=baseline
    )
    guarantee = a314.A313.portfolio_guarantee(
        portfolio=portfolio,
        band=band,
        fine=fine,
        baseline=baseline,
    )
    assert len(portfolio) == 4096
    assert set(portfolio) == set(range(4096))
    assert guarantee["violations"] == 0
    assert guarantee["maximum_observed_regret_factor"] <= 3


def test_ordered_discovery_stops_only_after_complete_selected_group(
    a314: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_prefix = 7
    candidate = (target_prefix << 20) | 0x13579
    calls: list[int] = []

    class Host:
        def close(self) -> None:
            return None

    def fake_filter(**kwargs: Any) -> dict[str, Any]:
        prefix = int(kwargs["prefix"])
        calls.append(prefix)
        return {
            "factual_candidates": [candidate] if prefix == target_prefix else [],
            "control_candidates": [],
            "gpu_seconds": 0.25,
            "slabs_executed": [0, 1, 2, 3],
            "logical_candidates": 1 << 33,
            "complete_W45_group_before_outcome_evaluation": True,
        }

    monkeypatch.setattr(a314.A311, "filter_complete_prefix", fake_filter)
    order = [3, 5, 7, *[value for value in range(4096) if value not in {3, 5, 7}]]
    progress: list[dict[str, Any]] = []
    challenge = {
        "target_words": [[0] * 16],
        "control_target_words": [1, *([0] * 15)],
    }
    observed = a314.ordered_discovery(
        host_factory=Host,
        challenge=challenge,
        order=order,
        host_refresh_groups=2,
        progress_callback=lambda row: progress.append(dict(row)),
    )
    assert calls == [3, 5, 7]
    assert observed["candidate"] == candidate
    assert observed["executed_prefix_groups"] == 3
    assert observed["executed_group_dispatches"] == 12
    assert observed["executed_assignments"] == 3 * (1 << 33)
    assert observed["matched_control_candidates"] == 0
    assert progress[0]["status"] == "running"
    assert progress[-1]["status"] == "candidate_found"
