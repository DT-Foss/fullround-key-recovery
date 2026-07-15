from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w43_width_conditioned_band_portfolio_a309.py"
)


@pytest.fixture(scope="module")
def a309() -> Any:
    spec = importlib.util.spec_from_file_location("test_a309_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_freezes_disjoint_width_calibration_before_a300(a309: Any) -> None:
    design = a309.load_design()
    assert design["attempt_id"] == "A309"
    assert design["operator_contract"]["fit"]["training_rows"] == [
        {
            "attempt_id": "A295",
            "confirmed_fine_rank_one_based": 2605,
            "unknown_key_bits": 24,
        },
        {
            "attempt_id": "A303",
            "confirmed_fine_rank_one_based": 2366,
            "unknown_key_bits": 32,
        },
        {
            "attempt_id": "A305",
            "confirmed_fine_rank_one_based": 2114,
            "unknown_key_bits": 43,
        },
    ]
    boundary = design["information_boundary"]
    assert boundary["A300_candidate_available_at_freeze"] is False
    assert boundary["A300_prefix_rank_available_at_freeze"] is False
    assert boundary["A300_target_assignment_available_at_freeze"] is False
    assert boundary["A302_result_available_at_freeze"] is False
    assert boundary["target_labels_used_from_A300"] == 0


def test_exact_fit_reconstructs_frozen_center_and_leave_one_out(a309: Any) -> None:
    rows = a309.load_design()["operator_contract"]["fit"]["training_rows"]
    fit = a309.exact_linear_fit(rows)
    assert fit["slope"] == {
        "numerator": -4671,
        "denominator": 182,
        "decimal": pytest.approx(-25.664835164835164),
    }
    assert fit["intercept"]["numerator"] == 1751899
    assert fit["intercept"]["denominator"] == 546
    assert fit["predicted_W43_rank"]["nearest_integer"] == 2105
    assert fit["maximum_absolute_training_residual"] < 22
    assert fit["maximum_absolute_leave_one_out_error"] < 77


def test_band_order_is_exact_and_starts_at_frozen_center(a309: Any) -> None:
    fine = list(reversed(range(a309.CELLS)))
    center = 2105
    order = a309.band_order(fine=fine, center=center)
    assert len(order) == a309.CELLS
    assert set(order) == set(range(a309.CELLS))
    rank_to_cell = {rank: cell for rank, cell in enumerate(fine, 1)}
    assert order[:5] == [
        rank_to_cell[2105],
        rank_to_cell[2104],
        rank_to_cell[2106],
        rank_to_cell[2103],
        rank_to_cell[2107],
    ]


def test_two_arm_merge_retains_exact_factor_two_bound(a309: Any) -> None:
    band = list(reversed(range(a309.CELLS)))
    baseline = list(range(a309.CELLS))
    portfolio = a309.two_arm_portfolio(band=band, baseline=baseline)
    guarantee = a309.portfolio_guarantee(
        portfolio=portfolio,
        band=band,
        baseline=baseline,
    )
    assert len(portfolio) == a309.CELLS
    assert set(portfolio) == set(range(a309.CELLS))
    assert guarantee["violations"] == 0
    assert guarantee["frozen_worst_case_bound_factor"] == 2
    assert guarantee["transitive_bound_vs_best_A300_component_factor"] == 6


def test_training_rows_and_ai_native_readback_are_authentic(a309: Any) -> None:
    design = a309.load_design()
    rows = a309.training_rows(design)
    assert [row["confirmed_fine_rank_one_based"] for row in rows] == [
        2605,
        2366,
        2114,
    ]
    assert len({row["public_challenge_sha256"] for row in rows}) == 3
    readback = a309.causal_readback(design)
    assert [row["api_id"] for row in readback] == [
        "a295w24",
        "a303w32",
        "a305w43",
    ]
    assert all(row["explicit_triplets"] == 2 for row in readback)
    assert all(row["materialized_inferred_triplets"] == 1 for row in readback)
    assert all(row["gaps"] == 1 for row in readback)


def test_real_a300_order_builds_target_blind_a309_cover(a309: Any) -> None:
    _protocol, _preflight, a300_order = a309.A300.load_order(
        a309.A300_PROTOCOL_SHA256,
        a309.A300_PREFLIGHT_SHA256,
        a309.A300_ORDER_SHA256,
    )
    rows = a309.training_rows(a309.load_design())
    fit = a309.exact_linear_fit(rows)
    fine = a300_order["component_orders"]["A295_fine_selected_channel"]
    band = a309.band_order(
        fine=fine,
        center=fit["predicted_W43_rank"]["nearest_integer"],
    )
    portfolio = a309.two_arm_portfolio(
        band=band,
        baseline=a300_order["portfolio_order"],
    )
    guarantee = a309.portfolio_guarantee(
        portfolio=portfolio,
        band=band,
        baseline=a300_order["portfolio_order"],
    )
    assert guarantee["violations"] == 0
    assert portfolio != a300_order["portfolio_order"]


def test_authentic_causal_roundtrip(
    a309: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a309.causal"
    monkeypatch.setattr(a309, "CAUSAL", path)
    payload = {
        "protocol_sha256": "11" * 32,
        "execution_sha256": "22" * 32,
        "evidence_stage": "TEST_CONFIRMED",
        "rank_analysis": {"portfolio_gain_bits_vs_complete_domain": 2.0},
        "portfolio_guarantee": {"violations": 0},
        "discovery": {"candidate": 0x123456789AB, "fine_prefix12": 0x345},
        "confirmation": {"total_cross_implementation_output_bits_checked": 8192},
    }
    graph = a309.build_causal(payload)
    assert graph["api_id"] == "a309w43"
    assert graph["explicit_triplets"] == 2
    assert graph["materialized_inferred_triplets"] == 1
    assert graph["embedded_rules"] == 2
    assert graph["clusters"] == 1
    assert graph["gaps"] == 1
    assert graph["sha256"] == a309.file_sha256(path)
