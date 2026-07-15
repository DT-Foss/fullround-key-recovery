from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_w44_width_conditioned_fine_portfolio_a313.py"


@pytest.fixture(scope="module")
def a313() -> Any:
    spec = importlib.util.spec_from_file_location("test_a313_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_is_pre_reveal_and_conditional(a313: Any) -> None:
    design = a313.load_design()
    assert design["attempt_id"] == "A313"
    boundary = design["information_boundary"]
    assert boundary["A308_result_available_at_design_freeze"] is False
    assert boundary["A308_candidate_available_at_design_freeze"] is False
    assert boundary["A312_measurement_complete_at_design_freeze"] is False
    assert boundary["A312_fine_order_available_at_design_freeze"] is False
    assert boundary["A312_direct_symbolic_outcome_available_at_design_freeze"] is False
    conditional = design["operator_contract"]["conditional_execution"]
    assert set(conditional) == {
        "A312_direct_symbolic_model",
        "A312_complete_model_free_fine_order",
    }


def test_exact_w44_fit_is_frozen_from_confirmed_disjoint_rows(a313: Any) -> None:
    design = a313.load_design()
    rows = a313.confirmed_training_rows(design)
    assert [(row["unknown_key_bits"], row["confirmed_fine_rank_one_based"]) for row in rows] == [
        (24, 2605),
        (32, 2366),
        (43, 2114),
    ]
    assert len({row["public_challenge_sha256"] for row in rows}) == 3
    fit = a313.exact_fit(rows)
    assert fit["slope"] == {"numerator": -4671, "denominator": 182}
    assert fit["intercept"] == {"numerator": 1751899, "denominator": 546}
    assert fit["predicted_W44_rank"] == {
        "numerator": 1135327,
        "denominator": 546,
        "decimal": 1135327 / 546,
        "nearest_integer": 2079,
    }


def test_band_is_exact_distance_order_around_rank_2079(a313: Any) -> None:
    fine = list(range(4096))
    band = a313.band_order(fine=fine)
    assert band[:7] == [2078, 2077, 2079, 2076, 2080, 2075, 2081]
    assert len(band) == 4096
    assert set(band) == set(range(4096))


def test_three_arm_merge_is_exact_and_factor_three_bounded(a313: Any) -> None:
    fine = list(range(4096))
    band = a313.band_order(fine=fine)
    baseline = list(reversed(fine))
    portfolio = a313.three_arm_portfolio(
        band=band,
        fine=fine,
        baseline=baseline,
    )
    assert len(portfolio) == 4096
    assert set(portfolio) == set(range(4096))
    guarantee = a313.portfolio_guarantee(
        portfolio=portfolio,
        band=band,
        fine=fine,
        baseline=baseline,
    )
    assert guarantee["violations"] == 0
    assert guarantee["maximum_observed_regret_factor"] <= 3.0
    ranks = {
        "portfolio": {cell: rank for rank, cell in enumerate(portfolio, 1)},
        "band": {cell: rank for rank, cell in enumerate(band, 1)},
        "fine": {cell: rank for rank, cell in enumerate(fine, 1)},
        "baseline": {cell: rank for rank, cell in enumerate(baseline, 1)},
    }
    assert all(
        ranks["portfolio"][cell]
        <= 3
        * min(
            ranks["band"][cell],
            ranks["fine"][cell],
            ranks["baseline"][cell],
        )
        for cell in range(4096)
    )


def test_portfolio_rejects_incomplete_arm(a313: Any) -> None:
    with pytest.raises(ValueError, match="exact cover"):
        a313.three_arm_portfolio(
            band=list(range(4095)),
            fine=list(range(4096)),
            baseline=list(range(4096)),
        )
