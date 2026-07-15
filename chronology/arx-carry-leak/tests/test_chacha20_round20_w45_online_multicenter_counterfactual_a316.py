from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_w45_online_multicenter_counterfactual_a316.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("a316_test_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


A316 = load_runner()


def synthetic_order() -> dict:
    fine = list(range(A316.CELLS))
    baseline = list(reversed(fine))
    original = fine[::2] + fine[1::2]
    return {
        "component_orders": {
            "fine_selected_channel": fine,
            "coarse_numeric_baseline": baseline,
        },
        "portfolio_order": original,
    }


def test_design_is_frozen_before_A314_order() -> None:
    design = A316.load_design()
    assert design["operator_contract"]["confirmed_fine_rank_centers_one_based"] == A316.CENTERS
    assert design["information_boundary"]["A314_order_available_at_design_freeze"] is False


def test_model_free_derivation_is_exact_and_deterministic() -> None:
    first = A316.derive_model_free_orders(synthetic_order())
    second = A316.derive_model_free_orders(synthetic_order())
    assert first["hashes"] == second["hashes"]
    for key in ("fine", "band", "baseline", "weighted", "A314_portfolio"):
        assert len(first[key]) == A316.CELLS
        assert set(first[key]) == set(range(A316.CELLS))
    assert first["guarantee"]["maximum_factor_vs_four_center_band"] <= 1.5
    assert first["guarantee"]["maximum_factor_vs_A308_baseline"] <= 3.0


def test_model_free_derivation_rejects_direct_branch_shape() -> None:
    with pytest.raises(ValueError):
        A316.derive_model_free_orders({"component_orders": None, "portfolio_order": None})
