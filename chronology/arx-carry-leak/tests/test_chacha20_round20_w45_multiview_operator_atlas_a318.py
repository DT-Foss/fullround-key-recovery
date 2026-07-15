from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_w45_multiview_operator_atlas_a318.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("a318_test_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


A318 = load_runner()


def synthetic_order() -> dict:
    fine = list(range(A318.CELLS))
    coarse = fine[::2] + fine[1::2]
    numeric = list(reversed(fine))
    portfolio = fine[1::2] + fine[::2]
    return {
        "component_orders": {
            "fine_selected_channel": fine,
            "coarse_high8_then_reflected_Gray4": coarse,
            "numeric_word0_prefix12": numeric,
        },
        "portfolio_order": portfolio,
    }


def test_design_is_frozen_before_A314_order() -> None:
    design = A318.load_design()
    assert design["operator_contract"]["confirmed_prototypes"] == [
        list(row) for row in A318.A317.PROTOTYPES
    ]
    assert design["information_boundary"]["A314_order_available_at_design_freeze"] is False


def test_model_free_multiview_derivation_is_exact_and_deterministic() -> None:
    first = A318.derive_model_free_atlas(synthetic_order())
    second = A318.derive_model_free_atlas(synthetic_order())
    assert first["hashes"] == second["hashes"]
    for metric in A318.A317.METRICS:
        assert len(first["atlas"][metric]) == A318.CELLS
        assert set(first["atlas"][metric]) == set(range(A318.CELLS))
    assert first["diversity"]["operator_pairs"] == 21


def test_model_free_derivation_rejects_direct_branch_shape() -> None:
    with pytest.raises(ValueError):
        A318.derive_model_free_atlas({"component_orders": None, "portfolio_order": None})
