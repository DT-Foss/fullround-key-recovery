from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_w44_online_multicenter_counterfactual_a315.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("a315_test_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


A315 = load_runner()


def test_online_multicenter_orders_are_exact_and_byte_frozen() -> None:
    value = A315.reconstruct()
    assert value["hashes"]["four_center_band_uint16be_sha256"] == (
        "36dd80fbfb697e4576518f2ad06f6b9bf69c8e49cac428afca77927904e18182"
    )
    assert value["hashes"]["weighted_dovetail_2_to_1_uint16be_sha256"] == (
        "c88b45cbc4c141c05d7280fee9bb47172d086f8a257c06c5cf39f25e98197bfc"
    )
    for key in ("fine", "band", "baseline", "weighted", "A313_portfolio"):
        assert len(value[key]) == A315.CELLS
        assert set(value[key]) == set(range(A315.CELLS))


def test_weighted_dovetail_has_exhaustive_finite_bound() -> None:
    value = A315.reconstruct()
    gate = value["guarantee"]
    assert gate["violations"] == 0
    assert gate["checked_prefix_cells"] == A315.CELLS
    assert gate["maximum_factor_vs_four_center_band"] <= 1.5
    assert gate["maximum_factor_vs_A308_baseline"] <= 3.0
    assert gate["maximum_factor_vs_best_arm"] <= 3.0


def test_multicenter_tie_break_is_deterministic() -> None:
    fine = list(range(A315.CELLS))
    first = A315.multicenter_band(fine=fine, centers=[10, 20])
    second = A315.multicenter_band(fine=fine, centers=[10, 20])
    assert first == second
    assert first[:4] == [9, 19, 8, 10]


def test_invalid_order_and_weights_are_rejected() -> None:
    fine = list(range(A315.CELLS))
    with pytest.raises(ValueError):
        A315.multicenter_band(fine=fine[:-1])
    with pytest.raises(ValueError):
        A315.multicenter_band(fine=fine, centers=[1, 1])
    with pytest.raises(ValueError):
        A315.weighted_dovetail(band=fine, baseline=fine, band_weight=0)
