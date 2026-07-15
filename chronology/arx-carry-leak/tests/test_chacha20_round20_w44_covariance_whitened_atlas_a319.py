from __future__ import annotations

import importlib.util
import sys
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w44_covariance_whitened_atlas_a319.py"
)


def load_runner():
    spec = importlib.util.spec_from_file_location("test_a319_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_exact_regularized_covariance_is_positive_definite_and_inverted() -> None:
    runner = load_runner()
    geometry = runner.exact_geometry()
    assert all(value > 0 for value in geometry["positive_definite_certificate"])
    covariance = geometry["shrunk_covariance"]
    inverse = geometry["inverse_shrunk_covariance"]
    identity = [
        [
            sum(covariance[row][inner] * inverse[inner][column] for inner in range(3))
            for column in range(3)
        ]
        for row in range(3)
    ]
    assert identity == [
        [Fraction(int(row == column)) for column in range(3)] for row in range(3)
    ]


def test_all_whitened_views_are_deterministic_exact_covers() -> None:
    runner = load_runner()
    source = runner.A317.coordinate_source_orders()
    geometry = runner.exact_geometry()
    orders = {
        metric: runner.whitened_order(
            fine=source["fine"],
            coarse=source["coarse"],
            numeric=source["numeric"],
            metric=metric,
            geometry=geometry,
        )
        for metric in runner.METRICS
    }
    for metric, order in orders.items():
        assert len(order) == runner.CELLS, metric
        assert set(order) == set(range(runner.CELLS)), metric
        assert order == runner.whitened_order(
            fine=source["fine"],
            coarse=source["coarse"],
            numeric=source["numeric"],
            metric=metric,
            geometry=geometry,
        )
    assert len({tuple(order) for order in orders.values()}) == len(runner.METRICS)


def test_design_and_reconstruction_retain_pre_reveal_boundary() -> None:
    runner = load_runner()
    value = runner.reconstruct()
    boundary = value["design"]["information_boundary"]
    assert boundary["A313_result_available_at_design_freeze"] is False
    assert boundary["A313_candidate_available_at_design_freeze"] is False
    assert boundary["A313_prefix_rank_available_at_design_freeze"] is False
    assert boundary["target_labels_used_from_A313"] == 0
    assert value["public_challenge_sha256"]
    assert value["diversity"]["target_labels_used"] == 0


def test_fraction_serialization_is_exact_and_canonical() -> None:
    runner = load_runner()
    assert runner._fraction(Fraction(4, 6)) == "2/3"
    geometry = runner.geometry_json(runner.exact_geometry())
    assert geometry["arithmetic"] == "exact_rational"
    assert geometry["fixed_shrinkage_weight"] == "1/2"
    assert all("/" in value for value in geometry["prototype_mean"])
