from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w24_fine_selected_channel_a295.py"
)


@pytest.fixture(scope="module")
def a295() -> Any:
    spec = importlib.util.spec_from_file_location("test_a295_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def synthetic_rows() -> list[dict[str, Any]]:
    return [
        {
            "prefix": f"{prefix:012b}",
            "redundant_clauses_delta": (prefix * 7) % 97,
            "metric_names": ["conflicts", "decisions", "search_propagations"],
            "metrics_delta": [(prefix * 11) % 89, prefix % 13, prefix % 17],
        }
        for prefix in range(4096)
    ]


def test_design_keeps_reader_and_launch_gate_frozen(a295: Any) -> None:
    value = a295.load_design()
    assert value["launch_gate"].startswith("execute_only_if_A293")
    assert value["readout"]["prefix_bits"] == 12
    assert value["readout"]["model_refits"] == 0
    assert value["readout"]["target_labels_used"] == 0


def test_metric_fields_are_prefix_indexed_and_nonnegative(a295: Any) -> None:
    rows = list(reversed(synthetic_rows()))
    accepted, conflicts = a295.metric_fields(rows)
    assert accepted.shape == conflicts.shape == (4096,)
    assert accepted[19] == (19 * 7) % 97
    assert conflicts[19] == (19 * 11) % 89
    assert np.min(accepted) >= 0
    assert np.min(conflicts) >= 0


def test_frozen_order_is_complete_and_deterministic(a295: Any) -> None:
    rows = synthetic_rows()
    first = a295.frozen_order(rows)
    second = a295.frozen_order(rows)
    order = first["complete_order"]
    assert order == second["complete_order"]
    assert len(order) == len(set(order)) == 4096
    assert set(order) == set(range(4096))
    assert first["target_labels_used"] == 0
    assert first["model_refits"] == 0


def test_public_hash_control_is_exact_and_deterministic(a295: Any) -> None:
    digest = "5beabf27dccaa98cfaa97eed7bf7420c6548dcc469b4c924af04f8a872ecc30f"
    first = a295.public_hash_order(digest)
    second = a295.public_hash_order(digest)
    assert first == second
    assert len(first) == len(set(first)) == 4096
    assert set(first) == set(range(4096))
