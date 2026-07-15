from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w32_fine_selected_channel_transfer_a298.py"
)


@pytest.fixture(scope="module")
def a298() -> Any:
    spec = importlib.util.spec_from_file_location("test_a298_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_prospective_design_precedes_every_a298_target(a298: Any) -> None:
    design = a298.load_design()
    assert design["attempt_id"] == "A298"
    assert design["information_boundary"]["A293_result_available_at_design_freeze"] is False
    assert design["information_boundary"]["A295_result_available_at_design_freeze"] is False
    assert design["information_boundary"]["A298_target_exists_at_design_freeze"] is False
    assert design["fine_measurement_contract"]["prefix_cells"] == 4096
    assert design["fine_measurement_contract"]["lane_seed_order"].startswith(
        "fresh_target_coarse_high8"
    )


def test_fine_lane_plan_is_an_exact_disjoint_cover(a298: Any) -> None:
    coarse = list(reversed(range(256)))
    preflight = {
        "target": {
            "CNF": {"path": "unused.cnf", "sha256": "00" * 32},
            "source_one_literals_bit0_upward": list(range(1, 33)),
        }
    }
    plan = a298.fine_lane_plan(coarse, preflight)
    assert len(plan["fine_seed_order"]) == 4096
    assert set(plan["fine_seed_order"]) == set(range(4096))
    active = [
        int(prefix, 2)
        for arm in plan["arms"]
        for prefix in arm["active_prefixes"]
    ]
    assert len(plan["arms"]) == 8
    assert all(len(arm["active_prefixes"]) == 512 for arm in plan["arms"])
    assert len(active) == len(set(active)) == 4096
    assert set(active) == set(range(4096))
    assert all(len(arm["model_one_literals_bit0_upward"]) == 32 for arm in plan["arms"])


def test_rank_analysis_uses_complete_fine_and_counterfactual_orders(a298: Any) -> None:
    prefix = 0xA5B
    primary = [prefix, *[value for value in range(4096) if value != prefix]]
    order_value = {
        "direct_symbolic_winner": None,
        "fine_readout": {"complete_order": primary},
        "coarse_readout": {"complete_coarse_order": list(range(256))},
    }
    ranks = a298.rank_analysis(
        discovery={"fine_prefix12": prefix},
        order_value=order_value,
        challenge_sha="ab" * 32,
    )
    assert ranks["prefix_ranks_one_based"]["A298_fine_selected_channel"] == 1
    assert ranks["prefix_ranks_one_based"]["numeric"] == prefix + 1
    assert ranks["A298_gain_bits_vs_complete_domain"] == 12.0
    assert ranks["assignment_upper_bounds"]["A298_fine_selected_channel"] == 1 << 20


def test_authentic_causal_roundtrip(a298: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "a298.causal"
    monkeypatch.setattr(a298, "CAUSAL", path)
    payload = {
        "order_sha256": "11" * 32,
        "measurement_sha256": "22" * 32,
        "rank_analysis": {"prefix_ranks_one_based": {"A298_fine_selected_channel": 1}},
        "discovery": {"candidate": 0x12345678, "fine_prefix12": 0x123},
        "confirmation": {"cross_implementation_output_bits_checked": 8192},
        "evidence_stage": "TEST_CONFIRMED",
    }
    graph = a298.build_causal(payload)
    assert graph["api_id"] == "a298w32"
    assert graph["explicit_triplets"] == 2
    assert graph["materialized_inferred_triplets"] == 1
    assert graph["embedded_rules"] == 2
    assert graph["clusters"] == 1
    assert graph["gaps"] == 1
    assert graph["sha256"] == a298.file_sha256(path)
