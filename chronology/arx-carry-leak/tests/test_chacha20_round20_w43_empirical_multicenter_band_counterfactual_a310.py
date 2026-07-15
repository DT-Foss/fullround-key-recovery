from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w43_empirical_multicenter_band_counterfactual_a310.py"
)


@pytest.fixture(scope="module")
def a310() -> Any:
    spec = importlib.util.spec_from_file_location("test_a310_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_contract_commits_exact_order_before_reveal(a310: Any) -> None:
    design, commitment = a310.load_frozen_contract()
    assert design["attempt_id"] == "A310"
    assert commitment["candidate_or_rank_available_at_commitment"] is False
    assert commitment["empirical_centers_one_based"] == [2114, 2366, 2605]
    assert commitment["cells"] == 4096
    assert commitment["maximum_observed_factor"] == 2.0


def test_multicenter_tiebreak_is_exact(a310: Any) -> None:
    fine = list(range(a310.CELLS))
    centers = [3, 7]
    order = a310.multicenter_band(fine=fine, centers=centers)
    assert order[:7] == [2, 6, 1, 3, 5, 7, 0]
    assert len(order) == a310.CELLS
    assert set(order) == set(range(a310.CELLS))


def test_real_orders_reconstruct_pre_reveal_commitment(a310: Any) -> None:
    _a300, reconstructed, commitment = a310.reconstruct()
    assert reconstructed["hashes"] == {
        "multicenter_band_order_uint16be_sha256": commitment[
            "multicenter_band_order_uint16be_sha256"
        ],
        "baseline_order_uint16be_sha256": commitment[
            "baseline_order_uint16be_sha256"
        ],
        "portfolio_order_uint16be_sha256": commitment[
            "portfolio_order_uint16be_sha256"
        ],
    }
    assert reconstructed["guarantee"]["violations"] == 0
    assert reconstructed["guarantee"]["maximum_observed_regret_factor"] == 2.0


def test_rank_analysis_retains_factor_two(a310: Any) -> None:
    _a300, reconstructed, _commitment = a310.reconstruct()
    order = {
        "component_orders": {
            "empirical_multicenter_band": reconstructed["multicenter"],
            "A300_three_operator_baseline": reconstructed["baseline"],
        },
        "portfolio_order": reconstructed["portfolio"],
    }
    observed = a310.rank_analysis(1234, order)
    ranks = observed["prefix_ranks_one_based"]
    assert ranks["A310_multicenter_plus_baseline"] <= 2 * min(
        ranks["empirical_multicenter_band"],
        ranks["A300_three_operator_baseline"],
    )
    assert observed["counterfactual_only_no_duplicate_candidate_execution"] is True


def test_authentic_causal_roundtrip(
    a310: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a310.causal"
    monkeypatch.setattr(a310, "CAUSAL", path)
    payload = {
        "order_commitment": {"portfolio_order_uint16be_sha256": "11" * 32},
        "portfolio_guarantee": {"violations": 0},
        "A309_result_sha256": "22" * 32,
        "rank_analysis": {"portfolio_gain_bits_vs_complete_domain": 1.0},
        "evidence_stage": "TEST_EVALUATED",
    }
    graph = a310.build_causal(payload)
    assert graph["api_id"] == "a310w43"
    assert graph["explicit_triplets"] == 2
    assert graph["materialized_inferred_triplets"] == 1
    assert graph["embedded_rules"] == 2
    assert graph["clusters"] == 1
    assert graph["gaps"] == 1
    assert graph["sha256"] == a310.file_sha256(path)
