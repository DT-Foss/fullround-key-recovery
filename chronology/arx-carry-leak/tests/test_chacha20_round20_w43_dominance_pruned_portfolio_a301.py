from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w43_dominance_pruned_portfolio_a301.py"
)


@pytest.fixture(scope="module")
def a301() -> Any:
    spec = importlib.util.spec_from_file_location("test_a301_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_freezes_pruning_before_a300_measurement(a301: Any) -> None:
    design = a301.load_design()
    assert design["attempt_id"] == "A301"
    assert design["operator_contract"]["candidate_execution_orders"] == [
        "A297_coarse_high8_then_reflected_Gray4",
        "numeric_word0_prefix12",
    ]
    assert design["operator_contract"]["audit_only_order"] == (
        "A295_fine_selected_channel"
    )
    boundary = design["information_boundary"]
    assert boundary["A300_measurement_or_order_available_at_freeze"] is False
    assert (
        boundary[
            "A300_production_assignment_model_candidate_filter_outcome_or_rank_available_at_freeze"
        ]
        is False
    )


def test_execution_contract_is_full_standard_w43(a301: Any) -> None:
    contract = a301.execution_contract()
    assert contract["primitive"] == "RFC8439_ChaCha20_block_function"
    assert contract["rounds"] == 20
    assert contract["feedforward_included"] is True
    assert contract["unknown_key_bits"] == 43
    assert contract["candidate_group_size"] == 1 << 31
    assert contract["complete_residual_domain"] == 1 << 43
    assert contract["reader_refits"] == contract["target_labels_used"] == 0


def test_two_operator_portfolio_is_exact_and_has_factor_two_bound(
    a301: Any,
) -> None:
    rng = np.random.default_rng(0xA301)
    coarse = rng.permutation(a301.CELLS).tolist()
    numeric = list(range(a301.CELLS))
    portfolio = a301.two_operator_portfolio(coarse=coarse, numeric=numeric)
    assert len(portfolio) == len(set(portfolio)) == a301.CELLS
    assert set(portfolio) == set(range(a301.CELLS))
    guarantee = a301.portfolio_guarantee(
        portfolio=portfolio, coarse=coarse, numeric=numeric
    )
    assert guarantee["checked_prefix_cells"] == a301.CELLS
    assert guarantee["violations"] == 0
    assert guarantee["maximum_observed_regret_factor"] <= 2.0
    assert guarantee["frozen_worst_case_bound_bits"] == 1.0


def test_duplicate_suppression_preserves_precedence(a301: Any) -> None:
    coarse = [0, 2, 1, *range(3, a301.CELLS)]
    numeric = list(range(a301.CELLS))
    portfolio = a301.two_operator_portfolio(coarse=coarse, numeric=numeric)
    assert portfolio[:3] == [0, 2, 1]
    assert portfolio.count(0) == portfolio.count(1) == portfolio.count(2) == 1


def test_fourteen_target_calibration_is_exact(a301: Any) -> None:
    value = a301.calibration_payload()
    assert value["evidence_stage"] == (
        "FOURTEEN_TARGET_TWO_OPERATOR_CALIBRATION_FROZEN"
    )
    assert value["aggregate"]["targets"] == 14
    assert value["aggregate"]["strict_subset_targets"] == 14
    assert value["aggregate"]["fine_operator_direct_calibrations"] == 2
    assert value["aggregate"]["fine_operator_dominated_calibrations"] == 2
    assert value["aggregate"]["maximum_portfolio_rank"] == 3534
    assert value["aggregate"]["geometric_mean_complete_domain_reduction"] == (
        pytest.approx(3.206509101787679, abs=1e-12)
    )
    rows = {row["target_id"]: row for row in value["rows"]}
    assert rows["A295"]["prefix_ranks_one_based"] == {
        "coarse": 202,
        "numeric": 1006,
        "two_operator_portfolio": 362,
        "fine": 2605,
    }
    assert rows["A299"]["prefix_ranks_one_based"] == {
        "coarse": 427,
        "numeric": 3952,
        "two_operator_portfolio": 853,
        "fine": 2114,
    }


def test_rank_analysis_includes_pruned_and_a300_counterfactual(
    a301: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    coarse = [*range(100, a301.CELLS), *range(100)]
    numeric = list(range(a301.CELLS))
    fine = list(reversed(range(a301.CELLS)))
    a300_portfolio = a301.A300.round_robin_portfolio(
        fine=fine, coarse=coarse, numeric=numeric
    )
    a300_order = tmp_path / "a300_order.json"
    a300_order.write_text(
        json.dumps(
            {
                "component_orders": {
                    "A295_fine_selected_channel": fine,
                    "A297_coarse_high8_then_reflected_Gray4": coarse,
                    "numeric_word0_prefix12": numeric,
                },
                "portfolio_order": a300_portfolio,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(a301.A300, "ORDER", a300_order)
    portfolio = a301.two_operator_portfolio(coarse=coarse, numeric=numeric)
    order_value = {
        "candidate_execution_orders": {
            "A297_coarse_high8_then_reflected_Gray4": coarse,
            "numeric_word0_prefix12": numeric,
        },
        "portfolio_order": portfolio,
    }
    result = a301.rank_analysis(
        prefix=99, order_value=order_value, challenge_sha="11" * 32
    )
    ranks = result["prefix_ranks_one_based"]
    assert result["rank_guarantee_holds"] is True
    assert ranks["A301_two_operator_portfolio"] <= 2 * result[
        "best_allocated_component_rank_one_based"
    ]
    assert "A295_fine_selected_channel_audit_only" in ranks
    assert "A300_three_operator_portfolio_counterfactual" in ranks


def test_authentic_causal_roundtrip(
    a301: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a301.causal"
    monkeypatch.setattr(a301, "CAUSAL", path)
    payload = {
        "calibration_sha256": "11" * 32,
        "calibration_aggregate": {"targets": 14, "strict_subset_targets": 14},
        "portfolio_guarantee": {"violations": 0},
        "execution_sha256": "22" * 32,
        "discovery": {"candidate": 0x123456789AB, "fine_prefix12": 0x345},
        "confirmation": {"total_cross_implementation_output_bits_checked": 8192},
        "evidence_stage": "TEST_CONFIRMED",
    }
    graph = a301.build_causal(payload)
    assert graph["api_id"] == "a301w43"
    assert graph["explicit_triplets"] == 2
    assert graph["materialized_inferred_triplets"] == 1
    assert graph["embedded_rules"] == 2
    assert graph["clusters"] == 1
    assert graph["gaps"] == 1
    assert graph["sha256"] == a301.file_sha256(path)
