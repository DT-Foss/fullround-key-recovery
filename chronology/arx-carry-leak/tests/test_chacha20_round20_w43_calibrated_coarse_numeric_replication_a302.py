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
    / "research/experiments/chacha20_round20_w43_calibrated_coarse_numeric_replication_a302.py"
)


@pytest.fixture(scope="module")
def a302() -> Any:
    spec = importlib.util.spec_from_file_location("test_a302_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_removes_fine_measurement_before_target(a302: Any) -> None:
    design = a302.load_design()
    assert design["attempt_id"] == "A302"
    measurement = design["measurement_contract"]
    assert measurement["coarse_cells"] == 256
    assert measurement["expected_model_free_stages"] == 1024
    assert measurement["fine_cells"] == 0
    assert measurement["fine_solver_stages"] == 0
    boundary = design["information_boundary"]
    assert boundary["A300_result_available_at_freeze"] is False
    assert boundary["A301_result_available_at_freeze"] is False
    assert (
        boundary[
            "A302_production_assignment_target_measurement_order_model_candidate_filter_outcome_or_rank_available_at_freeze"
        ]
        is False
    )


def test_execution_contract_is_full_standard_w43_and_coarse_only(
    a302: Any,
) -> None:
    contract = a302.execution_contract()
    assert contract["primitive"] == "RFC8439_ChaCha20_block_function"
    assert contract["rounds"] == 20
    assert contract["feedforward_included"] is True
    assert contract["unknown_key_bits"] == 43
    assert contract["coarse_cells"] == 256
    assert contract["conflict_horizons_per_cell"] == 4
    assert contract["fine_cells"] == 0
    assert contract["candidate_group_size"] == 1 << 31
    assert contract["complete_residual_domain"] == 1 << 43


def test_fresh_target_contains_no_assignment_or_full_key(a302: Any) -> None:
    challenge = a302.fresh_challenge()
    a302.A300.A299.W43._validate_challenge(challenge)
    assert challenge["unknown_assignment_included"] is False
    assert "assignment" not in challenge
    assert "full_key" not in challenge
    assert challenge["unknown_key_bits"] == 43
    assert len(challenge["target_words"]) == 8


def test_reader_adapter_preserves_target_and_dynamic_hash(a302: Any) -> None:
    challenge = a302.fresh_challenge()
    public_sha = a302.canonical_sha256(challenge)
    adapted = a302.reader_challenge(challenge, public_sha)
    assert adapted["challenge_id"] == (
        "a302-reader-view-of-chacha20-r20-w43-fresh-v1"
    )
    assert adapted["source_public_challenge_sha256"] == public_sha
    assert adapted["target_words"] == challenge["target_words"]
    assert adapted["known_key_mask_words"] == [
        0,
        0xFFFFF800,
        *([0xFFFFFFFF] * 6),
    ]
    assert adapted["unknown_global_bit_interval"] == [0, 42]


def test_inherited_two_operator_portfolio_has_factor_two_bound(a302: Any) -> None:
    rng = np.random.default_rng(0xA302)
    coarse = rng.permutation(a302.CELLS).tolist()
    numeric = list(range(a302.CELLS))
    portfolio = a302.A301.two_operator_portfolio(
        coarse=coarse, numeric=numeric
    )
    guarantee = a302.A301.portfolio_guarantee(
        portfolio=portfolio, coarse=coarse, numeric=numeric
    )
    assert len(portfolio) == len(set(portfolio)) == a302.CELLS
    assert guarantee["violations"] == 0
    assert guarantee["maximum_observed_regret_factor"] <= 2.0


def test_rank_analysis_enforces_factor_two_bound(a302: Any) -> None:
    coarse = [*range(100, a302.CELLS), *range(100)]
    numeric = list(range(a302.CELLS))
    portfolio = a302.A301.two_operator_portfolio(
        coarse=coarse, numeric=numeric
    )
    value = {
        "component_orders": {
            "A297_coarse_high8_then_reflected_Gray4": coarse,
            "numeric_word0_prefix12": numeric,
        },
        "portfolio_order": portfolio,
    }
    result = a302.rank_analysis(
        prefix=99, order_value=value, challenge_sha="11" * 32
    )
    ranks = result["prefix_ranks_one_based"]
    assert result["rank_guarantee_holds"] is True
    assert ranks["A302_two_operator_portfolio"] <= 2 * result[
        "best_component_rank_one_based"
    ]
    assert result["assignment_upper_bounds"]["A302_two_operator_portfolio"] == (
        ranks["A302_two_operator_portfolio"] * (1 << 31)
    )


def test_ordered_recovery_completes_entire_w43_group(a302: Any) -> None:
    prefix = 0x6B4
    target_outer = 11
    target_word0 = (prefix << 20) | 0x76543

    class Host:
        def __init__(self) -> None:
            self.outer = -1
            self.calls = 0

        def configure(
            self,
            initial: np.ndarray,
            _target: np.ndarray,
            _control: np.ndarray,
        ) -> None:
            self.outer = int(initial[5]) & 0x7FF

        def filter(self, first: int, count: int) -> dict[str, Any]:
            self.calls += 1
            assert first == prefix << 20
            assert count == 1 << 20
            factual = [target_word0] if self.outer == target_outer else []
            return {"factual": factual, "control": [], "gpu_seconds": 0.25}

    challenge = a302.fresh_challenge()
    host = Host()
    discovery = a302.A300.A299.ordered_discovery(
        host=host, challenge=challenge, order=[prefix]
    )
    assert discovery["candidate"] == (target_outer << 32) | target_word0
    assert discovery["executed_prefix_groups"] == 1
    assert discovery["executed_outer_slices"] == 2048
    assert discovery["executed_assignments"] == 1 << 31
    assert discovery["complete_group_execution_before_stop"] is True
    assert host.calls == 2048


def test_authentic_causal_roundtrip(
    a302: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a302.causal"
    monkeypatch.setattr(a302, "CAUSAL", path)
    payload = {
        "order_sha256": "11" * 32,
        "measurement_efficiency": {
            "coarse_cells": 256,
            "coarse_stages": 1024,
            "fine_cells": 0,
        },
        "portfolio_guarantee": {"violations": 0},
        "execution_sha256": "22" * 32,
        "discovery": {"candidate": 0x123456789AB, "fine_prefix12": 0x345},
        "confirmation": {"total_cross_implementation_output_bits_checked": 8192},
        "evidence_stage": "TEST_CONFIRMED",
    }
    graph = a302.build_causal(payload)
    assert graph["api_id"] == "a302w43"
    assert graph["explicit_triplets"] == 2
    assert graph["materialized_inferred_triplets"] == 1
    assert graph["embedded_rules"] == 2
    assert graph["clusters"] == 1
    assert graph["gaps"] == 1
    assert graph["sha256"] == a302.file_sha256(path)
