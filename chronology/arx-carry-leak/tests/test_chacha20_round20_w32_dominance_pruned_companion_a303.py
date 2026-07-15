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
    / "research/experiments/chacha20_round20_w32_dominance_pruned_companion_a303.py"
)


@pytest.fixture(scope="module")
def a303() -> Any:
    spec = importlib.util.spec_from_file_location("test_a303_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_freezes_companion_before_a298_order(a303: Any) -> None:
    design = a303.load_design()
    assert design["attempt_id"] == "A303"
    assert design["operator_contract"]["candidate_execution_orders"] == [
        "A297_coarse_high8_then_reflected_Gray4",
        "numeric_word0_prefix12",
    ]
    assert (
        design["information_boundary"][
            "A298_order_model_candidate_assignment_filter_outcome_or_result_available_at_freeze"
        ]
        is False
    )


def test_execution_contract_is_full_standard_w32(a303: Any) -> None:
    contract = a303.execution_contract()
    assert contract["primitive"] == "RFC8439_ChaCha20_block_function"
    assert contract["rounds"] == 20
    assert contract["feedforward_included"] is True
    assert contract["unknown_key_bits"] == 32
    assert contract["candidate_group_size"] == 1 << 20
    assert contract["complete_residual_domain"] == 1 << 32


def test_inherited_portfolio_has_factor_two_bound(a303: Any) -> None:
    rng = np.random.default_rng(0xA303)
    coarse = rng.permutation(a303.CELLS).tolist()
    numeric = list(range(a303.CELLS))
    portfolio = a303.A301.two_operator_portfolio(
        coarse=coarse, numeric=numeric
    )
    guarantee = a303.A301.portfolio_guarantee(
        portfolio=portfolio, coarse=coarse, numeric=numeric
    )
    assert len(portfolio) == len(set(portfolio)) == a303.CELLS
    assert guarantee["violations"] == 0
    assert guarantee["maximum_observed_regret_factor"] <= 2.0


def test_authentic_causal_roundtrip(
    a303: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a303.causal"
    monkeypatch.setattr(a303, "CAUSAL", path)
    payload = {
        "order_sha256": "11" * 32,
        "rank_analysis": {"prefix_ranks_one_based": {"A303": 1}},
        "portfolio_guarantee": {"violations": 0},
        "execution_sha256": "22" * 32,
        "discovery": {"candidate": 0x12345678, "fine_prefix12": 0x123},
        "confirmation": {"total_cross_implementation_output_bits_checked": 8192},
        "evidence_stage": "TEST_CONFIRMED",
    }
    graph = a303.build_causal(payload)
    assert graph["api_id"] == "a303w32"
    assert graph["explicit_triplets"] == 2
    assert graph["materialized_inferred_triplets"] == 1
    assert graph["embedded_rules"] == 2
    assert graph["clusters"] == 1
    assert graph["gaps"] == 1
    assert graph["sha256"] == a303.file_sha256(path)
