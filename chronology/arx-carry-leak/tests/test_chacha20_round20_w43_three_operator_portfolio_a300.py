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
    / "research/experiments/chacha20_round20_w43_three_operator_portfolio_a300.py"
)


@pytest.fixture(scope="module")
def a300() -> Any:
    spec = importlib.util.spec_from_file_location("test_a300_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_freezes_three_operator_contract_before_target(a300: Any) -> None:
    design = a300.load_design()
    assert design["attempt_id"] == "A300"
    assert design["operator_contract"]["merge_component_precedence"] == [
        "A295_fine_selected_channel",
        "A297_coarse_high8_then_reflected_Gray4",
        "numeric_word0_prefix12",
    ]
    boundary = design["information_boundary"]
    assert boundary["A299_fine_trace_order_available_at_freeze"] is False
    assert boundary["A299_candidate_prefix_rank_or_result_available_at_freeze"] is False
    assert boundary["A300_production_assignment_or_target_available_at_freeze"] is False


def test_execution_contract_is_full_standard_w43(a300: Any) -> None:
    contract = a300.execution_contract()
    assert contract["primitive"] == "RFC8439_ChaCha20_block_function"
    assert contract["rounds"] == 20
    assert contract["feedforward_included"] is True
    assert contract["unknown_key_bits"] == 43
    assert contract["candidate_group_size"] == 1 << 31
    assert contract["complete_residual_domain"] == 1 << 43
    assert contract["reader_refits"] == contract["target_labels_used"] == 0


def test_fresh_target_contains_no_assignment_or_full_key(a300: Any) -> None:
    challenge = a300.fresh_challenge()
    a300.A299.W43._validate_challenge(challenge)
    assert challenge["unknown_assignment_included"] is False
    assert "assignment" not in challenge
    assert "full_key" not in challenge
    assert challenge["unknown_key_bits"] == 43
    assert len(challenge["target_words"]) == 8


def test_reader_adapter_preserves_target_and_dynamic_hash(a300: Any) -> None:
    challenge = a300.fresh_challenge()
    public_sha = a300.canonical_sha256(challenge)
    adapted = a300.reader_challenge(challenge, public_sha)
    assert adapted["challenge_id"] == "a300-reader-view-of-chacha20-r20-w43-fresh-v1"
    assert adapted["source_public_challenge_sha256"] == public_sha
    assert adapted["target_words"] == challenge["target_words"]
    assert adapted["known_key_mask_words"] == [
        0,
        0xFFFFF800,
        *([0xFFFFFFFF] * 6),
    ]
    assert adapted["unknown_global_bit_interval"] == [0, 42]


def test_round_robin_is_exact_and_obeys_exhaustive_rank_bound(a300: Any) -> None:
    rng = np.random.default_rng(0xA300)
    fine = rng.permutation(a300.CELLS).tolist()
    coarse = rng.permutation(a300.CELLS).tolist()
    numeric = list(range(a300.CELLS))
    portfolio = a300.round_robin_portfolio(
        fine=fine, coarse=coarse, numeric=numeric
    )
    assert len(portfolio) == len(set(portfolio)) == a300.CELLS
    assert set(portfolio) == set(range(a300.CELLS))
    guarantee = a300.portfolio_guarantee(
        portfolio=portfolio,
        fine=fine,
        coarse=coarse,
        numeric=numeric,
    )
    assert guarantee["checked_prefix_cells"] == a300.CELLS
    assert guarantee["violations"] == 0
    assert guarantee["maximum_observed_regret_factor"] <= 3.0


def test_round_robin_precedence_and_duplicate_suppression(a300: Any) -> None:
    fine = list(range(a300.CELLS))
    coarse = [0, 2, 1, *range(3, a300.CELLS)]
    numeric = list(range(a300.CELLS))
    portfolio = a300.round_robin_portfolio(
        fine=fine, coarse=coarse, numeric=numeric
    )
    assert portfolio[:3] == [0, 1, 2]
    assert portfolio.count(0) == portfolio.count(1) == portfolio.count(2) == 1


def test_fine_lane_plan_is_disjoint_exact_cover(a300: Any) -> None:
    preflight = {
        "target": {
            "CNF": {"path": "unused.cnf", "sha256": "00" * 32},
            "source_one_literals_bit0_upward": list(range(1, 44)),
        }
    }
    plan = a300.fine_lane_plan(list(reversed(range(256))), preflight)
    active = [
        int(prefix, 2)
        for arm in plan["arms"]
        for prefix in arm["active_prefixes"]
    ]
    assert [arm["arm"] for arm in plan["arms"]] == [
        f"a300_fine12_lane{lane}" for lane in range(8)
    ]
    assert all(len(arm["active_prefixes"]) == 512 for arm in plan["arms"])
    assert len(active) == len(set(active)) == 4096
    assert set(active) == set(range(4096))


def test_rank_analysis_enforces_target_specific_guarantee(a300: Any) -> None:
    fine = list(reversed(range(a300.CELLS)))
    coarse = [*range(100, a300.CELLS), *range(100)]
    numeric = list(range(a300.CELLS))
    portfolio = a300.round_robin_portfolio(
        fine=fine, coarse=coarse, numeric=numeric
    )
    value = {
        "component_orders": {
            "A295_fine_selected_channel": fine,
            "A297_coarse_high8_then_reflected_Gray4": coarse,
            "numeric_word0_prefix12": numeric,
        },
        "portfolio_order": portfolio,
    }
    prefix = 99
    result = a300.rank_analysis(
        prefix=prefix, order_value=value, challenge_sha="11" * 32
    )
    ranks = result["prefix_ranks_one_based"]
    assert result["rank_guarantee_holds"] is True
    assert ranks["A300_three_operator_portfolio"] <= 3 * result[
        "best_component_rank_one_based"
    ]
    assert result["assignment_upper_bounds"]["A300_three_operator_portfolio"] == (
        ranks["A300_three_operator_portfolio"] * (1 << 31)
    )


def test_ordered_recovery_completes_entire_w43_group(a300: Any) -> None:
    prefix = 0x5A3
    target_outer = 9
    target_word0 = (prefix << 20) | 0x54321

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

    challenge = a300.fresh_challenge()
    host = Host()
    discovery = a300.A299.ordered_discovery(
        host=host, challenge=challenge, order=[prefix]
    )
    assert discovery["candidate"] == (target_outer << 32) | target_word0
    assert discovery["executed_prefix_groups"] == 1
    assert discovery["executed_outer_slices"] == 2048
    assert discovery["executed_assignments"] == 1 << 31
    assert discovery["complete_group_execution_before_stop"] is True
    assert host.calls == 2048


def test_runner_has_no_a299_outcome_input_path() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    assert "A299.ORDER" not in source
    assert "A299.RESULT" not in source
    assert "chacha20_round20_w43_fine_selected_channel_transfer_a299_order" not in source
    assert "chacha20_round20_w43_fine_selected_channel_transfer_a299_v1.json" not in source


def test_authentic_causal_roundtrip(
    a300: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a300.causal"
    monkeypatch.setattr(a300, "CAUSAL", path)
    payload = {
        "order_sha256": "11" * 32,
        "execution_sha256": "22" * 32,
        "rank_analysis": {
            "prefix_ranks_one_based": {"A300_three_operator_portfolio": 1}
        },
        "portfolio_guarantee": {"violations": 0},
        "discovery": {"candidate": 0x123456789AB, "fine_prefix12": 0x345},
        "confirmation": {"total_cross_implementation_output_bits_checked": 8192},
        "evidence_stage": "TEST_CONFIRMED",
    }
    graph = a300.build_causal(payload)
    assert graph["api_id"] == "a300w43"
    assert graph["explicit_triplets"] == 2
    assert graph["materialized_inferred_triplets"] == 1
    assert graph["embedded_rules"] == 2
    assert graph["clusters"] == 1
    assert graph["gaps"] == 1
    assert graph["sha256"] == a300.file_sha256(path)
