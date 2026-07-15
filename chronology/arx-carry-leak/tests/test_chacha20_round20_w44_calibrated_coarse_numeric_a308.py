from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_w44_calibrated_coarse_numeric_a308.py"


@pytest.fixture(scope="module")
def a308() -> Any:
    spec = importlib.util.spec_from_file_location("test_a308_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_freezes_real_w44_groups_before_target(a308: Any) -> None:
    design = a308.load_design()
    assert design["attempt_id"] == "A308"
    execution = design["execution_contract"]
    assert execution["unknown_key_bits"] == 44
    assert execution["candidate_group_size"] == 1 << 32
    assert execution["complete_residual_domain"] == 1 << 44
    assert execution["complete_group_execution_before_stop"] is True
    assert design["measurement_contract"]["coarse_cells"] == 256
    boundary = design["information_boundary"]
    assert (
        boundary[
            "A308_assignment_target_measurement_order_model_candidate_filter_outcome_or_rank_available_at_design_freeze"
        ]
        is False
    )


def test_challenge_discards_assignment_but_preserves_exact_outputs(a308: Any) -> None:
    assignment = 0xABC12345678
    challenge = a308.challenge_from_assignment(
        label="A308|test|deterministic", assignment=assignment
    )
    a308.validate_challenge(challenge)
    assert "assignment" not in challenge
    assert challenge["unknown_assignment_included"] is False
    assert challenge["known_zeroed_key_words"][0] == 0
    assert challenge["known_zeroed_key_words"][1] & 0xFFF == 0
    key = a308.apply_assignment(challenge["known_zeroed_key_words"], assignment)
    observed = a308.W43._reference_outputs(  # noqa: SLF001
        key, challenge["counter_start"], challenge["nonce_words"]
    )
    assert observed == challenge["target_words"]


def test_reader_view_exposes_outputs_but_not_key_label(a308: Any) -> None:
    challenge = a308.challenge_from_assignment(label="A308|test|reader", assignment=0x123456789AB)
    public_sha = a308.canonical_sha256(challenge)
    reader = a308.reader_challenge(challenge, public_sha)
    assert reader["unknown_key_bits"] == 44
    assert reader["known_key_mask_words"][1] == 0xFFFFF000
    assert reader["unknown_assignment_included"] is False
    assert reader["target_words"] == challenge["target_words"]


def test_ordered_discovery_refreshes_host_without_changing_groups(a308: Any) -> None:
    challenge = a308.challenge_from_assignment(
        label="A308|test|discovery", assignment=0x34500012345
    )
    target_prefix = 0x345
    target_word0 = (target_prefix << 20) | 0x12345
    target_outer12 = 7
    candidate = (target_outer12 << 32) | target_word0
    instances: list[Any] = []

    class Host:
        def __init__(self) -> None:
            self.slab = -1
            self.closed = False
            self.calls: list[tuple[int, int]] = []

        def configure(
            self,
            initial: np.ndarray,
            target: np.ndarray,
            control: np.ndarray,
        ) -> None:
            assert target.size >= 2 and control.size >= 2
            self.slab = (int(initial[5]) >> 11) & 1

        def filter_group(self, **kwargs: int) -> dict[str, Any]:
            prefix = kwargs["first_word0"] >> 20
            self.calls.append((prefix, self.slab))
            factual = (
                [[target_word0, target_outer12]]
                if prefix == target_prefix and self.slab == 0
                else []
            )
            return {"factual": factual, "control": [], "gpu_seconds": 0.25}

        def close(self) -> None:
            self.closed = True

    def factory() -> Host:
        host = Host()
        instances.append(host)
        return host

    order = [
        1,
        2,
        target_prefix,
        *(value for value in range(4096) if value not in {1, 2, target_prefix}),
    ]
    observed = a308.ordered_discovery(
        host_factory=factory,
        challenge=challenge,
        order=order,
        host_refresh_groups=2,
    )
    assert observed["candidate"] == candidate
    assert observed["executed_prefix_groups"] == 3
    assert observed["executed_group_dispatches"] == 6
    assert observed["executed_assignments"] == 3 * (1 << 32)
    assert observed["host_instances"] == 2
    assert all(host.closed for host in instances)
    assert [pair for host in instances for pair in host.calls] == [
        (1, 0),
        (1, 1),
        (2, 0),
        (2, 1),
        (target_prefix, 0),
        (target_prefix, 1),
    ]


def test_confirmation_checks_both_implementations(a308: Any) -> None:
    assignment = 0x789ABCDEF01
    challenge = a308.challenge_from_assignment(label="A308|test|confirm", assignment=assignment)
    confirmation = a308.confirm(challenge, assignment)
    assert confirmation["all_blocks_match"] is True
    assert confirmation["total_cross_implementation_output_bits_checked"] == 8192
    wrong = a308.confirm(challenge, assignment ^ 1)
    assert wrong["all_blocks_match"] is False


def test_rank_portfolio_retains_factor_two_bound(a308: Any) -> None:
    coarse = list(reversed(range(4096)))
    numeric = list(range(4096))
    portfolio = a308.A302.A301.two_operator_portfolio(coarse=coarse, numeric=numeric)
    order_value = {
        "portfolio_order": portfolio,
        "component_orders": {
            "A297_coarse_high8_then_reflected_Gray4": coarse,
            "numeric_word0_prefix12": numeric,
        },
    }
    ranks = a308.rank_analysis(prefix=3000, order_value=order_value, challenge_sha="11" * 32)
    assert ranks["rank_guarantee_holds"] is True
    assert (
        ranks["prefix_ranks_one_based"]["A308_two_operator_portfolio"]
        <= 2 * ranks["best_component_rank_one_based"]
    )


def test_authentic_causal_roundtrip(
    a308: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a308.causal"
    monkeypatch.setattr(a308, "CAUSAL", path)
    payload = {
        "order_sha256": "11" * 32,
        "execution_sha256": "22" * 32,
        "evidence_stage": "TEST_CONFIRMED",
        "qualification_gate": {"complete_W44_group_candidates": 1 << 32},
        "rank_analysis": {"portfolio_gain_bits_vs_complete_domain": 1.0},
        "discovery": {"candidate": 0x123456789AB, "prefix12": 0x345},
        "confirmation": {"total_cross_implementation_output_bits_checked": 8192},
    }
    graph = a308.build_causal(payload)
    assert graph["api_id"] == "a308w44"
    assert graph["explicit_triplets"] == 2
    assert graph["materialized_inferred_triplets"] == 1
    assert graph["embedded_rules"] == 2
    assert graph["clusters"] == 1
    assert graph["gaps"] == 1
    assert graph["sha256"] == a308.file_sha256(path)
