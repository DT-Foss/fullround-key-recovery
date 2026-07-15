from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_holdout_selected_w46_recovery_a325.py"


@pytest.fixture(scope="module")
def a325() -> Any:
    spec = importlib.util.spec_from_file_location("test_a325_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_freezes_unchanged_w46_transfer_before_results(a325: Any) -> None:
    design = a325.load_design()
    assert design["attempt_id"] == "A325"
    execution = design["execution_contract"]
    assert execution["unknown_key_bits"] == 46
    assert execution["candidates_per_prefix_group"] == 1 << 34
    assert execution["slabs_per_prefix_group"] == 8
    assert execution["host_refresh_interval_prefix_groups"] == 64
    transfer = design["order_transfer_contract"]
    assert transfer["parameter_refit_at_W46"] is False
    assert transfer["W46_protocol_must_freeze_before_A322_result"] is True
    boundary = design["information_boundary"]
    assert boundary["A321_selected_operator_available_at_design_freeze"] is False
    assert boundary["A322_result_available_at_design_freeze"] is False
    assert boundary["W46_challenge_available_at_design_freeze"] is False


def test_implementation_commitment_hashes_frozen_files(a325: Any) -> None:
    commitment = a325.load_implementation_commitment()
    assert commitment["A313_result_available_at_commitment"] is False
    assert commitment["A321_selection_available_at_commitment"] is False
    assert commitment["A322_result_available_at_commitment"] is False
    assert commitment["W46_challenge_available_at_commitment"] is False


def test_public_challenge_omits_assignment_and_dual_confirmation_recovers(a325: Any) -> None:
    assignment = 0x2D31_89ABCDEF
    challenge = a325.challenge_from_assignment(
        label="A325|test|fixed-public-material", assignment=assignment
    )
    a325.validate_challenge(challenge)
    assert challenge["unknown_assignment_included"] is False
    assert "assignment" not in challenge
    assert challenge["known_zeroed_key_words"][0] == 0
    assert challenge["known_zeroed_key_words"][1] & 0x3FFF == 0
    confirmation = a325.confirm(challenge, assignment)
    assert confirmation["all_blocks_match"] is True
    assert confirmation["total_cross_implementation_output_bits_checked"] == 8192


def test_all_transferred_orders_are_exact_and_distinct_from_target(a325: Any) -> None:
    orders = a325.transferred_orders()
    assert set(a325.A321.CANDIDATE_NAMES).issubset(orders)
    assert "A314_three_arm_portfolio" in orders
    assert all(len(order) == 4096 and set(order) == set(range(4096)) for order in orders.values())


def test_ordered_discovery_executes_complete_eight_slab_groups(a325: Any) -> None:
    assignment = (6 << 43) | (17 << 32) | (2 << 20) | 0x45678
    challenge = a325.challenge_from_assignment(
        label="A325|test|ordered-discovery", assignment=assignment
    )

    class Host:
        def __init__(self) -> None:
            self.slab = -1
            self.events: list[tuple[int, int]] = []

        def configure(
            self,
            initial: np.ndarray,
            target: np.ndarray,
            control: np.ndarray,
        ) -> None:
            assert target.size == 16 and control.size == 16
            self.slab = (int(initial[5]) >> 11) & 7

        def filter_group(self, **kwargs: int) -> dict[str, Any]:
            prefix = int(kwargs["first_word0"]) >> 20
            self.events.append((prefix, self.slab))
            factual = []
            if prefix == 2 and self.slab == 6:
                factual = [[assignment & 0xFFFFFFFF, 17]]
            return {"factual": factual, "control": [], "gpu_seconds": 0.25}

        def close(self) -> None:
            return None

    hosts: list[Host] = []

    def factory() -> Host:
        host = Host()
        hosts.append(host)
        return host

    progress: list[dict[str, Any]] = []
    observed = a325.ordered_discovery(
        host_factory=factory,
        challenge=challenge,
        order=list(range(4096)),
        progress_callback=lambda row: progress.append(dict(row)),
    )
    assert observed["candidate"] == assignment
    assert observed["executed_prefix_groups"] == 3
    assert observed["executed_assignments"] == 3 * (1 << 34)
    assert observed["matched_control_candidates"] == 0
    assert hosts[0].events == [
        (prefix, slab) for prefix in range(3) for slab in range(8)
    ]
    assert progress[-1]["status"] == "candidate_found"


def test_resume_fingerprint_restores_next_unexecuted_group(
    a325: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    progress_path = tmp_path / "progress.json"
    monkeypatch.setattr(a325, "PROGRESS", progress_path)
    progress_path.write_text(
        json.dumps(
            {
                "schema": "chacha20-round20-holdout-selected-w46-recovery-a325-progress-v1",
                "attempt_id": "A325",
                "protocol_sha256": "p",
                "selected_operator": "raw_nearest_prototype_Linf",
                "selected_W46_order_uint16be_sha256": "o",
                "A324_qualification_sha256": "q",
                "status": "running",
                "executed_prefix_groups": 321,
                "matched_control_candidates": 0,
                "factual_filter_candidates": 0,
                "gpu_seconds": 123.5,
                "host_instances": 6,
            }
        )
    )
    assert a325._load_resume(  # noqa: SLF001
        protocol_sha256="p", order_sha256="o", qualification_sha256="q"
    ) == (321, 123.5, 6, None)


def test_w46_bounds_are_rejected(a325: Any) -> None:
    with pytest.raises(ValueError, match="exceeds W46"):
        a325.apply_assignment([0] * 8, 1 << 46)
    with pytest.raises(ValueError, match="resume group"):
        a325.ordered_discovery(
            host_factory=lambda: object(),
            challenge={},
            order=list(range(4096)),
            start_group=4096,
        )
