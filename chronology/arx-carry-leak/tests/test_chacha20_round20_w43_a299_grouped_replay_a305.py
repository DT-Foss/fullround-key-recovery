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
    / "research/experiments/chacha20_round20_w43_a299_grouped_replay_a305.py"
)


@pytest.fixture(scope="module")
def a305() -> Any:
    spec = importlib.util.spec_from_file_location("test_a305_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_retains_prospective_a299_order(a305: Any) -> None:
    design = a305.load_design()
    boundary = design["information_boundary"]
    assert design["attempt_id"] == "A305"
    assert boundary[
        "A299_order_was_frozen_before_A299_candidate_or_rank_available"
    ] is True
    assert boundary["A305_engine_changes_A299_prefix_order"] is False
    assert boundary["A305_engine_changes_candidate_membership"] is False
    assert boundary["A305_candidate_supplied_to_grouped_runner"] is False
    assert boundary["A299_candidate_and_rank_available_when_A305_design_was_written"] is True
    implementation = design["implementation_boundary"]
    assert implementation["legacy_filter_dispatches_per_prefix_group"] == 2048
    assert implementation["new_filter_dispatches_per_prefix_group"] == 1


def test_grouped_replay_executes_complete_grid_per_a299_prefix(a305: Any) -> None:
    target_prefix = 2
    target_outer = 0x357
    target_word0 = (target_prefix << 20) | 0x76543

    class Host:
        def __init__(self) -> None:
            self.calls: list[tuple[int, int, int, int]] = []
            self.configurations = 0

        def configure(
            self,
            initial: np.ndarray,
            target: np.ndarray,
            control: np.ndarray,
        ) -> None:
            assert int(initial[5]) & 0x7FF == 0
            assert target.size >= 2 and control.size >= 2
            self.configurations += 1

        def filter_group(
            self,
            *,
            first_word0: int,
            word0_count: int,
            outer_first: int,
            outer_count: int,
        ) -> dict[str, Any]:
            self.calls.append(
                (first_word0, word0_count, outer_first, outer_count)
            )
            prefix = first_word0 >> 20
            factual = [[target_word0, target_outer]] if prefix == target_prefix else []
            return {"factual": factual, "control": [], "gpu_seconds": 0.25}

    protocol = json.loads(a305.A299.PROTOCOL.read_bytes())
    host = Host()
    discovery = a305.ordered_discovery(
        host=host,
        challenge=protocol["public_challenge"],
        order=list(range(a305.CELLS)),
    )
    assert discovery["candidate"] == (target_outer << 32) | target_word0
    assert discovery["source_operator_attempt"] == "A299"
    assert discovery["execution_engine_attempt"] == "A304"
    assert discovery["executed_prefix_groups"] == target_prefix + 1
    assert discovery["executed_group_dispatches"] == target_prefix + 1
    assert discovery["executed_assignments"] == (target_prefix + 1) * (1 << 31)
    assert discovery["complete_group_execution_before_stop"] is True
    assert discovery["early_stop_inside_group"] is False
    assert host.configurations == 1
    assert len(host.calls) == target_prefix + 1
    assert all(call[1:] == (1 << 20, 0, 2048) for call in host.calls)


def test_authentic_causal_roundtrip(
    a305: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a305.causal"
    monkeypatch.setattr(a305, "CAUSAL", path)
    payload = {
        "protocol_sha256": "11" * 32,
        "engine_efficiency": {
            "candidate_membership_identical": True,
            "filter_dispatch_reduction_factor": 2048,
        },
        "implementation_boundary": {
            "legacy_failure_signature": "Metal failure: empty buffer allocation failed"
        },
        "execution_sha256": "22" * 32,
        "discovery": {"candidate": 0x123456789AB, "fine_prefix12": 0x345},
        "confirmation": {
            "total_cross_implementation_output_bits_checked": 8192
        },
        "evidence_stage": "TEST_CONFIRMED",
    }
    graph = a305.build_causal(payload)
    assert graph["api_id"] == "a305w43"
    assert graph["explicit_triplets"] == 2
    assert graph["materialized_inferred_triplets"] == 1
    assert graph["embedded_rules"] == 2
    assert graph["clusters"] == 1
    assert graph["gaps"] == 1
    assert graph["sha256"] == a305.file_sha256(path)

