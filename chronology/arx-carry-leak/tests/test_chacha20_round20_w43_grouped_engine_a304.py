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
    / "research/experiments/chacha20_round20_w43_grouped_engine_a304.py"
)


@pytest.fixture(scope="module")
def a304() -> Any:
    spec = importlib.util.spec_from_file_location("test_a304_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_preserves_a302_order_and_candidate_membership(a304: Any) -> None:
    design = a304.load_design()
    assert design["attempt_id"] == "A304"
    engine = design["engine_contract"]
    assert engine["candidate_group_size"] == 1 << 31
    assert engine["complete_group_before_success_evaluation"] is True
    assert engine["early_stop_inside_group"] is False
    assert engine["full_rounds"] == 20
    assert engine["feedforward_included"] is True
    boundary = design["information_boundary"]
    assert boundary["engine_changes_frozen_prefix_order"] is False
    assert boundary["engine_changes_candidate_membership"] is False
    assert boundary["A302_candidate_available_at_freeze"] is False
    assert boundary["A302_filter_outcome_available_at_freeze"] is False


def test_grouped_pair_parser_enforces_canonical_pairs(a304: Any) -> None:
    pairs = [[0x12345678, 0], [0xABCDEF01, 7], [0x00000001, 2047]]
    assert a304.GroupedMetalHost._pairs(pairs, name="test") == pairs
    with pytest.raises(RuntimeError, match="order differs"):
        a304.GroupedMetalHost._pairs(list(reversed(pairs)), name="test")
    with pytest.raises(RuntimeError, match="duplicate"):
        a304.GroupedMetalHost._pairs([pairs[0], pairs[0]], name="test")
    with pytest.raises(RuntimeError, match="pair differs"):
        a304.GroupedMetalHost._pairs([[1, 2048]], name="test")


def test_grouped_discovery_executes_one_complete_grid_per_prefix(a304: Any) -> None:
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
            assert target.size >= 2
            assert control.size >= 2
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
            return {
                "factual": factual,
                "control": [],
                "gpu_seconds": 0.25,
            }

    protocol = json.loads(a304.A302.PROTOCOL.read_bytes())
    challenge = protocol["public_challenge"]
    order = [*range(a304.CELLS)]
    host = Host()
    discovery = a304.ordered_discovery(
        host=host, challenge=challenge, order=order
    )
    assert discovery["candidate"] == (target_outer << 32) | target_word0
    assert discovery["executed_prefix_groups"] == target_prefix + 1
    assert discovery["executed_group_dispatches"] == target_prefix + 1
    assert discovery["executed_outer_slices"] == (target_prefix + 1) * 2048
    assert discovery["executed_assignments"] == (target_prefix + 1) * (1 << 31)
    assert discovery["complete_group_execution_before_stop"] is True
    assert discovery["early_stop_inside_group"] is False
    assert host.configurations == 1
    assert len(host.calls) == target_prefix + 1
    assert all(call[1:] == (1 << 20, 0, 2048) for call in host.calls)


def test_scalar_grid_preserves_outer_to_word1_mapping(a304: Any) -> None:
    protocol = json.loads(a304.A302.PROTOCOL.read_bytes())
    challenge = protocol["public_challenge"]
    first = 0x76543000
    for outer in (0, 1, 1023, 2047):
        observed = a304._scalar_blocks(
            challenge=challenge,
            outer=outer,
            first_word0=first,
            count=2,
        )
        assert observed.shape == (2, 16)
        initial = a304.W43._initial(
            challenge["known_zeroed_key_words"],
            int(challenge["counter_start"]),
            challenge["nonce_words"],
            outer,
        )
        assert int(initial[5]) & 0x7FF == outer


def test_authentic_causal_roundtrip(
    a304: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a304.causal"
    monkeypatch.setattr(a304, "CAUSAL", path)
    payload = {
        "qualification_artifact_sha256": "11" * 32,
        "engine_efficiency": {
            "candidate_membership_identical": True,
            "filter_dispatch_reduction_factor": 2048,
        },
        "qualification_gate": {
            "synthetic_filter_exact": True,
            "production_target_used": False,
        },
        "execution_sha256": "22" * 32,
        "discovery": {
            "candidate": 0x123456789AB,
            "fine_prefix12": 0x345,
        },
        "confirmation": {
            "total_cross_implementation_output_bits_checked": 8192
        },
        "evidence_stage": "TEST_CONFIRMED",
    }
    graph = a304.build_causal(payload)
    assert graph["api_id"] == "a304w43"
    assert graph["explicit_triplets"] == 2
    assert graph["materialized_inferred_triplets"] == 1
    assert graph["embedded_rules"] == 2
    assert graph["clusters"] == 1
    assert graph["gaps"] == 1
    assert graph["sha256"] == a304.file_sha256(path)
