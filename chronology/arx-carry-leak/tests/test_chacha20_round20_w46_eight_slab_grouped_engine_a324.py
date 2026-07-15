from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_w46_eight_slab_grouped_engine_a324.py"


@pytest.fixture(scope="module")
def a324() -> Any:
    spec = importlib.util.spec_from_file_location("test_a324_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_is_target_free_complete_w46_adapter(a324: Any) -> None:
    design = a324.load_design()
    assert design["attempt_id"] == "A324"
    engine = design["engine_contract"]
    assert engine["unknown_key_bits"] == 46
    assert engine["candidate_group_size"] == 1 << 34
    assert engine["slabs"] == list(range(8))
    assert engine["filter_dispatches_per_W46_prefix_group"] == 8
    assert engine["host_refresh_interval_W46_prefix_groups"] == 64
    assert engine["complete_group_before_success_evaluation"] is True
    assert engine["early_stop_inside_group"] is False
    boundary = design["information_boundary"]
    assert boundary["W46_production_challenge_available_at_freeze"] is False
    assert boundary["W46_target_assignment_available_at_freeze"] is False
    assert boundary["A324_qualification_uses_only_synthetic_targets"] is True


def test_source_is_exactly_qualified_and_production_free(a324: Any) -> None:
    protocol, qualification = a324.load_a311_source()
    assert protocol["production_W45_challenge_available"] is False
    assert protocol["production_W45_candidate_available"] is False
    assert qualification["production_W45_challenge_used"] is False
    assert qualification["production_W45_candidate_used"] is False
    assert qualification["complete_group_gate"]["logical_candidates"] == 1 << 33
    assert qualification["complete_group_gate"]["control_candidates"] == []


def test_assignment_codec_is_exact_over_w46(a324: Any) -> None:
    for word0, slab, outer in (
        (0, 0, 0),
        (0xFFFFFFFF, 0, 2047),
        (0x12345678, 1, 0),
        (0xABCDEF01, 3, 2047),
        (0x13579BDF, 4, 0),
        (0x2468ACE0, 6, 2047),
        (0xDEADBEEF, 7, 0),
        (0xA5A5A5A5, 7, 2047),
    ):
        assignment = a324.encode_assignment(
            word0=word0, slab=slab, outer_low11=outer
        )
        decoded = a324.decode_assignment(assignment)
        assert decoded == {
            "word0": word0,
            "word1_low14": (slab << 11) | outer,
            "slab": slab,
            "outer_low11": outer,
        }


def test_complete_prefix_executes_all_eight_slabs_before_readout(a324: Any) -> None:
    challenge = json.loads(a324.A311.A307.A304.A302.PROTOCOL.read_bytes())[
        "public_challenge"
    ]
    target_word0 = (3 << 20) | 0x45678

    class Host:
        def __init__(self) -> None:
            self.slab = -1
            self.events: list[tuple[str, int]] = []

        def configure(
            self,
            initial: np.ndarray,
            target: np.ndarray,
            control: np.ndarray,
        ) -> None:
            assert target.size >= 2 and control.size >= 2
            self.slab = (int(initial[5]) >> 11) & 7
            self.events.append(("configure", self.slab))

        def filter_group(self, **kwargs: int) -> dict[str, Any]:
            assert kwargs == {
                "first_word0": 3 << 20,
                "word0_count": 1 << 20,
                "outer_first": 0,
                "outer_count": 1 << 11,
            }
            self.events.append(("filter", self.slab))
            return {
                "factual": [[target_word0, 17]] if self.slab == 6 else [],
                "control": [[target_word0 + 1, 19]] if self.slab == 7 else [],
                "gpu_seconds": 0.25,
            }

    host = Host()
    observed = a324.filter_complete_prefix(
        host=host,
        challenge=challenge,
        prefix=3,
        target=np.asarray([1, 2], dtype=np.uint32),
        control=np.asarray([3, 4], dtype=np.uint32),
    )
    assert host.events == [
        event
        for slab in range(8)
        for event in (("configure", slab), ("filter", slab))
    ]
    assert observed["logical_candidates"] == 1 << 34
    assert observed["filter_dispatches"] == 8
    assert observed["complete_W46_group_before_outcome_evaluation"] is True
    assert observed["factual_candidates"] == [
        target_word0 | (((6 << 11) | 17) << 32)
    ]
    assert observed["control_candidates"] == [
        (target_word0 + 1) | (((7 << 11) | 19) << 32)
    ]


def test_scalar_w46_boundaries_map_three_slab_bits_without_alias(a324: Any) -> None:
    challenge = json.loads(a324.A311.A307.A304.A302.PROTOCOL.read_bytes())[
        "public_challenge"
    ]
    first = 0x34567000
    boundaries = (0, 2047, 2048, 4095, 4096, 8191, 8192, 12287, 12288, 16383)
    blocks = {
        outer14: a324.scalar_blocks_w46(
            challenge=challenge,
            outer14=outer14,
            first_word0=first,
            count=2,
        )
        for outer14 in boundaries
    }
    assert all(value.shape == (2, 16) for value in blocks.values())
    for outer14 in boundaries:
        assert int(a324.initial_for_outer14(challenge, outer14)[5]) & 0x3FFF == outer14
    assert all(
        not np.array_equal(blocks[0], blocks[1 << bit]) for bit in (11, 12, 13)
    )


def test_w46_bounds_are_rejected(a324: Any) -> None:
    with pytest.raises(ValueError, match="outside"):
        a324.filter_complete_prefix(
            host=object(),
            challenge={},
            prefix=4096,
            target=np.asarray([0, 0], dtype=np.uint32),
            control=np.asarray([0, 0], dtype=np.uint32),
        )
    with pytest.raises(ValueError, match="zero through seven"):
        a324.initial_for_slab({}, 8)
    with pytest.raises(ValueError, match="exceeds W46"):
        a324.decode_assignment(1 << 46)
