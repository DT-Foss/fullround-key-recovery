from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_w45_four_slab_grouped_engine_a311.py"


@pytest.fixture(scope="module")
def a311() -> Any:
    spec = importlib.util.spec_from_file_location("test_a311_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_is_target_free_complete_w45_adapter(a311: Any) -> None:
    design = a311.load_design()
    assert design["attempt_id"] == "A311"
    engine = design["engine_contract"]
    assert engine["unknown_key_bits"] == 45
    assert engine["candidate_group_size"] == 1 << 33
    assert engine["slabs"] == [0, 1, 2, 3]
    assert engine["filter_dispatches_per_W45_prefix_group"] == 4
    assert engine["complete_group_before_success_evaluation"] is True
    assert engine["early_stop_inside_group"] is False
    boundary = design["information_boundary"]
    assert boundary["W45_production_challenge_available_at_freeze"] is False
    assert boundary["W45_target_assignment_available_at_freeze"] is False
    assert boundary["A311_qualification_uses_only_synthetic_targets"] is True


def test_source_is_exactly_qualified_and_production_free(a311: Any) -> None:
    protocol, qualification = a311.load_a307_source()
    assert protocol["production_W44_challenge_available"] is False
    assert protocol["production_W44_candidate_available"] is False
    assert qualification["production_W44_challenge_used"] is False
    assert qualification["production_W44_candidate_used"] is False
    assert qualification["complete_group_gate"]["logical_candidates"] == 1 << 32
    assert qualification["complete_group_gate"]["control_candidates"] == []


def test_assignment_codec_is_exact_over_w45(a311: Any) -> None:
    for word0, slab, outer in (
        (0, 0, 0),
        (0xFFFFFFFF, 0, 2047),
        (0x12345678, 1, 0),
        (0xABCDEF01, 2, 2047),
        (0x13579BDF, 3, 0),
        (0x2468ACE0, 3, 2047),
    ):
        assignment = a311.encode_assignment(word0=word0, slab=slab, outer_low11=outer)
        decoded = a311.decode_assignment(assignment)
        assert decoded == {
            "word0": word0,
            "word1_low13": (slab << 11) | outer,
            "slab": slab,
            "outer_low11": outer,
        }


def test_complete_prefix_executes_all_four_slabs_before_readout(a311: Any) -> None:
    challenge = json.loads(a311.A307.A304.A302.PROTOCOL.read_bytes())["public_challenge"]
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
            self.slab = (int(initial[5]) >> 11) & 3
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
                "factual": [[target_word0, 17]] if self.slab == 2 else [],
                "control": [[target_word0 + 1, 19]] if self.slab == 3 else [],
                "gpu_seconds": 0.25,
            }

    host = Host()
    observed = a311.filter_complete_prefix(
        host=host,
        challenge=challenge,
        prefix=3,
        target=np.asarray([1, 2], dtype=np.uint32),
        control=np.asarray([3, 4], dtype=np.uint32),
    )
    assert host.events == [
        ("configure", 0),
        ("filter", 0),
        ("configure", 1),
        ("filter", 1),
        ("configure", 2),
        ("filter", 2),
        ("configure", 3),
        ("filter", 3),
    ]
    assert observed["logical_candidates"] == 1 << 33
    assert observed["filter_dispatches"] == 4
    assert observed["complete_W45_group_before_outcome_evaluation"] is True
    assert observed["factual_candidates"] == [
        target_word0 | (((2 << 11) | 17) << 32)
    ]
    assert observed["control_candidates"] == [
        (target_word0 + 1) | (((3 << 11) | 19) << 32)
    ]


def test_scalar_w45_boundaries_map_two_slab_bits_without_alias(a311: Any) -> None:
    challenge = json.loads(a311.A307.A304.A302.PROTOCOL.read_bytes())["public_challenge"]
    first = 0x34567000
    boundaries = (0, 2047, 2048, 4095, 4096, 6143, 6144, 8191)
    blocks = {
        outer13: a311.scalar_blocks_w45(
            challenge=challenge,
            outer13=outer13,
            first_word0=first,
            count=2,
        )
        for outer13 in boundaries
    }
    assert all(value.shape == (2, 16) for value in blocks.values())
    for outer13 in boundaries:
        assert int(a311.initial_for_outer13(challenge, outer13)[5]) & 0x1FFF == outer13
    assert all(not np.array_equal(blocks[0], blocks[1 << bit]) for bit in (11, 12))


def test_w45_bounds_are_rejected(a311: Any) -> None:
    with pytest.raises(ValueError, match="outside"):
        a311.filter_complete_prefix(
            host=object(),
            challenge={},
            prefix=4096,
            target=np.asarray([0, 0], dtype=np.uint32),
            control=np.asarray([0, 0], dtype=np.uint32),
        )
    with pytest.raises(ValueError, match="zero through three"):
        a311.initial_for_slab({}, 4)
    with pytest.raises(ValueError, match="exceeds W45"):
        a311.decode_assignment(1 << 45)
