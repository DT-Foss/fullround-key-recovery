from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_w44_two_slab_grouped_engine_a307.py"


@pytest.fixture(scope="module")
def a307() -> Any:
    spec = importlib.util.spec_from_file_location("test_a307_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_is_target_free_complete_w44_adapter(a307: Any) -> None:
    design = a307.load_design()
    assert design["attempt_id"] == "A307"
    engine = design["engine_contract"]
    assert engine["unknown_key_bits"] == 44
    assert engine["candidate_group_size"] == 1 << 32
    assert engine["slabs"] == [0, 1]
    assert engine["filter_dispatches_per_W44_prefix_group"] == 2
    assert engine["complete_group_before_success_evaluation"] is True
    assert engine["early_stop_inside_group"] is False
    boundary = design["information_boundary"]
    assert boundary["W44_production_challenge_available_at_freeze"] is False
    assert boundary["W44_target_assignment_available_at_freeze"] is False
    assert boundary["A307_qualification_uses_only_synthetic_targets"] is True


def test_assignment_codec_is_exact_over_w44(a307: Any) -> None:
    for word0, slab, outer in (
        (0, 0, 0),
        (0xFFFFFFFF, 0, 2047),
        (0x12345678, 1, 0),
        (0xABCDEF01, 1, 2047),
    ):
        assignment = a307.encode_assignment(word0=word0, slab=slab, outer_low11=outer)
        decoded = a307.decode_assignment(assignment)
        assert decoded == {
            "word0": word0,
            "word1_low12": (slab << 11) | outer,
            "slab": slab,
            "outer_low11": outer,
        }


def test_complete_prefix_executes_both_slabs_before_readout(a307: Any) -> None:
    challenge = json.loads(a307.A304.A302.PROTOCOL.read_bytes())["public_challenge"]
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
            self.slab = (int(initial[5]) >> 11) & 1
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
                "factual": [[target_word0, 17]] if self.slab == 0 else [],
                "control": [],
                "gpu_seconds": 0.25,
            }

    host = Host()
    observed = a307.filter_complete_prefix(
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
    ]
    assert observed["logical_candidates"] == 1 << 32
    assert observed["filter_dispatches"] == 2
    assert observed["complete_W44_group_before_outcome_evaluation"] is True
    assert observed["factual_candidates"] == [target_word0 | (17 << 32)]


def test_scalar_w44_boundary_maps_slab_bit_without_alias(a307: Any) -> None:
    challenge = json.loads(a307.A304.A302.PROTOCOL.read_bytes())["public_challenge"]
    first = 0x34567000
    blocks = {
        outer12: a307.scalar_blocks_w44(
            challenge=challenge,
            outer12=outer12,
            first_word0=first,
            count=2,
        )
        for outer12 in (0, 2047, 2048, 4095)
    }
    assert all(value.shape == (2, 16) for value in blocks.values())
    assert int(a307.initial_for_outer12(challenge, 2047)[5]) & 0xFFF == 2047
    assert int(a307.initial_for_outer12(challenge, 2048)[5]) & 0xFFF == 2048
    assert not np.array_equal(blocks[0], blocks[2048])


def test_filter_rejects_non_cover_prefix(a307: Any) -> None:
    with pytest.raises(ValueError, match="outside"):
        a307.filter_complete_prefix(
            host=object(),
            challenge={},
            prefix=4096,
            target=np.asarray([0, 0], dtype=np.uint32),
            control=np.asarray([0, 0], dtype=np.uint32),
        )
