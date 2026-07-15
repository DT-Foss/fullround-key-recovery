from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).parents[1]
SOURCE = (
    ROOT
    / "research/experiments/chacha20_round20_w24_causal_ordered_metal_a294.py"
)


def load_runner():
    spec = importlib.util.spec_from_file_location("a294_test_runner", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_frozen_causal_and_hash_orders_are_exact_covers() -> None:
    module = load_runner()
    a291 = json.loads(module.A291_RESULT.read_bytes())
    causal = module.fine_order(a291)
    hashed = module.public_hash_order(
        "5beabf27dccaa98cfaa97eed7bf7420c6548dcc469b4c924af04f8a872ecc30f"
    )
    assert len(causal) == len(hashed) == 4096
    assert set(causal) == set(hashed) == set(range(4096))
    assert causal[:16] == [1984, 1985, 1987, 1986, 1990, 1991, 1989, 1988, 1996, 1997, 1999, 1998, 1994, 1995, 1993, 1992]


def test_initial_state_preserves_only_public_known_material() -> None:
    module = load_runner()
    protocol = json.loads(module.A287_PROTOCOL.read_bytes())
    challenge = protocol["public_challenge"]
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state = module.initial_state(challenge, constants)
    assert state.dtype == np.uint32
    assert state.shape == (16,)
    assert state[:4].tolist() == constants
    assert state[4:12].tolist() == challenge["known_key_value_words"]
    assert int(state[4]) & ((1 << 24) - 1) == 0
    assert int(state[12]) == challenge["counter_start"]
    assert state[13:16].tolist() == challenge["nonce_words"]


def test_ordered_discovery_stops_at_first_matching_group() -> None:
    module = load_runner()
    protocol = json.loads(module.A287_PROTOCOL.read_bytes())
    challenge = protocol["public_challenge"]
    order = [7, 11, 3, *[value for value in range(4096) if value not in {7, 11, 3}]]
    candidate = (3 << 12) | 0x5A5
    full_word0 = challenge["known_key_value_words"][0] | candidate

    class FakeHost:
        def configure(self, initial, target, control):
            assert initial.shape == (16,)
            assert target.shape == control.shape == (16,)

        def filter(self, first, count):
            factual = [full_word0] if first <= full_word0 < first + count else []
            return {"factual": factual, "control": [], "gpu_seconds": 0.25}

    result = module.ordered_discovery(
        host=FakeHost(), challenge=challenge, order=order
    )
    assert result["candidate_low24"] == candidate
    assert result["Causal_prefix_rank_one_based"] == 3
    assert result["executed_prefix_groups"] == 3
    assert result["executed_assignments_upper_bound"] == 3 * 4096
    assert result["strict_subset_of_complete_domain"] is True
    assert result["matched_control_candidates"] == 0


def test_frozen_protocol_reloads_without_secret_or_target_prefix() -> None:
    module = load_runner()
    protocol_sha256 = module.file_sha256(module.PROTOCOL)
    protocol = module.load_protocol(protocol_sha256)
    boundary = protocol["information_boundary"]
    assert boundary["secret_assignment_available_to_protocol_or_runner"] is False
    assert boundary["target_prefix_or_model_available_before_order_freeze"] is False
    assert protocol["execution_plan"]["complete_residual_domain"] == 1 << 24
    raw = module.PROTOCOL.read_text(encoding="ascii").lower()
    assert '"secret_assignment"' not in raw
    assert '"target_prefix12"' not in raw


def test_dual_reference_confirmation_reconstructs_all_eight_blocks() -> None:
    module = load_runner()
    root_reference = module.load_module(
        module.ROOT_REFERENCE, "a294_test_root_reference"
    )
    candidate = 0x123456
    known = [
        0xAB000000,
        0x10203040,
        0x50607080,
        0x90A0B0C0,
        0xD0E0F000,
        0x11223344,
        0x55667788,
        0x99AABBCC,
    ]
    key = [known[0] | candidate, *known[1:]]
    counter = 0x31415926
    nonce = [0x01234567, 0x89ABCDEF, 0x0F1E2D3C]
    targets = [
        root_reference.chacha20_block(
            key, (counter + block) & module.MASK32, nonce
        )
        for block in range(module.BLOCKS)
    ]
    control = list(targets[0])
    control[0] ^= 1
    challenge = {
        "known_key_value_words": known,
        "counter_start": counter,
        "nonce_words": nonce,
        "target_words": targets,
        "target_block_sha256": [
            module.sha256(module.word_bytes(row)) for row in targets
        ],
        "control_target_words": control,
    }
    confirmation = module.confirm(
        {"candidate_low24": candidate}, challenge, root_reference
    )
    assert confirmation["recovered_unknown_low24"] == candidate
    assert confirmation["root_operation_reference_all_eight_blocks_match"] is True
    assert confirmation["independent_byte_reference_all_eight_blocks_match"] is True
    assert confirmation["cross_implementation_output_bits_checked"] == 8192
