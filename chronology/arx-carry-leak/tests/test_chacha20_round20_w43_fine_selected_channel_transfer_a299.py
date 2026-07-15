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
    / "research/experiments/chacha20_round20_w43_fine_selected_channel_transfer_a299.py"
)


@pytest.fixture(scope="module")
def a299() -> Any:
    spec = importlib.util.spec_from_file_location("test_a299_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_is_frozen_before_w43_reveal(a299: Any) -> None:
    design = a299.load_design()
    assert design["attempt_id"] == "A299"
    boundary = design["information_boundary"]
    assert boundary["CHACHA20KR43_result_available_at_design_freeze"] is False
    assert boundary["CHACHA20KR43_assignment_available_at_design_freeze"] is False
    assert (
        boundary["CHACHA20KR43_checkpoint_candidate_values_read_at_design_freeze"]
        is False
    )
    assert design["fine_measurement_contract"]["prefix_cells"] == 4096
    assert design["recovery_contract"]["candidate_group_size"] == 1 << 31


def test_implementation_is_byte_frozen_before_w43_reveal(a299: Any) -> None:
    frozen = a299.load_implementation_freeze()
    assert frozen["runner_sha256"] == a299.PRE_REVEAL_RUNNER_SHA256
    assert frozen["test_sha256"] == a299.PRE_REVEAL_TEST_SHA256
    assert (
        frozen["information_boundary"][
            "W43_complete_domain_result_available_at_freeze"
        ]
        is False
    )
    correction = a299.load_implementation_correction()
    assert correction["scientific_contract_changed"] is False
    assert correction["runner_sha256"] == a299.CORRECTION_V2_RUNNER_SHA256
    assert correction["test_sha256"] == a299.CORRECTION_V2_TEST_SHA256
    assert (
        correction["information_boundary"][
            "reader_operator_order_partition_or_recovery_changed"
        ]
        is False
    )
    correction_v3 = a299.load_implementation_correction_v3()
    assert correction_v3["scientific_contract_changed"] is False
    assert correction_v3["runner_sha256"] == a299.file_sha256(
        a299.Path(a299.__file__)
    )
    assert correction_v3["test_sha256"] == a299.file_sha256(a299.A299_TEST)


def test_non_nibble_partial_word_literal_is_width_corrected(a299: Any) -> None:
    source = a299._load_public_w43_protocol()
    adapted = a299.reader_challenge(source["challenge"])
    a223 = a299.load_module(a299.A297.A223_SOURCE, "test_a299_a223_literal")
    original = a299.A297.A296.b1_formula(a223, adapted, a299.WIDTH)
    corrected = a299.correct_non_nibble_known_word_literal(
        original, adapted, a299.WIDTH
    )
    known = int(adapted["known_key_value_words"][1]) >> 11
    invalid = f"#x{known:05x}"
    expected = f"#b{known:021b}"
    assert invalid in original
    assert invalid not in corrected
    assert corrected.count(expected) == 1
    assert "((_ extract 31 11) k1)" in corrected


def test_w43_helper_capacity_derivation_preserves_solver_semantics(
    a299: Any, tmp_path: Path
) -> None:
    source = tmp_path / "w43-helper.cpp"
    binary = tmp_path / "w43-helper"
    build = a299.compile_w43_helper(output=binary, derived_source=source)
    raw = source.read_bytes()
    assert build["model_width_max"] == 64
    assert build["scientific_solver_semantics_changed"] is False
    assert b"model_one_literals.size() > 64" in raw
    assert b"model_one_literals.size() > 32" not in raw
    assert b"model-one-literals must contain 9 through 64 literals" in raw
    assert build["binary_sha256"] == a299.file_sha256(binary)


def test_public_w43_reader_adapter_preserves_exact_target(a299: Any) -> None:
    source = a299._load_public_w43_protocol()
    adapted = a299.reader_challenge(source["challenge"])
    assert adapted["known_key_value_words"] == source["challenge"][
        "known_zeroed_key_words"
    ]
    assert adapted["known_key_mask_words"] == [0, 0xFFFFF800, *([0xFFFFFFFF] * 6)]
    assert adapted["target_words"] == source["challenge"]["target_words"]
    assert adapted["unknown_global_bit_interval"] == [0, 42]
    assert adapted["source_public_challenge_sha256"] == a299.W43_PUBLIC_CHALLENGE_SHA256


def test_model_permutation_places_word0_prefix_in_helper_high12(a299: Any) -> None:
    permutation = a299.solver_model_permutation()
    assert permutation[31:43] == list(range(20, 32))
    assert [permutation[index] for index in range(42, 30, -1)] == list(
        range(31, 19, -1)
    )
    samples = [0, 1, (1 << 43) - 1, 0x3456789ABCD & ((1 << 43) - 1)]
    for candidate in samples:
        permuted = sum(
            ((candidate >> original) & 1) << model_index
            for model_index, original in enumerate(permutation)
        )
        assert a299.decode_permuted_candidate(permuted) == candidate


def test_fine_lane_plan_is_exact_word0_prefix_cover(a299: Any) -> None:
    preflight = {
        "target": {
            "CNF": {"path": "unused.cnf", "sha256": "00" * 32},
            "source_one_literals_bit0_upward": list(range(1, 44)),
        }
    }
    plan = a299.fine_lane_plan(list(reversed(range(256))), preflight)
    active = [
        int(prefix, 2)
        for arm in plan["arms"]
        for prefix in arm["active_prefixes"]
    ]
    assert len(plan["arms"]) == 8
    assert all(len(arm["active_prefixes"]) == 512 for arm in plan["arms"])
    assert len(active) == len(set(active)) == 4096
    assert set(active) == set(range(4096))
    for arm in plan["arms"]:
        mapping = arm["model_one_literals_bit0_upward"]
        assert [mapping[index] for index in range(42, 30, -1)] == list(
            range(32, 20, -1)
        )


def test_ordered_discovery_executes_complete_outer11_group(a299: Any) -> None:
    prefix = 0xA5B
    target_outer = 7
    target_word0 = (prefix << 20) | 0x12345

    class Host:
        def __init__(self) -> None:
            self.outer = -1
            self.calls = 0

        def configure(self, initial: np.ndarray, _target: np.ndarray, _control: np.ndarray) -> None:
            self.outer = int(initial[5]) & 0x7FF

        def filter(self, first: int, count: int) -> dict[str, Any]:
            self.calls += 1
            assert first == prefix << 20
            assert count == 1 << 20
            factual = [target_word0] if self.outer == target_outer else []
            return {"factual": factual, "control": [], "gpu_seconds": 0.25}

    challenge = a299._load_public_w43_protocol()["challenge"]
    host = Host()
    discovery = a299.ordered_discovery(host=host, challenge=challenge, order=[prefix])
    expected = (target_outer << 32) | target_word0
    assert discovery["candidate"] == expected
    assert discovery["executed_prefix_groups"] == 1
    assert discovery["executed_outer_slices"] == 2048
    assert discovery["executed_assignments"] == 1 << 31
    assert discovery["strict_subset_of_complete_domain"] is True
    assert host.calls == 2048


def test_rank_analysis_counts_full_w43_groups(a299: Any) -> None:
    prefix = 0x123
    primary = [prefix, *[value for value in range(4096) if value != prefix]]
    value = {
        "direct_symbolic_winner": None,
        "fine_readout": {"complete_order": primary},
        "coarse_readout": {"complete_coarse_order": list(range(256))},
    }
    ranks = a299.rank_analysis(
        discovery={"fine_prefix12": prefix},
        order_value=value,
        challenge_sha=a299.W43_PUBLIC_CHALLENGE_SHA256,
    )
    assert ranks["prefix_ranks_one_based"]["A299_fine_selected_channel"] == 1
    assert ranks["assignment_upper_bounds"]["A299_fine_selected_channel"] == 1 << 31
    assert ranks["A299_gain_bits_vs_complete_domain"] == 12.0


def test_runner_has_no_w43_checkpoint_or_result_input_path() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    assert "chacha20_round20_w43_metal_record_v1.checkpoint.json" not in source
    assert 'W43_RESULT =' not in source


def test_authentic_causal_roundtrip(
    a299: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a299.causal"
    monkeypatch.setattr(a299, "CAUSAL", path)
    payload = {
        "order_sha256": "11" * 32,
        "measurement_sha256": "22" * 32,
        "rank_analysis": {
            "prefix_ranks_one_based": {"A299_fine_selected_channel": 1}
        },
        "discovery": {"candidate": 0x123456789AB, "fine_prefix12": 0x345},
        "confirmation": {"total_cross_implementation_output_bits_checked": 8192},
        "evidence_stage": "TEST_CONFIRMED",
    }
    graph = a299.build_causal(payload)
    assert graph["api_id"] == "a299w43"
    assert graph["explicit_triplets"] == 2
    assert graph["materialized_inferred_triplets"] == 1
    assert graph["embedded_rules"] == 2
    assert graph["clusters"] == 1
    assert graph["gaps"] == 1
    assert graph["sha256"] == a299.file_sha256(path)
