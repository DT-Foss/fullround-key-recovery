from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_causal_search_gain_panel_a296.py"
)
ROOT_REFERENCE = (
    ROOT / "research/experiments/chacha20_round20_multitarget_root_confirm.py"
)


def load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def a296() -> Any:
    return load(RUNNER, "test_a296_runner")


def test_frozen_design_and_plan_are_eight_target_zero_refit(a296: Any) -> None:
    design = a296.design()
    plan = a296.execution_plan()
    assert len(design["panel"]) == 8
    assert [row["unknown_key_bits"] for row in design["panel"]] == [
        24,
        24,
        24,
        24,
        28,
        28,
        28,
        28,
    ]
    assert plan["reader_refits"] == 0
    assert plan["target_labels_used"] == 0
    assert plan["rounds"] == 20
    assert plan["feedforward_included"] is True


@pytest.mark.parametrize("width", [24, 28])
def test_synthetic_reader_mapping_selects_low12_and_high8(
    a296: Any, width: int
) -> None:
    mapping = list(range(1, width + 1))
    observed = a296.synthetic_reader_mapping(mapping, width)
    assert observed == [*mapping[:12], *mapping[-8:]]
    assert len(observed) == 20


def test_fine_and_public_hash_orders_are_exact_and_deterministic(a296: Any) -> None:
    coarse = list(range(255, -1, -1))
    fine = a296.fine_order(coarse)
    assert len(fine) == 4096
    assert set(fine) == set(range(4096))
    assert fine[:16] == [
        (255 << 4) | (value ^ (value >> 1)) for value in range(16)
    ]
    digest = "5beabf27dccaa98cfaa97eed7bf7420c6548dcc469b4c924af04f8a872ecc30f"
    first = a296.public_hash_order(digest)
    second = a296.public_hash_order(digest)
    assert first == second
    assert len(first) == 4096
    assert set(first) == set(range(4096))


@pytest.mark.parametrize("width", [24, 28])
def test_ephemeral_challenge_hides_assignment_and_matches_reference(
    a296: Any, monkeypatch: pytest.MonkeyPatch, width: int
) -> None:
    reference = load(ROOT_REFERENCE, f"test_a296_root_{width}")
    values = iter(
        [
            0x9A3ED6F3,
            0x12345678,
            0x89ABCDEF,
            0x0BADF00D,
            0xCAFEBABE,
            0x31415926,
            0x27182818,
            0xDEADBEEF,
            0x10203040,
            0x50607080,
            0x90A0B0C0,
            0x11223344,
        ]
    )
    monkeypatch.setattr(a296.secrets, "randbits", lambda _bits: next(values))
    monkeypatch.setattr(a296.secrets, "token_hex", lambda _size: "ab" * 16)
    challenge = a296.challenge_from_ephemeral_secret(reference, width)
    key = [
        0x9A3ED6F3,
        0x12345678,
        0x89ABCDEF,
        0x0BADF00D,
        0xCAFEBABE,
        0x31415926,
        0x27182818,
        0xDEADBEEF,
    ]
    nonce = [0x10203040, 0x50607080, 0x90A0B0C0]
    expected = [
        reference.chacha20_block(key, (0x11223344 + block) & 0xFFFFFFFF, nonce)
        for block in range(8)
    ]
    assert challenge["target_words"] == expected
    assert challenge["known_key_value_words"][0] == key[0] & ~(
        (1 << width) - 1
    )
    assert challenge["unknown_assignment_included"] is False
    assert challenge["unknown_assignment_value_included"] is False
    assert challenge["full_key_included"] is False
    assert "recovered_unknown_assignment" not in challenge


def test_aggregate_preserves_width_strata_and_paired_counts(a296: Any) -> None:
    rows = []
    for width, causal, numeric, hashed in (
        (24, 10, 20, 30),
        (24, 40, 20, 50),
        (28, 80, 100, 70),
        (28, 160, 200, 300),
    ):
        rows.append(
            {
                "unknown_key_bits": width,
                "discovery": {
                    "search_gain_bits": 12 - a296.math.log2(causal),
                    "matched_control_candidates": 0,
                    "strict_subset_of_complete_domain": True,
                },
                "rank_analysis": {
                    "prefix_ranks_one_based": {
                        "Causal": causal,
                        "numeric": numeric,
                        "public_hash_control": hashed,
                    }
                },
                "confirmation": {
                    "cross_implementation_blocks_match": True,
                    "cross_implementation_output_bits_checked": 8192,
                },
            }
        )
    result = a296.aggregate(rows)
    assert result["targets"] == 4
    assert result["confirmed_recoveries"] == 4
    assert result["matched_control_candidates"] == 0
    assert result["strict_subset_recoveries"] == 4
    assert result["Causal_earlier_than_numeric"] == 3
    assert result["Causal_earlier_than_public_hash"] == 3
    assert result["by_width"]["24"]["targets"] == 2
    assert result["by_width"]["28"]["targets"] == 2
