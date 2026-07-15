from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w32_causal_search_gain_panel_a297.py"
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
def a297() -> Any:
    return load(RUNNER, "test_a297_runner")


def test_frozen_design_and_plan_are_four_target_w32_zero_refit(a297: Any) -> None:
    design = a297.load_design()
    plan = a297.execution_plan()
    assert design["panel"] == [
        {"target_id": f"w32_t{index:02d}", "unknown_key_bits": 32}
        for index in range(4)
    ]
    assert plan["target_count"] == 4
    assert plan["unknown_key_bits"] == 32
    assert plan["reader_refits"] == 0
    assert plan["target_labels_used"] == 0
    assert plan["rounds"] == 20
    assert plan["feedforward_included"] is True
    assert plan["candidate_group_size"] == 1 << 20
    assert plan["complete_residual_domain"] == 1 << 32


def test_a296_mapping_view_selects_low12_and_high8(a297: Any) -> None:
    mapping = list(range(1, 33))
    observed = a297.A296.synthetic_reader_mapping(mapping, 32)
    assert observed == [*mapping[:12], *mapping[24:32]]
    assert len(observed) == len(set(observed)) == 20


def test_fine_and_public_hash_orders_are_exact_and_deterministic(a297: Any) -> None:
    coarse = list(range(255, -1, -1))
    fine = a297.A296.fine_order(coarse)
    assert len(fine) == len(set(fine)) == 4096
    assert set(fine) == set(range(4096))
    assert fine[:16] == [
        (255 << 4) | (value ^ (value >> 1)) for value in range(16)
    ]
    digest = "5beabf27dccaa98cfaa97eed7bf7420c6548dcc469b4c924af04f8a872ecc30f"
    first = a297.public_hash_order(digest)
    second = a297.public_hash_order(digest)
    assert first == second
    assert len(first) == len(set(first)) == 4096
    assert set(first) == set(range(4096))


def test_ephemeral_w32_challenge_hides_assignment_and_matches_reference(
    a297: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference = load(ROOT_REFERENCE, "test_a297_root")
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
    monkeypatch.setattr(a297.secrets, "randbits", lambda _bits: next(values))
    monkeypatch.setattr(a297.secrets, "token_hex", lambda _size: "ab" * 16)
    challenge = a297.challenge_from_ephemeral_secret(reference)
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
    assert challenge["known_key_value_words"][0] == 0
    assert challenge["known_key_mask_words"] == [0, *([0xFFFFFFFF] * 7)]
    assert challenge["unknown_assignment_included"] is False
    assert challenge["unknown_assignment_value_included"] is False
    assert challenge["full_key_included"] is False
    assert "recovered_unknown_assignment" not in challenge


def test_rank_analysis_uses_exact_prefix_positions(a297: Any) -> None:
    order = list(range(4095, -1, -1))
    digest = "5beabf27dccaa98cfaa97eed7bf7420c6548dcc469b4c924af04f8a872ecc30f"
    observed = a297.rank_analysis(
        {"fine_prefix12": 17}, order, digest
    )
    ranks = observed["prefix_ranks_one_based"]
    assert ranks["Causal"] == 4096 - 17
    assert ranks["numeric"] == 18
    assert ranks["public_hash_control"] == a297.public_hash_order(digest).index(17) + 1


def test_aggregate_preserves_panel_counts_and_geometric_means(a297: Any) -> None:
    rows = []
    for causal, numeric, hashed in (
        (10, 20, 30),
        (40, 20, 50),
        (80, 100, 70),
        (160, 200, 300),
    ):
        rows.append(
            {
                "discovery": {
                    "matched_control_candidates": 0,
                    "strict_subset_of_complete_domain": True,
                },
                "rank_analysis": {
                    "prefix_ranks_one_based": {
                        "Causal": causal,
                        "numeric": numeric,
                        "public_hash_control": hashed,
                    },
                    "Causal_speedup_vs_numeric_rank": numeric / causal,
                    "Causal_speedup_vs_public_hash_rank": hashed / causal,
                },
                "confirmation": {
                    "cross_implementation_blocks_match": True,
                    "cross_implementation_output_bits_checked": 8192,
                },
            }
        )
    result = a297.aggregate(rows)
    assert result["targets"] == 4
    assert result["confirmed_recoveries"] == 4
    assert result["matched_control_candidates"] == 0
    assert result["strict_subset_recoveries"] == 4
    assert result["cross_implementation_output_bits_checked"] == 32768
    assert result["Causal_earlier_than_numeric"] == 3
    assert result["Causal_earlier_than_public_hash"] == 3
    assert result["geometric_mean_domain_reduction"] == pytest.approx(
        (4096 / 10 * 4096 / 40 * 4096 / 80 * 4096 / 160) ** 0.25
    )
