from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from arx_carry_leak.chacha20_rfc8439_reference import chacha20_block

ROOT = Path(__file__).parents[1]
RESULTS = ROOT / "research/results/v1"
CONFIGS = ROOT / "research/configs"


def _load(relative: str) -> dict[str, Any]:
    return json.loads((ROOT / relative).read_bytes())


def _words_bytes(words: list[int]) -> bytes:
    return b"".join(int(word).to_bytes(4, "little") for word in words)


def _confirm_challenge(challenge: dict[str, Any], key_words: list[int]) -> list[str]:
    key = _words_bytes(key_words)
    nonce = _words_bytes(challenge["nonce_words"])
    block_count = int(challenge.get("block_count", challenge.get("public_output_blocks", 8)))
    outputs = [
        chacha20_block(
            key=key,
            counter=(int(challenge["counter_start"]) + index) & 0xFFFFFFFF,
            nonce=nonce,
        )
        for index in range(block_count)
    ]
    expected = [_words_bytes(row) for row in challenge["target_words"]]
    assert outputs == expected
    hashes = [hashlib.sha256(block).hexdigest() for block in outputs]
    assert hashes == challenge["target_block_sha256"]
    return hashes


def _key_from_word0(challenge: dict[str, Any], word0: int) -> list[int]:
    words = [int(value) for value in challenge["known_key_value_words"]]
    words[0] = int(word0)
    return words


def _assert_single_word0_record(
    *, result_name: str, challenge: dict[str, Any], attempt_id: str
) -> None:
    result = _load(f"research/results/v1/{result_name}")
    assert result["attempt_id"] == attempt_id
    assert result["discovery"]["strict_subset_of_complete_domain"] is True
    assert result["discovery"]["matched_control_candidates"] == 0
    confirmation = result["confirmation"]
    hashes = _confirm_challenge(
        challenge, _key_from_word0(challenge, int(confirmation["recovered_full_key_word0"]))
    )
    assert hashes == confirmation["block_sha256"]
    assert confirmation["cross_implementation_output_bits_checked"] == 8192


def _assert_w43_record(
    *, result_name: str, challenge: dict[str, Any], attempt_id: str
) -> None:
    result = _load(f"research/results/v1/{result_name}")
    assert result["attempt_id"] == attempt_id
    discovery = result["discovery"]
    assert discovery["strict_subset_of_complete_domain"] is True
    assert discovery["matched_control_candidates"] == 0
    confirmation = result["confirmation"]
    hashes = _confirm_challenge(
        challenge, [int(value) for value in confirmation["recovered_key_words"]]
    )
    assert hashes == confirmation["byte_reference_sha256"]
    assert hashes == confirmation["word_reference_sha256"]
    assert confirmation["total_cross_implementation_output_bits_checked"] == 8192


def _key_from_w44_confirmation(confirmation: dict[str, Any]) -> list[int]:
    words = [int(value) for value in confirmation["recovered_key_words"]]
    assert (words[0] | ((words[1] & 0xFFF) << 32)) == int(confirmation["assignment"])
    return words


def test_chacha20kr43_complete_domain_record() -> None:
    config = _load("research/configs/chacha20_round20_w43_metal_record_v1.json")
    result = _load("research/results/v1/chacha20_round20_w43_metal_record_v1.json")
    assert result["attempt_id"] == "CHACHA20KR43"
    assert result["evidence_stage"] == "FULLROUND_CHACHA20_W43_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    execution = result["execution"]
    assert execution["complete_domain_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["executed_assignment_count"] == 2**43
    assert execution["factual_full_matches"] == [2_800_167_095_032]
    assert execution["control_full_matches"] == []
    confirmation = result["confirmation"]
    hashes = _confirm_challenge(
        config["challenge"], [int(value) for value in confirmation["recovered_key_words"]]
    )
    assert hashes == confirmation["byte_reference_sha256"]
    assert hashes == confirmation["word_reference_sha256"]


def test_a294_a295_same_target_independent_orders() -> None:
    challenge = _load(
        "research/configs/chacha20_round20_w24_causal_ordered_metal_a294_v1.json"
    )["public_challenge"]
    _assert_single_word0_record(
        result_name="chacha20_round20_w24_causal_ordered_metal_a294_v1.json",
        challenge=challenge,
        attempt_id="A294",
    )
    _assert_single_word0_record(
        result_name="chacha20_round20_w24_fine_selected_channel_a295_v1.json",
        challenge=challenge,
        attempt_id="A295",
    )
    a294 = _load("research/results/v1/chacha20_round20_w24_causal_ordered_metal_a294_v1.json")
    a295 = _load("research/results/v1/chacha20_round20_w24_fine_selected_channel_a295_v1.json")
    assert a294["discovery"]["Causal_prefix_rank_one_based"] == 202
    assert a295["discovery"]["Causal_prefix_rank_one_based"] == 2605


def test_a296_eight_target_panel_recomputed() -> None:
    config = _load("research/configs/chacha20_round20_causal_search_gain_panel_a296_v1.json")
    result = _load("research/results/v1/chacha20_round20_causal_search_gain_panel_a296_v1.json")
    assert result["attempt_id"] == "A296"
    assert result["aggregate"]["confirmed_recoveries"] == 8
    assert result["aggregate"]["strict_subset_recoveries"] == 8
    assert result["aggregate"]["matched_control_candidates"] == 0
    by_id = {row["target_id"]: row["public_challenge"] for row in config["targets"]}
    for row in result["targets"]:
        challenge = by_id[row["target_id"]]
        confirmation = row["confirmation"]
        hashes = _confirm_challenge(
            challenge,
            _key_from_word0(challenge, int(confirmation["recovered_full_key_word0"])),
        )
        assert hashes == confirmation["block_sha256"]
        assert row["discovery"]["matched_control_candidates"] == 0
        assert row["discovery"]["strict_subset_of_complete_domain"] is True


def test_a297_four_target_w32_panel_recomputed() -> None:
    config = _load("research/configs/chacha20_round20_w32_causal_search_gain_panel_a297_v1.json")
    result = _load("research/results/v1/chacha20_round20_w32_causal_search_gain_panel_a297_v1.json")
    assert result["attempt_id"] == "A297"
    assert result["aggregate"]["confirmed_recoveries"] == 4
    assert result["aggregate"]["strict_subset_recoveries"] == 4
    assert result["aggregate"]["matched_control_candidates"] == 0
    by_id = {row["target_id"]: row["public_challenge"] for row in config["targets"]}
    for row in result["targets"]:
        challenge = by_id[row["target_id"]]
        confirmation = row["confirmation"]
        hashes = _confirm_challenge(
            challenge,
            _key_from_word0(challenge, int(confirmation["recovered_full_key_word0"])),
        )
        assert hashes == confirmation["block_sha256"]
        assert row["discovery"]["matched_control_candidates"] == 0
        assert row["discovery"]["strict_subset_of_complete_domain"] is True


def test_a303_w32_recomputed() -> None:
    challenge = _load(
        "research/configs/chacha20_round20_w32_fine_selected_channel_transfer_a298_v1.json"
    )["public_challenge"]
    _assert_single_word0_record(
        result_name="chacha20_round20_w32_dominance_pruned_companion_a303_v1.json",
        challenge=challenge,
        attempt_id="A303",
    )


def test_a304_a305_a309_w43_recomputed() -> None:
    rows = (
        (
            "chacha20_round20_w43_grouped_engine_a304_v1.json",
            "research/configs/chacha20_round20_w43_calibrated_coarse_numeric_replication_a302_v1.json",
            "A304",
        ),
        (
            "chacha20_round20_w43_a299_grouped_replay_a305_v1.json",
            "research/configs/chacha20_round20_w43_fine_selected_channel_transfer_a299_v1.json",
            "A305",
        ),
        (
            "chacha20_round20_w43_width_conditioned_band_portfolio_a309_v1.json",
            "research/configs/chacha20_round20_w43_three_operator_portfolio_a300_v1.json",
            "A309",
        ),
    )
    for result_name, config_name, attempt_id in rows:
        challenge = _load(config_name)["public_challenge"]
        _assert_w43_record(
            result_name=result_name, challenge=challenge, attempt_id=attempt_id
        )


def test_a313_w44_strict_subset_recomputed() -> None:
    challenge = _load(
        "research/configs/chacha20_round20_w44_calibrated_coarse_numeric_a308_v1.json"
    )["public_challenge"]
    result = _load(
        "research/results/v1/chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.json"
    )
    assert result["attempt_id"] == "A313"
    discovery = result["discovery"]
    assert discovery["executed_prefix_groups"] == 2753
    assert discovery["executed_assignments"] == 11_824_044_965_888
    assert discovery["complete_domain_assignments"] == 2**44
    assert discovery["strict_subset_of_complete_domain"] is True
    assert discovery["complete_W44_group_execution_before_stop"] is True
    assert discovery["early_stop_inside_group"] is False
    assert discovery["factual_filter_candidates"] == [662_233_243_956]
    assert discovery["control_filter_candidates"] == []
    confirmation = result["confirmation"]
    hashes = _confirm_challenge(challenge, _key_from_w44_confirmation(confirmation))
    assert hashes == confirmation["byte_reference_sha256"]
    assert hashes == confirmation["word_reference_sha256"]
    assert confirmation["total_cross_implementation_output_bits_checked"] == 8192


def test_a315_a317_a319_a321_rank_only_records() -> None:
    a315 = _load(
        "research/results/v1/chacha20_round20_w44_online_multicenter_counterfactual_a315_v1.json"
    )
    assert a315["rank_analysis"]["prefix_ranks_one_based"] == {
        "A308_two_operator_baseline": 1427,
        "A313_three_arm_portfolio": 2753,
        "A315_four_center_nearest_rank_band": 2949,
        "A315_weighted_dovetail_2_to_1": 3342,
    }
    a317 = _load(
        "research/results/v1/chacha20_round20_w44_multiview_operator_atlas_a317_v1.json"
    )
    assert a317["rank_analysis"]["best_atlas_view"] == "nearest_prototype_Linf"
    assert a317["rank_analysis"]["best_atlas_rank_one_based"] == 2159
    a319 = _load(
        "research/results/v1/chacha20_round20_w44_covariance_whitened_atlas_a319_v1.json"
    )
    assert a319["rank_analysis"]["best_whitened_rank_one_based"] == 2955
    for payload in (a315, a317, a319):
        assert payload["candidate_execution"]["duplicate_candidate_execution"] is False
        assert payload["information_boundary"]["reader_refits_after_A313_reveal"] == 0
        assert payload["information_boundary"]["target_labels_used_from_A313"] == 0
    a321 = _load(
        "research/results/v1/chacha20_round20_holdout_selected_w45_operator_a321_order_v1.json"
    )
    assert a321["selection"]["selected_operator"] == "raw_nearest_prototype_Linf"
    assert a321["selection"]["selected_calibration_rank_one_based"] == 2159
    assert a321["information_boundary"]["target_labels_used_from_A314"] == 0


def test_a324_target_free_w46_engine_qualification() -> None:
    result = _load(
        "research/results/v1/chacha20_round20_w46_eight_slab_grouped_engine_a324_qualification_v1.json"
    )
    gate = result["complete_group_gate"]
    assert result["attempt_id"] == "A324"
    assert gate["logical_candidates"] == 2**34
    assert gate["slabs_executed"] == list(range(8))
    assert gate["factual_candidates"] == [57_412_341_020_025]
    assert gate["control_candidates"] == []
    assert result["total_boundary_output_bits_checked"] == 147_968
    assert result["production_W46_challenge_used"] is False
    assert result["production_W46_candidate_used"] is False


def test_open_execution_results_are_absent() -> None:
    forbidden = (
        RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json",
        RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.causal",
        RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json",
        RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.causal",
    )
    assert not any(path.exists() for path in forbidden)
    assert (RESULTS / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_order_v1.json").is_file()
    assert (
        CONFIGS / "chacha20_round20_holdout_selected_w45_recovery_a322_design_v1.json"
    ).is_file()


def test_headline_causal_artifacts_present() -> None:
    stems = (
        "chacha20_round20_w24_causal_ordered_metal_a294_v1",
        "chacha20_round20_w24_fine_selected_channel_a295_v1",
        "chacha20_round20_causal_search_gain_panel_a296_v1",
        "chacha20_round20_w32_causal_search_gain_panel_a297_v1",
        "chacha20_round20_w32_dominance_pruned_companion_a303_v1",
        "chacha20_round20_w43_grouped_engine_a304_v1",
        "chacha20_round20_w43_a299_grouped_replay_a305_v1",
        "chacha20_round20_w43_width_conditioned_band_portfolio_a309_v1",
        "chacha20_round20_w43_metal_record_v1",
        "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1",
        "chacha20_round20_w44_online_multicenter_counterfactual_a315_v1",
        "chacha20_round20_w44_multiview_operator_atlas_a317_v1",
        "chacha20_round20_w44_covariance_whitened_atlas_a319_v1",
        "chacha20_round20_holdout_selected_w45_operator_a321_order_v1",
    )
    assert all((RESULTS / f"{stem}.causal").is_file() for stem in stems)
