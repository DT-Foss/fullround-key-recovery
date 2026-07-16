from __future__ import annotations

from pathlib import Path

from fullround_key_recovery.verify import verify_all, verify_result

ROOT = Path(__file__).parents[1]


def test_a184_independent_full_block_confirmation() -> None:
    result = verify_result("chacha20", ROOT)
    assert result["attempt_id"] == "A184"
    assert result["logical_candidates"] == 2**40
    assert result["recovered_assignment"] == 173_754_364_436
    assert result["independent_confirmation_bits"] == 512


def test_a237_independent_three_block_confirmation_and_full_key() -> None:
    result = verify_result("speck32_64", ROOT)
    assert result["attempt_id"] == "A237"
    assert result["logical_candidates"] == 2**42
    assert result["recovered_assignment"] == 3_099_631_123_999
    assert result["reconstructed_master_key_words"] == [32287, 45161, 6865, 10980]


def test_a240_independent_full_block_confirmation_and_full_key() -> None:
    result = verify_result("threefish256", ROOT)
    assert result["attempt_id"] == "A240"
    assert result["logical_candidates"] == 2**38
    assert result["recovered_assignment"] == 68_427_043_728
    assert result["reconstructed_master_key_words"] == [
        0x791DFA4FEE91D390,
        0xA916D6F73BB320B4,
        0x9BCC3C33817FD61E,
        0x2977E6C10A496AB8,
    ]


def test_new_cross_family_recovery_anchors() -> None:
    expected = {
        "speck64_128": ("A244", 2**44, 17_005_369_072_308, 128),
        "simon64_128": ("A246", 2**43, 4_109_884_320_956, 128),
        "rc5_32_12_16": ("A248", 2**40, 964_575_894_496, 128),
        "present80": ("A253", 2**38, 250_884_064_964, 128),
        "ascon_aead128": ("A256", 2**40, 56_559_342_585, 384),
        "aes128": ("AES-W41", 2**41, 1_914_598_048_454, 256),
        "salsa20_20": ("A264", 2**42, 1_767_048_180_590, 512),
    }
    for name, values in expected.items():
        attempt, candidates, assignment, confirmation_bits = values
        result = verify_result(name, ROOT)
        assert result["attempt_id"] == attempt
        assert result["logical_candidates"] == candidates
        assert result["recovered_assignment"] == assignment
        assert result["independent_confirmation_bits"] == confirmation_bits
        assert result["factual_models"] == 1
        assert result["control_models"] == 0


def test_new_complete_domain_present128_and_aes256_records() -> None:
    expected = {
        "present128": ("P128R1", 2**38, 198_790_436_326, 128),
        "aes256": ("AES256R1", 2**41, 534_703_724_815, 256),
    }
    for name, (attempt, candidates, assignment, confirmation_bits) in expected.items():
        result = verify_result(name, ROOT)
        assert result["attempt_id"] == attempt
        assert result["logical_candidates"] == candidates
        assert result["recovered_assignment"] == assignment
        assert result["independent_confirmation_bits"] == confirmation_bits
        assert result["factual_models"] == 1
        assert result["control_models"] == 0


def test_extended_complete_domain_records() -> None:
    expected = {
        "blake3_keyed": ("B3KR1", 2**43, 6_241_046_275_180, 256),
        "siphash24": ("SIPKR1", 2**43, 31_398_082_423, 128),
        "tea": ("TEAKR1", 2**43, 3_588_575_041_194, 128),
        "xtea": ("XTEAKR1", 2**43, 5_121_519_399_188, 128),
        "threefish1024": ("TF1024KR1", 2**39, 167_907_888_337, 2048),
    }
    for name, (attempt, candidates, assignment, confirmation_bits) in expected.items():
        result = verify_result(name, ROOT)
        assert result["attempt_id"] == attempt
        assert result["logical_candidates"] == candidates
        assert result["recovered_assignment"] == assignment
        assert result["independent_confirmation_bits"] == confirmation_bits
        assert result["factual_models"] == 1
        assert result["control_models"] == 0


def test_a322_a325_a350_a374_strict_subset_records() -> None:
    expected = {
        "chacha20_a322": ("A322", 45, 1459, 12_532_714_569_728, 9_971_050_529_000),
        "chacha20_a325": ("A325", 46, 77, 1_322_849_927_168, 32_932_650_148_774),
        "chacha20_a350": ("A350", 46, 445, 7_645_041_786_880, 67_179_618_068_862),
        "chacha20_a374": ("A374", 48, 102, 7_009_386_627_072, 255_004_576_462_523),
    }
    for name, (attempt, width, rank, executed, assignment) in expected.items():
        result = verify_result(name, ROOT)
        assert result["attempt_id"] == attempt
        assert result["unknown_key_bits"] == width
        assert result["frozen_order_rank"] == rank
        assert result["executed_assignments"] == executed
        assert result["recovered_assignment"] == assignment
        assert result["strict_subset_recovery"] is True
        assert result["control_models"] == 0


def test_target_blind_strict_subset_chacha20_recoveries() -> None:
    a281 = verify_result("chacha20_cross_material", ROOT)
    assert a281["attempt_id"] == "A281"
    assert a281["strict_subset_recovery"] is True
    assert a281["complete_domain_executed"] is False
    assert a281["frozen_order_rank"] == 37
    assert a281["logical_assignments"] == 151_552
    assert a281["recovered_assignment"] == 0xBF9F3

    a286 = verify_result("chacha20_multitarget_panel", ROOT)
    assert a286["attempt_id"] == "A286"
    assert a286["strict_subset_recoveries"] == 4
    assert a286["complete_domain_executed"] is False
    assert a286["independent_confirmation_bits"] == 16_384
    assert [row["recovered_assignment"] for row in a286["target_results"]] == [
        0x18E26,
        0xE28A0,
        0x57A0F,
        0x2527D,
    ]


def test_chacha20_w43_complete_domain_record() -> None:
    result = verify_result("chacha20_w43_complete", ROOT)
    assert result["attempt_id"] == "CHACHA20KR43"
    assert result["logical_candidates"] == 2**43
    assert result["recovered_assignment"] == 2_800_167_095_032
    assert result["independent_confirmation_bits"] == 8192
    assert result["factual_models"] == 1
    assert result["control_models"] == 0


def test_new_strict_subset_chacha20_single_target_records() -> None:
    expected = {
        "chacha20_a294": ("A294", 202, 827_392, 4_118_259),
        "chacha20_a295": ("A295", 2605, 10_670_080, 4_118_259),
        "chacha20_a303": ("A303", 3801, 3_985_637_376, 3_352_070_490),
        "chacha20_a304": ("A304", 2473, 5_310_727_061_504, 3_697_242_003_407),
        "chacha20_a305": ("A305", 2114, 4_539_780_431_872, 2_800_167_095_032),
        "chacha20_a309": ("A309", 4044, 8_684_423_872_512, 7_060_014_834_815),
        "chacha20_a313": ("A313", 2753, 11_824_044_965_888, 662_233_243_956),
    }
    for name, (attempt, rank, upper_bound, assignment) in expected.items():
        result = verify_result(name, ROOT)
        assert result["attempt_id"] == attempt
        assert result["strict_subset_recovery"] is True
        assert result["complete_domain_executed"] is False
        assert result["frozen_order_rank"] == rank
        assert (
            result.get("executed_assignments_upper_bound", result.get("executed_assignments"))
            == upper_bound
        )
        assert result["recovered_assignment"] == assignment
        assert result["independent_confirmation_bits"] == 8192
        assert result["control_models"] == 0


def test_new_strict_subset_chacha20_panels() -> None:
    a296 = verify_result("chacha20_a296", ROOT)
    assert a296["attempt_id"] == "A296"
    assert a296["targets"] == 8
    assert a296["strict_subset_recoveries"] == 8
    assert a296["independent_confirmation_bits"] == 65_536
    assert [row["frozen_order_rank"] for row in a296["target_results"]] == [
        2750,
        2948,
        1485,
        213,
        1144,
        2113,
        520,
        3019,
    ]

    a297 = verify_result("chacha20_a297", ROOT)
    assert a297["attempt_id"] == "A297"
    assert a297["targets"] == 4
    assert a297["strict_subset_recoveries"] == 4
    assert a297["independent_confirmation_bits"] == 32_768
    assert [row["frozen_order_rank"] for row in a297["target_results"]] == [
        2867,
        2032,
        926,
        3932,
    ]


def test_a322_and_a325_terminal_outcomes_are_published() -> None:
    root = ROOT / "chronology" / "arx-carry-leak"
    result_dir = root / "research" / "results" / "v1"
    assert (
        result_dir / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.json"
    ).is_file()
    assert (
        result_dir / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.causal"
    ).is_file()
    assert (ROOT / "results/chacha20_round20_holdout_selected_w45_recovery_a322_v1.json").is_file()
    assert (ROOT / "causal/chacha20_round20_holdout_selected_w45_recovery_a322_v1.causal").is_file()
    assert (ROOT / "results/chacha20_round20_holdout_selected_w46_recovery_a325_v1.json").is_file()
    assert (ROOT / "causal/chacha20_round20_holdout_selected_w46_recovery_a325_v1.causal").is_file()
    assert (
        result_dir / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_order_v1.json"
    ).is_file()
    assert (
        root
        / "research"
        / "configs"
        / "chacha20_round20_holdout_selected_w45_recovery_a322_design_v1.json"
    ).is_file()


def test_complete_suite_opens_all_causal_and_protocol_artifacts() -> None:
    result = verify_all(ROOT)
    assert result["status"] == "verified"
    assert result["author"] == "David Tom Foss"
    assert result["artifact_count"] == len(result["artifacts"])
    assert [row["attempt_id"] for row in result["results"]] == [
        "A184",
        "A237",
        "A240",
        "A244",
        "A246",
        "A248",
        "A253",
        "A256",
        "AES-W41",
        "A264",
        "P128R1",
        "AES256R1",
        "A281",
        "A286",
        "CHACHA20KR43",
        "A294",
        "A295",
        "A296",
        "A297",
        "A303",
        "A304",
        "A305",
        "A309",
        "A313",
        "B3KR1",
        "SIPKR1",
        "TEAKR1",
        "XTEAKR1",
        "TF1024KR1",
        "A322",
        "A325",
        "A350",
        "A374",
    ]
    assert len(result["causal"]) == 48
    assert len(result["chronology_causal"]) == 26
