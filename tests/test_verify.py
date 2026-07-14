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


def test_complete_suite_opens_all_causal_and_protocol_artifacts() -> None:
    result = verify_all(ROOT)
    assert result["status"] == "verified"
    assert result["author"] == "David Tom Foss"
    assert result["artifact_count"] == 94
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
    ]
    assert len(result["causal"]) == 10
