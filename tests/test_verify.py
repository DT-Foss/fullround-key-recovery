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


def test_complete_suite_opens_all_causal_and_protocol_artifacts() -> None:
    result = verify_all(ROOT)
    assert result["status"] == "verified"
    assert result["author"] == "David Tom Foss"
    assert result["artifact_count"] == 17
    assert [row["attempt_id"] for row in result["results"]] == ["A184", "A237", "A240"]
    assert len(result["causal"]) == 3
