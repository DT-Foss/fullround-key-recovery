"""Independent verification of retained complete-domain and strict-subset recoveries."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .aes128_reference import apply_low_residual_bits
from .aes128_reference import encrypt_blocks as aes128_encrypt_blocks
from .aes256_reference import apply_low_residual_bits as aes256_apply_low_residual_bits
from .aes256_reference import encrypt_blocks as aes256_encrypt_blocks
from .artifacts import (
    CONFIG_FILES,
    EXPECTED_SHA256,
    load_result,
    repository_root,
    sha256_file,
    verify_artifact_hashes,
)
from .ascon_aead128_reference import encrypt_combined as ascon_aead128_encrypt
from .causal import read_causal
from .ciphers import (
    chacha20_block,
    simon64_128_encrypt,
    speck32_64_encrypt,
    speck64_128_encrypt,
    threefish256_encrypt,
)
from .present80_reference import encrypt_int as present80_encrypt
from .present80_reference import key_parts_to_int, key_schedule
from .present128_reference import encrypt_int as present128_encrypt
from .present128_reference import key_parts_to_int as present128_key_parts_to_int
from .present128_reference import key_schedule as present128_key_schedule
from .rc5_reference import encrypt_words as rc5_encrypt
from .rc5_reference import expand_key_words as rc5_expand_key
from .salsa20_reference import block as salsa20_block


def _words_sha(words: list[int], width: int) -> str:
    raw = b"".join(word.to_bytes(width // 8, "little") for word in words)
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _common_gates(
    payload: dict[str, Any], *, attempt: str | None, candidates: int
) -> None:
    execution = payload.get("execution", {})
    if (
        (attempt is not None and payload.get("attempt_id") != attempt)
        or execution.get("logical_candidate_count") != candidates
        or execution.get("complete_domain_executed") is not True
        or execution.get("early_stop_used") is not False
        or execution.get("unique_exact_assignment") is not True
        or execution.get("control_target_rejected") is not True
        or len(execution.get("factual_full_matches", [])) != 1
        or execution.get("control_full_matches") != []
    ):
        raise RuntimeError(f"retained execution gates failed for {attempt}")


def verify_chacha20(root: Path) -> dict[str, Any]:
    payload = load_result("chacha20", root)
    _common_gates(payload, attempt="A184", candidates=1 << 40)
    challenge = payload["public_challenge"]
    assignment = int(payload["execution"]["factual_full_matches"][0])
    word0 = assignment & 0xFFFFFFFF
    word1_low = assignment >> 32
    key = [
        word0,
        int(challenge["known_key_word1_upper24"]) | word1_low,
        *[int(value) for value in challenge["known_key_words_2_through_7"]],
    ]
    output = chacha20_block(
        key,
        int(challenge["counter"]),
        [int(value) for value in challenge["nonce_words"]],
    )
    if (
        output != challenge["target_words"]
        or _words_sha(output, 32) != challenge["target_block_sha256"]
        or payload["recovery"]["recovered_key_word0"] != [word0]
        or payload["recovery"]["recovered_key_word1_low_value"] != [word1_low]
    ):
        raise RuntimeError("A184 independent 512-bit confirmation failed")
    return {
        "attempt_id": "A184",
        "cipher": "ChaCha20 block function",
        "rounds": 20,
        "unknown_key_bits": 40,
        "known_key_bits": 216,
        "logical_candidates": 1 << 40,
        "recovered_assignment": assignment,
        "factual_models": 1,
        "control_models": 0,
        "independent_confirmation_bits": 512,
    }


def verify_speck32_64(root: Path) -> dict[str, Any]:
    payload = load_result("speck32_64", root)
    _common_gates(payload, attempt="A237", candidates=1 << 42)
    challenge = payload["public_challenge"]
    assignment = int(payload["execution"]["factual_full_matches"][0])
    inner = assignment & 0xFFFFFFFF
    key = [
        inner & 0xFFFF,
        (inner >> 16) & 0xFFFF,
        int(challenge["known_key2_upper6"]) | (assignment >> 32),
        int(challenge["known_key3"]),
    ]
    plaintext = challenge["plaintext_words_xy_order"]
    output: list[int] = []
    for offset in range(0, len(plaintext), 2):
        output.extend(speck32_64_encrypt(plaintext[offset], plaintext[offset + 1], key))
    if (
        output != challenge["target_ciphertext_words_xy_order"]
        or _words_sha(output, 16) != challenge["target_ciphertext_little_u16_sha256"]
        or payload["recovery"]["recovered_key0"] != [key[0]]
        or payload["recovery"]["recovered_key1"] != [key[1]]
        or payload["recovery"]["recovered_key2_low10"] != [assignment >> 32]
    ):
        raise RuntimeError("A237 independent 96-bit confirmation failed")
    return {
        "attempt_id": "A237",
        "cipher": "Speck32/64",
        "rounds": 22,
        "unknown_key_bits": 42,
        "known_key_bits": 22,
        "logical_candidates": 1 << 42,
        "recovered_assignment": assignment,
        "reconstructed_master_key_words": key,
        "factual_models": 1,
        "control_models": 0,
        "independent_confirmation_bits": 96,
        "gpu_seconds": payload["execution"]["gpu_seconds"],
    }


def verify_threefish256(root: Path) -> dict[str, Any]:
    payload = load_result("threefish256", root)
    _common_gates(payload, attempt="A240", candidates=1 << 38)
    challenge = payload["public_challenge"]
    assignment = int(payload["execution"]["factual_full_matches"][0])
    key = [
        int(challenge["known_key0_upper26"]) | assignment,
        *[int(value) for value in challenge["known_key_words_1_through_3"]],
    ]
    output = threefish256_encrypt(
        challenge["plaintext_words"], key, challenge["known_tweak_words"], 72
    )
    if (
        output != challenge["target_ciphertext_words"]
        or _words_sha(output, 64) != challenge["target_ciphertext_little_u64_sha256"]
        or payload["recovery"]["recovered_key0_low32"] != [assignment & 0xFFFFFFFF]
        or payload["recovery"]["recovered_key0_bits32_37"] != [assignment >> 32]
    ):
        raise RuntimeError("A240 independent 256-bit confirmation failed")
    return {
        "attempt_id": "A240",
        "cipher": "Threefish-256",
        "rounds": 72,
        "unknown_key_bits": 38,
        "known_key_bits": 218,
        "logical_candidates": 1 << 38,
        "recovered_assignment": assignment,
        "reconstructed_master_key_words": key,
        "factual_models": 1,
        "control_models": 0,
        "independent_confirmation_bits": 256,
        "gpu_seconds": payload["execution"]["gpu_seconds"],
    }


def _verify_two_u32_block_cipher(
    *,
    root: Path,
    name: str,
    attempt: str,
    rounds: int,
    unknown_bits: int,
    known_bits: int,
    known_key1_field: str,
    recovered_key1_field: str,
    encrypt: Any,
) -> dict[str, Any]:
    payload = load_result(name, root)
    _common_gates(payload, attempt=attempt, candidates=1 << unknown_bits)
    challenge = payload["public_challenge"]
    assignment = int(payload["execution"]["factual_full_matches"][0])
    key = [
        assignment & 0xFFFFFFFF,
        int(challenge[known_key1_field]) | (assignment >> 32),
        int(challenge["known_key2"]),
        int(challenge["known_key3"]),
    ]
    plaintext = challenge["plaintext_words_xy_order"]
    output: list[int] = []
    for offset in range(0, len(plaintext), 2):
        output.extend(encrypt(int(plaintext[offset]), int(plaintext[offset + 1]), key))
    if (
        output != challenge["target_ciphertext_words_xy_order"]
        or payload["recovery"]["recovered_key0"] != [key[0]]
        or payload["recovery"][recovered_key1_field] != [assignment >> 32]
    ):
        raise RuntimeError(f"{attempt} independent two-block confirmation failed")
    return {
        "attempt_id": attempt,
        "cipher": challenge["cipher"],
        "rounds": rounds,
        "unknown_key_bits": unknown_bits,
        "known_key_bits": known_bits,
        "logical_candidates": 1 << unknown_bits,
        "recovered_assignment": assignment,
        "reconstructed_master_key_words": key,
        "factual_models": 1,
        "control_models": 0,
        "independent_confirmation_bits": 128,
        "gpu_seconds": payload["execution"]["gpu_seconds"],
    }


def verify_speck64_128(root: Path) -> dict[str, Any]:
    return _verify_two_u32_block_cipher(
        root=root,
        name="speck64_128",
        attempt="A244",
        rounds=27,
        unknown_bits=44,
        known_bits=84,
        known_key1_field="known_key1_upper20",
        recovered_key1_field="recovered_key1_low12",
        encrypt=speck64_128_encrypt,
    )


def verify_simon64_128(root: Path) -> dict[str, Any]:
    return _verify_two_u32_block_cipher(
        root=root,
        name="simon64_128",
        attempt="A246",
        rounds=44,
        unknown_bits=43,
        known_bits=85,
        known_key1_field="known_key1_upper21",
        recovered_key1_field="recovered_key1_low11",
        encrypt=simon64_128_encrypt,
    )


def verify_rc5_32_12_16(root: Path) -> dict[str, Any]:
    payload = load_result("rc5_32_12_16", root)
    _common_gates(payload, attempt="A248", candidates=1 << 40)
    challenge = payload["public_challenge"]
    assignment = int(payload["execution"]["factual_full_matches"][0])
    key = [
        assignment & 0xFFFFFFFF,
        int(challenge["known_key1"]) | (assignment >> 32),
        int(challenge["known_key2"]),
        int(challenge["known_key3"]),
    ]
    subkeys = rc5_expand_key(key)
    plaintext = challenge["plaintext_words_ab_order"]
    output: list[int] = []
    for offset in range(0, len(plaintext), 2):
        output.extend(rc5_encrypt(plaintext[offset], plaintext[offset + 1], subkeys))
    if (
        output != challenge["target_ciphertext_words_ab_order"]
        or payload["recovery"]["recovered_key0"] != [key[0]]
        or payload["recovery"]["recovered_key1_low_bits"] != [assignment >> 32]
    ):
        raise RuntimeError("A248 independent two-block confirmation failed")
    return {
        "attempt_id": "A248",
        "cipher": "RC5-32/12/16",
        "rounds": 12,
        "unknown_key_bits": 40,
        "known_key_bits": 88,
        "logical_candidates": 1 << 40,
        "recovered_assignment": assignment,
        "reconstructed_master_key_words": key,
        "factual_models": 1,
        "control_models": 0,
        "independent_confirmation_bits": 128,
        "gpu_seconds": payload["execution"]["gpu_seconds"],
    }


def verify_present80(root: Path) -> dict[str, Any]:
    payload = load_result("present80", root)
    _common_gates(payload, attempt="A253", candidates=1 << 38)
    challenge = payload["public_challenge"]
    assignment = int(payload["execution"]["factual_full_matches"][0])
    low32 = assignment & 0xFFFFFFFF
    middle32 = int(challenge["known_middle32"]) | (assignment >> 32)
    key = key_parts_to_int(int(challenge["known_high16"]), middle32, low32)
    round_keys = key_schedule(key)
    plaintext = challenge["plaintext_words_big_endian"]
    output: list[int] = []
    for offset in range(0, len(plaintext), 2):
        block = (int(plaintext[offset]) << 32) | int(plaintext[offset + 1])
        encrypted = present80_encrypt(block, round_keys)
        output.extend((encrypted >> 32, encrypted & 0xFFFFFFFF))
    if (
        output != challenge["target_ciphertext_words_big_endian"]
        or payload["recovery"]["recovered_low32"] != [low32]
        or payload["recovery"]["recovered_middle32_low_bits"] != [assignment >> 32]
    ):
        raise RuntimeError("A253 independent two-block confirmation failed")
    return {
        "attempt_id": "A253",
        "cipher": "PRESENT-80",
        "rounds": 31,
        "unknown_key_bits": 38,
        "known_key_bits": 42,
        "logical_candidates": 1 << 38,
        "recovered_assignment": assignment,
        "reconstructed_master_key_hex": f"{key:020x}",
        "factual_models": 1,
        "control_models": 0,
        "independent_confirmation_bits": 128,
        "gpu_seconds": payload["execution"]["gpu_seconds"],
    }


def verify_ascon_aead128(root: Path) -> dict[str, Any]:
    payload = load_result("ascon_aead128", root)
    _common_gates(payload, attempt="A256", candidates=1 << 40)
    challenge = payload["public_challenge"]
    assignment = int(payload["execution"]["factual_full_matches"][0])
    words = [
        assignment & 0xFFFFFFFF,
        int(challenge["known_key_words_little_endian"][1]) | (assignment >> 32),
        *[int(value) for value in challenge["known_key_words_little_endian"][2:]],
    ]
    key = b"".join(word.to_bytes(4, "little") for word in words)
    output = ascon_aead128_encrypt(
        key,
        bytes.fromhex(challenge["nonce_hex"]),
        bytes.fromhex(challenge["associated_data_hex"]),
        bytes.fromhex(challenge["message_hex"]),
    )
    if (
        output.hex() != challenge["target_ciphertext_and_tag_hex"]
        or payload["recovery"]["recovered_key_word0"] != [words[0]]
        or payload["recovery"]["recovered_key_word1_low_bits"] != [assignment >> 32]
    ):
        raise RuntimeError("A256 independent AEAD confirmation failed")
    return {
        "attempt_id": "A256",
        "cipher": "Ascon-AEAD128",
        "rounds": "12/8/12 permutation schedule",
        "unknown_key_bits": 40,
        "known_key_bits": 88,
        "logical_candidates": 1 << 40,
        "recovered_assignment": assignment,
        "reconstructed_master_key_hex": key.hex(),
        "factual_models": 1,
        "control_models": 0,
        "independent_confirmation_bits": 384,
        "gpu_seconds": payload["execution"]["gpu_seconds"],
    }


def verify_aes128(root: Path) -> dict[str, Any]:
    payload = load_result("aes128", root)
    _common_gates(payload, attempt=None, candidates=1 << 41)
    challenge = payload["public_challenge"]
    assignment = int(payload["execution"]["factual_full_matches"][0])
    key = apply_low_residual_bits(
        bytes.fromhex(challenge["known_key_zeroed_residual_hex"]), assignment, 41
    )
    output = aes128_encrypt_blocks(key, bytes.fromhex(challenge["plaintext_hex"]))
    if (
        output.hex() != challenge["target_ciphertext_hex"]
        or payload["recovery"]["recovered_key_word2_low_bits"] != [assignment >> 32]
        or payload["recovery"]["recovered_key_word3"] != [assignment & 0xFFFFFFFF]
    ):
        raise RuntimeError("AES-W41 independent two-block confirmation failed")
    return {
        "attempt_id": "AES-W41",
        "cipher": "AES-128",
        "rounds": 10,
        "unknown_key_bits": 41,
        "known_key_bits": 87,
        "logical_candidates": 1 << 41,
        "recovered_assignment": assignment,
        "reconstructed_master_key_hex": key.hex(),
        "factual_models": 1,
        "control_models": 0,
        "independent_confirmation_bits": 256,
        "gpu_seconds": payload["execution"]["gpu_seconds"],
    }


def verify_salsa20_20(root: Path) -> dict[str, Any]:
    payload = load_result("salsa20_20", root)
    _common_gates(payload, attempt="A264", candidates=1 << 42)
    challenge = payload["public_challenge"]
    assignment = int(payload["execution"]["factual_full_matches"][0])
    words = [int(value) for value in challenge["known_key_words_little_endian"]]
    words[0] = assignment & 0xFFFFFFFF
    words[1] |= assignment >> 32
    key = b"".join(word.to_bytes(4, "little") for word in words)
    output = salsa20_block(
        key,
        bytes.fromhex(challenge["nonce_hex"]),
        int(challenge["counter"]),
    )
    if (
        output.hex() != challenge["target_block_hex"]
        or payload["recovery"]["recovered_key_word0"] != [words[0]]
        or payload["recovery"]["recovered_key_word1_low_bits"] != [assignment >> 32]
    ):
        raise RuntimeError("A264 independent 512-bit confirmation failed")
    return {
        "attempt_id": "A264",
        "cipher": "Salsa20/20 block function",
        "rounds": 20,
        "unknown_key_bits": 42,
        "known_key_bits": 214,
        "logical_candidates": 1 << 42,
        "recovered_assignment": assignment,
        "reconstructed_master_key_hex": key.hex(),
        "factual_models": 1,
        "control_models": 0,
        "independent_confirmation_bits": 512,
        "gpu_seconds": payload["execution"]["gpu_seconds"],
    }


def verify_present128(root: Path) -> dict[str, Any]:
    payload = load_result("present128", root)
    _common_gates(payload, attempt="P128R1", candidates=1 << 38)
    challenge = payload["public_challenge"]
    assignment = int(payload["execution"]["factual_full_matches"][0])
    low32 = assignment & 0xFFFFFFFF
    middle32 = int(challenge["known_mid_low32"]) | (assignment >> 32)
    key = present128_key_parts_to_int(int(challenge["known_high64"]), middle32, low32)
    round_keys = present128_key_schedule(key)
    plaintext = challenge["plaintext_words_big_endian"]
    output: list[int] = []
    for offset in range(0, len(plaintext), 2):
        block = (int(plaintext[offset]) << 32) | int(plaintext[offset + 1])
        encrypted = present128_encrypt(block, round_keys)
        output.extend((encrypted >> 32, encrypted & 0xFFFFFFFF))
    if (
        output != challenge["target_ciphertext_words_big_endian"]
        or hashlib.sha256(
            b"".join(int(word).to_bytes(4, "big") for word in output)
        ).hexdigest()
        != challenge["target_ciphertext_big_u32_sha256"]
        or payload["recovery"]["recovered_low32"] != [low32]
        or payload["recovery"]["recovered_mid_low32_low_bits"] != [assignment >> 32]
        or payload["recovery"]["recovered_full_master_key_hex"] != [f"{key:032x}"]
    ):
        raise RuntimeError("P128R1 independent two-block confirmation failed")
    return {
        "attempt_id": "P128R1",
        "cipher": "PRESENT-128",
        "rounds": "31 + K32 whitening",
        "unknown_key_bits": 38,
        "known_key_bits": 90,
        "logical_candidates": 1 << 38,
        "recovered_assignment": assignment,
        "reconstructed_master_key_hex": f"{key:032x}",
        "factual_models": 1,
        "control_models": 0,
        "independent_confirmation_bits": 128,
        "gpu_seconds": payload["execution"]["gpu_seconds"],
    }


def verify_aes256(root: Path) -> dict[str, Any]:
    payload = load_result("aes256", root)
    _common_gates(payload, attempt="AES256R1", candidates=1 << 41)
    challenge = payload["public_challenge"]
    assignment = int(payload["execution"]["factual_full_matches"][0])
    key = aes256_apply_low_residual_bits(
        bytes.fromhex(challenge["known_key_zeroed_residual_hex"]), assignment, 41
    )
    output = aes256_encrypt_blocks(key, bytes.fromhex(challenge["plaintext_hex"]))
    if (
        output.hex() != challenge["target_ciphertext_hex"]
        or hashlib.sha256(output).hexdigest() != challenge["target_ciphertext_sha256"]
        or payload["recovery"]["recovered_key_word6_low_bits"] != [assignment >> 32]
        or payload["recovery"]["recovered_key_word7"] != [assignment & 0xFFFFFFFF]
        or payload["execution"]["factual_confirmations"][0]["key_hex"] != key.hex()
    ):
        raise RuntimeError("AES256R1 independent two-block confirmation failed")
    return {
        "attempt_id": "AES256R1",
        "cipher": "AES-256",
        "rounds": 14,
        "unknown_key_bits": 41,
        "known_key_bits": 215,
        "logical_candidates": 1 << 41,
        "recovered_assignment": assignment,
        "reconstructed_master_key_hex": key.hex(),
        "factual_models": 1,
        "control_models": 0,
        "independent_confirmation_bits": 256,
        "gpu_seconds": payload["execution"]["gpu_seconds"],
    }


def _verify_chacha20_target(
    *, challenge: dict[str, Any], recovered_low20: int
) -> tuple[list[list[int]], list[str], list[int]]:
    key = [
        int(challenge["known_key_word0_upper12"]) | recovered_low20,
        *[int(value) for value in challenge["known_key_words_1_through_7"]],
    ]
    blocks = [
        chacha20_block(
            key,
            (int(challenge["counter_start"]) + block_index) & 0xFFFFFFFF,
            [int(value) for value in challenge["nonce_words"]],
        )
        for block_index in range(int(challenge["block_count"]))
    ]
    block_hashes = [_words_sha(block, 32) for block in blocks]
    return blocks, block_hashes, key


def verify_chacha20_cross_material(root: Path) -> dict[str, Any]:
    payload = load_result("chacha20_cross_material", root)
    target = json.loads((root / "configs" / CONFIG_FILES["chacha20_cross_material"]).read_text())
    challenge = target["public_challenge"]
    confirmation = payload["confirmation"]
    recovered = int(confirmation["recovered_unknown_low20"])
    blocks, block_hashes, key = _verify_chacha20_target(
        challenge=challenge, recovered_low20=recovered
    )
    summary = payload["top_execution_summary"]
    boundary = payload["information_boundary"]
    if (
        payload.get("attempt_id") != "A281"
        or blocks != challenge["target_words"]
        or block_hashes != challenge["target_block_sha256"]
        or block_hashes != confirmation["candidate_block_sha256"]
        or confirmation["all_blocks_match"] is not True
        or confirmation["all_cross_implementation_blocks_match"] is not True
        or confirmation["output_bits_checked"] != 4096
        or confirmation["control_first_block_match"] is not False
        or blocks[0] == challenge["control_target_words"]
        or summary != {
            "all_attempted_cells_exact_UNSAT": False,
            "attempted_cells": 37,
            "logical_assignments_inside_attempted_cells": 151552,
            "retained_state_continuity_verified": True,
            "sat": 1,
            "sat_found": True,
            "unknown": 0,
            "unsat": 36,
        }
        or boundary["complete_full_domain_enumeration_used"] is not False
        or boundary["correct_prefix_or_rank_known_before_execution"] is not False
        or boundary["order_frozen_before_execution"] is not True
        or boundary["target_label_available"] is not False
    ):
        raise RuntimeError("A281 strict-subset ChaCha20-R20 confirmation failed")
    return {
        "attempt_id": "A281",
        "cipher": "ChaCha20 block function",
        "rounds": 20,
        "unknown_key_bits": 20,
        "known_key_bits": 236,
        "complete_domain_executed": False,
        "strict_subset_recovery": True,
        "frozen_order_rank": 37,
        "attempted_prefix_cells": 37,
        "logical_assignments": 151552,
        "search_fraction": 37 / 256,
        "recovered_assignment": recovered,
        "reconstructed_master_key_words": key,
        "independent_confirmation_bits": 4096,
        "control_models": 0,
    }


def _published_anchor_path(root: Path, source_path: str) -> Path:
    name = Path(source_path).name
    if source_path.endswith(".causal"):
        return root / "causal" / name
    if "/configs/" in source_path:
        return root / "configs" / name
    if "/experiments/" in source_path:
        return root / "experiments" / "original" / name
    return root / "results" / name


def verify_chacha20_multitarget_panel(root: Path) -> dict[str, Any]:
    payload = load_result("chacha20_multitarget_panel", root)
    headline = payload["headline"]
    canonical_input = {
        "shared_anchors": payload["shared_anchors"],
        "rfc8439_gate": payload["rfc8439_gate"],
        "targets": payload["targets"],
        "headline": headline,
    }
    if (
        payload.get("attempt_id") != "A286"
        or payload.get("evidence_stage")
        != "FULLROUND_R20_FOUR_OF_FOUR_CROSS_MATERIAL_RECOVERIES_INDEPENDENTLY_CONFIRMED"
        or _canonical_sha(canonical_input) != payload["confirmation_sha256"]
        or headline["fresh_public_material_targets"] != 4
        or headline["confirmed_recoveries"] != 4
        or headline["independently_recomputed_output_bits"] != 16384
        or headline["complete_full_domain_enumeration_used"] is not False
        or headline["reader_refits"] != 0
        or headline["target_labels_used"] != 0
        or headline["all_one_bit_controls_rejected"] is not True
    ):
        raise RuntimeError("A286 panel headline or root hash failed")

    for anchor in payload["shared_anchors"].values():
        path = _published_anchor_path(root, anchor["path"])
        if sha256_file(path) != anchor["sha256"]:
            raise RuntimeError(f"A286 shared anchor failed: {path.name}")

    rows = []
    for row in payload["targets"]:
        for anchor in row["anchors"].values():
            path = _published_anchor_path(root, anchor["path"])
            if sha256_file(path) != anchor["sha256"]:
                raise RuntimeError(f"A286 target anchor failed: {path.name}")
        target_path = _published_anchor_path(root, row["anchors"]["target"]["path"])
        result_path = _published_anchor_path(root, row["anchors"]["result"]["path"])
        canonical_path = _published_anchor_path(root, row["anchors"]["canonical"]["path"])
        target = json.loads(target_path.read_text())
        result = json.loads(result_path.read_text())
        canonical = json.loads(canonical_path.read_text())
        challenge = target["public_challenge"]
        confirmation = result["confirmation"]
        recovered = int(row["recovered_unknown_low20"])
        blocks, block_hashes, key = _verify_chacha20_target(
            challenge=challenge, recovered_low20=recovered
        )
        if (
            blocks != challenge["target_words"]
            or block_hashes != challenge["target_block_sha256"]
            or block_hashes != confirmation["candidate_block_sha256"]
            or block_hashes != row["standalone_block_sha256"]
            or confirmation["recovered_unknown_low20"] != recovered
            or confirmation["output_bits_checked"] != 4096
            or confirmation["control_first_block_match"] is not False
            or blocks[0] == challenge["control_target_words"]
            or row["standalone_direct_spec_all_8_blocks_match"] is not True
            or row["standalone_output_bits_checked"] != 4096
            or row["one_bit_control_rejected"] is not True
            or row["complete_full_domain_enumeration_used"] is not False
            or canonical["source_result"]["sha256"] != row["anchors"]["result"]["sha256"]
            or canonical["causal"]["sha256"] != row["anchors"]["causal"]["sha256"]
        ):
            raise RuntimeError(f"A286 independent confirmation failed: {row['target_id']}")
        rows.append(
            {
                "target_id": row["target_id"],
                "discovery_stage": row["discovery_stage"],
                "frozen_order_rank": row["frozen_order_rank"],
                "recovered_assignment": recovered,
                "reconstructed_master_key_words": key,
            }
        )
    causal = payload["causal"]
    if (
        sha256_file(root / "causal" / Path(causal["path"]).name) != causal["sha256"]
        or headline["discovery_modes"] != [row["discovery_stage"] for row in rows]
        or headline["frozen_order_ranks_when_applicable"]
        != [row["frozen_order_rank"] for row in rows if row["frozen_order_rank"] is not None]
    ):
        raise RuntimeError("A286 Causal or rank summary failed")
    return {
        "attempt_id": "A286",
        "cipher": "ChaCha20 block function",
        "rounds": 20,
        "targets": 4,
        "unknown_key_bits_per_target": 20,
        "known_key_bits_per_target": 236,
        "complete_domain_executed": False,
        "strict_subset_recoveries": 4,
        "independent_confirmation_bits": 16384,
        "control_models": 0,
        "target_results": rows,
    }


VERIFY_FUNCTIONS = {
    "chacha20": verify_chacha20,
    "speck32_64": verify_speck32_64,
    "threefish256": verify_threefish256,
    "speck64_128": verify_speck64_128,
    "simon64_128": verify_simon64_128,
    "rc5_32_12_16": verify_rc5_32_12_16,
    "present80": verify_present80,
    "ascon_aead128": verify_ascon_aead128,
    "aes128": verify_aes128,
    "salsa20_20": verify_salsa20_20,
    "present128": verify_present128,
    "aes256": verify_aes256,
    "chacha20_cross_material": verify_chacha20_cross_material,
    "chacha20_multitarget_panel": verify_chacha20_multitarget_panel,
}


def verify_result(name: str, root: Path | None = None) -> dict[str, Any]:
    base = (root or repository_root()).resolve()
    if name not in VERIFY_FUNCTIONS:
        raise KeyError(f"unknown result: {name}")
    verify_artifact_hashes(base)
    return VERIFY_FUNCTIONS[name](base)


def verify_all(root: Path | None = None) -> dict[str, Any]:
    base = (root or repository_root()).resolve()
    artifact_hashes = verify_artifact_hashes(base)
    results = [function(base) for function in VERIFY_FUNCTIONS.values()]
    from .artifacts import RESULT_FILES

    for name in VERIFY_FUNCTIONS:
        result_file = RESULT_FILES[name]
        payload = json.loads((base / "results" / result_file).read_text())
        config = json.loads((base / "configs" / CONFIG_FILES[name]).read_text())
        if (
            "public_challenge" in payload
            and "public_challenge" in config
            and payload["public_challenge"] != config["public_challenge"]
        ):
            raise RuntimeError(f"protocol/result challenge mismatch: {name}")

    causal = {}
    for path in sorted((base / "causal").glob("*.causal")):
        row = read_causal(path)
        if row["file_sha256"] != EXPECTED_SHA256[f"causal/{path.name}"]:
            raise RuntimeError(f"Causal hash mismatch after Reader open: {path.name}")
        causal[path.name] = row
    return {
        "status": "verified",
        "author": "David Tom Foss",
        "artifact_count": len(artifact_hashes),
        "artifacts": artifact_hashes,
        "results": results,
        "causal": causal,
    }
