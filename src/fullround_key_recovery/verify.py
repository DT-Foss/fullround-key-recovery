"""Independent verification of the ten retained recovery anchors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .aes128_reference import apply_low_residual_bits
from .aes128_reference import encrypt_blocks as aes128_encrypt_blocks
from .artifacts import EXPECTED_SHA256, load_result, repository_root, verify_artifact_hashes
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
from .rc5_reference import encrypt_words as rc5_encrypt
from .rc5_reference import expand_key_words as rc5_expand_key
from .salsa20_reference import block as salsa20_block


def _words_sha(words: list[int], width: int) -> str:
    raw = b"".join(word.to_bytes(width // 8, "little") for word in words)
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
        config = json.loads((base / "configs" / result_file).read_text())
        if payload["public_challenge"] != config["public_challenge"]:
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
