"""Independent verification of the three retained recovery anchors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .artifacts import EXPECTED_SHA256, load_result, repository_root, verify_artifact_hashes
from .causal import read_causal
from .ciphers import chacha20_block, speck32_64_encrypt, threefish256_encrypt


def _words_sha(words: list[int], width: int) -> str:
    raw = b"".join(word.to_bytes(width // 8, "little") for word in words)
    return hashlib.sha256(raw).hexdigest()


def _common_gates(payload: dict[str, Any], *, attempt: str, candidates: int) -> None:
    execution = payload.get("execution", {})
    if (
        payload.get("attempt_id") != attempt
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


VERIFY_FUNCTIONS = {
    "chacha20": verify_chacha20,
    "speck32_64": verify_speck32_64,
    "threefish256": verify_threefish256,
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
    protocols = {
        path.name: json.loads(path.read_text()) for path in sorted((base / "configs").glob("*.json"))
    }
    for result in results:
        name = {
            "A184": "chacha20_metal_width40_partial_key_recovery_v1.json",
            "A237": "speck32_64_metal_width42_recovery_v1.json",
            "A240": "threefish256_metal_width38_recovery_v1.json",
        }[result["attempt_id"]]
        payload = json.loads((base / "results" / name).read_text())
        config = next(value for value in protocols.values() if value["attempt_id"] == result["attempt_id"])
        if payload["public_challenge"] != config["public_challenge"]:
            raise RuntimeError(f"protocol/result challenge mismatch: {result['attempt_id']}")

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
