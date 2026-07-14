#!/usr/bin/env python3
"""Create the one-shot pre-execution protocol for A244 Speck64/128 W44."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.ciphers import (
    SPECK_VARIANTS,
    speck_encrypt_block,
    speck_round_keys,
)

ATTEMPT_ID = "A244"
QUALIFICATION_ATTEMPT_ID = "A243"
SCHEMA = "speck64-128-metal-width44-recovery-protocol-v1"
UNKNOWN_BITS = 44
OUTER_BITS = 12
KNOWN_KEY_BITS = 128 - UNKNOWN_BITS
INNER_CANDIDATES = 1 << 32
OUTER_SLICES = 1 << OUTER_BITS
LOGICAL_CANDIDATES = 1 << UNKNOWN_BITS
STREAM_CANDIDATES = 1 << 30
PLAINTEXT_BLOCKS = 2
FILTER_BITS = PLAINTEXT_BLOCKS * 64
KNOWN_MATERIAL_LABEL = "speck64-128/a244/fullround/w44/known-material/v1"
QUALIFICATION_FILENAME = "speck64_128_metal_qualification_v1.json"
QUALIFICATION_SHA256 = "ea16b7947e8b7fd3e18791e33149e119d60ede8b678df94dbbec7507733ed653"
NATIVE_SOURCE_FILENAME = "speck64_128_metal_native.swift"
NATIVE_SOURCE_SHA256 = "67c0ff467314db77fa24b7715bd9d8bb3672ae91794d35ca8e39b421ef21fdb0"
VARIANT = SPECK_VARIANTS["speck64_128"]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return _sha256(raw)


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _known_material() -> tuple[int, int, int, list[int], str]:
    raw = hashlib.shake_256(KNOWN_MATERIAL_LABEL.encode()).digest(28)
    key1_known_upper20 = int.from_bytes(raw[:4], "big") & 0xFFFFF000
    key2 = int.from_bytes(raw[4:8], "big")
    key3 = int.from_bytes(raw[8:12], "big")
    plaintext_words = [
        int.from_bytes(raw[offset : offset + 4], "big")
        for offset in range(12, 28, 4)
    ]
    blocks = {
        tuple(plaintext_words[offset : offset + 2])
        for offset in range(0, len(plaintext_words), 2)
    }
    if len(blocks) != PLAINTEXT_BLOCKS:
        raise RuntimeError("A244 deterministic plaintext blocks are not distinct")
    return key1_known_upper20, key2, key3, plaintext_words, _sha256(raw)


def _target_words(
    assignment: int,
    key1_known_upper20: int,
    key2: int,
    key3: int,
    plaintext_words: list[int],
) -> list[int]:
    if assignment < 0 or assignment >= LOGICAL_CANDIDATES:
        raise ValueError("A244 assignment is outside the W44 domain")
    inner = assignment & 0xFFFFFFFF
    outer = assignment >> 32
    master_key = [inner, key1_known_upper20 | outer, key2, key3]
    round_keys = speck_round_keys(VARIANT, master_key, VARIANT.full_rounds)
    output: list[int] = []
    for offset in range(0, len(plaintext_words), 2):
        output.extend(
            speck_encrypt_block(
                plaintext_words[offset],
                plaintext_words[offset + 1],
                round_keys,
                VARIANT,
            )
        )
    return output


def _qualification_gate(payload: dict[str, Any]) -> None:
    launch = payload.get("launch_gate", {})
    if (
        payload.get("schema") != "speck64-128-metal-qualification-v1"
        or payload.get("attempt_id") != QUALIFICATION_ATTEMPT_ID
        or payload.get("evidence_stage")
        != "SPECK64_128_METAL_PRE_TARGET_QUALIFICATION"
        or payload.get("cipher", {}).get("rounds") != 27
        or payload.get("cipher", {}).get("master_key_bits") != 128
        or payload.get("official_kat_gate", {}).get("two_block_scalar_identity")
        is not True
        or payload.get("cross_implementation_gate", {}).get(
            "exact_scalar_identity"
        )
        is not True
        or payload.get("boundary_filter_gate", {}).get("exact_boundary_identity")
        is not True
        or payload.get("information_boundary", {}).get("production_target_selected")
        is not False
        or launch.get("target_width") != UNKNOWN_BITS
        or launch.get("selected_width") != UNKNOWN_BITS
        or launch.get("width44_under_two_hours") is not True
        or launch.get("full_domain_launch_authorized") is not True
        or float(launch.get("projected_width44_seconds_at_observed_minimum", 1e99))
        > float(launch.get("maximum_complete_domain_seconds", 0))
    ):
        raise RuntimeError("A244 qualification semantic or two-hour gate differs")


def build_protocol(*, qualification: Path, native_source: Path) -> dict[str, Any]:
    if _file_sha256(qualification) != QUALIFICATION_SHA256:
        raise RuntimeError("A244 qualification anchor hash differs")
    qualification_payload = json.loads(qualification.read_text())
    _qualification_gate(qualification_payload)
    if _file_sha256(native_source) != NATIVE_SOURCE_SHA256:
        raise RuntimeError("A244 native source anchor hash differs")

    (
        key1_known_upper20,
        key2,
        key3,
        plaintext_words,
        known_material_sha256,
    ) = _known_material()
    unknown_assignment = secrets.randbits(UNKNOWN_BITS)
    target_words = _target_words(
        unknown_assignment,
        key1_known_upper20,
        key2,
        key3,
        plaintext_words,
    )
    control_words = list(target_words)
    control_words[-1] ^= 1
    target_raw = np.array(target_words, dtype="<u4").tobytes()
    control_raw = np.array(control_words, dtype="<u4").tobytes()
    public_challenge = {
        "cipher": "Speck64/128",
        "rounds": VARIANT.full_rounds,
        "plaintext_blocks": PLAINTEXT_BLOCKS,
        "plaintext_words_xy_order": plaintext_words,
        "target_ciphertext_words_xy_order": target_words,
        "control_ciphertext_words_xy_order": control_words,
        "target_ciphertext_little_u32_sha256": _sha256(target_raw),
        "control_ciphertext_little_u32_sha256": _sha256(control_raw),
        "known_material_derivation_label": KNOWN_MATERIAL_LABEL,
        "known_material_derivation_sha256": known_material_sha256,
        "known_key1_upper20": key1_known_upper20,
        "known_key2": key2,
        "known_key3": key3,
        "unknown_key0_bits": 32,
        "unknown_key1_low_bits": OUTER_BITS,
        "unknown_assignment_bits": UNKNOWN_BITS,
        "known_master_key_bits": KNOWN_KEY_BITS,
        "candidate_encoding": "assignment=(key1_low12<<32)|key0",
        "unknown_assignment_included": False,
        "unknown_key0_included": False,
        "unknown_key1_low12_included": False,
        "control_relation": "target_ciphertext_final_word_xor_0x00000001",
    }
    public_challenge_sha256 = _canonical_sha256(public_challenge)
    execution_plan = {
        "primitive": "Speck64/128_block_cipher",
        "rounds": VARIANT.full_rounds,
        "unknown_key_bits": UNKNOWN_BITS,
        "known_key_bits": KNOWN_KEY_BITS,
        "known_plaintext_ciphertext_pairs": PLAINTEXT_BLOCKS,
        "filter_output_bits": FILTER_BITS,
        "logical_candidate_count": LOGICAL_CANDIDATES,
        "outer_key1_low12_slice_count": OUTER_SLICES,
        "inner_key0_candidate_count_per_slice": INNER_CANDIDATES,
        "combined_assignment_encoding": "key1_low12_times_2^32_plus_key0",
        "gpu_threads_per_candidate": 1,
        "gpu_logical_thread_count": LOGICAL_CANDIDATES,
        "stream_candidate_count": STREAM_CANDIDATES,
        "stream_batches_per_slice": INNER_CANDIDATES // STREAM_CANDIDATES,
        "stream_batch_count": LOGICAL_CANDIDATES // STREAM_CANDIDATES,
        "result_capacity_per_batch": 64,
        "complete_domain_required": True,
        "early_stop_used": False,
        "checkpoint_resume_enabled": True,
        "persistent_host_process": True,
        "host_reconfiguration_per_outer_slice": True,
        "runtime_shader_compilation": True,
        "full_confirmation": (
            "independent_Python_Speck64/128_all_two_blocks_all_128_output_bits"
        ),
        "control_target_required": True,
        "fresh_public_challenge": True,
        "unknown_assignment_available_to_runner_before_execution": False,
        "volatile_wallclock_excluded_from_success_rule": True,
    }
    qualification_launch_gate = qualification_payload["launch_gate"]
    return {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_any_A244_candidate_execution",
        "primary_sources": {
            "algorithm_and_Speck64_128_test_vector": (
                "https://eprint.iacr.org/2013/404.pdf"
            ),
            "official_NSA_publications_index": (
                "https://nsacyber.github.io/simon-speck/publications/"
            ),
        },
        "anchors": {
            "qualification": {
                "attempt_id": QUALIFICATION_ATTEMPT_ID,
                "filename": QUALIFICATION_FILENAME,
                "sha256": QUALIFICATION_SHA256,
            },
            "native_host": {
                "filename": NATIVE_SOURCE_FILENAME,
                "sha256": NATIVE_SOURCE_SHA256,
            },
        },
        "qualification_launch_gate": qualification_launch_gate,
        "public_challenge": public_challenge,
        "public_challenge_sha256": public_challenge_sha256,
        "execution_plan": execution_plan,
        "execution_plan_sha256": _canonical_sha256(execution_plan),
        "prospective_prediction": {
            "claim_type": "fresh_fullround_44_bit_residual_key_recovery",
            "complete_domain_will_be_executed": True,
            "expected_unique_exact_assignment": True,
            "expected_control_exact_assignments": 0,
            "success_requires_independent_two_block_confirmation": True,
            "asymptotic_search_advantage_claimed": False,
        },
        "required_validation_gates": {
            "pre_target_official_KAT_passed": True,
            "pre_target_scalar_Metal_cross_gate_passed": True,
            "pre_target_uint32_boundary_gate_passed": True,
            "pre_target_width44_two_hour_gate_passed": True,
            "candidate_execution_against_public_A244_target_before_freeze": False,
            "all_2^44_assignments_must_execute": True,
            "early_stop_forbidden": True,
            "independent_two_block_confirmation_required": True,
            "bit_flipped_control_required": True,
            "authentic_AI_native_causal_artifact_required": True,
            "authentic_CausalReader_reopen_required": True,
        },
        "information_boundary": {
            "unknown_assignment_generated_once_from_os_randomness": True,
            "unknown_assignment_used_only_to_construct_public_ciphertexts": True,
            "unknown_assignment_in_protocol_or_source": False,
            "unknown_assignment_logged_or_returned_by_protocol_builder": False,
            "unknown_assignment_available_to_runner_before_execution": False,
            "A244_candidate_outcomes_used_before_protocol_freeze": False,
            "benchmark_outcome_used_only_to_select_width_and_batch_size": True,
        },
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            research_root / "configs" / "speck64_128_metal_width44_recovery_v1.json"
        ),
    )
    parser.add_argument(
        "--qualification",
        type=Path,
        default=research_root / "results" / "v1" / QUALIFICATION_FILENAME,
    )
    parser.add_argument(
        "--native-source",
        type=Path,
        default=Path(__file__).with_name(NATIVE_SOURCE_FILENAME),
    )
    args = parser.parse_args(argv)
    if args.output.exists():
        raise FileExistsError(f"A244 protocol already exists: {args.output}")
    protocol = build_protocol(
        qualification=args.qualification, native_source=args.native_source
    )
    _atomic_json(args.output, protocol)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "protocol_sha256": _file_sha256(args.output),
                "public_challenge_sha256": protocol["public_challenge_sha256"],
                "unknown_assignment_in_output": False,
                "protocol_state": protocol["protocol_state"],
                "width44_launch_gate": protocol["qualification_launch_gate"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
