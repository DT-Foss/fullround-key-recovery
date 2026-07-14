#!/usr/bin/env python3
"""Freeze the one-shot A248 protocol after A247 selects a safe width.

Importing this module is side-effect free.  The public challenge is generated
only by an explicit CLI invocation after the retained A247 qualification has
passed every semantic and two-hour launch gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.rc5_reference import ROUNDS, encrypt_words, expand_key_words

ATTEMPT_ID = "A248"
QUALIFICATION_ATTEMPT_ID = "A247"
QUALIFICATION_SCHEMA = "rc5-32-12-16-metal-qualification-v1"
QUALIFICATION_FILENAME = "rc5_32_12_16_metal_qualification_v1.json"
NATIVE_SOURCE_FILENAME = "rc5_32_12_16_metal_native.swift"
INNER_CANDIDATES = 1 << 32
STREAM_CANDIDATES = 1 << 30
PLAINTEXT_BLOCKS = 2
FILTER_BITS = PLAINTEXT_BLOCKS * 64
FULL_ROUNDS = ROUNDS
MIN_RESIDUAL_WIDTH = 32
MAX_RESIDUAL_WIDTH = 64


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


def _width_parameters(width: int) -> dict[str, int]:
    if width < MIN_RESIDUAL_WIDTH or width > MAX_RESIDUAL_WIDTH:
        raise ValueError("A248 residual width must be in 32...64")
    outer_bits = width - 32
    key1_known_mask = (0xFFFFFFFF << outer_bits) & 0xFFFFFFFF
    return {
        "unknown_bits": width,
        "outer_bits": outer_bits,
        "known_key_bits": 128 - width,
        "outer_slices": 1 << outer_bits,
        "logical_candidates": 1 << width,
        "key1_known_mask": key1_known_mask,
    }


def _known_material(width: int) -> tuple[int, int, int, list[int], str, str]:
    params = _width_parameters(width)
    label = f"rc5-32-12-16/a248/fullround/w{width}/known-material/v1"
    raw = hashlib.shake_256(label.encode()).digest(28)
    key1_known = int.from_bytes(raw[:4], "big") & params["key1_known_mask"]
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
        raise RuntimeError("A248 deterministic plaintext blocks are not distinct")
    return key1_known, key2, key3, plaintext_words, label, _sha256(raw)


def _target_words(
    assignment: int,
    *,
    width: int,
    key1_known: int,
    key2: int,
    key3: int,
    plaintext_words: list[int],
) -> list[int]:
    params = _width_parameters(width)
    if assignment < 0 or assignment >= params["logical_candidates"]:
        raise ValueError(f"A248 assignment is outside the W{width} domain")
    inner = assignment & 0xFFFFFFFF
    outer = assignment >> 32
    subkeys = expand_key_words([inner, key1_known | outer, key2, key3])
    output: list[int] = []
    for offset in range(0, len(plaintext_words), 2):
        output.extend(
            encrypt_words(
                plaintext_words[offset], plaintext_words[offset + 1], subkeys
            )
        )
    return output


def _qualification_gate(payload: dict[str, Any]) -> int:
    launch = payload.get("launch_gate", {})
    width = launch.get("selected_width")
    if not isinstance(width, int):
        raise RuntimeError("A247 qualification did not select an integer width")
    _width_parameters(width)
    rivest_vectors = payload.get("provenance_kat_gate", {}).get(
        "rivest_original_paper_scalar_vectors", []
    )
    rfc2040_vector = payload.get("provenance_kat_gate", {}).get(
        "rfc2040_derived_r12_raw_block_vector", {}
    )
    if (
        payload.get("schema") != QUALIFICATION_SCHEMA
        or payload.get("attempt_id") != QUALIFICATION_ATTEMPT_ID
        or payload.get("evidence_stage")
        != "RC5_32_12_16_METAL_PRE_TARGET_QUALIFICATION"
        or payload.get("cipher", {}).get("rounds") != FULL_ROUNDS
        or payload.get("cipher", {}).get("master_key_bits") != 128
        or len(rivest_vectors) != 5
        or not all(row.get("pass") is True for row in rivest_vectors)
        or rfc2040_vector.get("pass") is not True
        or payload.get("provenance_kat_gate", {}).get("two_block_scalar_identity")
        is not True
        or payload.get("cross_implementation_gate", {}).get(
            "exact_scalar_identity"
        )
        is not True
        or payload.get("boundary_filter_gate", {}).get("exact_boundary_identity")
        is not True
        or payload.get("information_boundary", {}).get("production_target_selected")
        is not False
        or launch.get("selected_width_under_two_hours") is not True
        or launch.get("full_domain_launch_authorized") is not True
        or float(
            launch.get("projected_selected_width_seconds_at_observed_minimum", 1e99)
        )
        > float(launch.get("maximum_complete_domain_seconds", 0))
    ):
        raise RuntimeError("A247 qualification semantic or two-hour gate differs")
    return width


def build_protocol(*, qualification: Path, native_source: Path) -> dict[str, Any]:
    """Generate a fresh public A248 challenge and discard its hidden assignment."""

    qualification_sha256 = _file_sha256(qualification)
    qualification_payload = json.loads(qualification.read_text())
    width = _qualification_gate(qualification_payload)
    params = _width_parameters(width)
    native_source_sha256 = _file_sha256(native_source)
    if (
        qualification_payload.get("native_build", {}).get("source_sha256")
        != native_source_sha256
    ):
        raise RuntimeError("A247 qualification and RC5 native source hashes differ")

    (
        key1_known,
        key2,
        key3,
        plaintext_words,
        known_material_label,
        known_material_sha256,
    ) = _known_material(width)
    unknown_assignment = secrets.randbits(width)
    target_words = _target_words(
        unknown_assignment,
        width=width,
        key1_known=key1_known,
        key2=key2,
        key3=key3,
        plaintext_words=plaintext_words,
    )
    control_words = list(target_words)
    control_words[-1] ^= 1
    target_raw = np.array(target_words, dtype="<u4").tobytes()
    control_raw = np.array(control_words, dtype="<u4").tobytes()
    outer_bits = params["outer_bits"]
    public_challenge = {
        "cipher": "RC5-32/12/16",
        "rounds": FULL_ROUNDS,
        "plaintext_blocks": PLAINTEXT_BLOCKS,
        "plaintext_words_ab_order": plaintext_words,
        "target_ciphertext_words_ab_order": target_words,
        "control_ciphertext_words_ab_order": control_words,
        "target_ciphertext_little_u32_sha256": _sha256(target_raw),
        "control_ciphertext_little_u32_sha256": _sha256(control_raw),
        "known_material_derivation_label": known_material_label,
        "known_material_derivation_sha256": known_material_sha256,
        "known_key1": key1_known,
        "known_key1_mask": params["key1_known_mask"],
        "known_key2": key2,
        "known_key3": key3,
        "unknown_key0_bits": 32,
        "unknown_key1_low_bits": outer_bits,
        "unknown_assignment_bits": width,
        "known_master_key_bits": params["known_key_bits"],
        "candidate_encoding": (
            f"assignment=(key1_low{outer_bits}<<32)|key0"
            if outer_bits
            else "assignment=key0"
        ),
        "unknown_assignment_included": False,
        "unknown_key0_included": False,
        "unknown_key1_low_bits_included": False,
        "control_relation": "target_ciphertext_final_word_xor_0x00000001",
    }
    public_challenge_sha256 = _canonical_sha256(public_challenge)
    execution_plan = {
        "primitive": "RC5-32/12/16_block_cipher",
        "rounds": FULL_ROUNDS,
        "unknown_key_bits": width,
        "known_key_bits": params["known_key_bits"],
        "known_plaintext_ciphertext_pairs": PLAINTEXT_BLOCKS,
        "filter_output_bits": FILTER_BITS,
        "logical_candidate_count": params["logical_candidates"],
        "outer_key1_low_bit_count": outer_bits,
        "outer_key1_slice_count": params["outer_slices"],
        "inner_key0_candidate_count_per_slice": INNER_CANDIDATES,
        "combined_assignment_encoding": public_challenge["candidate_encoding"],
        "gpu_threads_per_candidate": 1,
        "gpu_logical_thread_count": params["logical_candidates"],
        "stream_candidate_count": STREAM_CANDIDATES,
        "stream_batches_per_slice": INNER_CANDIDATES // STREAM_CANDIDATES,
        "stream_batch_count": params["logical_candidates"] // STREAM_CANDIDATES,
        "result_capacity_per_batch": 64,
        "complete_domain_required": True,
        "early_stop_used": False,
        "checkpoint_resume_enabled": True,
        "persistent_host_process": True,
        "host_reconfiguration_per_outer_slice": True,
        "runtime_shader_compilation": True,
        "full_confirmation": (
            "independent_Python_RC5-32/12/16_all_two_blocks_all_128_output_bits"
        ),
        "control_target_required": True,
        "fresh_public_challenge": True,
        "unknown_assignment_available_to_runner_before_execution": False,
        "volatile_wallclock_excluded_from_success_rule": True,
    }
    return {
        "schema": f"rc5-32-12-16-metal-width{width}-recovery-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_any_A248_candidate_execution",
        "primary_sources": {
            "algorithm_and_test_vectors": "https://www.rfc-editor.org/rfc/rfc2040",
        },
        "anchors": {
            "qualification": {
                "attempt_id": QUALIFICATION_ATTEMPT_ID,
                "filename": qualification.name,
                "sha256": qualification_sha256,
            },
            "native_host": {
                "filename": native_source.name,
                "sha256": native_source_sha256,
            },
        },
        "qualification_launch_gate": qualification_payload["launch_gate"],
        "public_challenge": public_challenge,
        "public_challenge_sha256": public_challenge_sha256,
        "execution_plan": execution_plan,
        "execution_plan_sha256": _canonical_sha256(execution_plan),
        "prospective_prediction": {
            "claim_type": f"fresh_fullround_{width}_bit_residual_key_recovery",
            "complete_domain_will_be_executed": True,
            "expected_unique_exact_assignment": True,
            "expected_control_exact_assignments": 0,
            "success_requires_independent_two_block_confirmation": True,
            "asymptotic_search_advantage_claimed": False,
        },
        "required_validation_gates": {
            "pre_target_RFC2040_KATs_passed": True,
            "pre_target_scalar_Metal_cross_gate_passed": True,
            "pre_target_uint32_boundary_gate_passed": True,
            "pre_target_selected_width_two_hour_gate_passed": True,
            "candidate_execution_against_public_A248_target_before_freeze": False,
            "all_assignments_must_execute": True,
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
            "A248_candidate_outcomes_used_before_protocol_freeze": False,
            "benchmark_outcome_used_only_to_select_width_and_batch_size": True,
        },
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument("--output", type=Path)
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
    qualification_payload = json.loads(args.qualification.read_text())
    width = _qualification_gate(qualification_payload)
    output = args.output or (
        research_root
        / "configs"
        / f"rc5_32_12_16_metal_width{width}_recovery_v1.json"
    )
    if output.exists():
        raise FileExistsError(f"A248 protocol already exists: {output}")
    protocol = build_protocol(
        qualification=args.qualification, native_source=args.native_source
    )
    _atomic_json(output, protocol)
    print(
        json.dumps(
            {
                "output": str(output),
                "protocol_sha256": _file_sha256(output),
                "public_challenge_sha256": protocol["public_challenge_sha256"],
                "unknown_assignment_in_output": False,
                "protocol_state": protocol["protocol_state"],
                "selected_width": width,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
