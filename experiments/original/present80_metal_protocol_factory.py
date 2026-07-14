#!/usr/bin/env python3
"""Freeze A253 only after retained A252 selects a safe PRESENT-80 width.

Importing this module is side-effect free.  A public challenge is created only
by an explicit CLI invocation after every retained qualification gate passes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from arx_carry_leak.present80_reference import ROUNDS, encrypt_int, key_parts_to_int, key_schedule

ATTEMPT_ID = "A253"
QUALIFICATION_ATTEMPT_ID = "A252"
QUALIFICATION_SCHEMA = "present80-metal-qualification-v1"
QUALIFICATION_FILENAME = "present80_metal_qualification_v1.json"
NATIVE_SOURCE_FILENAME = "present80_metal_native.swift"
REFERENCE_SOURCE_FILENAME = "present80_reference.py"
INNER_CANDIDATES = 1 << 32
STREAM_CANDIDATES = 1 << 30
PLAINTEXT_BLOCKS = 2
FILTER_BITS = PLAINTEXT_BLOCKS * 64
FULL_ROUNDS = ROUNDS
MASTER_KEY_BITS = 80
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
        raise ValueError("A253 residual width must be in 32...64")
    outer_bits = width - 32
    middle_known_mask = (0xFFFFFFFF << outer_bits) & 0xFFFFFFFF
    return {
        "unknown_bits": width,
        "outer_bits": outer_bits,
        "known_key_bits": MASTER_KEY_BITS - width,
        "outer_slices": 1 << outer_bits,
        "logical_candidates": 1 << width,
        "middle_known_mask": middle_known_mask,
    }


def _known_material(width: int) -> tuple[int, int, list[int], str, str, str]:
    params = _width_parameters(width)
    label = f"present80/a253/fullround/w{width}/known-material/v1"
    raw = hashlib.shake_256(label.encode()).digest(24)
    middle32_known = int.from_bytes(raw[:4], "big") & params["middle_known_mask"]
    high16 = int.from_bytes(raw[4:6], "big")
    derivation_guard = raw[6:8].hex()
    plaintext_words = [
        int.from_bytes(raw[offset : offset + 4], "big")
        for offset in range(8, 24, 4)
    ]
    blocks = {
        tuple(plaintext_words[offset : offset + 2])
        for offset in range(0, len(plaintext_words), 2)
    }
    if len(blocks) != PLAINTEXT_BLOCKS:
        raise RuntimeError("A253 deterministic plaintext blocks are not distinct")
    return (
        middle32_known,
        high16,
        plaintext_words,
        label,
        _sha256(raw),
        derivation_guard,
    )


def _target_words(
    assignment: int,
    *,
    width: int,
    middle32_known: int,
    high16: int,
    plaintext_words: list[int],
) -> list[int]:
    params = _width_parameters(width)
    if assignment < 0 or assignment >= params["logical_candidates"]:
        raise ValueError(f"A253 assignment is outside the W{width} domain")
    candidate = assignment & 0xFFFFFFFF
    outer = assignment >> 32
    middle32 = middle32_known | outer
    round_keys = key_schedule(key_parts_to_int(high16, middle32, candidate))
    output: list[int] = []
    for offset in range(0, len(plaintext_words), 2):
        plaintext = (plaintext_words[offset] << 32) | plaintext_words[offset + 1]
        ciphertext = encrypt_int(plaintext, round_keys)
        output.extend([ciphertext >> 32, ciphertext & 0xFFFFFFFF])
    return output


def _qualification_gate(payload: dict[str, Any]) -> int:
    launch = payload.get("launch_gate", {})
    width = launch.get("selected_width")
    if not isinstance(width, int):
        raise RuntimeError("A252 qualification did not select an integer width")
    _width_parameters(width)
    provenance = payload.get("provenance_kat_gate", {})
    ches_vectors = provenance.get("ches_2007_scalar_vectors", [])
    iso_vector = provenance.get("iso_iec_29192_2_2012_annex_b_1_1", {})
    orientation = provenance.get("nonpalindromic_orientation_sentinels", [])
    if (
        payload.get("schema") != QUALIFICATION_SCHEMA
        or payload.get("attempt_id") != QUALIFICATION_ATTEMPT_ID
        or payload.get("evidence_stage") != "PRESENT80_METAL_PRE_TARGET_QUALIFICATION"
        or payload.get("cipher", {}).get("rounds") != FULL_ROUNDS
        or payload.get("cipher", {}).get("master_key_bits") != MASTER_KEY_BITS
        or payload.get("cipher", {}).get("final_whitening_key") != "K32"
        or len(ches_vectors) != 4
        or not all(row.get("pass") is True for row in ches_vectors)
        or iso_vector.get("pass") is not True
        or len(orientation) != 2
        or not all(row.get("pass") is True for row in orientation)
        or provenance.get("two_block_scalar_identity") is not True
        or payload.get("cross_implementation_gate", {}).get("exact_scalar_identity")
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
        raise RuntimeError("A252 qualification semantic or two-hour gate differs")
    return width


def build_protocol(
    *, qualification: Path, native_source: Path, reference_source: Path
) -> dict[str, Any]:
    """Generate one fresh public A253 challenge and discard its assignment."""

    qualification_sha256 = _file_sha256(qualification)
    qualification_payload = json.loads(qualification.read_text())
    width = _qualification_gate(qualification_payload)
    params = _width_parameters(width)
    native_source_sha256 = _file_sha256(native_source)
    reference_source_sha256 = _file_sha256(reference_source)
    if (
        qualification_payload.get("native_build", {}).get("source_sha256")
        != native_source_sha256
    ):
        raise RuntimeError("A252 qualification and PRESENT-80 native hashes differ")

    (
        middle32_known,
        high16,
        plaintext_words,
        known_material_label,
        known_material_sha256,
        known_material_guard,
    ) = _known_material(width)
    unknown_assignment = secrets.randbits(width)
    target_words = _target_words(
        unknown_assignment,
        width=width,
        middle32_known=middle32_known,
        high16=high16,
        plaintext_words=plaintext_words,
    )
    control_words = list(target_words)
    control_words[-1] ^= 1
    target_raw = b"".join(word.to_bytes(4, "big") for word in target_words)
    control_raw = b"".join(word.to_bytes(4, "big") for word in control_words)
    outer_bits = params["outer_bits"]
    public_challenge = {
        "cipher": "PRESENT-80",
        "rounds": FULL_ROUNDS,
        "final_whitening_key": "K32",
        "plaintext_blocks": PLAINTEXT_BLOCKS,
        "plaintext_words_big_endian": plaintext_words,
        "target_ciphertext_words_big_endian": target_words,
        "control_ciphertext_words_big_endian": control_words,
        "target_ciphertext_big_u32_sha256": _sha256(target_raw),
        "control_ciphertext_big_u32_sha256": _sha256(control_raw),
        "known_material_derivation_label": known_material_label,
        "known_material_derivation_sha256": known_material_sha256,
        "known_material_guard_hex": known_material_guard,
        "known_middle32": middle32_known,
        "known_middle32_mask": params["middle_known_mask"],
        "known_high16": high16,
        "unknown_low32_bits": 32,
        "unknown_middle32_low_bits": outer_bits,
        "unknown_assignment_bits": width,
        "known_master_key_bits": params["known_key_bits"],
        "candidate_encoding": (
            f"assignment=(middle32_low{outer_bits}<<32)|low32"
            if outer_bits
            else "assignment=low32"
        ),
        "unknown_assignment_included": False,
        "unknown_low32_included": False,
        "unknown_middle32_low_bits_included": False,
        "control_relation": "target_ciphertext_final_word_xor_0x00000001",
    }
    public_challenge_sha256 = _canonical_sha256(public_challenge)
    execution_plan = {
        "primitive": "PRESENT-80_block_cipher",
        "rounds": FULL_ROUNDS,
        "final_whitening_key": "K32",
        "unknown_key_bits": width,
        "known_key_bits": params["known_key_bits"],
        "known_plaintext_ciphertext_pairs": PLAINTEXT_BLOCKS,
        "filter_output_bits": FILTER_BITS,
        "logical_candidate_count": params["logical_candidates"],
        "outer_middle32_low_bit_count": outer_bits,
        "outer_middle32_slice_count": params["outer_slices"],
        "inner_low32_candidate_count_per_slice": INNER_CANDIDATES,
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
            "independent_Python_PRESENT-80_all_two_blocks_all_128_output_bits"
        ),
        "control_target_required": True,
        "fresh_public_challenge": True,
        "unknown_assignment_available_to_runner_before_execution": False,
        "volatile_wallclock_excluded_from_success_rule": True,
    }
    return {
        "schema": f"present80-metal-width{width}-recovery-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_any_A253_candidate_execution",
        "primary_sources": {
            "algorithm_and_test_vectors": (
                "https://www.iacr.org/archive/ches2007/47270450/47270450.pdf"
            ),
            "orientation_trace": "ISO/IEC 29192-2:2012 Annex B.1.1",
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
            "scalar_reference": {
                "filename": reference_source.name,
                "sha256": reference_source_sha256,
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
            "pre_target_CHES_and_ISO_KATs_passed": True,
            "pre_target_scalar_Metal_cross_gate_passed": True,
            "pre_target_uint32_boundary_gate_passed": True,
            "pre_target_selected_width_two_hour_gate_passed": True,
            "candidate_execution_against_public_A253_target_before_freeze": False,
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
            "A253_candidate_outcomes_used_before_protocol_freeze": False,
            "benchmark_outcome_used_only_to_select_width": True,
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
    parser.add_argument(
        "--reference-source",
        type=Path,
        default=research_root.parent / "src" / "arx_carry_leak" / REFERENCE_SOURCE_FILENAME,
    )
    args = parser.parse_args(argv)
    qualification_payload = json.loads(args.qualification.read_text())
    width = _qualification_gate(qualification_payload)
    output = args.output or (
        research_root / "configs" / f"present80_metal_width{width}_recovery_v1.json"
    )
    if output.exists():
        raise FileExistsError(f"A253 protocol already exists: {output}")
    protocol = build_protocol(
        qualification=args.qualification,
        native_source=args.native_source,
        reference_source=args.reference_source,
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
