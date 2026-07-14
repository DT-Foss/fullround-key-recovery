#!/usr/bin/env python3
"""Freeze a fresh public A256 Ascon-AEAD128 challenge after A255 review.

Importing this module is side-effect free.  The CLI requires an explicit root
review acknowledgement.  The hidden assignment exists only in this builder
process, is removed from local references before return, is never serialized,
and the recovery runner is constructed only by a later independent process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from arx_carry_leak.ascon_aead128_reference import (
    OFFICIAL_KAT_COMMIT,
    OFFICIAL_KAT_FILE_SHA256,
    SP800_232_PDF_SHA256,
    encrypt_combined,
)

ATTEMPT_ID = "A256"
QUALIFICATION_ATTEMPT_ID = "A255"
QUALIFICATION_SCHEMA = "ascon-aead128-sp800-232-metal-qualification-v1"
QUALIFICATION_FILENAME = "ascon_aead128_metal_a255_qualification_v1.json"
QUALIFICATION_SOURCE_FILENAME = "ascon_aead128_metal_qualification.py"
NATIVE_SOURCE_FILENAME = "ascon_aead128_metal_native.swift"
REFERENCE_SOURCE_FILENAME = "ascon_aead128_reference.py"
RECOVERY_SOURCE_FILENAME = "ascon_aead128_metal_recovery.py"
MIN_RESIDUAL_WIDTH = 32
MAX_RESIDUAL_WIDTH = 64
INNER_CANDIDATES = 1 << 32
MESSAGE_BYTES = 32
ASSOCIATED_DATA_BYTES = 17
TAG_BYTES = 16
FILTER_BITS = (MESSAGE_BYTES + TAG_BYTES) * 8
RESULT_CAPACITY = 64


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return _sha256(raw)


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _width_context(width: int, stream_candidates: int) -> dict[str, int]:
    if width < MIN_RESIDUAL_WIDTH or width > MAX_RESIDUAL_WIDTH:
        raise ValueError("A256 residual width must be in 32...64")
    if (
        stream_candidates < 1
        or stream_candidates >= 2**32
        or stream_candidates & (stream_candidates - 1)
        or INNER_CANDIDATES % stream_candidates
    ):
        raise ValueError(
            "A256 stream candidates must be a power of two below 2^32"
        )
    outer_bits = width - 32
    return {
        "width": width,
        "outer_bits": outer_bits,
        "known_key_bits": 128 - width,
        "logical_candidates": 1 << width,
        "outer_slices": 1 << outer_bits,
        "inner_candidates": INNER_CANDIDATES,
        "stream_candidates": stream_candidates,
        "stream_batches": (1 << width) // stream_candidates,
        "key_word1_known_mask": (0xFFFFFFFF << outer_bits) & 0xFFFFFFFF,
        "key_known_mask_128": ((1 << 128) - 1) ^ ((1 << width) - 1),
    }


def _known_material(
    width: int, stream_candidates: int
) -> tuple[bytes, bytes, bytes, bytes, str, str]:
    context = _width_context(width, stream_candidates)
    label = f"ascon-aead128/a256/sp800-232/fullround/w{width}/known-material/v1"
    raw = hashlib.shake_256(label.encode()).digest(
        16 + 16 + ASSOCIATED_DATA_BYTES + MESSAGE_BYTES
    )
    key_integer = int.from_bytes(raw[:16], "little") & context["key_known_mask_128"]
    known_key = key_integer.to_bytes(16, "little")
    nonce = raw[16:32]
    associated_data = raw[32 : 32 + ASSOCIATED_DATA_BYTES]
    message = raw[32 + ASSOCIATED_DATA_BYTES :]
    if (
        len(nonce) != 16
        or len(associated_data) != ASSOCIATED_DATA_BYTES
        or len(message) != MESSAGE_BYTES
        or known_key == known_key[::-1]
        or nonce == nonce[::-1]
    ):
        raise RuntimeError("A256 deterministic known-material derivation gate failed")
    return known_key, nonce, associated_data, message, label, _sha256(raw)


def _target_for_assignment(
    assignment: int,
    *,
    width: int,
    stream_candidates: int,
    known_key: bytes,
    nonce: bytes,
    associated_data: bytes,
    message: bytes,
) -> bytes:
    context = _width_context(width, stream_candidates)
    if assignment < 0 or assignment >= context["logical_candidates"]:
        raise ValueError("A256 assignment is outside the selected domain")
    known_integer = int.from_bytes(known_key, "little")
    if known_integer & ~context["key_known_mask_128"]:
        raise ValueError("A256 known key has nonzero residual bits")
    key = (known_integer | assignment).to_bytes(16, "little")
    return encrypt_combined(key, nonce, associated_data, message)


def _qualification_gate(payload: dict[str, Any]) -> tuple[int, int]:
    launch = payload.get("launch_gate", {})
    width = launch.get("selected_width")
    stream_candidates = launch.get("selected_stream_candidate_count")
    if not isinstance(width, int) or not isinstance(stream_candidates, int):
        raise RuntimeError("A255 qualification did not select integer parameters")
    _width_context(width, stream_candidates)
    scalar_vectors = payload.get("official_kat_gate", {}).get(
        "scalar_vectors", []
    )
    metal_vectors = payload.get("official_kat_gate", {}).get("metal_vectors", [])
    if (
        payload.get("schema") != QUALIFICATION_SCHEMA
        or payload.get("attempt_id") != QUALIFICATION_ATTEMPT_ID
        or payload.get("evidence_stage")
        != "ASCON_AEAD128_SP800_232_METAL_PRE_TARGET_QUALIFICATION"
        or payload.get("algorithm", {}).get("byte_semantics")
        != "SP800-232_little_endian"
        or payload.get("algorithm", {}).get("legacy_submission_endian_semantics")
        is not False
        or len(scalar_vectors) < 4
        or not all(row.get("pass") is True for row in scalar_vectors)
        or len(metal_vectors) < 4
        or not all(row.get("exact_cpu_metal_identity") is True for row in metal_vectors)
        or payload.get("official_kat_gate", {})
        .get("nonpalindromic_orientation_sentinel", {})
        .get("pass")
        is not True
        or payload.get("cross_implementation_gate", {}).get(
            "exact_cpu_metal_identity"
        )
        is not True
        or payload.get("boundary_mapping_gate", {}).get("exact_boundary_identity")
        is not True
        or payload.get("qualification_resource_cap", {}).get(
            "cannot_occupy_gpu_for_two_minutes"
        )
        is not True
        or payload.get("information_boundary", {}).get("production_protocol_frozen")
        is not False
        or launch.get("parameters_safe_for_post_review_freeze") is not True
        or launch.get("selected_width_under_two_hours") is not True
        or launch.get("full_domain_launch_authorized") is not False
        or float(
            launch.get("projected_selected_width_seconds_at_observed_minimum", 1e99)
        )
        > float(launch.get("maximum_complete_domain_seconds", 0))
    ):
        raise RuntimeError("A255 retained qualification semantic gate failed")
    return width, stream_candidates


def build_protocol(
    *,
    qualification: Path,
    qualification_source: Path,
    native_source: Path,
    reference_source: Path,
    recovery_source: Path,
    root_review_acknowledged: bool,
) -> dict[str, Any]:
    """Build public A256 protocol and discard all hidden assignment references."""

    if root_review_acknowledged is not True:
        raise RuntimeError("A256 freeze requires explicit root review acknowledgement")
    qualification_sha256 = _file_sha256(qualification)
    qualification_payload = json.loads(qualification.read_text())
    width, stream_candidates = _qualification_gate(qualification_payload)
    context = _width_context(width, stream_candidates)
    qualification_source_sha256 = _file_sha256(qualification_source)
    native_sha256 = _file_sha256(native_source)
    reference_sha256 = _file_sha256(reference_source)
    recovery_sha256 = _file_sha256(recovery_source)
    anchors = qualification_payload.get("content_anchors", {})
    if (
        anchors.get("qualification_source", {}).get("sha256")
        != qualification_source_sha256
        or anchors.get("native_source", {}).get("sha256") != native_sha256
        or anchors.get("cpu_reference", {}).get("sha256") != reference_sha256
        or anchors.get("official_kat", {}).get("sha256")
        != OFFICIAL_KAT_FILE_SHA256
        or anchors.get("official_kat", {}).get("commit") != OFFICIAL_KAT_COMMIT
        or anchors.get("nist_standard", {}).get("pdf_sha256")
        != SP800_232_PDF_SHA256
    ):
        raise RuntimeError("A255/A256 content anchor gate failed")

    known_key, nonce, associated_data, message, material_label, material_sha256 = (
        _known_material(width, stream_candidates)
    )
    hidden_assignment = secrets.randbits(width)
    target = _target_for_assignment(
        hidden_assignment,
        width=width,
        stream_candidates=stream_candidates,
        known_key=known_key,
        nonce=nonce,
        associated_data=associated_data,
        message=message,
    )
    control = bytearray(target)
    control[-1] ^= 0x01
    control_bytes = bytes(control)
    key_words = list(int.from_bytes(known_key[offset : offset + 4], "little") for offset in range(0, 16, 4))
    public_challenge = {
        "algorithm": "Ascon-AEAD128",
        "standard": "NIST_SP_800-232",
        "byte_semantics": "little_endian",
        "legacy_submission_endian_semantics": False,
        "message_hex": message.hex(),
        "message_bytes": len(message),
        "associated_data_hex": associated_data.hex(),
        "associated_data_bytes": len(associated_data),
        "nonce_hex": nonce.hex(),
        "known_key_zeroed_residual_hex": known_key.hex(),
        "known_key_words_little_endian": key_words,
        "known_key_mask_hex_little_endian_integer": (
            context["key_known_mask_128"].to_bytes(16, "little").hex()
        ),
        "known_key_word1_mask": context["key_word1_known_mask"],
        "target_ciphertext_and_tag_hex": target.hex(),
        "control_ciphertext_and_tag_hex": control_bytes.hex(),
        "target_ciphertext_and_tag_sha256": _sha256(target),
        "control_ciphertext_and_tag_sha256": _sha256(control_bytes),
        "ciphertext_bytes": MESSAGE_BYTES,
        "tag_bytes": TAG_BYTES,
        "filter_bits": FILTER_BITS,
        "known_material_derivation_label": material_label,
        "known_material_derivation_sha256": material_sha256,
        "unknown_key_word0_bits": 32,
        "unknown_key_word1_low_bits": context["outer_bits"],
        "unknown_assignment_bits": width,
        "known_master_key_bits": context["known_key_bits"],
        "candidate_encoding": (
            f"assignment=(key_word1_low{context['outer_bits']}_bits<<32)|"
            "key_word0_little_endian"
            if context["outer_bits"]
            else "assignment=key_word0_little_endian"
        ),
        "unknown_assignment_included": False,
        "unknown_key_word0_included": False,
        "unknown_key_word1_low_bits_included": False,
        "control_relation": "identical_inputs_target_final_tag_byte_xor_0x01",
    }
    public_challenge_sha256 = _canonical_sha256(public_challenge)
    execution_plan = {
        "primitive": "NIST_SP800-232_Ascon-AEAD128",
        "permutation_rounds_initial_final": 12,
        "permutation_rounds_intermediate": 8,
        "unknown_key_bits": width,
        "known_key_bits": context["known_key_bits"],
        "logical_candidate_count": context["logical_candidates"],
        "outer_key_word1_low_bit_count": context["outer_bits"],
        "outer_slice_count": context["outer_slices"],
        "inner_key_word0_candidate_count_per_slice": INNER_CANDIDATES,
        "stream_candidate_count": stream_candidates,
        "stream_batch_count": context["stream_batches"],
        "gpu_threads_per_candidate": 1,
        "gpu_logical_thread_count": context["logical_candidates"],
        "filter_bits_per_relation": FILTER_BITS,
        "factual_and_control_computed_by_same_kernel_invocation": True,
        "result_capacity_per_batch": RESULT_CAPACITY,
        "complete_domain_required": True,
        "early_stop_used": False,
        "early_stop_forbidden": True,
        "checkpoint_resume_enabled": True,
        "persistent_host_process": True,
        "host_reconfiguration_per_outer_slice": True,
        "full_confirmation": (
            "independent_Python_SP800-232_full_32_byte_ciphertext_plus_16_byte_tag"
        ),
        "control_target_required": True,
        "authentic_dotcausal_v1_required": True,
        "authentic_CausalReader_reopen_required": True,
        "materialized_inferred_closure_required": True,
        "final_manifest_binds_causal_artifact": True,
        "volatile_wallclock_excluded_from_success_rule": True,
    }
    protocol = {
        "schema": f"ascon-aead128-sp800-232-metal-width{width}-recovery-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": (
            "frozen_after_root_review_before_any_A256_candidate_execution"
        ),
        "primary_sources": {
            "standard": "https://doi.org/10.6028/NIST.SP.800-232",
            "standard_pdf_sha256": SP800_232_PDF_SHA256,
            "official_kat_commit": OFFICIAL_KAT_COMMIT,
            "official_kat_sha256": OFFICIAL_KAT_FILE_SHA256,
        },
        "content_manifest": {
            "qualification": {
                "attempt_id": QUALIFICATION_ATTEMPT_ID,
                "filename": qualification.name,
                "sha256": qualification_sha256,
            },
            "qualification_source": {
                "filename": qualification_source.name,
                "sha256": qualification_source_sha256,
            },
            "native_source": {
                "filename": native_source.name,
                "sha256": native_sha256,
            },
            "cpu_reference": {
                "filename": reference_source.name,
                "sha256": reference_sha256,
            },
            "prospective_recovery": {
                "filename": recovery_source.name,
                "sha256": recovery_sha256,
            },
            "protocol_factory": {
                "filename": Path(__file__).name,
                "sha256": _file_sha256(Path(__file__)),
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
            "success_requires_independent_full_ciphertext_and_tag_confirmation": True,
            "asymptotic_search_advantage_claimed": False,
        },
        "required_validation_gates": {
            "A255_official_standardized_KATs_passed": True,
            "A255_nonpalindromic_orientation_sentinel_passed": True,
            "A255_CPU_Metal_complete_output_gate_passed": True,
            "A255_boundary_mapping_gate_passed": True,
            "A255_selected_width_two_hour_projection_passed": True,
            "root_review_acknowledged_before_freeze": True,
            "all_assignments_must_execute": True,
            "early_stop_forbidden": True,
            "independent_full_ciphertext_and_tag_confirmation_required": True,
            "one_bit_flipped_matched_control_required": True,
            "authentic_dotcausal_v1_required": True,
            "authentic_CausalReader_reopen_required": True,
            "materialized_inferred_closure_required": True,
            "final_manifest_must_bind_causal_artifact": True,
        },
        "information_boundary": {
            "unknown_assignment_generated_once_from_os_randomness": True,
            "unknown_assignment_used_only_to_construct_public_relation": True,
            "unknown_assignment_in_protocol_or_source": False,
            "unknown_assignment_logged_or_returned_by_protocol_builder": False,
            "unknown_assignment_local_references_discarded_before_return": True,
            "builder_process_must_exit_before_runner_construction": True,
            "runner_imported_or_constructed_by_builder": False,
            "unknown_assignment_available_to_runner_before_execution": False,
            "A256_candidate_outcomes_used_before_protocol_freeze": False,
            "benchmark_outcome_used_only_to_select_width_and_batch_size": True,
        },
    }
    # CPython cannot promise physical memory erasure for immutable objects.  The
    # enforceable boundary is process separation: remove all live references,
    # serialize only `protocol`, then exit before the runner process is started.
    hidden_assignment = None
    target = b""
    control = bytearray()
    del hidden_assignment, target, control
    if "unknown_assignment" in json.dumps(protocol, sort_keys=True):
        # Expected schema keys contain the phrase, but no value-bearing secret key
        # is permitted.  The explicit boolean fields above are safe and required.
        forbidden = {
            "unknown_assignment_value",
            "hidden_assignment",
            "secret_assignment",
        }
        if forbidden & set(public_challenge):
            raise RuntimeError("A256 hidden assignment leaked into public challenge")
    return protocol


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    reference_default = (
        Path(__file__).parents[2]
        / "src"
        / "arx_carry_leak"
        / REFERENCE_SOURCE_FILENAME
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--qualification",
        type=Path,
        default=research_root / "results" / "v1" / QUALIFICATION_FILENAME,
    )
    parser.add_argument(
        "--qualification-source",
        type=Path,
        default=Path(__file__).with_name(QUALIFICATION_SOURCE_FILENAME),
    )
    parser.add_argument(
        "--native-source",
        type=Path,
        default=Path(__file__).with_name(NATIVE_SOURCE_FILENAME),
    )
    parser.add_argument(
        "--reference-source", type=Path, default=reference_default
    )
    parser.add_argument(
        "--recovery-source",
        type=Path,
        default=Path(__file__).with_name(RECOVERY_SOURCE_FILENAME),
    )
    parser.add_argument(
        "--acknowledge-root-review",
        action="store_true",
        help="confirm root reviewed A255 and intentionally freeze a fresh A256 challenge",
    )
    args = parser.parse_args(argv)
    if not args.acknowledge_root_review:
        parser.error("A256 freeze requires --acknowledge-root-review")
    qualification_payload = json.loads(args.qualification.read_text())
    width, _stream = _qualification_gate(qualification_payload)
    output = args.output or (
        research_root
        / "configs"
        / f"ascon_aead128_metal_width{width}_a256_recovery_v1.json"
    )
    if output.exists():
        raise FileExistsError(f"A256 protocol already exists: {output}")
    protocol = build_protocol(
        qualification=args.qualification,
        qualification_source=args.qualification_source,
        native_source=args.native_source,
        reference_source=args.reference_source,
        recovery_source=args.recovery_source,
        root_review_acknowledged=True,
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
                "runner_constructed": False,
                "builder_must_exit_now": True,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
