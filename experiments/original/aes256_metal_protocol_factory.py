#!/usr/bin/env python3
"""Prospective fresh-challenge factory for full-round FIPS-197 AES-256.

Importing this module is side-effect free.  A challenge can be frozen only by
an explicit CLI acknowledgement after a retained Metal qualification artifact
passes all content, semantic, endian, resource-cap, and launch-projection gates.
No qualification or candidate execution is initiated here.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import secrets
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from arx_carry_leak.aes256_reference import (
    FIPS197_URL,
    LOCAL_INDEPENDENT_REFERENCE,
    ROUNDS,
    apply_low_residual_bits,
    encrypt_blocks,
    key_words_big_endian,
    zero_low_residual_bits,
)

SCHEMA_PREFIX = "aes256-fips197-metal"
ATTEMPT_ID = "AES256R1"
QUALIFICATION_ATTEMPT_ID = "AES256Q1"
QUALIFICATION_SCHEMA = "aes256-fips197-metal-qualification-v1"
QUALIFICATION_STAGE = "AES256_FIPS197_METAL_PRE_TARGET_QUALIFICATION"
NATIVE_SOURCE_FILENAME = "aes256_metal_native.swift"
QUALIFICATION_SOURCE_FILENAME = "aes256_metal_qualification.py"
REFERENCE_SOURCE_FILENAME = "aes256_reference.py"
RECOVERY_SOURCE_FILENAME = "aes256_metal_recovery.py"
MIN_RESIDUAL_WIDTH = 32
MAX_RESIDUAL_WIDTH = 64
INNER_CANDIDATES = 1 << 32
PLAINTEXT_BLOCKS = 2
FILTER_BITS = PLAINTEXT_BLOCKS * 128
RESULT_CAPACITY = 64


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_QUALIFICATION = _import_sibling(
    QUALIFICATION_SOURCE_FILENAME, "aes256_qualification_for_protocol_factory"
)


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
        raise ValueError("AES-256 residual width must be in 32...64")
    if (
        stream_candidates < 1
        or stream_candidates >= INNER_CANDIDATES
        or stream_candidates & (stream_candidates - 1)
        or INNER_CANDIDATES % stream_candidates
    ):
        raise ValueError("AES-256 stream candidates must be a power of two below 2^32")
    outer_bits = width - 32
    residual_mask = (1 << width) - 1
    return {
        "width": width,
        "outer_bits": outer_bits,
        "known_key_bits": 256 - width,
        "logical_candidates": 1 << width,
        "outer_slices": 1 << outer_bits,
        "inner_candidates": INNER_CANDIDATES,
        "stream_candidates": stream_candidates,
        "stream_batches": (1 << width) // stream_candidates,
        "key_word6_known_mask": (0xFFFFFFFF << outer_bits) & 0xFFFFFFFF,
        "key_known_mask_256": ((1 << 256) - 1) ^ residual_mask,
    }


def _known_material(
    width: int, stream_candidates: int
) -> tuple[bytes, bytes, str, str]:
    _width_context(width, stream_candidates)
    label = f"aes256/fips197/fullround/fresh/w{width}/known-material/v1"
    raw = hashlib.shake_256(label.encode()).digest(64)
    known_key = zero_low_residual_bits(raw[:32], width)
    plaintext = raw[32:]
    if (
        len(plaintext) != 32
        or plaintext[:16] == plaintext[16:]
        or known_key == known_key[::-1]
        or plaintext == plaintext[::-1]
    ):
        raise RuntimeError("AES-256 deterministic known-material derivation gate failed")
    return known_key, plaintext, label, _sha256(raw)


def _target_for_assignment(
    assignment: int,
    *,
    width: int,
    stream_candidates: int,
    known_key: bytes,
    plaintext: bytes,
) -> bytes:
    context = _width_context(width, stream_candidates)
    if assignment < 0 or assignment >= context["logical_candidates"]:
        raise ValueError("assignment is outside the selected AES-256 residual domain")
    key = apply_low_residual_bits(known_key, assignment, width)
    return encrypt_blocks(key, plaintext)


def _qualification_gate(payload: dict[str, Any]) -> tuple[int, int]:
    launch = payload.get("launch_gate", {})
    width = launch.get("selected_width")
    stream = launch.get("selected_stream_candidate_count")
    if not isinstance(width, int) or not isinstance(stream, int):
        raise RuntimeError("AES-256 qualification did not select integer parameters")
    _width_context(width, stream)
    scalar = payload.get("cpu_kat_gate", {}).get("scalar_reference_vectors", [])
    independent = payload.get("cpu_kat_gate", {}).get("independent_numpy_vectors", [])
    sentinels = payload.get("cpu_kat_gate", {}).get(
        "nonpalindromic_orientation_and_round_key_sentinels", {}
    )
    round_key_sentinels = sentinels.get("round_key_word_sentinels", {})
    metal_vectors = payload.get("metal_kat_cross_gate", {}).get("fips197_vectors", [])
    boundary = payload.get("information_boundary", {})
    if (
        payload.get("schema") != QUALIFICATION_SCHEMA
        or payload.get("attempt_id") != QUALIFICATION_ATTEMPT_ID
        or payload.get("evidence_stage") != QUALIFICATION_STAGE
        or payload.get("metal_executed") is not True
        or payload.get("algorithm", {}).get("rounds") != ROUNDS
        or payload.get("algorithm", {}).get("block_bits") != 128
        or payload.get("algorithm", {}).get("key_bits") != 256
        or len(scalar) < 2
        or not all(row.get("pass") is True for row in scalar)
        or len(independent) < 2
        or not all(row.get("pass") is True for row in independent)
        or sentinels.get("orientation_pass") is not True
        or sentinels.get("decrypt_roundtrip_pass") is not True
        or len(round_key_sentinels) != 4
        or not all(
            row.get("pass") is True for row in round_key_sentinels.values()
        )
        or len(metal_vectors) < 2
        or not all(row.get("exact_cpu_metal_identity") is True for row in metal_vectors)
        or payload.get("metal_kat_cross_gate", {}).get("exact_cpu_metal_identity") is not True
        or payload.get("metal_boundary_mapping_gate", {}).get("exact_boundary_identity") is not True
        or payload.get("qualification_resource_cap", {}).get("cannot_occupy_gpu_for_two_minutes") is not True
        or boundary.get("production_target_selected") is not False
        or boundary.get("production_unknown_assignment_generated") is not False
        or boundary.get("production_protocol_frozen") is not False
        or boundary.get("complete_residual_key_domain_executed") is not False
        or boundary.get("benchmark_used_only_for_prospective_width_and_stream_selection")
        is not True
        or launch.get("parameters_safe_for_later_review") is not True
        or launch.get("full_domain_launch_authorized") is not False
        or width not in launch.get("selectable_widths", [])
        or float(launch.get("projected_selected_width_seconds_at_observed_minimum", 1e99))
        > float(launch.get("maximum_complete_domain_seconds", 0))
    ):
        raise RuntimeError("AES-256 retained qualification semantic gate failed")
    _QUALIFICATION.validate_metal_evidence_ledger(payload)
    return width, stream


def build_protocol(
    *,
    qualification: Path,
    qualification_source: Path,
    native_source: Path,
    reference_source: Path,
    independent_source: Path,
    recovery_source: Path,
    freeze_acknowledged: bool,
) -> dict[str, Any]:
    """Generate one fresh public relation and omit its hidden assignment."""

    if freeze_acknowledged is not True:
        raise RuntimeError("AES-256 freeze requires explicit review acknowledgement")
    qualification_payload = json.loads(qualification.read_text())
    width, stream = _qualification_gate(qualification_payload)
    metal_evidence_ledger_sha256 = (
        _QUALIFICATION.validate_metal_evidence_ledger(qualification_payload)
    )
    context = _width_context(width, stream)
    hashes = {
        "qualification": _file_sha256(qualification),
        "qualification_source": _file_sha256(qualification_source),
        "native_source": _file_sha256(native_source),
        "cpu_reference": _file_sha256(reference_source),
        "independent_numpy_reference": _file_sha256(independent_source),
        "prospective_recovery": _file_sha256(recovery_source),
        "protocol_factory": _file_sha256(Path(__file__)),
    }
    retained_anchors = qualification_payload.get("content_anchors", {})
    if (
        retained_anchors.get("qualification_source", {}).get("sha256")
        != hashes["qualification_source"]
        or retained_anchors.get("native_source", {}).get("sha256")
        != hashes["native_source"]
        or retained_anchors.get("cpu_reference", {}).get("sha256")
        != hashes["cpu_reference"]
        or retained_anchors.get("local_independent_numpy_reference", {}).get("path")
        != LOCAL_INDEPENDENT_REFERENCE
        or retained_anchors.get("local_independent_numpy_reference", {}).get("sha256")
        != hashes["independent_numpy_reference"]
    ):
        raise RuntimeError("AES-256 qualification/factory content hashes differ")

    known_key, plaintext, material_label, material_sha256 = _known_material(width, stream)
    hidden_assignment = secrets.randbits(width)
    target = _target_for_assignment(
        hidden_assignment,
        width=width,
        stream_candidates=stream,
        known_key=known_key,
        plaintext=plaintext,
    )
    control_buffer = bytearray(target)
    control_buffer[-1] ^= 0x01
    control = bytes(control_buffer)
    known_words = key_words_big_endian(known_key)
    public_challenge = {
        "algorithm": "AES-256",
        "standard": "FIPS_197",
        "rounds": ROUNDS,
        "block_bits": 128,
        "plaintext_blocks": PLAINTEXT_BLOCKS,
        "plaintext_hex": plaintext.hex(),
        "known_key_zeroed_residual_hex": known_key.hex(),
        "known_key_words_big_endian": list(known_words),
        "known_key_mask_hex": context["key_known_mask_256"].to_bytes(32, "big").hex(),
        "known_key_word6_mask": context["key_word6_known_mask"],
        "target_ciphertext_hex": target.hex(),
        "control_ciphertext_hex": control.hex(),
        "target_ciphertext_sha256": _sha256(target),
        "control_ciphertext_sha256": _sha256(control),
        "filter_bits": FILTER_BITS,
        "known_material_derivation_label": material_label,
        "known_material_derivation_sha256": material_sha256,
        "unknown_assignment_bits": width,
        "known_master_key_bits": context["known_key_bits"],
        "candidate_encoding": (
            "assignment=(low_bits_of_FIPS_key_word6<<32)|FIPS_key_word7; "
            "assignment bit 0 is key byte 31 bit 0"
        ),
        "unknown_assignment_included": False,
        "hidden_assignment_included": False,
        "control_relation": "identical_relation_target_final_ciphertext_byte_xor_0x01",
    }
    execution_plan = {
        "primitive": "FIPS_197_AES_256_block_cipher",
        "rounds": ROUNDS,
        "block_bits": 128,
        "unknown_key_bits": width,
        "known_key_bits": context["known_key_bits"],
        "logical_candidate_count": context["logical_candidates"],
        "outer_key_word6_low_bit_count": context["outer_bits"],
        "outer_slice_count": context["outer_slices"],
        "inner_key_word7_candidate_count_per_slice": INNER_CANDIDATES,
        "stream_candidate_count": stream,
        "stream_batch_count": context["stream_batches"],
        "known_plaintext_ciphertext_pairs": PLAINTEXT_BLOCKS,
        "filter_bits_per_relation": FILTER_BITS,
        "factual_and_control_computed_by_same_kernel_invocation": True,
        "result_capacity_per_batch": RESULT_CAPACITY,
        "complete_domain_required": True,
        "early_stop_forbidden": True,
        "checkpoint_resume_enabled": True,
        "persistent_host_process": True,
        "host_reconfiguration_per_outer_slice": True,
        "full_confirmation": (
            "scalar_FIPS197_reference_plus_independent_NumPy_AES_all_two_blocks"
        ),
        "authentic_dotcausal_v1_required": True,
        "authentic_CausalReader_reopen_required": True,
        "materialized_inferred_closure_required": True,
        "volatile_wallclock_excluded_from_success_rule": True,
    }
    protocol = {
        "schema": f"{SCHEMA_PREFIX}-width{width}-recovery-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "qualification_attempt_id": QUALIFICATION_ATTEMPT_ID,
        "protocol_state": "frozen_after_review_before_any_candidate_execution",
        "primary_sources": {
            "standard": FIPS197_URL,
            "local_scalar_reference": REFERENCE_SOURCE_FILENAME,
            "local_independent_reference": LOCAL_INDEPENDENT_REFERENCE,
        },
        "content_manifest": {
            name: {"filename": path.name, "sha256": hashes[name]}
            for name, path in {
                "qualification": qualification,
                "qualification_source": qualification_source,
                "native_source": native_source,
                "cpu_reference": reference_source,
                "independent_numpy_reference": independent_source,
                "prospective_recovery": recovery_source,
                "protocol_factory": Path(__file__),
            }.items()
        },
        "qualification_launch_gate": qualification_payload["launch_gate"],
        "metal_evidence_ledger_anchor": {
            "schema": _QUALIFICATION.METAL_EVIDENCE_LEDGER_SCHEMA,
            "attempt_id": QUALIFICATION_ATTEMPT_ID,
            "sha256": metal_evidence_ledger_sha256,
            "embedded_in_qualification": qualification.name,
            "provenance_scope": (
                "semantic_execution_provenance_not_hardware_attestation"
            ),
        },
        "public_challenge": public_challenge,
        "public_challenge_sha256": _canonical_sha256(public_challenge),
        "execution_plan": execution_plan,
        "execution_plan_sha256": _canonical_sha256(execution_plan),
        "prospective_prediction": {
            "claim_type": f"fresh_fullround_{width}_bit_residual_key_recovery",
            "complete_domain_will_be_executed": True,
            "expected_unique_exact_assignment": True,
            "expected_control_exact_assignments": 0,
            "success_requires_two_independent_CPU_confirmations": True,
            "asymptotic_search_advantage_claimed": False,
        },
        "required_validation_gates": {
            "FIPS197_KATs_passed_before_freeze": True,
            "independent_NumPy_identity_passed_before_freeze": True,
            "CPU_Metal_two_block_identity_passed_before_freeze": True,
            "endian_boundary_mapping_passed_before_freeze": True,
            "selected_width_two_hour_projection_passed": True,
            "hash_bound_actual_Metal_evidence_ledger_passed": True,
            "review_acknowledged_before_freeze": True,
            "all_assignments_must_execute": True,
            "early_stop_forbidden": True,
            "one_bit_flipped_matched_control_required": True,
            "authentic_dotcausal_v1_required": True,
            "authentic_CausalReader_reopen_required": True,
        },
        "information_boundary": {
            "unknown_assignment_generated_once_from_os_randomness": True,
            "unknown_assignment_used_only_to_construct_public_ciphertexts": True,
            "unknown_assignment_in_protocol_or_source": False,
            "unknown_assignment_logged_or_returned_by_builder": False,
            "builder_process_must_exit_before_runner_construction": True,
            "unknown_assignment_available_to_runner_before_execution": False,
            "candidate_outcomes_used_before_protocol_freeze": False,
            "benchmark_used_only_to_select_width_and_stream_size": True,
        },
    }
    hidden_assignment = None
    target = b""
    control_buffer.clear()
    del hidden_assignment, target, control_buffer
    forbidden = {"unknown_assignment_value", "hidden_assignment", "secret_assignment"}
    if forbidden & set(public_challenge):
        raise RuntimeError("AES-256 hidden assignment leaked into the public challenge")
    return protocol


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).parents[2]
    parser.add_argument("--freeze-challenge", action="store_true")
    parser.add_argument("--review-acknowledged", action="store_true")
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--qualification-source",
        type=Path,
        default=Path(__file__).with_name(QUALIFICATION_SOURCE_FILENAME),
    )
    parser.add_argument(
        "--native-source", type=Path, default=Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    )
    parser.add_argument(
        "--reference-source",
        type=Path,
        default=root / "src" / "arx_carry_leak" / REFERENCE_SOURCE_FILENAME,
    )
    parser.add_argument(
        "--recovery-source",
        type=Path,
        default=Path(__file__).with_name(RECOVERY_SOURCE_FILENAME),
    )
    parser.add_argument(
        "--independent-source",
        type=Path,
        default=root / LOCAL_INDEPENDENT_REFERENCE,
    )
    args = parser.parse_args(argv)
    if not args.freeze_challenge:
        raise RuntimeError("AES-256 protocol freeze requires --freeze-challenge")
    if args.output.exists():
        raise FileExistsError(f"AES-256 protocol already exists: {args.output}")
    protocol = build_protocol(
        qualification=args.qualification,
        qualification_source=args.qualification_source,
        native_source=args.native_source,
        reference_source=args.reference_source,
        independent_source=args.independent_source,
        recovery_source=args.recovery_source,
        freeze_acknowledged=args.review_acknowledged,
    )
    _atomic_json(args.output, protocol)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "protocol_sha256": _file_sha256(args.output),
                "public_challenge_sha256": protocol["public_challenge_sha256"],
                "unknown_assignment_in_output": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
