#!/usr/bin/env python3
"""Freeze a fresh Salsa20/20 public relation after retained qualification.

Importing this module never selects a secret.  Freezing requires both a retained
A263 qualification artifact and an explicit root-review acknowledgement.
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

from arx_carry_leak.salsa20_reference import (
    BERNSTEIN_REFERENCE_SHA256,
    SPECIFICATION_PDF_SHA256,
    block,
)


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import Salsa20 factory dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ATTEMPT_ID = "A264"
QUALIFICATION_ATTEMPT_ID = "A263"
QUALIFICATION_SCHEMA = "salsa20-20-metal-qualification-v1"
QUALIFICATION_FILENAME = "salsa20_20_metal_a263_qualification_v1.json"
QUALIFICATION_SOURCE_FILENAME = "salsa20_20_metal_qualification.py"
NATIVE_SOURCE_FILENAME = "salsa20_20_metal_native.swift"
REFERENCE_SOURCE_FILENAME = "salsa20_reference.py"
RECOVERY_SOURCE_FILENAME = "salsa20_20_metal_recovery.py"
MIN_RESIDUAL_WIDTH = 32
MAX_RESIDUAL_WIDTH = 64
KEY_BITS = 256
OUTPUT_BITS = 512
INNER_CANDIDATES = 1 << 32
RESULT_CAPACITY = 64

_QUALIFICATION = _import_sibling(
    QUALIFICATION_SOURCE_FILENAME,
    "salsa20_20_qualification_for_protocol_factory",
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_sha256(value: Any) -> str:
    return _sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    )


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _width_context(width: int, stream_candidates: int) -> dict[str, int]:
    if width < MIN_RESIDUAL_WIDTH or width > MAX_RESIDUAL_WIDTH:
        raise ValueError("A264 residual width must be in 32...64")
    if (
        stream_candidates < 1
        or stream_candidates >= 1 << 32
        or stream_candidates & (stream_candidates - 1)
        or INNER_CANDIDATES % stream_candidates
    ):
        raise ValueError("A264 stream candidates must be a power of two below 2^32")
    outer_bits = width - 32
    return {
        "width": width,
        "outer_bits": outer_bits,
        "known_key_bits": KEY_BITS - width,
        "logical_candidates": 1 << width,
        "outer_slices": 1 << outer_bits,
        "inner_candidates": INNER_CANDIDATES,
        "stream_candidates": stream_candidates,
        "stream_batches": (1 << width) // stream_candidates,
        "key_word1_known_mask": (0xFFFFFFFF << outer_bits) & 0xFFFFFFFF,
        "key_known_mask_256": ((1 << KEY_BITS) - 1) ^ ((1 << width) - 1),
    }


def _known_material(width: int, stream_candidates: int) -> tuple[bytes, bytes, int, str, str]:
    context = _width_context(width, stream_candidates)
    label = f"salsa20-20/a264/fullround/w{width}/known-material/v1"
    raw = hashlib.shake_256(label.encode()).digest(48)
    key_integer = int.from_bytes(raw[:32], "little") & context["key_known_mask_256"]
    known_key = key_integer.to_bytes(32, "little")
    nonce = raw[32:40]
    counter = int.from_bytes(raw[40:48], "little")
    if known_key == known_key[::-1] or nonce == nonce[::-1]:
        raise RuntimeError("A264 deterministic known-material orientation gate failed")
    return known_key, nonce, counter, label, _sha256(raw)


def _target_for_assignment(
    assignment: int,
    *,
    width: int,
    stream_candidates: int,
    known_key: bytes,
    nonce: bytes,
    counter: int,
) -> bytes:
    context = _width_context(width, stream_candidates)
    if assignment < 0 or assignment >= context["logical_candidates"]:
        raise ValueError("A264 assignment is outside the selected domain")
    known_integer = int.from_bytes(known_key, "little")
    if known_integer & ~context["key_known_mask_256"]:
        raise ValueError("A264 known key contains nonzero residual bits")
    key = (known_integer | assignment).to_bytes(32, "little")
    return block(key, nonce, counter)


def _qualification_gate(payload: dict[str, Any]) -> tuple[int, int]:
    launch = payload.get("launch_gate", {})
    width = launch.get("selected_width")
    stream_candidates = launch.get("selected_stream_candidate_count")
    if not isinstance(width, int) or not isinstance(stream_candidates, int):
        raise RuntimeError("A263 qualification did not select integer parameters")
    _width_context(width, stream_candidates)
    scalar = payload.get("specification_kat_gate", {}).get("scalar_vectors", [])
    metal = payload.get("specification_kat_gate", {}).get("metal_256_bit_expansion_vector", {})
    if (
        payload.get("schema") != QUALIFICATION_SCHEMA
        or payload.get("attempt_id") != QUALIFICATION_ATTEMPT_ID
        or payload.get("recovery_attempt_id") != ATTEMPT_ID
        or payload.get("evidence_stage") != "SALSA20_20_METAL_PRE_TARGET_QUALIFICATION"
        or payload.get("metal_executed") is not True
        or payload.get("full_domain_launched") is not False
        or payload.get("algorithm", {}).get("rounds") != 20
        or payload.get("algorithm", {}).get("key_bits") != KEY_BITS
        or payload.get("algorithm", {}).get("byte_semantics") != "Bernstein_little_endian"
        or len(scalar) != 2
        or not all(row.get("pass") is True for row in scalar)
        or metal.get("exact_cpu_metal_identity") is not True
        or payload.get("cross_implementation_gate", {}).get("exact_cpu_metal_identity") is not True
        or payload.get("boundary_mapping_gate", {}).get("exact_boundary_identity") is not True
        or payload.get("qualification_resource_cap", {}).get("cannot_occupy_gpu_for_two_minutes")
        is not True
        or payload.get("qualification_resource_cap", {}).get("deadline_covers_ready_wait")
        is not True
        or payload.get("qualification_resource_cap", {}).get("deadline_covers_every_response_wait")
        is not True
        or payload.get("information_boundary", {}).get("production_target_selected") is not False
        or payload.get("information_boundary", {}).get("production_protocol_frozen") is not False
        or launch.get("parameters_safe_for_post_review_freeze") is not True
        or launch.get("selected_width_under_two_hours") is not True
        or launch.get("full_domain_launch_authorized") is not False
        or launch.get("projection_rate_basis") != "minimum_end_to_end_candidates_per_second"
        or float(launch.get("projected_selected_width_seconds_at_observed_minimum", 1e99))
        > float(launch.get("maximum_complete_domain_seconds", 0))
    ):
        raise RuntimeError("A263 retained qualification semantic gate failed")
    _QUALIFICATION.validate_metal_evidence_ledger(payload)
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
    """Generate a public relation and destroy the in-process secret reference."""

    if root_review_acknowledged is not True:
        raise RuntimeError("A264 freeze requires explicit root review acknowledgement")
    qualification_sha256 = _file_sha256(qualification)
    qualification_payload = json.loads(qualification.read_text())
    width, stream_candidates = _qualification_gate(qualification_payload)
    metal_evidence_ledger_sha256 = _QUALIFICATION.validate_metal_evidence_ledger(
        qualification_payload
    )
    context = _width_context(width, stream_candidates)
    content = qualification_payload.get("content_anchors", {})
    expected_hashes = {
        "qualification_source": _file_sha256(qualification_source),
        "native_source": _file_sha256(native_source),
        "cpu_reference": _file_sha256(reference_source),
        "protocol_factory": _file_sha256(Path(__file__)),
        "recovery_source": _file_sha256(recovery_source),
    }
    if any(
        content.get(name, {}).get("sha256") != digest for name, digest in expected_hashes.items()
    ):
        raise RuntimeError("A263/A264 local content anchor gate failed")
    if (
        content.get("primary_specification", {}).get("pdf_sha256") != SPECIFICATION_PDF_SHA256
        or content.get("bernstein_reference", {}).get("sha256") != BERNSTEIN_REFERENCE_SHA256
    ):
        raise RuntimeError("A263/A264 external provenance anchor gate failed")

    known_key, nonce, counter, material_label, material_sha256 = _known_material(
        width, stream_candidates
    )
    hidden_assignment = secrets.randbits(width)
    target = _target_for_assignment(
        hidden_assignment,
        width=width,
        stream_candidates=stream_candidates,
        known_key=known_key,
        nonce=nonce,
        counter=counter,
    )
    control = target[:-1] + bytes([target[-1] ^ 1])
    key_words = [
        int.from_bytes(known_key[offset : offset + 4], "little") for offset in range(0, 32, 4)
    ]
    public_challenge = {
        "algorithm": "Salsa20/20",
        "rounds": 20,
        "key_bits": KEY_BITS,
        "nonce_bits": 64,
        "counter_bits": 64,
        "byte_semantics": "Bernstein_little_endian",
        "known_key_zeroed_residual_hex": known_key.hex(),
        "known_key_words_little_endian": key_words,
        "known_key_mask_hex_little_endian_integer": context["key_known_mask_256"]
        .to_bytes(32, "little")
        .hex(),
        "known_key_word1_mask": context["key_word1_known_mask"],
        "nonce_hex": nonce.hex(),
        "counter": counter,
        "counter_words_little_endian": [counter & 0xFFFFFFFF, counter >> 32],
        "target_block_hex": target.hex(),
        "control_block_hex": control.hex(),
        "target_block_sha256": _sha256(target),
        "control_block_sha256": _sha256(control),
        "filter_bits": OUTPUT_BITS,
        "known_material_derivation_label": material_label,
        "known_material_derivation_sha256": material_sha256,
        "unknown_key_word0_bits": 32,
        "unknown_key_word1_low_bits": context["outer_bits"],
        "unknown_assignment_bits": width,
        "known_master_key_bits": context["known_key_bits"],
        "candidate_encoding": (
            f"assignment=(key_word1_low{context['outer_bits']}_bits<<32)|key_word0_little_endian"
            if context["outer_bits"]
            else "assignment=key_word0_little_endian"
        ),
        "unknown_assignment_included": False,
        "unknown_key_word0_included": False,
        "unknown_key_word1_low_bits_included": False,
        "control_relation": "identical_input_target_final_block_bit_xor_0x01",
    }
    public_challenge_sha256 = _canonical_sha256(public_challenge)
    execution_plan = {
        "primitive": "Salsa20/20_stream_block_function",
        "rounds": 20,
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
        "filter_output_bits": OUTPUT_BITS,
        "factual_and_control_computed_by_same_kernel_invocation": True,
        "result_capacity_per_batch": RESULT_CAPACITY,
        "complete_domain_required": True,
        "early_stop_used": False,
        "early_stop_forbidden": True,
        "checkpoint_resume_enabled": True,
        "persistent_host_process": True,
        "host_reconfiguration_per_outer_slice": True,
        "runtime_shader_compilation": True,
        "independent_confirmation": (
            "separate_direct_schedule_Python_Salsa20/20_full_512_bit_block"
        ),
        "control_target_required": True,
        "fresh_public_challenge": True,
        "unknown_assignment_available_to_runner_before_execution": False,
        "volatile_wallclock_excluded_from_success_rule": True,
    }
    protocol = {
        "schema": f"salsa20-20-metal-width{width}-recovery-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "qualification_attempt_id": QUALIFICATION_ATTEMPT_ID,
        "protocol_state": "frozen_before_any_A264_candidate_execution",
        "primary_sources": {
            "specification": "https://cr.yp.to/snuffle/spec.pdf",
            "reference_implementation": ("https://cr.yp.to/snuffle/salsa20/ref/salsa20.c"),
        },
        "anchors": {
            "qualification": {
                "filename": qualification.name,
                "sha256": qualification_sha256,
            },
            **{
                name: {"filename": path.name, "sha256": expected_hashes[name]}
                for name, path in {
                    "qualification_source": qualification_source,
                    "native_source": native_source,
                    "cpu_reference": reference_source,
                    "protocol_factory": Path(__file__),
                    "recovery_source": recovery_source,
                }.items()
            },
        },
        "qualification_launch_gate": qualification_payload["launch_gate"],
        "metal_evidence_ledger_anchor": {
            "schema": _QUALIFICATION.METAL_EVIDENCE_LEDGER_SCHEMA,
            "sha256": metal_evidence_ledger_sha256,
            "embedded_in_qualification": qualification.name,
            "provenance_scope": ("semantic_execution_provenance_not_hardware_attestation"),
        },
        "public_challenge": public_challenge,
        "public_challenge_sha256": public_challenge_sha256,
        "execution_plan": execution_plan,
        "execution_plan_sha256": _canonical_sha256(execution_plan),
        "prospective_prediction": {
            "claim_type": f"fresh_fullround_{width}_bit_residual_key_recovery",
            "complete_domain_will_be_executed": True,
            "expected_unique_exact_assignment": True,
            "expected_control_exact_assignments": 0,
            "success_requires_independent_full_block_confirmation": True,
            "asymptotic_search_advantage_claimed": False,
        },
        "required_validation_gates": {
            "pre_target_specification_KATs_passed": True,
            "pre_target_scalar_Metal_cross_gate_passed": True,
            "pre_target_uint32_boundary_gate_passed": True,
            "pre_target_selected_width_two_hour_gate_passed": True,
            "hash_bound_actual_Metal_evidence_ledger_passed": True,
            "qualification_deadline_covered_startup_and_all_reads": True,
            "width_selected_from_minimum_end_to_end_wall_throughput": True,
            "candidate_execution_against_public_target_before_freeze": False,
            "all_assignments_must_execute": True,
            "early_stop_forbidden": True,
            "independent_full_block_confirmation_required": True,
            "bit_flipped_control_required": True,
            "authentic_AI_native_causal_artifact_required": True,
            "authentic_CausalReader_reopen_required": True,
        },
        "information_boundary": {
            "unknown_assignment_generated_once_from_os_randomness": True,
            "unknown_assignment_used_only_to_construct_public_block": True,
            "unknown_assignment_in_protocol_or_source": False,
            "unknown_assignment_logged_or_returned_by_protocol_builder": False,
            "unknown_assignment_available_to_runner_before_execution": False,
            "candidate_outcomes_used_before_protocol_freeze": False,
            "benchmark_outcome_used_only_to_select_width_and_batch_size": True,
            "runner_imported_or_constructed_by_builder": False,
        },
    }
    hidden_assignment = None
    del hidden_assignment
    forbidden = {
        "hidden_assignment",
        "secret_assignment",
        "unknown_assignment_value",
    }
    if forbidden & set(public_challenge):
        raise RuntimeError("A264 hidden assignment leaked into the public challenge")
    return protocol


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).parents[2]
    experiments = Path(__file__).parent
    parser.add_argument(
        "--qualification",
        type=Path,
        default=root / "research" / "results" / "v1" / QUALIFICATION_FILENAME,
    )
    parser.add_argument(
        "--qualification-source",
        type=Path,
        default=experiments / QUALIFICATION_SOURCE_FILENAME,
    )
    parser.add_argument("--native-source", type=Path, default=experiments / NATIVE_SOURCE_FILENAME)
    parser.add_argument(
        "--reference-source",
        type=Path,
        default=root / "src" / "arx_carry_leak" / REFERENCE_SOURCE_FILENAME,
    )
    parser.add_argument(
        "--recovery-source",
        type=Path,
        default=experiments / RECOVERY_SOURCE_FILENAME,
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--root-review-acknowledged", action="store_true")
    args = parser.parse_args(argv)
    qualification_payload = json.loads(args.qualification.read_text())
    width, _stream = _qualification_gate(qualification_payload)
    output = args.output or (
        root / "research" / "configs" / f"salsa20_20_metal_width{width}_recovery_v1.json"
    )
    if output.exists():
        raise FileExistsError(f"A264 protocol already exists: {output}")
    protocol = build_protocol(
        qualification=args.qualification,
        qualification_source=args.qualification_source,
        native_source=args.native_source,
        reference_source=args.reference_source,
        recovery_source=args.recovery_source,
        root_review_acknowledged=args.root_review_acknowledged,
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
