#!/usr/bin/env python3
"""A256: hash-gated, resumable, complete-domain Ascon-AEAD128 recovery."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from arx_carry_leak.ascon_aead128_reference import (
    OFFICIAL_KAT_COMMIT,
    OFFICIAL_KAT_FILE_SHA256,
    SP800_232_PDF_SHA256,
    encrypt_combined,
)


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_QUAL = _import_sibling(
    "ascon_aead128_metal_qualification.py",
    "ascon_aead128_a255_qualification_for_a256",
)

ATTEMPT_ID = "A256"
QUALIFICATION_ATTEMPT_ID = "A255"
QUALIFICATION_SCHEMA = "ascon-aead128-sp800-232-metal-qualification-v1"
NATIVE_SOURCE_FILENAME = "ascon_aead128_metal_native.swift"
REFERENCE_SOURCE_FILENAME = "ascon_aead128_reference.py"
PROTOCOL_FACTORY_FILENAME = "ascon_aead128_metal_protocol_factory.py"
RESULT_CAPACITY = 64
MESSAGE_BYTES = 32
ASSOCIATED_DATA_BYTES = 17
TAG_BYTES = 16
FILTER_BITS = (MESSAGE_BYTES + TAG_BYTES) * 8
INNER_CANDIDATES = 1 << 32
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
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


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(value)
    temporary.replace(path)


def _width_context(width: int, stream_candidates: int) -> dict[str, int]:
    if width < 32 or width > 64:
        raise ValueError("A256 residual width must be in 32...64")
    if (
        stream_candidates < 1
        or stream_candidates >= 2**32
        or stream_candidates & (stream_candidates - 1)
        or INNER_CANDIDATES % stream_candidates
    ):
        raise ValueError("A256 stream size must be a power of two below 2^32")
    outer_bits = width - 32
    return {
        "width": width,
        "outer_bits": outer_bits,
        "known_key_bits": 128 - width,
        "outer_slices": 1 << outer_bits,
        "inner_candidates": INNER_CANDIDATES,
        "logical_candidates": 1 << width,
        "stream_candidates": stream_candidates,
        "stream_batches": (1 << width) // stream_candidates,
        "key_word1_known_mask": (0xFFFFFFFF << outer_bits) & 0xFFFFFFFF,
        "key_known_mask_128": ((1 << 128) - 1) ^ ((1 << width) - 1),
    }


def _known_material(
    width: int, stream_candidates: int, label: str
) -> tuple[bytes, bytes, bytes, bytes, str]:
    context = _width_context(width, stream_candidates)
    expected_label = (
        f"ascon-aead128/a256/sp800-232/fullround/w{width}/known-material/v1"
    )
    if label != expected_label:
        raise RuntimeError("A256 known-material label differs")
    raw = hashlib.shake_256(label.encode()).digest(
        16 + 16 + ASSOCIATED_DATA_BYTES + MESSAGE_BYTES
    )
    key_integer = int.from_bytes(raw[:16], "little") & context["key_known_mask_128"]
    return (
        key_integer.to_bytes(16, "little"),
        raw[16:32],
        raw[32 : 32 + ASSOCIATED_DATA_BYTES],
        raw[32 + ASSOCIATED_DATA_BYTES :],
        _sha256(raw),
    )


def _expected_execution_plan(
    context: dict[str, int], candidate_encoding: str
) -> dict[str, Any]:
    return {
        "primitive": "NIST_SP800-232_Ascon-AEAD128",
        "permutation_rounds_initial_final": 12,
        "permutation_rounds_intermediate": 8,
        "unknown_key_bits": context["width"],
        "known_key_bits": context["known_key_bits"],
        "logical_candidate_count": context["logical_candidates"],
        "outer_key_word1_low_bit_count": context["outer_bits"],
        "outer_slice_count": context["outer_slices"],
        "inner_key_word0_candidate_count_per_slice": INNER_CANDIDATES,
        "stream_candidate_count": context["stream_candidates"],
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


def _validate_challenge(challenge: dict[str, Any], context: dict[str, int]) -> None:
    width = context["width"]
    target = bytes.fromhex(str(challenge.get("target_ciphertext_and_tag_hex", "")))
    control = bytes.fromhex(
        str(challenge.get("control_ciphertext_and_tag_hex", ""))
    )
    expected_control = bytearray(target)
    if expected_control:
        expected_control[-1] ^= 0x01
    known_key, nonce, associated_data, message, material_sha256 = _known_material(
        width,
        context["stream_candidates"],
        str(challenge.get("known_material_derivation_label", "")),
    )
    words = [
        int.from_bytes(known_key[offset : offset + 4], "little")
        for offset in range(0, 16, 4)
    ]
    if (
        challenge.get("algorithm") != "Ascon-AEAD128"
        or challenge.get("standard") != "NIST_SP_800-232"
        or challenge.get("byte_semantics") != "little_endian"
        or challenge.get("legacy_submission_endian_semantics") is not False
        or challenge.get("message_bytes") != MESSAGE_BYTES
        or bytes.fromhex(str(challenge.get("message_hex", ""))) != message
        or challenge.get("associated_data_bytes") != ASSOCIATED_DATA_BYTES
        or bytes.fromhex(str(challenge.get("associated_data_hex", "")))
        != associated_data
        or bytes.fromhex(str(challenge.get("nonce_hex", ""))) != nonce
        or bytes.fromhex(
            str(challenge.get("known_key_zeroed_residual_hex", ""))
        )
        != known_key
        or challenge.get("known_key_words_little_endian") != words
        or challenge.get("known_key_word1_mask")
        != context["key_word1_known_mask"]
        or challenge.get("known_material_derivation_sha256") != material_sha256
        or challenge.get("unknown_key_word0_bits") != 32
        or challenge.get("unknown_key_word1_low_bits") != context["outer_bits"]
        or challenge.get("unknown_assignment_bits") != width
        or challenge.get("known_master_key_bits") != context["known_key_bits"]
        or challenge.get("filter_bits") != FILTER_BITS
        or len(target) != MESSAGE_BYTES + TAG_BYTES
        or control != bytes(expected_control)
        or _sha256(target) != challenge.get("target_ciphertext_and_tag_sha256")
        or _sha256(control) != challenge.get("control_ciphertext_and_tag_sha256")
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("unknown_key_word0_included") is not False
        or challenge.get("unknown_key_word1_low_bits_included") is not False
        or challenge.get("control_relation")
        != "identical_inputs_target_final_tag_byte_xor_0x01"
    ):
        raise RuntimeError("A256 public challenge semantic gate failed")


def analyze(
    *,
    protocol_path: Path,
    expected_protocol_sha256: str,
    results_dir: Path,
) -> dict[str, Any]:
    protocol_sha256 = _file_sha256(protocol_path)
    if protocol_sha256 != expected_protocol_sha256:
        raise RuntimeError("A256 frozen protocol hash differs from explicit CLI anchor")
    protocol = json.loads(protocol_path.read_text())
    plan = protocol.get("execution_plan", {})
    width = plan.get("unknown_key_bits")
    stream_candidates = plan.get("stream_candidate_count")
    if not isinstance(width, int) or not isinstance(stream_candidates, int):
        raise RuntimeError("A256 protocol has no integer width/stream parameters")
    context = _width_context(width, stream_candidates)
    challenge = protocol.get("public_challenge", {})
    expected_plan = _expected_execution_plan(
        context, str(challenge.get("candidate_encoding", ""))
    )
    manifest = protocol.get("content_manifest", {})
    qualification_anchor = manifest.get("qualification", {})
    qualification_source_anchor = manifest.get("qualification_source", {})
    native_anchor = manifest.get("native_source", {})
    reference_anchor = manifest.get("cpu_reference", {})
    factory_anchor = manifest.get("protocol_factory", {})
    recovery_anchor = manifest.get("prospective_recovery", {})
    boundary = protocol.get("information_boundary", {})
    launch = protocol.get("qualification_launch_gate", {})
    if (
        protocol.get("schema")
        != f"ascon-aead128-sp800-232-metal-width{width}-recovery-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_root_review_before_any_A256_candidate_execution"
        or protocol.get("public_challenge_sha256")
        != _canonical_sha256(challenge)
        or protocol.get("execution_plan") != expected_plan
        or protocol.get("execution_plan_sha256")
        != _canonical_sha256(expected_plan)
        or protocol.get("primary_sources", {}).get("standard_pdf_sha256")
        != SP800_232_PDF_SHA256
        or protocol.get("primary_sources", {}).get("official_kat_commit")
        != OFFICIAL_KAT_COMMIT
        or protocol.get("primary_sources", {}).get("official_kat_sha256")
        != OFFICIAL_KAT_FILE_SHA256
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution")
        is not False
        or boundary.get("runner_imported_or_constructed_by_builder") is not False
        or boundary.get("builder_process_must_exit_before_runner_construction")
        is not True
        or boundary.get("A256_candidate_outcomes_used_before_protocol_freeze")
        is not False
        or launch.get("selected_width") != width
        or launch.get("selected_stream_candidate_count") != stream_candidates
        or launch.get("parameters_safe_for_post_review_freeze") is not True
        or protocol.get("required_validation_gates", {}).get(
            "root_review_acknowledged_before_freeze"
        )
        is not True
    ):
        raise RuntimeError("A256 frozen protocol identity gate failed")

    qualification = results_dir / str(qualification_anchor.get("filename", ""))
    qualification_source = Path(__file__).with_name(
        str(
            qualification_source_anchor.get(
                "filename", "ascon_aead128_metal_qualification.py"
            )
        )
    )
    native_source = Path(__file__).with_name(
        str(native_anchor.get("filename", NATIVE_SOURCE_FILENAME))
    )
    reference_source = (
        Path(__file__).parents[2]
        / "src"
        / "arx_carry_leak"
        / str(reference_anchor.get("filename", REFERENCE_SOURCE_FILENAME))
    )
    factory_source = Path(__file__).with_name(
        str(factory_anchor.get("filename", PROTOCOL_FACTORY_FILENAME))
    )
    recovery_source = Path(__file__).with_name(
        str(recovery_anchor.get("filename", Path(__file__).name))
    )
    if (
        qualification_anchor.get("attempt_id") != QUALIFICATION_ATTEMPT_ID
        or _file_sha256(qualification) != qualification_anchor.get("sha256")
        or qualification_source.name != "ascon_aead128_metal_qualification.py"
        or _file_sha256(qualification_source)
        != qualification_source_anchor.get("sha256")
        or native_source.name != NATIVE_SOURCE_FILENAME
        or _file_sha256(native_source) != native_anchor.get("sha256")
        or reference_source.name != REFERENCE_SOURCE_FILENAME
        or _file_sha256(reference_source) != reference_anchor.get("sha256")
        or factory_source.name != PROTOCOL_FACTORY_FILENAME
        or _file_sha256(factory_source) != factory_anchor.get("sha256")
        or recovery_source.name != Path(__file__).name
        or _file_sha256(recovery_source) != recovery_anchor.get("sha256")
    ):
        raise RuntimeError("A256 content manifest hash gate failed")
    qualification_payload = json.loads(qualification.read_text())
    if (
        qualification_payload.get("schema") != QUALIFICATION_SCHEMA
        or qualification_payload.get("attempt_id") != QUALIFICATION_ATTEMPT_ID
        or qualification_payload.get("official_kat_gate", {}).get(
            "all_official_kat_gates_passed"
        )
        is not True
        or qualification_payload.get("cross_implementation_gate", {}).get(
            "exact_cpu_metal_identity"
        )
        is not True
        or qualification_payload.get("boundary_mapping_gate", {}).get(
            "exact_boundary_identity"
        )
        is not True
        or qualification_payload.get("launch_gate", {}).get("selected_width")
        != width
        or qualification_payload.get("launch_gate", {}).get(
            "selected_stream_candidate_count"
        )
        != stream_candidates
    ):
        raise RuntimeError("A256 retained A255 qualification gate failed")
    _validate_challenge(challenge, context)
    return {
        "protocol": protocol,
        "protocol_path": str(protocol_path),
        "public_challenge": challenge,
        "execution_plan": expected_plan,
        "qualification": qualification_payload,
        "context": context,
        "content_paths": {
            "qualification": str(qualification),
            "qualification_source": str(qualification_source),
            "native_source": str(native_source),
            "cpu_reference": str(reference_source),
            "protocol_factory": str(factory_source),
            "recovery_source": str(recovery_source),
        },
        "anchor_gates": {
            "protocol_sha256": protocol_sha256,
            "public_challenge_sha256": _canonical_sha256(challenge),
            "qualification_sha256": qualification_anchor["sha256"],
            "qualification_source_sha256": qualification_source_anchor["sha256"],
            "native_source_sha256": native_anchor["sha256"],
            "cpu_reference_sha256": reference_anchor["sha256"],
            "protocol_factory_sha256": factory_anchor["sha256"],
            "recovery_source_sha256": recovery_anchor["sha256"],
        },
        "candidate_execution_started": False,
    }


def _challenge_bytes(challenge: dict[str, Any]) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    return (
        bytes.fromhex(challenge["message_hex"]),
        bytes.fromhex(challenge["associated_data_hex"]),
        bytes.fromhex(challenge["nonce_hex"]),
        bytes.fromhex(challenge["target_ciphertext_and_tag_hex"]),
        bytes.fromhex(challenge["control_ciphertext_and_tag_hex"]),
    )


def _known_key_words(challenge: dict[str, Any]) -> list[int]:
    values = [int(value) for value in challenge["known_key_words_little_endian"]]
    if len(values) != 4:
        raise RuntimeError("A256 public known key must contain four words")
    return values


def _configure_outer(
    host: Any,
    challenge: dict[str, Any],
    context: dict[str, int],
    outer: int,
    *,
    target: bytes | None = None,
    control: bytes | None = None,
) -> None:
    if outer < 0 or outer >= context["outer_slices"]:
        raise ValueError("A256 outer assignment is outside the frozen domain")
    message, associated_data, nonce, public_target, public_control = _challenge_bytes(
        challenge
    )
    words = _known_key_words(challenge)
    if words[0] != 0 or words[1] & ~context["key_word1_known_mask"]:
        raise RuntimeError("A256 known key residual-bit gate failed")
    host.configure(
        message=message,
        associated_data=associated_data,
        nonce=nonce,
        target=public_target if target is None else target,
        control=public_control if control is None else control,
        key_words_1_to_3=(words[1] | outer, words[2], words[3]),
    )


def _scalar_output(
    challenge: dict[str, Any], context: dict[str, int], assignment: int
) -> bytes:
    if assignment < 0 or assignment >= context["logical_candidates"]:
        raise ValueError("A256 assignment is outside the frozen domain")
    known_key = bytes.fromhex(challenge["known_key_zeroed_residual_hex"])
    key_integer = int.from_bytes(known_key, "little") | assignment
    message, associated_data, nonce, _target, _control = _challenge_bytes(challenge)
    return encrypt_combined(
        key_integer.to_bytes(16, "little"), nonce, associated_data, message
    )


def _mapping_gate(
    host: Any, challenge: dict[str, Any], context: dict[str, int]
) -> dict[str, Any]:
    cases = (
        (0, 0x0000FFFC, 8, 4, "inner_low16_carry"),
        (context["outer_slices"] // 2, 0x7FFFFFFC, 8, 4, "inner_high_bit"),
        (context["outer_slices"] - 1, 0xFFFFFFF8, 8, 7, "inner_terminal"),
    )
    rows: list[dict[str, Any]] = []
    for outer, first, count, target_offset, label in cases:
        expected = [
            _scalar_output(challenge, context, (outer << 32) | (first + index))
            for index in range(count)
        ]
        target = expected[target_offset]
        control = bytearray(target)
        control[-1] ^= 0x01
        _configure_outer(
            host,
            challenge,
            context,
            outer,
            target=target,
            control=bytes(control),
        )
        observed = host.encryptions(first, count, len(target))
        filtered = host.filter(first, count)
        expected_inner = first + target_offset
        if (
            observed != expected
            or filtered["factual"] != [expected_inner]
            or filtered["control"] != []
        ):
            raise RuntimeError(f"A256 post-freeze mapping gate failed at {label}")
        rows.append(
            {
                "label": label,
                "outer_assignment": outer,
                "first_inner_candidate": first,
                "candidate_count": count,
                "factual_inner_candidate": expected_inner,
                "factual_combined_assignment": (outer << 32) | expected_inner,
                "complete_outputs_sha256": _sha256(b"".join(observed)),
                "control_matches": [],
            }
        )
    return {
        "rows": rows,
        "logical_candidates_checked": sum(row["candidate_count"] for row in rows),
        "complete_ciphertext_and_tag_bits_checked": sum(
            row["candidate_count"] * FILTER_BITS for row in rows
        ),
        "exact_scalar_filter_and_mapping_identity": True,
    }


def _confirm(
    challenge: dict[str, Any],
    context: dict[str, int],
    expected: bytes,
    assignment: int,
    relation: str,
) -> dict[str, Any]:
    output = _scalar_output(challenge, context, assignment)
    return {
        "combined_assignment": assignment,
        "key_word0": assignment & 0xFFFFFFFF,
        "key_word1_low_bits": assignment >> 32,
        "relation": relation,
        "complete_ciphertext_and_tag_match": output == expected,
        "ciphertext_bytes_checked": MESSAGE_BYTES,
        "tag_bytes_checked": TAG_BYTES,
        "output_bits_checked": FILTER_BITS,
        "candidate_output_sha256": _sha256(output),
        "expected_output_sha256": _sha256(expected),
        "implementation": (
            "independent_Python_exact_NIST_SP800-232_little_endian_reference"
        ),
    }


def _checkpoint_fingerprint(
    challenge: dict[str, Any], context: dict[str, int], anchors: dict[str, str]
) -> dict[str, Any]:
    return {
        "schema": f"ascon-aead128-metal-width{context['width']}-checkpoint-v1",
        **anchors,
        "target_sha256": challenge["target_ciphertext_and_tag_sha256"],
        "control_sha256": challenge["control_ciphertext_and_tag_sha256"],
        "unknown_key_bits": context["width"],
        "stream_candidates": context["stream_candidates"],
        "result_capacity": RESULT_CAPACITY,
    }


def _enumerate_domain(
    *,
    host: Any,
    challenge: dict[str, Any],
    context: dict[str, int],
    anchors: dict[str, str],
    checkpoint_path: Path,
    resume: bool,
) -> dict[str, Any]:
    target = bytes.fromhex(challenge["target_ciphertext_and_tag_hex"])
    control = bytes.fromhex(challenge["control_ciphertext_and_tag_hex"])
    logical = context["logical_candidates"]
    inner_count = context["inner_candidates"]
    stream_count = context["stream_candidates"]
    next_assignment = 0
    factual_filtered: list[int] = []
    control_filtered: list[int] = []
    gpu_seconds = 0.0
    fingerprint = _checkpoint_fingerprint(challenge, context, anchors)
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("A256 checkpoint fingerprint differs")
        next_assignment = int(checkpoint["next_assignment"])
        factual_filtered = [int(value) for value in checkpoint["factual_filtered"]]
        control_filtered = [int(value) for value in checkpoint["control_filtered"]]
        gpu_seconds = float(checkpoint.get("gpu_seconds", 0.0))
        if (
            next_assignment < 0
            or next_assignment > logical
            or next_assignment % stream_count
            or any(value < 0 or value >= next_assignment for value in factual_filtered)
            or any(value < 0 or value >= next_assignment for value in control_filtered)
            or len(factual_filtered) != len(set(factual_filtered))
            or len(control_filtered) != len(set(control_filtered))
            or gpu_seconds < 0
        ):
            raise RuntimeError("A256 checkpoint progress is invalid")
    resumed_assignment_count = next_assignment
    configured_outer: int | None = None
    wall_start = time.perf_counter()
    while next_assignment < logical:
        outer = next_assignment // inner_count
        first_inner = next_assignment % inner_count
        batch_count = min(
            stream_count, inner_count - first_inner, logical - next_assignment
        )
        if configured_outer != outer:
            _configure_outer(host, challenge, context, outer)
            configured_outer = outer
        response = host.filter(first_inner, batch_count)
        for inner in response["factual"]:
            combined = outer * inner_count + int(inner)
            if combined < next_assignment or combined >= next_assignment + batch_count:
                raise RuntimeError("A256 factual filter returned out-of-batch candidate")
            factual_filtered.append(combined)
        for inner in response["control"]:
            combined = outer * inner_count + int(inner)
            if combined < next_assignment or combined >= next_assignment + batch_count:
                raise RuntimeError("A256 control filter returned out-of-batch candidate")
            control_filtered.append(combined)
        if (
            len(factual_filtered) != len(set(factual_filtered))
            or len(control_filtered) != len(set(control_filtered))
        ):
            raise RuntimeError("A256 filter returned duplicate combined assignment")
        gpu_seconds += float(response["gpu_seconds"])
        next_assignment += batch_count
        _atomic_json(
            checkpoint_path,
            {
                **fingerprint,
                "next_assignment": next_assignment,
                "logical_candidate_count": logical,
                "factual_filtered": factual_filtered,
                "control_filtered": control_filtered,
                "gpu_seconds": gpu_seconds,
                "early_stop_used": False,
                "complete_domain_executed": next_assignment == logical,
            },
        )
    wall_seconds = time.perf_counter() - wall_start
    factual_confirmations = [
        _confirm(challenge, context, target, assignment, "factual")
        for assignment in factual_filtered
    ]
    control_confirmations = [
        _confirm(challenge, context, control, assignment, "control")
        for assignment in control_filtered
    ]
    factual_full = [
        row["combined_assignment"]
        for row in factual_confirmations
        if row["complete_ciphertext_and_tag_match"]
    ]
    control_full = [
        row["combined_assignment"]
        for row in control_confirmations
        if row["complete_ciphertext_and_tag_match"]
    ]
    complete = next_assignment == logical
    return {
        "unknown_key_bits": context["width"],
        "known_key_bits": context["known_key_bits"],
        "logical_candidate_count": logical,
        "executed_assignment_count": next_assignment,
        "resumed_assignment_count": resumed_assignment_count,
        "newly_executed_assignment_count": next_assignment
        - resumed_assignment_count,
        "complete_domain_executed": complete,
        "early_stop_used": False,
        "success_evaluated_only_after_complete_domain": True,
        "factual_filter_matches": factual_filtered,
        "control_filter_matches": control_filtered,
        "factual_confirmations": factual_confirmations,
        "control_confirmations": control_confirmations,
        "factual_full_matches": factual_full,
        "control_full_matches": control_full,
        "unique_exact_assignment": complete
        and len(factual_full) == 1
        and len(factual_filtered) == 1,
        "control_target_rejected": complete
        and not control_full
        and not control_filtered,
        "independent_full_ciphertext_and_tag_confirmation_after_completion": complete,
        "gpu_seconds": gpu_seconds,
        "volatile_wall_seconds": wall_seconds,
        "volatile_candidates_per_gpu_second": (
            next_assignment / gpu_seconds if gpu_seconds > 0 else None
        ),
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        io_module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError(
                "dotcausal is required; install requirements or pass --dotcausal-src"
            ) from None
        sys.path.insert(0, str(dotcausal_src))
        io_module = importlib.import_module("dotcausal.io")
    writer = io_module.CausalWriter
    reader = io_module.CausalReader
    io_path = Path(inspect.getsourcefile(reader) or "")
    if not io_path.is_file():
        raise RuntimeError("A256 authoritative dotcausal.io source is unavailable")
    return (
        writer,
        reader,
        {
            "module": "dotcausal.io",
            "io_path": str(io_path),
            "io_sha256": _file_sha256(io_path),
        },
    )


def _build_authentic_causal(
    *, path: Path, payload: dict[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, reader_source = _load_dotcausal(dotcausal_src)
    execution = payload["execution"]
    width = int(execution["unknown_key_bits"])
    logical = int(execution["logical_candidate_count"])
    recovered_outcome = f"A256:unique_verified_{width}_bit_residual_key"
    writer = CausalWriter(api_id="a256")
    writer._rules = []
    writer.add_rule(
        name="complete_domain_plus_independent_confirmation",
        description=(
            "Complete residual-key enumeration plus independent exact ciphertext "
            "and tag confirmation establishes the recovered assignment."
        ),
        pattern=["complete_domain_enumeration", "independent_exact_confirmation"],
        conclusion="verified_residual_key_recovery",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="matched_control_separation",
        description=(
            "The identical complete search returning zero exact models for the "
            "one-bit control establishes target-specific separation."
        ),
        pattern=["same_complete_search", "zero_exact_control_models"],
        conclusion="target_specific_recovery_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A255:pre_target_Ascon_AEAD128_Metal_qualification",
        mechanism=(
            "official_KAT_plus_scalar_cross_gate_plus_residual_boundary_gate"
        ),
        outcome="A256:qualified_fullround_Ascon_AEAD128_enumerator",
        confidence=1.0,
        source=payload["anchor_gates"]["qualification_sha256"],
        quantification=(
            "NIST SP 800-232 p[12]/p[8]; 384 output bits; exact byte identity"
        ),
        evidence=json.dumps(payload["mapping_gate"], sort_keys=True),
        domain="Ascon-AEAD128 implementation equivalence",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"A256:frozen_public_W{width}_relation",
        mechanism="complete_domain_enumeration",
        outcome="A256:factual_filter_candidate_set",
        confidence=1.0,
        source=payload["execution_content_sha256"],
        quantification=f"{logical} assignments; no early stop",
        evidence=json.dumps(
            {
                "complete": execution["complete_domain_executed"],
                "filter_matches": execution["factual_filter_matches"],
            },
            sort_keys=True,
        ),
        domain="full-round residual-key enumeration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A256:factual_filter_candidate_set",
        mechanism="independent_exact_confirmation",
        outcome=recovered_outcome,
        confidence=1.0,
        source=payload["confirmation_content_sha256"],
        quantification=(
            f"{MESSAGE_BYTES} ciphertext bytes plus {TAG_BYTES} tag bytes; "
            "independent NIST SP 800-232 Python implementation"
        ),
        evidence=json.dumps(execution["factual_confirmations"], sort_keys=True),
        domain="independent key confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A256:one_bit_flipped_control_relation",
        mechanism="same_complete_search",
        outcome="A256:control_filter_candidate_set",
        confidence=1.0,
        source=payload["execution_content_sha256"],
        quantification=f"{logical} assignments; identical kernel and budget",
        evidence=json.dumps(
            {"control_filter_matches": execution["control_filter_matches"]},
            sort_keys=True,
        ),
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A256:control_filter_candidate_set",
        mechanism="zero_exact_control_models",
        outcome="A256:control_relation_rejected",
        confidence=1.0,
        source=payload["confirmation_content_sha256"],
        quantification="zero independently confirmed assignments",
        evidence=json.dumps(execution["control_confirmations"], sort_keys=True),
        domain="matched negative control",
        quality_score=1.0,
    )
    # Retain the useful closure in-file: the authoritative reader reopens the
    # amplified graph without recomputing generic inference at startup.
    writer.add_triplet(
        trigger=f"A256:frozen_public_W{width}_relation",
        mechanism="verified_complete_enumeration_and_confirmation_chain",
        outcome=recovered_outcome,
        confidence=1.0,
        source="materialized:complete_domain_plus_independent_confirmation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after complete execution and exact confirmation.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_triplet(
        trigger="A256:one_bit_flipped_control_relation",
        mechanism="verified_matched_control_chain",
        outcome="A256:control_relation_rejected",
        confidence=1.0,
        source="materialized:matched_control_separation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after the identical complete control search.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A256 verified recovery chain",
        entities=[
            f"A256:frozen_public_W{width}_relation",
            "complete_domain_enumeration",
            "A256:factual_filter_candidate_set",
            "independent_exact_confirmation",
            recovered_outcome,
        ],
    )
    writer.add_cluster(
        name="A256 matched control chain",
        entities=[
            "A256:one_bit_flipped_control_relation",
            "same_complete_search",
            "A256:control_filter_candidate_set",
            "zero_exact_control_models",
            "A256:control_relation_rejected",
        ],
    )
    writer.add_gap(
        subject=recovered_outcome,
        predicate="next_required_gain",
        expected_object_type=(
            f"prospectively_selected_strict_subset_of_W{width}_domain"
        ),
        confidence=1.0,
        suggested_queries=[
            f"Which frozen public operator ranks the held-out W{width} region early?",
            f"Can a causal reader reduce executed W{width} candidates?",
        ],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    writer_stats = writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    materialized = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a256"
        or len(explicit) != 5
        or len(all_rows) != 7
        or len(materialized) != 2
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
        or all_rows[-2]["outcome"] != recovered_outcome
        or all_rows[-1]["outcome"] != "A256:control_relation_rejected"
    ):
        raise RuntimeError("A256 authentic Causal Reader reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "file_sha256": _file_sha256(path),
        "file_bytes": path.stat().st_size,
        "magic": path.read_bytes()[:8].decode("ascii", errors="replace"),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(materialized),
        "total_triplets": len(all_rows),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "inference_recomputed_on_reader_open": False,
        "amplified_state_materialized_in_file": True,
        "integrity_verified_by_authoritative_reader": True,
        "reader_source": reader_source,
        "writer_stats": writer_stats,
        "personal_semantic_readback": {
            "recovery_chain": [
                row for row in all_rows if row["outcome"] == recovered_outcome
            ],
            "control_chain": [
                row
                for row in all_rows
                if row["outcome"] == "A256:control_relation_rejected"
            ],
            "next_gap": reader._gaps[0],
        },
    }


def _report(payload: dict[str, Any]) -> str:
    execution = payload["execution"]
    recovery = payload["recovery"]
    causal = payload["causal"]
    width = execution["unknown_key_bits"]
    return "\n".join(
        [
            f"# A256 — Ascon-AEAD128 W{width} residual-key recovery",
            "",
            "The public NIST SP 800-232 relation was searched over its complete "
            f"`2^{width}` residual-key domain without early stopping.",
            "",
            "## Result",
            "",
            f"- Complete domain: **{execution['executed_assignment_count']:,} / {execution['logical_candidate_count']:,}**",
            f"- Recovered assignment(s): **`{recovery['recovered_assignments']}`**",
            f"- Exact factual/control models: **{len(execution['factual_full_matches'])} / {len(execution['control_full_matches'])}**",
            f"- Independent confirmation: **{MESSAGE_BYTES} ciphertext bytes plus {TAG_BYTES} tag bytes ({FILTER_BITS} bits)**",
            f"- GPU / volatile wall time: **{execution['gpu_seconds']:.3f} / {execution['volatile_wall_seconds']:.3f} s**",
            "",
            "The factual and one-bit-flipped control relations used identical inputs, "
            "candidate enumeration, kernel invocations, and completion criteria.",
            "",
            "## AI-native Causal artifact",
            "",
            f"- Reader integrity gate: **{causal['integrity_verified_by_authoritative_reader']}**",
            f"- Explicit / retained inferred edges: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
            f"- Embedded rules / clusters / gaps: **{causal['embedded_rules']} / {causal['clusters']} / {causal['gaps']}**",
            "- Amplified inference state is retained in-file and reopened by the authoritative Causal Reader.",
            "",
        ]
    )


def run(
    *,
    protocol_path: Path,
    expected_protocol_sha256: str,
    results_dir: Path,
    output: Path,
    causal_output: Path,
    manifest_output: Path,
    report_output: Path,
    checkpoint_path: Path,
    build_dir: Path,
    swiftc: str,
    dotcausal_src: Path,
    resume: bool,
    execute_full_domain: bool,
) -> dict[str, Any]:
    if execute_full_domain is not True:
        raise RuntimeError(
            "A256 full-domain execution requires explicit execute_full_domain=True"
        )
    analysis = analyze(
        protocol_path=protocol_path,
        expected_protocol_sha256=expected_protocol_sha256,
        results_dir=results_dir,
    )
    executable, native_build = _QUAL._compile_native(build_dir, swiftc)
    host = _QUAL.MetalAsconAEAD128Host(executable)
    try:
        mapping_gate = _mapping_gate(
            host, analysis["public_challenge"], analysis["context"]
        )
        execution = _enumerate_domain(
            host=host,
            challenge=analysis["public_challenge"],
            context=analysis["context"],
            anchors=analysis["anchor_gates"],
            checkpoint_path=checkpoint_path,
            resume=resume,
        )
        host_identity = host.identity
    finally:
        host.close()
    if (
        execution["complete_domain_executed"] is not True
        or execution["unique_exact_assignment"] is not True
        or execution["control_target_rejected"] is not True
        or execution["early_stop_used"] is not False
        or execution[
            "independent_full_ciphertext_and_tag_confirmation_after_completion"
        ]
        is not True
    ):
        raise RuntimeError("A256 complete-domain recovery gate failed")
    width = analysis["context"]["width"]
    payload = {
        "schema": f"ascon-aead128-sp800-232-metal-width{width}-recovery-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            f"ASCON_AEAD128_SP800_232_FULLROUND_{width}BIT_RESIDUAL_KEY_RECOVERY"
        ),
        "protocol_gate": {
            "artifact_sha256": analysis["anchor_gates"]["protocol_sha256"],
            "protocol_state": analysis["protocol"]["protocol_state"],
            "information_boundary": analysis["protocol"]["information_boundary"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": analysis["anchor_gates"][
            "public_challenge_sha256"
        ],
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
        "native_build": native_build,
        "host_identity": host_identity,
        "mapping_gate": mapping_gate,
        "execution": execution,
        "execution_content_sha256": _canonical_sha256(
            {
                key: value
                for key, value in execution.items()
                if key
                not in {
                    "gpu_seconds",
                    "volatile_wall_seconds",
                    "volatile_candidates_per_gpu_second",
                }
            }
        ),
        "confirmation_content_sha256": _canonical_sha256(
            {
                "factual": execution["factual_confirmations"],
                "control": execution["control_confirmations"],
            }
        ),
        "recovery": {
            "recovered_assignments": execution["factual_full_matches"],
            "recovered_key_word0": [
                value & 0xFFFFFFFF for value in execution["factual_full_matches"]
            ],
            "recovered_key_word1_low_bits": [
                value >> 32 for value in execution["factual_full_matches"]
            ],
            "accepted_only_after_complete_domain_execution": True,
            "independent_cpu_confirmation_after_completion": True,
            "unknown_assignment_source_discarded_before_runner_construction": True,
        },
        "final_artifact_manifest_filename": manifest_output.name,
    }
    payload["causal"] = _build_authentic_causal(
        path=causal_output,
        payload=payload,
        dotcausal_src=dotcausal_src,
    )
    _atomic_json(output, payload)
    _atomic_text(report_output, _report(payload))
    final_manifest = {
        "schema": "ascon-aead128-a256-final-content-manifest-v1",
        "attempt_id": ATTEMPT_ID,
        "files": {
            "protocol": {
                "path": str(protocol_path),
                "sha256": _file_sha256(protocol_path),
            },
            "qualification": {
                "path": analysis["content_paths"]["qualification"],
                "sha256": _file_sha256(
                    Path(analysis["content_paths"]["qualification"])
                ),
            },
            "qualification_source": {
                "path": analysis["content_paths"]["qualification_source"],
                "sha256": _file_sha256(
                    Path(analysis["content_paths"]["qualification_source"])
                ),
            },
            "native_source": {
                "path": analysis["content_paths"]["native_source"],
                "sha256": _file_sha256(
                    Path(analysis["content_paths"]["native_source"])
                ),
            },
            "cpu_reference": {
                "path": analysis["content_paths"]["cpu_reference"],
                "sha256": _file_sha256(
                    Path(analysis["content_paths"]["cpu_reference"])
                ),
            },
            "protocol_factory": {
                "path": analysis["content_paths"]["protocol_factory"],
                "sha256": _file_sha256(
                    Path(analysis["content_paths"]["protocol_factory"])
                ),
            },
            "recovery_source": {
                "path": analysis["content_paths"]["recovery_source"],
                "sha256": _file_sha256(
                    Path(analysis["content_paths"]["recovery_source"])
                ),
            },
            "result": {"path": str(output), "sha256": _file_sha256(output)},
            "causal": {
                "path": str(causal_output),
                "sha256": _file_sha256(causal_output),
            },
            "report": {
                "path": str(report_output),
                "sha256": _file_sha256(report_output),
            },
        },
        "complete_domain_executed": True,
        "early_stop_used": False,
        "independent_full_confirmation_passed": True,
        "authentic_causal_reader_verified": True,
        "causal_artifact_bound_to_result": (
            payload["causal"]["file_sha256"] == _file_sha256(causal_output)
        ),
    }
    _atomic_json(manifest_output, final_manifest)
    checkpoint_path.unlink(missing_ok=True)
    reopened = json.loads(output.read_text())
    reopened_manifest = json.loads(manifest_output.read_text())
    _CausalWriter, CausalReader, _reader_source = _load_dotcausal(dotcausal_src)
    reader = CausalReader(str(causal_output), verify_integrity=True)
    if (
        reopened != payload
        or reopened_manifest != final_manifest
        or _file_sha256(output)
        != reopened_manifest["files"]["result"]["sha256"]
        or _file_sha256(causal_output)
        != reopened_manifest["files"]["causal"]["sha256"]
        or _file_sha256(causal_output) != payload["causal"]["file_sha256"]
        or len(reader.get_all_triplets(include_inferred=True)) != 7
        or reader.api_id != "a256"
        or not report_output.is_file()
    ):
        raise RuntimeError("A256 final artifact reopen gate failed")
    return {
        "output": str(output),
        "json_sha256": _file_sha256(output),
        "causal_output": str(causal_output),
        "causal_sha256": _file_sha256(causal_output),
        "manifest_output": str(manifest_output),
        "manifest_sha256": _file_sha256(manifest_output),
        "report_output": str(report_output),
        "report_sha256": _file_sha256(report_output),
        "complete_domain_executed": True,
        "logical_candidate_count": execution["logical_candidate_count"],
        "recovered_assignments": execution["factual_full_matches"],
        "control_full_matches": execution["control_full_matches"],
        "gpu_seconds": execution["gpu_seconds"],
        "volatile_wall_seconds": execution["volatile_wall_seconds"],
        "authentic_causal_reader_verified": True,
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    results_default = research_root / "results" / "v1"
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--expected-protocol-sha256", required=True)
    parser.add_argument("--results-dir", type=Path, default=results_default)
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--causal-output", type=Path)
    parser.add_argument("--manifest-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--execute-full-domain",
        action="store_true",
        help="acknowledge and start the hash-gated complete A256 domain",
    )
    args = parser.parse_args(argv)
    analysis = analyze(
        protocol_path=args.protocol,
        expected_protocol_sha256=args.expected_protocol_sha256,
        results_dir=args.results_dir,
    )
    if args.analyze_only:
        print(json.dumps(analysis, indent=2, sort_keys=True))
        return
    width = analysis["context"]["width"]
    stem = f"ascon_aead128_metal_width{width}_a256_recovery_v1"
    output = args.output or results_default / f"{stem}.json"
    causal_output = args.causal_output or results_default / f"{stem}.causal"
    manifest_output = args.manifest_output or results_default / f"{stem}.manifest.json"
    report_output = args.report_output or (
        research_root / "reports" / f"ASCON_AEAD128_METAL_WIDTH{width}_A256_RECOVERY_V1.md"
    )
    checkpoint = args.checkpoint or results_default / f"{stem}.checkpoint.json"
    build_dir = args.build_dir or (
        research_root / "build" / f"ascon_aead128_metal_width{width}_a256"
    )
    print(
        json.dumps(
            run(
                protocol_path=args.protocol,
                expected_protocol_sha256=args.expected_protocol_sha256,
                results_dir=args.results_dir,
                output=output,
                causal_output=causal_output,
                manifest_output=manifest_output,
                report_output=report_output,
                checkpoint_path=checkpoint,
                build_dir=build_dir,
                swiftc=args.swiftc,
                dotcausal_src=args.dotcausal_src,
                resume=args.resume,
                execute_full_domain=args.execute_full_domain,
            ),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
