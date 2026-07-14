#!/usr/bin/env python3
"""Hash-gated, resumable complete-domain runner for a future AES-128 record."""

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

from arx_carry_leak.aes128_reference import (
    FIPS197_URL,
    LOCAL_INDEPENDENT_REFERENCE,
    ROUNDS,
    apply_low_residual_bits,
    encrypt_blocks,
    key_words_big_endian,
    zero_low_residual_bits,
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
    "aes128_metal_qualification.py", "aes128_qualification_for_future_recovery"
)

QUALIFICATION_SCHEMA = "aes128-fips197-metal-qualification-v1"
QUALIFICATION_STAGE = "AES128_FIPS197_METAL_PRE_TARGET_QUALIFICATION"
NATIVE_SOURCE_FILENAME = "aes128_metal_native.swift"
REFERENCE_SOURCE_FILENAME = "aes128_reference.py"
QUALIFICATION_SOURCE_FILENAME = "aes128_metal_qualification.py"
PROTOCOL_FACTORY_FILENAME = "aes128_metal_protocol_factory.py"
INNER_CANDIDATES = 1 << 32
PLAINTEXT_BLOCKS = 2
FILTER_BYTES = 32
FILTER_BITS = 256
RESULT_CAPACITY = 64
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


def _width_context(width: int, stream_candidates: int) -> dict[str, int]:
    if width < 32 or width > 64:
        raise ValueError("AES-128 residual width must be in 32...64")
    if (
        stream_candidates < 1
        or stream_candidates >= INNER_CANDIDATES
        or stream_candidates & (stream_candidates - 1)
        or INNER_CANDIDATES % stream_candidates
    ):
        raise ValueError("AES-128 stream size must be a power of two below 2^32")
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
        "key_word2_known_mask": (0xFFFFFFFF << outer_bits) & 0xFFFFFFFF,
        "key_known_mask_128": ((1 << 128) - 1) ^ ((1 << width) - 1),
    }


def _known_material(width: int, stream: int, label: str) -> tuple[bytes, bytes, str]:
    _width_context(width, stream)
    expected_label = f"aes128/fips197/fullround/fresh/w{width}/known-material/v1"
    if label != expected_label:
        raise RuntimeError("AES-128 known-material label differs")
    raw = hashlib.shake_256(label.encode()).digest(48)
    return zero_low_residual_bits(raw[:16], width), raw[16:], _sha256(raw)


def _expected_execution_plan(context: dict[str, int]) -> dict[str, Any]:
    return {
        "primitive": "FIPS_197_AES_128_block_cipher",
        "rounds": ROUNDS,
        "block_bits": 128,
        "unknown_key_bits": context["width"],
        "known_key_bits": context["known_key_bits"],
        "logical_candidate_count": context["logical_candidates"],
        "outer_key_word2_low_bit_count": context["outer_bits"],
        "outer_slice_count": context["outer_slices"],
        "inner_key_word3_candidate_count_per_slice": INNER_CANDIDATES,
        "stream_candidate_count": context["stream_candidates"],
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


def _validate_challenge(challenge: dict[str, Any], context: dict[str, int]) -> None:
    known_key, plaintext, material_sha = _known_material(
        context["width"],
        context["stream_candidates"],
        str(challenge.get("known_material_derivation_label", "")),
    )
    target = bytes.fromhex(str(challenge.get("target_ciphertext_hex", "")))
    control = bytes.fromhex(str(challenge.get("control_ciphertext_hex", "")))
    expected_control = bytearray(target)
    if expected_control:
        expected_control[-1] ^= 1
    known_words = list(key_words_big_endian(known_key))
    if (
        challenge.get("algorithm") != "AES-128"
        or challenge.get("standard") != "FIPS_197"
        or challenge.get("rounds") != ROUNDS
        or challenge.get("block_bits") != 128
        or challenge.get("plaintext_blocks") != PLAINTEXT_BLOCKS
        or bytes.fromhex(str(challenge.get("plaintext_hex", ""))) != plaintext
        or bytes.fromhex(str(challenge.get("known_key_zeroed_residual_hex", "")))
        != known_key
        or challenge.get("known_key_words_big_endian") != known_words
        or challenge.get("known_key_word2_mask") != context["key_word2_known_mask"]
        or challenge.get("known_key_mask_hex")
        != context["key_known_mask_128"].to_bytes(16, "big").hex()
        or challenge.get("known_material_derivation_sha256") != material_sha
        or challenge.get("unknown_assignment_bits") != context["width"]
        or challenge.get("known_master_key_bits") != context["known_key_bits"]
        or challenge.get("filter_bits") != FILTER_BITS
        or len(target) != FILTER_BYTES
        or control != bytes(expected_control)
        or _sha256(target) != challenge.get("target_ciphertext_sha256")
        or _sha256(control) != challenge.get("control_ciphertext_sha256")
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("hidden_assignment_included") is not False
        or challenge.get("control_relation")
        != "identical_relation_target_final_ciphertext_byte_xor_0x01"
    ):
        raise RuntimeError("AES-128 public challenge semantic gate failed")


def analyze(
    *, protocol_path: Path, expected_protocol_sha256: str, results_dir: Path
) -> dict[str, Any]:
    protocol_sha = _file_sha256(protocol_path)
    if protocol_sha != expected_protocol_sha256:
        raise RuntimeError("AES-128 protocol hash differs from the explicit CLI anchor")
    protocol = json.loads(protocol_path.read_text())
    plan = protocol.get("execution_plan", {})
    width = plan.get("unknown_key_bits")
    stream = plan.get("stream_candidate_count")
    if not isinstance(width, int) or not isinstance(stream, int):
        raise RuntimeError("AES-128 protocol has no integer width/stream parameters")
    context = _width_context(width, stream)
    expected_plan = _expected_execution_plan(context)
    challenge = protocol.get("public_challenge", {})
    manifest = protocol.get("content_manifest", {})
    metal_evidence_anchor = protocol.get("metal_evidence_ledger_anchor", {})
    boundary = protocol.get("information_boundary", {})
    launch = protocol.get("qualification_launch_gate", {})
    if (
        protocol.get("schema")
        != f"aes128-fips197-metal-width{width}-recovery-protocol-v1"
        or protocol.get("protocol_state")
        != "frozen_after_review_before_any_candidate_execution"
        or protocol.get("primary_sources", {}).get("standard") != FIPS197_URL
        or protocol.get("primary_sources", {}).get("local_independent_reference")
        != LOCAL_INDEPENDENT_REFERENCE
        or protocol.get("public_challenge_sha256") != _canonical_sha256(challenge)
        or plan != expected_plan
        or protocol.get("execution_plan_sha256") != _canonical_sha256(expected_plan)
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution") is not False
        or boundary.get("builder_process_must_exit_before_runner_construction") is not True
        or boundary.get("candidate_outcomes_used_before_protocol_freeze") is not False
        or launch.get("selected_width") != width
        or launch.get("selected_stream_candidate_count") != stream
        or launch.get("parameters_safe_for_later_review") is not True
        or launch.get("full_domain_launch_authorized") is not False
        or metal_evidence_anchor.get("schema")
        != _QUAL.METAL_EVIDENCE_LEDGER_SCHEMA
        or metal_evidence_anchor.get("embedded_in_qualification")
        != manifest.get("qualification", {}).get("filename")
        or metal_evidence_anchor.get("provenance_scope")
        != "semantic_execution_provenance_not_hardware_attestation"
        or protocol.get("required_validation_gates", {}).get(
            "hash_bound_actual_Metal_evidence_ledger_passed"
        )
        is not True
        or protocol.get("required_validation_gates", {}).get(
            "review_acknowledged_before_freeze"
        )
        is not True
    ):
        raise RuntimeError("AES-128 frozen protocol identity gate failed")

    root = Path(__file__).parents[2]
    records = {
        "qualification": results_dir / str(manifest.get("qualification", {}).get("filename", "")),
        "qualification_source": Path(__file__).with_name(
            str(manifest.get("qualification_source", {}).get("filename", ""))
        ),
        "native_source": Path(__file__).with_name(
            str(manifest.get("native_source", {}).get("filename", ""))
        ),
        "cpu_reference": root
        / "src"
        / "arx_carry_leak"
        / str(manifest.get("cpu_reference", {}).get("filename", "")),
        "independent_numpy_reference": _QUAL.independent_numpy_source_path(),
        "prospective_recovery": Path(__file__).with_name(
            str(manifest.get("prospective_recovery", {}).get("filename", ""))
        ),
        "protocol_factory": Path(__file__).with_name(
            str(manifest.get("protocol_factory", {}).get("filename", ""))
        ),
    }
    expected_names = {
        "qualification_source": QUALIFICATION_SOURCE_FILENAME,
        "native_source": NATIVE_SOURCE_FILENAME,
        "cpu_reference": REFERENCE_SOURCE_FILENAME,
        "independent_numpy_reference": Path(LOCAL_INDEPENDENT_REFERENCE).name,
        "prospective_recovery": Path(__file__).name,
        "protocol_factory": PROTOCOL_FACTORY_FILENAME,
    }
    for name, path in records.items():
        record = manifest.get(name, {})
        if (
            not path.is_file()
            or _file_sha256(path) != record.get("sha256")
            or (name in expected_names and path.name != expected_names[name])
        ):
            raise RuntimeError(f"AES-128 content manifest gate failed for {name}")
    qualification = json.loads(records["qualification"].read_text())
    qualification_boundary = qualification.get("information_boundary", {})
    independent_anchor = qualification.get("content_anchors", {}).get(
        "local_independent_numpy_reference", {}
    )
    if (
        qualification.get("schema") != QUALIFICATION_SCHEMA
        or qualification.get("evidence_stage") != QUALIFICATION_STAGE
        or qualification.get("metal_executed") is not True
        or qualification.get("metal_kat_cross_gate", {}).get("exact_cpu_metal_identity")
        is not True
        or qualification.get("metal_boundary_mapping_gate", {}).get(
            "exact_boundary_identity"
        )
        is not True
        or qualification.get("launch_gate", {}).get("selected_width") != width
        or qualification.get("launch_gate", {}).get("selected_stream_candidate_count")
        != stream
        or independent_anchor.get("path") != LOCAL_INDEPENDENT_REFERENCE
        or independent_anchor.get("sha256")
        != manifest.get("independent_numpy_reference", {}).get("sha256")
        or qualification_boundary.get("production_target_selected") is not False
        or qualification_boundary.get("production_unknown_assignment_generated")
        is not False
        or qualification_boundary.get("production_protocol_frozen") is not False
        or qualification_boundary.get("complete_residual_key_domain_executed")
        is not False
        or qualification_boundary.get(
            "benchmark_used_only_for_prospective_width_and_stream_selection"
        )
        is not True
    ):
        raise RuntimeError("AES-128 retained qualification gate failed")
    metal_evidence_ledger_sha256 = _QUAL.validate_metal_evidence_ledger(
        qualification
    )
    if metal_evidence_ledger_sha256 != metal_evidence_anchor.get("sha256"):
        raise RuntimeError("AES-128 Metal evidence ledger protocol anchor differs")
    _validate_challenge(challenge, context)
    return {
        "protocol": protocol,
        "public_challenge": challenge,
        "execution_plan": expected_plan,
        "qualification": qualification,
        "context": context,
        "content_paths": {name: str(path) for name, path in records.items()},
        "anchor_gates": {
            "protocol_sha256": protocol_sha,
            "public_challenge_sha256": _canonical_sha256(challenge),
            "metal_evidence_ledger_sha256": metal_evidence_ledger_sha256,
            **{
                f"{name}_sha256": manifest[name]["sha256"]
                for name in records
            },
        },
        "candidate_execution_started": False,
    }


def _challenge_bytes(challenge: dict[str, Any]) -> tuple[bytes, bytes, bytes]:
    return (
        bytes.fromhex(challenge["plaintext_hex"]),
        bytes.fromhex(challenge["target_ciphertext_hex"]),
        bytes.fromhex(challenge["control_ciphertext_hex"]),
    )


def _known_key_words(challenge: dict[str, Any]) -> list[int]:
    values = [int(value) for value in challenge["known_key_words_big_endian"]]
    if len(values) != 4:
        raise RuntimeError("AES-128 public key must contain four FIPS words")
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
        raise ValueError("AES-128 outer assignment is outside the frozen domain")
    plaintext, public_target, public_control = _challenge_bytes(challenge)
    words = _known_key_words(challenge)
    if words[3] != 0 or words[2] & ~context["key_word2_known_mask"]:
        raise RuntimeError("AES-128 known key residual-bit gate failed")
    host.configure(
        plaintext=plaintext,
        target=public_target if target is None else target,
        control=public_control if control is None else control,
        key_words_0_to_2=(words[0], words[1], words[2] | outer),
    )


def _scalar_output(
    challenge: dict[str, Any], context: dict[str, int], assignment: int
) -> bytes:
    if assignment < 0 or assignment >= context["logical_candidates"]:
        raise ValueError("AES-128 assignment is outside the frozen domain")
    known_key = bytes.fromhex(challenge["known_key_zeroed_residual_hex"])
    key = apply_low_residual_bits(known_key, assignment, context["width"])
    return encrypt_blocks(key, bytes.fromhex(challenge["plaintext_hex"]))


def _mapping_gate(
    host: Any, challenge: dict[str, Any], context: dict[str, int]
) -> dict[str, Any]:
    cases = (
        (0, 0x0000FFFC, 8, 4, "inner_low16_carry"),
        (context["outer_slices"] // 2, 0x7FFFFFFC, 8, 4, "inner_high_bit"),
        (context["outer_slices"] - 1, 0xFFFFFFF8, 8, 7, "inner_terminal"),
    )
    rows: list[dict[str, Any]] = []
    for outer, first, count, offset, label in cases:
        expected = [
            _scalar_output(challenge, context, (outer << 32) | (first + index))
            for index in range(count)
        ]
        target = expected[offset]
        control = bytearray(target)
        control[-1] ^= 1
        _configure_outer(
            host, challenge, context, outer, target=target, control=bytes(control)
        )
        observed = host.blocks(first, count)
        filtered = host.filter(first, count)
        expected_inner = first + offset
        if (
            observed != expected
            or filtered["factual"] != [expected_inner]
            or filtered["control"]
        ):
            raise RuntimeError(f"AES-128 post-freeze mapping gate failed at {label}")
        rows.append(
            {
                "label": label,
                "outer_assignment": outer,
                "first_inner_candidate": first,
                "candidate_count": count,
                "factual_inner_candidate": expected_inner,
                "factual_combined_assignment": (outer << 32) | expected_inner,
                "outputs_sha256": _sha256(b"".join(observed)),
                "control_matches": [],
            }
        )
    return {
        "rows": rows,
        "exact_scalar_filter_and_mapping_identity": True,
        "fips197_big_endian_key_word_mapping": True,
    }


def _confirm(
    challenge: dict[str, Any],
    context: dict[str, int],
    expected: bytes,
    assignment: int,
    relation: str,
    expected_independent_source_sha256: str,
) -> dict[str, Any]:
    known_key = bytes.fromhex(challenge["known_key_zeroed_residual_hex"])
    key = apply_low_residual_bits(known_key, assignment, context["width"])
    plaintext = bytes.fromhex(challenge["plaintext_hex"])
    scalar = encrypt_blocks(key, plaintext)
    independent_source = _QUAL.independent_numpy_source_path()
    independent_source_sha256 = _file_sha256(independent_source)
    if independent_source_sha256 != expected_independent_source_sha256:
        raise RuntimeError(
            "AES-128 independent NumPy implementation hash changed before confirmation"
        )
    independent = _QUAL.independent_numpy_encrypt(key, plaintext)
    return {
        "combined_assignment": assignment,
        "relation": relation,
        "key_hex": key.hex(),
        "scalar_ciphertext_sha256": _sha256(scalar),
        "independent_ciphertext_sha256": _sha256(independent),
        "scalar_independent_identity": scalar == independent,
        "independent_source_sha256": independent_source_sha256,
        "complete_two_block_match": scalar == independent == expected,
        "output_bits_checked": FILTER_BITS,
    }


def _checkpoint_fingerprint(
    anchors: dict[str, str], context: dict[str, int]
) -> dict[str, Any]:
    return {
        "schema": "aes128-fips197-complete-domain-checkpoint-v1",
        "anchors": anchors,
        "width": context["width"],
        "logical_candidate_count": context["logical_candidates"],
        "stream_candidate_count": context["stream_candidates"],
        "candidate_encoding": "combined=(outer_word2_low_bits<<32)|inner_word3",
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
    logical = context["logical_candidates"]
    inner_count = context["inner_candidates"]
    stream_count = context["stream_candidates"]
    fingerprint = _checkpoint_fingerprint(anchors, context)
    next_assignment = 0
    factual_filtered: list[int] = []
    control_filtered: list[int] = []
    gpu_seconds = 0.0
    if checkpoint_path.exists() and not resume:
        raise FileExistsError(
            "AES-128 checkpoint exists; pass resume=True or choose a new path"
        )
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("AES-128 checkpoint anchors or domain differ")
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
            raise RuntimeError("AES-128 checkpoint progress is invalid")
    resumed_count = next_assignment
    configured_outer: int | None = None
    wall_started = time.perf_counter()
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
        for relation, destination in (
            ("factual", factual_filtered),
            ("control", control_filtered),
        ):
            for inner in response[relation]:
                combined = outer * inner_count + int(inner)
                if combined < next_assignment or combined >= next_assignment + batch_count:
                    raise RuntimeError(
                        f"AES-128 {relation} filter returned an out-of-batch candidate"
                    )
                destination.append(combined)
            if len(destination) != len(set(destination)):
                raise RuntimeError(f"AES-128 {relation} filter returned a duplicate")
        gpu_seconds += float(response["gpu_seconds"])
        next_assignment += batch_count
        _atomic_json(
            checkpoint_path,
            {
                **fingerprint,
                "next_assignment": next_assignment,
                "factual_filtered": factual_filtered,
                "control_filtered": control_filtered,
                "gpu_seconds": gpu_seconds,
                "early_stop_used": False,
                "success_evaluated_before_complete_domain": False,
                "complete_domain_executed": next_assignment == logical,
            },
        )
    wall_seconds = time.perf_counter() - wall_started
    plaintext, target, control = _challenge_bytes(challenge)
    assert len(plaintext) == FILTER_BYTES
    factual_confirmations = [
        _confirm(
            challenge,
            context,
            target,
            assignment,
            "factual",
            anchors["independent_numpy_reference_sha256"],
        )
        for assignment in factual_filtered
    ]
    control_confirmations = [
        _confirm(
            challenge,
            context,
            control,
            assignment,
            "control",
            anchors["independent_numpy_reference_sha256"],
        )
        for assignment in control_filtered
    ]
    factual_full = [
        row["combined_assignment"]
        for row in factual_confirmations
        if row["complete_two_block_match"]
    ]
    control_full = [
        row["combined_assignment"]
        for row in control_confirmations
        if row["complete_two_block_match"]
    ]
    complete = next_assignment == logical
    return {
        "unknown_key_bits": context["width"],
        "known_key_bits": context["known_key_bits"],
        "logical_candidate_count": logical,
        "executed_assignment_count": next_assignment,
        "resumed_assignment_count": resumed_count,
        "newly_executed_assignment_count": next_assignment - resumed_count,
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
        and len(factual_filtered) == 1
        and len(factual_full) == 1,
        "control_target_rejected": complete
        and not control_filtered
        and not control_full,
        "independent_two_reference_confirmation_after_completion": complete,
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
                "dotcausal is required; install project dependencies or pass --dotcausal-src"
            ) from None
        sys.path.insert(0, str(dotcausal_src))
        io_module = importlib.import_module("dotcausal.io")
    writer = io_module.CausalWriter
    reader = io_module.CausalReader
    io_path = Path(inspect.getsourcefile(reader) or "")
    if not io_path.is_file():
        raise RuntimeError("authoritative dotcausal.io source is unavailable")
    return writer, reader, {
        "module": "dotcausal.io",
        "io_path": str(io_path),
        "io_sha256": _file_sha256(io_path),
    }


def _build_authentic_causal(
    *, path: Path, payload: dict[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, reader_source = _load_dotcausal(dotcausal_src)
    execution = payload["execution"]
    width = int(execution["unknown_key_bits"])
    logical = int(execution["logical_candidate_count"])
    recovered = f"AES128:unique_verified_{width}_bit_residual_key"
    writer = CausalWriter(api_id="aes128v1")
    writer._rules = []
    writer.add_rule(
        name="complete_domain_plus_two_reference_confirmation",
        description=(
            "Complete residual-key enumeration plus exact scalar and independent "
            "NumPy confirmation establishes the recovered assignment."
        ),
        pattern=["complete_domain_enumeration", "two_reference_exact_confirmation"],
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
        trigger="AES128:pre_target_Metal_qualification",
        mechanism="FIPS197_KAT_plus_CPU_Metal_and_endian_boundary_gates",
        outcome="AES128:qualified_fullround_enumerator",
        confidence=1.0,
        source=payload["anchor_gates"]["qualification_sha256"],
        quantification="10 rounds; 2 blocks; 256 output bits; exact byte identity",
        evidence=json.dumps(payload["mapping_gate"], sort_keys=True),
        domain="AES-128 implementation equivalence",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"AES128:frozen_public_W{width}_relation",
        mechanism="complete_domain_enumeration",
        outcome="AES128:factual_filter_candidate_set",
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
        trigger="AES128:factual_filter_candidate_set",
        mechanism="two_reference_exact_confirmation",
        outcome=recovered,
        confidence=1.0,
        source=payload["confirmation_content_sha256"],
        quantification="2 blocks; 256 bits; scalar FIPS and independent NumPy AES",
        evidence=json.dumps(execution["factual_confirmations"], sort_keys=True),
        domain="independent key confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="AES128:one_bit_flipped_control_relation",
        mechanism="same_complete_search",
        outcome="AES128:control_filter_candidate_set",
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
        trigger="AES128:control_filter_candidate_set",
        mechanism="zero_exact_control_models",
        outcome="AES128:control_relation_rejected",
        confidence=1.0,
        source=payload["confirmation_content_sha256"],
        quantification="zero independently confirmed assignments",
        evidence=json.dumps(execution["control_confirmations"], sort_keys=True),
        domain="matched negative control",
        quality_score=1.0,
    )
    def add_materialized(**kwargs: Any) -> None:
        try:
            writer.add_triplet(**kwargs, is_inferred=True)
        except TypeError:
            index = writer.add_triplet(**kwargs)
            writer._triplets[index]["is_inferred"] = True

    add_materialized(
        trigger=f"AES128:frozen_public_W{width}_relation",
        mechanism="verified_complete_enumeration_and_confirmation_chain",
        outcome=recovered,
        confidence=1.0,
        source="materialized:complete_domain_plus_two_reference_confirmation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after complete execution and exact confirmation.",
        domain="AI-native retained inference",
        quality_score=1.0,
    )
    add_materialized(
        trigger="AES128:one_bit_flipped_control_relation",
        mechanism="verified_matched_control_chain",
        outcome="AES128:control_relation_rejected",
        confidence=1.0,
        source="materialized:matched_control_separation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after the identical complete control search.",
        domain="AI-native retained inference",
        quality_score=1.0,
    )
    writer.add_cluster(
        name="AES-128 verified recovery chain",
        entities=[
            f"AES128:frozen_public_W{width}_relation",
            "complete_domain_enumeration",
            "AES128:factual_filter_candidate_set",
            "two_reference_exact_confirmation",
            recovered,
        ],
    )
    writer.add_cluster(
        name="AES-128 matched control chain",
        entities=[
            "AES128:one_bit_flipped_control_relation",
            "same_complete_search",
            "AES128:control_filter_candidate_set",
            "zero_exact_control_models",
            "AES128:control_relation_rejected",
        ],
    )
    writer.add_gap(
        subject=recovered,
        predicate="next_required_gain",
        expected_object_type=f"prospectively_selected_strict_subset_of_W{width}_domain",
        confidence=1.0,
        suggested_queries=[
            f"Which frozen public operator ranks a held-out W{width} region early?",
            f"Can a causal reader reduce executed W{width} assignments?",
        ],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    writer_stats = writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    persisted_rows = []
    for row in reader._triplets:
        persisted_rows.append(
            {
                **{
                    key: value
                    for key, value in row.items()
                    if key not in {"s_idx", "m_idx", "o_idx"}
                },
                "trigger": reader.get_entity(row["s_idx"]),
                "mechanism": reader.get_entity(row["m_idx"]),
                "outcome": reader.get_entity(row["o_idx"]),
                "is_inferred": bool(row.get("is_inferred", False)),
            }
        )
    explicit = [row for row in persisted_rows if not row["is_inferred"]]
    materialized = [row for row in persisted_rows if row["is_inferred"]]
    all_rows = explicit + materialized
    if (
        reader.version != 1
        or reader.api_id != "aes128v1"
        or len(explicit) != 5
        or len(all_rows) != 7
        or len(materialized) != 2
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
        or all_rows[-2]["outcome"] != recovered
        or all_rows[-1]["outcome"] != "AES128:control_relation_rejected"
    ):
        raise RuntimeError("AES-128 authentic CausalReader reopen gate failed")
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
        "semantic_readback": {
            "recovery_chain": [row for row in all_rows if row["outcome"] == recovered],
            "control_chain": [
                row
                for row in all_rows
                if row["outcome"] == "AES128:control_relation_rejected"
            ],
            "next_gap": reader._gaps[0],
        },
    }


def run(
    *,
    protocol_path: Path,
    expected_protocol_sha256: str,
    results_dir: Path,
    output: Path,
    causal_output: Path,
    manifest_output: Path,
    checkpoint_path: Path,
    build_dir: Path,
    swiftc: str,
    dotcausal_src: Path,
    resume: bool,
    execute_full_domain: bool,
) -> dict[str, Any]:
    if execute_full_domain is not True:
        raise RuntimeError(
            "AES-128 full-domain execution requires explicit execute_full_domain=True"
        )
    analysis = analyze(
        protocol_path=protocol_path,
        expected_protocol_sha256=expected_protocol_sha256,
        results_dir=results_dir,
    )
    executable, native_build = _QUAL._compile_native(build_dir, swiftc)
    host = _QUAL.MetalAES128Host(executable)
    try:
        mapping_gate = _mapping_gate(host, analysis["public_challenge"], analysis["context"])
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
        or execution["independent_two_reference_confirmation_after_completion"]
        is not True
    ):
        raise RuntimeError("AES-128 complete-domain recovery gate failed")
    width = analysis["context"]["width"]
    payload: dict[str, Any] = {
        "schema": f"aes128-fips197-metal-width{width}-recovery-v1",
        "evidence_stage": f"AES128_FIPS197_FULLROUND_{width}BIT_RESIDUAL_KEY_RECOVERY",
        "protocol_gate": {
            "artifact_sha256": analysis["anchor_gates"]["protocol_sha256"],
            "protocol_state": analysis["protocol"]["protocol_state"],
            "information_boundary": analysis["protocol"]["information_boundary"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": analysis["anchor_gates"]["public_challenge_sha256"],
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
            "recovered_key_word3": [
                value & 0xFFFFFFFF for value in execution["factual_full_matches"]
            ],
            "recovered_key_word2_low_bits": [
                value >> 32 for value in execution["factual_full_matches"]
            ],
            "accepted_only_after_complete_domain": True,
            "candidate_identities_persisted_in_checkpoint": True,
            "success_evaluated_only_after_complete_domain": True,
        },
    }
    payload["causal"] = _build_authentic_causal(
        path=causal_output, payload=payload, dotcausal_src=dotcausal_src
    )
    _atomic_json(output, payload)
    manifest = {
        "schema": "aes128-fips197-recovery-artifact-manifest-v1",
        "files": {
            "result": {"path": str(output), "sha256": _file_sha256(output)},
            "causal": {"path": str(causal_output), "sha256": _file_sha256(causal_output)},
        },
        "protocol_sha256": analysis["anchor_gates"]["protocol_sha256"],
        "complete_domain_executed": True,
        "authentic_dotcausal_v1_reader_verified": True,
        "causal_artifact_bound_to_result": True,
    }
    _atomic_json(manifest_output, manifest)
    checkpoint_path.unlink(missing_ok=True)
    _Writer, CausalReader, _source = _load_dotcausal(dotcausal_src)
    reader = CausalReader(str(causal_output), verify_integrity=True)
    if (
        json.loads(output.read_text()) != payload
        or json.loads(manifest_output.read_text()) != manifest
        or len(reader._triplets) != 7
    ):
        raise RuntimeError("AES-128 final artifact reopen gate failed")
    return {
        "output": str(output),
        "json_sha256": _file_sha256(output),
        "causal_output": str(causal_output),
        "causal_sha256": _file_sha256(causal_output),
        "manifest_output": str(manifest_output),
        "manifest_sha256": _file_sha256(manifest_output),
        "complete_domain_executed": True,
        "logical_candidate_count": execution["logical_candidate_count"],
        "recovered_assignments": execution["factual_full_matches"],
        "control_full_matches": execution["control_full_matches"],
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
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--execute-full-domain", action="store_true")
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
    stem = f"aes128_fips197_metal_width{width}_recovery_v1"
    output = args.output or args.results_dir / f"{stem}.json"
    causal = args.causal_output or args.results_dir / f"{stem}.causal"
    manifest = args.manifest_output or args.results_dir / f"{stem}.manifest.json"
    checkpoint = args.checkpoint or args.results_dir / f"{stem}.checkpoint.json"
    build_dir = args.build_dir or research_root / "build" / stem
    print(
        json.dumps(
            run(
                protocol_path=args.protocol,
                expected_protocol_sha256=args.expected_protocol_sha256,
                results_dir=args.results_dir,
                output=output,
                causal_output=causal,
                manifest_output=manifest,
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
