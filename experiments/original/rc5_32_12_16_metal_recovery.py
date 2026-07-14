#!/usr/bin/env python3
"""A248: hash-gated, resumable full-domain RC5-32/12/16 recovery."""

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

import numpy as np

from arx_carry_leak.rc5_reference import ROUNDS, encrypt_words, expand_key_words


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_QUAL = _import_sibling(
    "rc5_32_12_16_metal_qualification.py", "rc5_32_12_16_a247_qualification"
)

ATTEMPT_ID = "A248"
QUALIFICATION_ATTEMPT_ID = "A247"
QUALIFICATION_SCHEMA = "rc5-32-12-16-metal-qualification-v1"
NATIVE_SOURCE_FILENAME = "rc5_32_12_16_metal_native.swift"
RESULT_CAPACITY = 64
PLAINTEXT_BLOCKS = 2
FILTER_WORDS = PLAINTEXT_BLOCKS * 2
FILTER_BITS = FILTER_WORDS * 32
FULL_ROUNDS = ROUNDS
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


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


def _atomic_text(path: Path, value: str) -> None:
    raw = value.encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _width_context(width: int, *, stream_candidates: int = 1 << 30) -> dict[str, int]:
    if width < 32 or width > 64:
        raise ValueError("A248 residual width must be in 32...64")
    if stream_candidates < 1 or stream_candidates > 2**32 - 1:
        raise ValueError("A248 stream size must fit one positive UInt32 request")
    outer_bits = width - 32
    logical_candidates = 1 << width
    inner_candidates = 1 << 32
    if inner_candidates % stream_candidates != 0:
        raise ValueError("A248 stream size must divide the 32-bit inner domain")
    return {
        "width": width,
        "outer_bits": outer_bits,
        "known_key_bits": 128 - width,
        "outer_slices": 1 << outer_bits,
        "inner_candidates": inner_candidates,
        "logical_candidates": logical_candidates,
        "stream_candidates": stream_candidates,
        "key1_known_mask": (0xFFFFFFFF << outer_bits) & 0xFFFFFFFF,
    }


def _known_material(width: int, label: str) -> tuple[int, int, int, list[int], str]:
    context = _width_context(width)
    expected_label = f"rc5-32-12-16/a248/fullround/w{width}/known-material/v1"
    if label != expected_label:
        raise RuntimeError("A248 known-material label differs")
    raw = hashlib.shake_256(label.encode()).digest(28)
    key1_known = int.from_bytes(raw[:4], "big") & context["key1_known_mask"]
    key2 = int.from_bytes(raw[4:8], "big")
    key3 = int.from_bytes(raw[8:12], "big")
    plaintext = [
        int.from_bytes(raw[offset : offset + 4], "big")
        for offset in range(12, 28, 4)
    ]
    return key1_known, key2, key3, plaintext, _sha256(raw)


def _validate_challenge(challenge: dict[str, Any], context: dict[str, int]) -> None:
    width = context["width"]
    if (
        challenge.get("cipher") != "RC5-32/12/16"
        or challenge.get("rounds") != FULL_ROUNDS
        or challenge.get("plaintext_blocks") != PLAINTEXT_BLOCKS
        or len(challenge.get("plaintext_words_ab_order", [])) != FILTER_WORDS
        or len(challenge.get("target_ciphertext_words_ab_order", []))
        != FILTER_WORDS
        or len(challenge.get("control_ciphertext_words_ab_order", []))
        != FILTER_WORDS
        or challenge.get("unknown_assignment_bits") != width
        or challenge.get("known_master_key_bits") != context["known_key_bits"]
        or challenge.get("unknown_key0_bits") != 32
        or challenge.get("unknown_key1_low_bits") != context["outer_bits"]
        or challenge.get("known_key1_mask") != context["key1_known_mask"]
        or int(challenge.get("known_key1", 0)) & ~context["key1_known_mask"]
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("unknown_key0_included") is not False
        or challenge.get("unknown_key1_low_bits_included") is not False
    ):
        raise RuntimeError("A248 public challenge semantic gate failed")
    key1, key2, key3, plaintext, derived_sha = _known_material(
        width, str(challenge["known_material_derivation_label"])
    )
    if (
        key1 != challenge["known_key1"]
        or key2 != challenge["known_key2"]
        or key3 != challenge["known_key3"]
        or plaintext != challenge["plaintext_words_ab_order"]
        or derived_sha != challenge["known_material_derivation_sha256"]
        or len({tuple(plaintext[i : i + 2]) for i in range(0, FILTER_WORDS, 2)})
        != PLAINTEXT_BLOCKS
    ):
        raise RuntimeError("A248 public known-material derivation gate failed")
    target = np.array(challenge["target_ciphertext_words_ab_order"], dtype="<u4")
    control = np.array(
        challenge["control_ciphertext_words_ab_order"], dtype="<u4"
    )
    expected_control = target.copy()
    expected_control[-1] ^= np.uint32(1)
    if (
        _sha256(target.tobytes())
        != challenge["target_ciphertext_little_u32_sha256"]
        or _sha256(control.tobytes())
        != challenge["control_ciphertext_little_u32_sha256"]
        or not np.array_equal(control, expected_control)
    ):
        raise RuntimeError("A248 target/control byte gate failed")


def analyze(
    *,
    protocol_path: Path,
    expected_protocol_sha256: str,
    results_dir: Path,
) -> dict[str, Any]:
    protocol_sha256 = _file_sha256(protocol_path)
    if protocol_sha256 != expected_protocol_sha256:
        raise RuntimeError("A248 frozen protocol hash differs from explicit CLI anchor")
    protocol = json.loads(protocol_path.read_text())
    plan = protocol.get("execution_plan", {})
    width = plan.get("unknown_key_bits")
    if not isinstance(width, int):
        raise RuntimeError("A248 frozen protocol has no integer residual width")
    context = _width_context(width, stream_candidates=int(plan.get("stream_candidate_count", 0)))
    challenge = protocol.get("public_challenge", {})
    challenge_sha256 = _canonical_sha256(challenge)
    anchors = protocol.get("anchors", {})
    qualification_anchor = anchors.get("qualification", {})
    native_anchor = anchors.get("native_host", {})
    boundary = protocol.get("information_boundary", {})
    expected_plan = {
        "primitive": "RC5-32/12/16_block_cipher",
        "rounds": FULL_ROUNDS,
        "unknown_key_bits": width,
        "known_key_bits": context["known_key_bits"],
        "known_plaintext_ciphertext_pairs": PLAINTEXT_BLOCKS,
        "filter_output_bits": FILTER_BITS,
        "logical_candidate_count": context["logical_candidates"],
        "outer_key1_low_bit_count": context["outer_bits"],
        "outer_key1_slice_count": context["outer_slices"],
        "inner_key0_candidate_count_per_slice": context["inner_candidates"],
        "combined_assignment_encoding": challenge.get("candidate_encoding"),
        "gpu_threads_per_candidate": 1,
        "gpu_logical_thread_count": context["logical_candidates"],
        "stream_candidate_count": context["stream_candidates"],
        "stream_batches_per_slice": context["inner_candidates"]
        // context["stream_candidates"],
        "stream_batch_count": context["logical_candidates"]
        // context["stream_candidates"],
        "result_capacity_per_batch": RESULT_CAPACITY,
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
    if (
        protocol.get("schema")
        != f"rc5-32-12-16-metal-width{width}-recovery-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_before_any_A248_candidate_execution"
        or protocol.get("public_challenge_sha256") != challenge_sha256
        or protocol.get("execution_plan") != expected_plan
        or protocol.get("execution_plan_sha256") != _canonical_sha256(expected_plan)
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution")
        is not False
        or boundary.get("A248_candidate_outcomes_used_before_protocol_freeze")
        is not False
        or protocol.get("qualification_launch_gate", {}).get(
            "full_domain_launch_authorized"
        )
        is not True
        or protocol.get("qualification_launch_gate", {}).get("selected_width")
        != width
    ):
        raise RuntimeError("A248 frozen protocol identity gate failed")
    qualification = results_dir / str(qualification_anchor.get("filename", ""))
    native_source = Path(__file__).with_name(
        str(native_anchor.get("filename", NATIVE_SOURCE_FILENAME))
    )
    if (
        qualification_anchor.get("attempt_id") != QUALIFICATION_ATTEMPT_ID
        or _file_sha256(qualification) != qualification_anchor.get("sha256")
        or native_source.name != NATIVE_SOURCE_FILENAME
        or _file_sha256(native_source) != native_anchor.get("sha256")
    ):
        raise RuntimeError("A248 implementation anchor hash differs")
    qualification_payload = json.loads(qualification.read_text())
    rivest_vectors = qualification_payload.get("provenance_kat_gate", {}).get(
        "rivest_original_paper_scalar_vectors", []
    )
    rfc2040_vector = qualification_payload.get("provenance_kat_gate", {}).get(
        "rfc2040_derived_r12_raw_block_vector", {}
    )
    if (
        qualification_payload.get("schema") != QUALIFICATION_SCHEMA
        or qualification_payload.get("attempt_id") != QUALIFICATION_ATTEMPT_ID
        or len(rivest_vectors) != 5
        or not all(row.get("pass") is True for row in rivest_vectors)
        or rfc2040_vector.get("pass") is not True
        or qualification_payload.get("provenance_kat_gate", {}).get(
            "two_block_scalar_identity"
        )
        is not True
        or qualification_payload.get("cross_implementation_gate", {}).get(
            "exact_scalar_identity"
        )
        is not True
        or qualification_payload.get("boundary_filter_gate", {}).get(
            "exact_boundary_identity"
        )
        is not True
        or qualification_payload.get("launch_gate", {}).get(
            "full_domain_launch_authorized"
        )
        is not True
        or qualification_payload.get("launch_gate", {}).get("selected_width")
        != width
    ):
        raise RuntimeError("A248 retained qualification gate failed")
    _validate_challenge(challenge, context)
    return {
        "protocol": protocol,
        "protocol_path": str(protocol_path),
        "public_challenge": challenge,
        "execution_plan": expected_plan,
        "qualification": qualification_payload,
        "context": context,
        "anchor_gates": {
            "protocol_sha256": protocol_sha256,
            "public_challenge_sha256": challenge_sha256,
            "qualification_sha256": qualification_anchor["sha256"],
            "native_source_sha256": native_anchor["sha256"],
        },
        "candidate_execution_started": False,
    }


def _arrays(challenge: dict[str, Any]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    return (
        np.array(challenge["plaintext_words_ab_order"], dtype=np.uint32),
        np.array(challenge["target_ciphertext_words_ab_order"], dtype=np.uint32),
        np.array(challenge["control_ciphertext_words_ab_order"], dtype=np.uint32),
    )


def _configure_outer(
    host: Any,
    challenge: dict[str, Any],
    context: dict[str, int],
    outer: int,
    plaintext: np.ndarray,
    target: np.ndarray,
    control: np.ndarray,
) -> None:
    if outer < 0 or outer >= context["outer_slices"]:
        raise ValueError("A248 outer assignment is outside the frozen domain")
    host.configure(
        plaintext=plaintext,
        target=target,
        control=control,
        key1=int(challenge["known_key1"]) | outer,
        key2=int(challenge["known_key2"]),
        key3=int(challenge["known_key3"]),
    )


def _scalar_outputs(
    challenge: dict[str, Any], context: dict[str, int], assignment: int
) -> np.ndarray:
    if assignment < 0 or assignment >= context["logical_candidates"]:
        raise ValueError("A248 combined assignment is outside the frozen domain")
    inner = assignment & 0xFFFFFFFF
    outer = assignment >> 32
    subkeys = expand_key_words(
        [
            inner,
            int(challenge["known_key1"]) | outer,
            int(challenge["known_key2"]),
            int(challenge["known_key3"]),
        ]
    )
    plaintext = challenge["plaintext_words_ab_order"]
    output: list[int] = []
    for offset in range(0, FILTER_WORDS, 2):
        output.extend(
            encrypt_words(
                int(plaintext[offset]), int(plaintext[offset + 1]), subkeys
            )
        )
    return np.array(output, dtype=np.uint32)


def _mapping_gate(
    host: Any, challenge: dict[str, Any], context: dict[str, int]
) -> dict[str, Any]:
    plaintext, _target, _control = _arrays(challenge)
    first = 184_032
    count = 256
    offset = 73
    outer_values = sorted(
        {0, context["outer_slices"] // 2, context["outer_slices"] - 1}
    )
    rows = []
    for outer in outer_values:
        expected = np.stack(
            [
                _scalar_outputs(challenge, context, (outer << 32) | inner)
                for inner in range(first, first + count)
            ]
        )
        target = expected[offset].copy()
        control = target.copy()
        control[-1] ^= np.uint32(1)
        _configure_outer(
            host, challenge, context, outer, plaintext, target, control
        )
        observed = host.blocks(first, count)
        filtered = host.filter(first, count)
        if (
            not np.array_equal(observed, expected)
            or filtered["factual"] != [first + offset]
            or filtered["control"] != []
        ):
            raise RuntimeError("A248 synthetic outer-slice mapping gate failed")
        rows.append(
            {
                "outer_key1_low_bits": outer,
                "first_inner_candidate": first,
                "candidate_count": count,
                "complete_output_bits_checked": int(observed.size * 32),
                "factual_inner_candidate": first + offset,
                "factual_combined_assignment": (outer << 32) | (first + offset),
                "control_matches": [],
                "output_sha256": _sha256(
                    observed.astype("<u4", copy=False).tobytes()
                ),
            }
        )
    return {
        "outer_values_checked": outer_values,
        "logical_candidates_checked": len(rows) * count,
        "complete_output_bits_checked": sum(
            row["complete_output_bits_checked"] for row in rows
        ),
        "rows": rows,
        "exact_scalar_filter_and_mapping_identity": True,
    }


def _confirm(
    challenge: dict[str, Any],
    context: dict[str, int],
    target: np.ndarray,
    assignment: int,
) -> dict[str, Any]:
    output = _scalar_outputs(challenge, context, assignment)
    return {
        "combined_assignment": assignment,
        "key0": assignment & 0xFFFFFFFF,
        "key1_low_bits": assignment >> 32,
        "complete_two_block_match": bool(np.array_equal(output, target)),
        "output_words_checked": FILTER_WORDS,
        "output_bits_checked": FILTER_BITS,
        "candidate_output_little_u32_sha256": _sha256(
            output.astype("<u4").tobytes()
        ),
        "target_output_little_u32_sha256": _sha256(
            target.astype("<u4").tobytes()
        ),
        "implementation": "independent_Python_canonical_RC5-32/12/16",
    }


def _checkpoint_fingerprint(
    challenge: dict[str, Any], context: dict[str, int], anchors: dict[str, str]
) -> dict[str, Any]:
    return {
        "schema": f"rc5-32-12-16-metal-width{context['width']}-checkpoint-v1",
        **anchors,
        "target_ciphertext_sha256": challenge[
            "target_ciphertext_little_u32_sha256"
        ],
        "control_ciphertext_sha256": challenge[
            "control_ciphertext_little_u32_sha256"
        ],
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
    plaintext, target, control = _arrays(challenge)
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
            raise RuntimeError("A248 checkpoint fingerprint differs")
        next_assignment = int(checkpoint["next_assignment"])
        factual_filtered = [int(value) for value in checkpoint["factual_filtered"]]
        control_filtered = [int(value) for value in checkpoint["control_filtered"]]
        gpu_seconds = float(checkpoint.get("gpu_seconds", 0.0))
        if (
            next_assignment < 0
            or next_assignment > logical
            or next_assignment % stream_count != 0
            or any(value < 0 or value >= next_assignment for value in factual_filtered)
            or any(value < 0 or value >= next_assignment for value in control_filtered)
            or len(factual_filtered) != len(set(factual_filtered))
            or len(control_filtered) != len(set(control_filtered))
            or gpu_seconds < 0.0
        ):
            raise RuntimeError("A248 checkpoint progress is invalid")
    resumed_assignment_count = next_assignment
    configured_outer: int | None = None
    wall_start = time.perf_counter()
    while next_assignment < logical:
        outer = next_assignment // inner_count
        first_inner = next_assignment % inner_count
        batch_count = min(stream_count, inner_count - first_inner, logical - next_assignment)
        if configured_outer != outer:
            _configure_outer(
                host, challenge, context, outer, plaintext, target, control
            )
            configured_outer = outer
        response = host.filter(first_inner, batch_count)
        gpu_seconds += float(response["gpu_seconds"])
        factual_filtered.extend(
            outer * inner_count + int(candidate) for candidate in response["factual"]
        )
        control_filtered.extend(
            outer * inner_count + int(candidate) for candidate in response["control"]
        )
        next_assignment += batch_count
        _atomic_json(
            checkpoint_path,
            {
                **fingerprint,
                "next_assignment": next_assignment,
                "factual_filtered": factual_filtered,
                "control_filtered": control_filtered,
                "gpu_seconds": gpu_seconds,
                "candidate_matches_persisted": True,
                "success_evaluated_before_complete_domain": False,
            },
        )
        if next_assignment == logical or next_assignment % (16 * inner_count) == 0:
            print(
                f"A248 Metal slices={next_assignment // inner_count}/"
                f"{context['outer_slices']} assignments={next_assignment}/{logical}",
                flush=True,
            )
    wall_seconds = time.perf_counter() - wall_start
    factual_confirmations = [
        _confirm(challenge, context, target, value) for value in factual_filtered
    ]
    control_confirmations = [
        _confirm(challenge, context, control, value) for value in control_filtered
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
    return {
        "unknown_key_bits": context["width"],
        "known_key_bits": context["known_key_bits"],
        "logical_candidate_count": logical,
        "outer_slice_count": context["outer_slices"],
        "inner_candidate_count_per_slice": inner_count,
        "stream_candidate_count": stream_count,
        "stream_batch_count": logical // stream_count,
        "resumed_assignment_count": resumed_assignment_count,
        "newly_executed_assignment_count": logical - resumed_assignment_count,
        "complete_domain_executed": next_assignment == logical,
        "early_stop_used": False,
        "filter_output_bits": FILTER_BITS,
        "factual_filter_matches": factual_filtered,
        "factual_full_matches": factual_full,
        "factual_confirmations": factual_confirmations,
        "control_filter_matches": control_filtered,
        "control_full_matches": control_full,
        "control_confirmations": control_confirmations,
        "unique_exact_assignment": len(factual_full) == 1,
        "control_target_rejected": len(control_full) == 0,
        "gpu_seconds": gpu_seconds,
        "volatile_wall_seconds": wall_seconds,
        "volatile_candidates_per_gpu_second": logical / max(gpu_seconds, 1e-12),
        "unknown_assignment_available_to_runner_before_execution": False,
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        io_module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError(
                "dotcausal 0.3.1 is required; install requirements.txt or pass "
                "--dotcausal-src"
            ) from None
        sys.path.insert(0, str(dotcausal_src))
        io_module = importlib.import_module("dotcausal.io")
    writer = io_module.CausalWriter
    reader = io_module.CausalReader
    io_path = Path(inspect.getsourcefile(reader) or "")
    if not io_path.is_file():
        raise RuntimeError("A248 authoritative dotcausal.io source is unavailable")
    return writer, reader, {
        "module": "dotcausal.io",
        "io_path": str(io_path),
        "io_sha256": _file_sha256(io_path),
    }


def _build_authentic_causal(
    *, path: Path, payload: dict[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, reader_source = _load_dotcausal(dotcausal_src)
    width = int(payload["execution"]["unknown_key_bits"])
    logical = int(payload["execution"]["logical_candidate_count"])
    writer = CausalWriter(api_id="a248")
    writer._rules = []
    writer.add_rule(
        name="complete_domain_plus_independent_confirmation",
        description=(
            "Complete residual-key enumeration plus independent exact multi-block "
            "confirmation establishes the recovered assignment."
        ),
        pattern=["complete_domain_enumeration", "independent_exact_confirmation"],
        conclusion="verified_residual_key_recovery",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="control_separates_target_specific_recovery",
        description=(
            "The identical complete search returning zero exact models for the "
            "one-bit control establishes target-specific separation."
        ),
        pattern=["same_complete_search", "zero_exact_control_models"],
        conclusion="target_specific_recovery_evidence",
        confidence_modifier=1.0,
    )
    execution = payload["execution"]
    writer.add_triplet(
        trigger="A247:pre_target_Metal_qualification",
        mechanism="provenance_KATs_plus_scalar_cross_gate_plus_uint32_boundary_gate",
        outcome="A248:qualified_fullround_RC5_32_12_16_enumerator",
        confidence=1.0,
        source=payload["anchor_gates"]["qualification_sha256"],
        quantification="12 rounds; 2 plaintext blocks; exact uint32 word identity",
        evidence=json.dumps(payload["mapping_gate"], sort_keys=True),
        domain="RC5-32/12/16 implementation equivalence",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"A248:frozen_public_W{width}_relation",
        mechanism="complete_domain_enumeration",
        outcome="A248:factual_filter_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
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
        trigger="A248:factual_filter_candidate_set",
        mechanism="independent_exact_confirmation",
        outcome=f"A248:unique_verified_{width}_bit_residual_key",
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="2 blocks; 128 output bits; canonical Python implementation",
        evidence=json.dumps(execution["factual_confirmations"], sort_keys=True),
        domain="independent key confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A248:one_bit_flipped_control_relation",
        mechanism="same_complete_search",
        outcome="A248:control_filter_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{logical} assignments; identical execution plan",
        evidence=json.dumps(
            {"control_filter_matches": execution["control_filter_matches"]},
            sort_keys=True,
        ),
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A248:control_filter_candidate_set",
        mechanism="zero_exact_control_models",
        outcome="A248:control_relation_rejected",
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="zero independently confirmed assignments",
        evidence=json.dumps(execution["control_confirmations"], sort_keys=True),
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"A248:frozen_public_W{width}_relation",
        mechanism="verified_complete_enumeration_and_confirmation_chain",
        outcome=f"A248:unique_verified_{width}_bit_residual_key",
        confidence=1.0,
        source="materialized:complete_domain_plus_independent_confirmation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after complete execution and exact confirmation.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_triplet(
        trigger="A248:one_bit_flipped_control_relation",
        mechanism="verified_matched_control_chain",
        outcome="A248:control_relation_rejected",
        confidence=1.0,
        source="materialized:control_separates_target_specific_recovery",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after the identical complete control search.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A248 verified recovery chain",
        entities=[
            f"A248:frozen_public_W{width}_relation",
            "complete_domain_enumeration",
            "A248:factual_filter_candidate_set",
            "independent_exact_confirmation",
            f"A248:unique_verified_{width}_bit_residual_key",
        ],
    )
    writer.add_cluster(
        name="A248 matched control chain",
        entities=[
            "A248:one_bit_flipped_control_relation",
            "same_complete_search",
            "A248:control_filter_candidate_set",
            "zero_exact_control_models",
            "A248:control_relation_rejected",
        ],
    )
    writer.add_gap(
        subject=f"A248:unique_verified_{width}_bit_residual_key",
        predicate="next_required_gain",
        expected_object_type=f"prospectively_selected_strict_subset_of_W{width}_domain",
        confidence=1.0,
        suggested_queries=[
            f"Which frozen operator ranks the held-out W{width} slice early?",
            f"Does typed propagation reduce executed W{width} candidates?",
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
        or reader.api_id != "a248"
        or len(explicit) != 5
        or len(all_rows) != 7
        or len(materialized) != 2
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
        or all_rows[-2]["outcome"]
        != f"A248:unique_verified_{width}_bit_residual_key"
        or all_rows[-1]["outcome"] != "A248:control_relation_rejected"
    ):
        raise RuntimeError("A248 authentic Causal Reader reopen gate failed")
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
                row
                for row in all_rows
                if row["outcome"]
                == f"A248:unique_verified_{width}_bit_residual_key"
            ],
            "control_chain": [
                row
                for row in all_rows
                if row["outcome"] == "A248:control_relation_rejected"
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
            f"# A248 — Full-round RC5-32/12/16 W{width} residual-key recovery",
            "",
            f"The frozen public relation was searched over every one of its `2^{width}` residual-key assignments for all 12 standard rounds, without early stopping.",
            "",
            "## Result",
            "",
            f"- Complete domain: **{execution['logical_candidate_count']:,} / {execution['logical_candidate_count']:,}**",
            f"- Recovered assignment: **`{recovery['recovered_combined_assignments'][0]}`**",
            f"- Unknown / known master-key bits: **{width} / {execution['known_key_bits']}**",
            f"- Independent confirmation: **{FILTER_BITS} output bits across {PLAINTEXT_BLOCKS} blocks**",
            f"- Exact factual models: **{len(execution['factual_full_matches'])}**",
            f"- Exact one-bit-control models: **{len(execution['control_full_matches'])}**",
            f"- GPU time: **{execution['gpu_seconds']:.3f} s**",
            f"- Volatile wall time: **{execution['volatile_wall_seconds']:.3f} s**",
            "",
            "## Exact scope",
            "",
            f"All 32 bits of `K0` and the low {execution['unknown_key_bits'] - 32} bits of `K1` are unknown; {execution['known_key_bits']} key bits are public. The complete residual domain is enumerated on commodity Apple Silicon.",
            "",
            "## AI-native Causal artifact",
            "",
            f"- Authentic Reader integrity gate: **{causal['integrity_verified_by_authoritative_reader']}**",
            f"- Explicit / materialized inferred edges: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
            f"- Embedded rules / clusters / gaps: **{causal['embedded_rules']} / {causal['clusters']} / {causal['gaps']}**",
            "- The amplified inference state is retained in-file and reopened by the authoritative Causal Reader.",
            "",
            "## Primary sources",
            "",
            "- Ronald L. Rivest, *The RC5 Encryption Algorithm*, FSE 1994 / LNCS 1008.",
            "- RFC 2040, *The RC5, RC5-CBC, RC5-CBC-Pad, and RC5-CTS Algorithms*.",
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
            "A248 full-domain execution requires explicit execute_full_domain=True"
        )
    analysis = analyze(
        protocol_path=protocol_path,
        expected_protocol_sha256=expected_protocol_sha256,
        results_dir=results_dir,
    )
    executable, native_build = _QUAL._compile_native(build_dir, swiftc)
    host = _QUAL.MetalRC5321216Host(executable)
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
    ):
        raise RuntimeError("A248 complete-domain recovery gate failed")
    width = analysis["context"]["width"]
    payload: dict[str, Any] = {
        "schema": f"rc5-32-12-16-metal-width{width}-recovery-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            f"RC5_32_12_16_FULLROUND_{width}BIT_RESIDUAL_KEY_RECOVERY_RETAINED"
        ),
        "result": (
            f"The native Metal runner executed the complete fresh {width}-bit "
            "residual-key domain for all 12 RC5-32/12/16 rounds and independently "
            "confirmed the unique assignment across two public blocks."
        ),
        "protocol_gate": {
            "artifact_sha256": analysis["anchor_gates"]["protocol_sha256"],
            "protocol_state": analysis["protocol"]["protocol_state"],
            "prospective_prediction": analysis["protocol"]["prospective_prediction"],
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
        "execution_sha256": _canonical_sha256(
            {
                key: value
                for key, value in execution.items()
                if key
                not in {
                    "factual_confirmations",
                    "control_confirmations",
                    "volatile_wall_seconds",
                    "gpu_seconds",
                    "volatile_candidates_per_gpu_second",
                }
            }
        ),
        "confirmation_sha256": _canonical_sha256(
            {
                "factual": execution["factual_confirmations"],
                "control": execution["control_confirmations"],
            }
        ),
        "recovery": {
            "recovered_combined_assignments": execution["factual_full_matches"],
            "recovered_key0": [
                value & 0xFFFFFFFF for value in execution["factual_full_matches"]
            ],
            "recovered_key1_low_bits": [
                value >> 32 for value in execution["factual_full_matches"]
            ],
            "recovery_accepted_only_after_complete_domain_execution": True,
            "candidate_identities_persisted_in_checkpoint": True,
            "success_evaluated_only_after_complete_domain": True,
            "unknown_assignment_source_was_discarded_before_runner_construction": True,
        },
    }
    payload["causal"] = _build_authentic_causal(
        path=causal_output, payload=payload, dotcausal_src=dotcausal_src
    )
    _atomic_json(output, payload)
    _atomic_text(report_output, _report(payload))
    checkpoint_path.unlink(missing_ok=True)
    _CausalWriter, CausalReader, _source = _load_dotcausal(dotcausal_src)
    reader = CausalReader(str(causal_output), verify_integrity=True)
    reopened = json.loads(output.read_text())
    if (
        reopened != payload
        or _file_sha256(causal_output) != payload["causal"]["file_sha256"]
        or len(reader.get_all_triplets(include_inferred=True)) != 7
        or not report_output.is_file()
    ):
        raise RuntimeError("A248 final artifact reopen gate failed")
    return {
        "output": str(output),
        "json_sha256": _file_sha256(output),
        "causal_output": str(causal_output),
        "causal_sha256": _file_sha256(causal_output),
        "report_output": str(report_output),
        "report_sha256": _file_sha256(report_output),
        "complete_domain_executed": True,
        "logical_candidate_count": execution["logical_candidate_count"],
        "recovered_combined_assignments": execution["factual_full_matches"],
        "control_full_matches": execution["control_full_matches"],
        "gpu_seconds": execution["gpu_seconds"],
        "volatile_wall_seconds": execution["volatile_wall_seconds"],
        "authentic_causal_reader_verified": True,
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    results_dir_default = research_root / "results" / "v1"
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--expected-protocol-sha256", required=True)
    parser.add_argument("--results-dir", type=Path, default=results_dir_default)
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--causal-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--execute-full-domain",
        action="store_true",
        help="acknowledge and start the hash-gated complete residual-domain execution",
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
    stem = f"rc5_32_12_16_metal_width{width}_recovery_v1"
    output = args.output or args.results_dir / f"{stem}.json"
    causal_output = args.causal_output or args.results_dir / f"{stem}.causal"
    report_output = args.report_output or (
        research_root / "reports" / f"FULLROUND_RC5_32_12_16_METAL_WIDTH{width}_RECOVERY_V1.md"
    )
    checkpoint = args.checkpoint or args.results_dir / f"{stem}.checkpoint.json"
    build_dir = args.build_dir or research_root / "build" / f"rc5_32_12_16_metal_width{width}"
    print(
        json.dumps(
            run(
                protocol_path=args.protocol,
                expected_protocol_sha256=args.expected_protocol_sha256,
                results_dir=args.results_dir,
                output=output,
                causal_output=causal_output,
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
