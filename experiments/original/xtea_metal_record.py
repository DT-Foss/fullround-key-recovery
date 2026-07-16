#!/usr/bin/env python3
"""Qualify and execute a complete full-round XTEA residual-key search."""

from __future__ import annotations

import argparse
import importlib.util
import json
import secrets
import statistics
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
FRAMEWORK_SOURCE = Path(__file__).with_name("tea_metal_record.py")
SPEC = importlib.util.spec_from_file_location("xtea_tea_family_framework", FRAMEWORK_SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load TEA-family Metal framework")
FAMILY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FAMILY
SPEC.loader.exec_module(FAMILY)

ATTEMPT_ID = "XTEAKR1"
NATIVE_SOURCE = FAMILY.NATIVE_SOURCE
DEFAULT_DOTCAUSAL_SRC = FAMILY.DEFAULT_DOTCAUSAL_SRC
DEFAULT_BUILD = ROOT / "research/build/xtea_metal_v1"
DEFAULT_QUALIFICATION = ROOT / "research/results/v1/xtea_metal_qualification_v1.json"
DEFAULT_PROTOCOL = ROOT / "research/configs/xtea_metal_recovery_v1.json"
DEFAULT_RESULT = ROOT / "research/results/v1/xtea_metal_recovery_v1.json"
DEFAULT_CHECKPOINT = ROOT / "research/results/v1/xtea_metal_recovery_v1.checkpoint.json"
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = ROOT / "research/reports/FULLROUND_XTEA_METAL_RECOVERY_V1.md"

MASK32 = FAMILY.MASK32
DELTA = FAMILY.DELTA
ZERO_REFERENCE_CIPHERTEXT = (0xDEE9D4D8, 0xF7131ED9)
STREAM_CANDIDATES = FAMILY.STREAM_CANDIDATES
QUALIFICATION_CANDIDATES = FAMILY.QUALIFICATION_CANDIDATES
QUALIFICATION_REPETITIONS = FAMILY.QUALIFICATION_REPETITIONS
QUALIFICATION_BUDGET_SECONDS = FAMILY.QUALIFICATION_BUDGET_SECONDS
QUALIFICATION_SAFETY_FACTOR = FAMILY.QUALIFICATION_SAFETY_FACTOR
MIN_WIDTH = FAMILY.MIN_WIDTH
MAX_WIDTH = FAMILY.MAX_WIDTH

_sha256 = FAMILY._sha256
_file_sha256 = FAMILY._file_sha256
_canonical_bytes = FAMILY._canonical_bytes
_canonical_sha256 = FAMILY._canonical_sha256
_atomic_bytes = FAMILY._atomic_bytes
_atomic_json = FAMILY._atomic_json
_artifact_path = FAMILY._artifact_path
_context = FAMILY._context
apply_assignment = FAMILY.apply_assignment
MetalTEAHost = FAMILY.MetalTEAHost


def scalar_encrypt(
    plaintext: Sequence[int], key: Sequence[int]
) -> tuple[int, int]:
    if len(plaintext) != 2 or len(key) != 4:
        raise ValueError("XTEA requires two plaintext words and four key words")
    value0, value1 = (int(word) & MASK32 for word in plaintext)
    keys = tuple(int(word) & MASK32 for word in key)
    running_sum = 0
    for _ in range(32):
        value0 = (
            value0
            + (
                ((((value1 << 4) & MASK32) ^ (value1 >> 5)) + value1) & MASK32
                ^ ((running_sum + keys[running_sum & 3]) & MASK32)
            )
        ) & MASK32
        running_sum = (running_sum + DELTA) & MASK32
        value1 = (
            value1
            + (
                ((((value0 << 4) & MASK32) ^ (value0 >> 5)) + value0) & MASK32
                ^ ((running_sum + keys[(running_sum >> 11) & 3]) & MASK32)
            )
        ) & MASK32
    return value0, value1


def scalar_decrypt(
    ciphertext: Sequence[int], key: Sequence[int]
) -> tuple[int, int]:
    if len(ciphertext) != 2 or len(key) != 4:
        raise ValueError("XTEA requires two ciphertext words and four key words")
    value0, value1 = (int(word) & MASK32 for word in ciphertext)
    keys = tuple(int(word) & MASK32 for word in key)
    running_sum = (DELTA * 32) & MASK32
    for _ in range(32):
        value1 = (
            value1
            - (
                ((((value0 << 4) & MASK32) ^ (value0 >> 5)) + value0) & MASK32
                ^ ((running_sum + keys[(running_sum >> 11) & 3]) & MASK32)
            )
        ) & MASK32
        running_sum = (running_sum - DELTA) & MASK32
        value0 = (
            value0
            - (
                ((((value1 << 4) & MASK32) ^ (value1 >> 5)) + value1) & MASK32
                ^ ((running_sum + keys[running_sum & 3]) & MASK32)
            )
        ) & MASK32
    return value0, value1


def numpy_encrypt(
    plaintext: Sequence[int], key: Sequence[int]
) -> tuple[int, int]:
    if len(plaintext) != 2 or len(key) != 4:
        raise ValueError("XTEA requires two plaintext words and four key words")
    values = np.asarray([int(word) & MASK32 for word in plaintext], dtype=np.uint64)
    keys = np.asarray([int(word) & MASK32 for word in key], dtype=np.uint64)
    mask = np.uint64(MASK32)
    running_sum = 0
    for _ in range(32):
        index0 = running_sum & 3
        sum0 = np.uint64(running_sum)
        values[0] = (
            values[0]
            + (
                ((((values[1] << np.uint64(4)) & mask) ^ (values[1] >> np.uint64(5))) + values[1])
                ^ (sum0 + keys[index0])
            )
        ) & mask
        running_sum = (running_sum + DELTA) & MASK32
        index1 = (running_sum >> 11) & 3
        sum1 = np.uint64(running_sum)
        values[1] = (
            values[1]
            + (
                ((((values[0] << np.uint64(4)) & mask) ^ (values[0] >> np.uint64(5))) + values[0])
                ^ (sum1 + keys[index1])
            )
        ) & mask
    return int(values[0]), int(values[1])


def reference_gate() -> dict[str, Any]:
    zero = scalar_encrypt((0, 0), (0, 0, 0, 0))
    zero_numpy = numpy_encrypt((0, 0), (0, 0, 0, 0))
    if zero != ZERO_REFERENCE_CIPHERTEXT or zero_numpy != zero:
        raise RuntimeError("XTEA published-reference zero vector gate failed")
    rows = []
    for index in range(8):
        plaintext = (
            (0xA5A5A5A5 ^ (0x1020304 * index)) & MASK32,
            (0x5A5A5A5A + 0x01020304 * index) & MASK32,
        )
        key = tuple(
            (0x9E3779B9 * (index + word + 1) + 0x13579BDF * word) & MASK32
            for word in range(4)
        )
        scalar = scalar_encrypt(plaintext, key)
        independent = numpy_encrypt(plaintext, key)
        decrypted = scalar_decrypt(scalar, key)
        if scalar != independent or decrypted != plaintext:
            raise RuntimeError("XTEA independent-reference gate failed")
        rows.append(
            {
                "case": index,
                "plaintext_words": list(plaintext),
                "key_words": list(key),
                "ciphertext_words": list(scalar),
                "scalar_numpy_exact": True,
                "decrypt_roundtrip_exact": True,
            }
        )
    return {
        "reference": "Needham and Wheeler XTEA 32-cycle recurrence",
        "zero_key_zero_plaintext_ciphertext": list(ZERO_REFERENCE_CIPHERTEXT),
        "zero_vector_exact": True,
        "cross_reference_rows": rows,
        "all_exact": True,
    }


def encrypt_relation(
    plaintext_words: Sequence[int], key_words: Sequence[int]
) -> tuple[int, int, int, int]:
    if len(plaintext_words) != 4:
        raise ValueError("XTEAKR1 requires exactly two plaintext blocks")
    return (*scalar_encrypt(plaintext_words[:2], key_words), *scalar_encrypt(plaintext_words[2:], key_words))


def numpy_relation(
    plaintext_words: Sequence[int], key_words: Sequence[int]
) -> tuple[int, int, int, int]:
    if len(plaintext_words) != 4:
        raise ValueError("XTEAKR1 requires exactly two plaintext blocks")
    return (*numpy_encrypt(plaintext_words[:2], key_words), *numpy_encrypt(plaintext_words[2:], key_words))


def _configure_reference(host: MetalTEAHost, *, width: int) -> None:
    plaintext = (0, 0, 0x01234567, 0x89ABCDEF)
    key = (0, 0, 0, 0)
    target = encrypt_relation(plaintext, key)
    host.configure(
        target=target,
        control=(target[0] ^ 1, *target[1:]),
        known_zeroed_key=key,
        plaintext_words=plaintext,
        width=width,
        algorithm="xtea",
    )


def _metal_mapping_gate(host: MetalTEAHost, *, width: int) -> dict[str, Any]:
    context = _context(width)
    plaintext = (0, 0, 0x01234567, 0x89ABCDEF)
    zeroed = (0, 0, 0, 0)
    _configure_reference(host, width=width)
    rows = []
    for assignment in (0, 1, (1 << 32) - 1, 1 << 32, (1 << width) - 1):
        observed = host.blocks(assignment >> 32, assignment & MASK32, 1)[0]
        key = apply_assignment(zeroed, assignment, width)
        scalar = encrypt_relation(plaintext, key)
        independent = numpy_relation(plaintext, key)
        if observed != scalar or observed != independent:
            raise RuntimeError("XTEA Metal residual mapping gate failed")
        rows.append(
            {
                "assignment": assignment,
                "outer": assignment >> 32,
                "inner": assignment & MASK32,
                "output_sha256": _sha256(_canonical_bytes(observed)),
                "exact": True,
            }
        )
    return {
        "width": width,
        "outer_mask": context["outer_mask"],
        "rows": rows,
        "scalar_numpy_metal_exact": True,
    }


def qualify(*, output: Path, build_dir: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"XTEA qualification already exists: {output}")
    references = reference_gate()
    executable, build = FAMILY._compile_native(build_dir)
    with MetalTEAHost(executable) as host:
        mapping = _metal_mapping_gate(host, width=MAX_WIDTH)
        _configure_reference(host, width=MAX_WIDTH)
        timings = []
        for _ in range(QUALIFICATION_REPETITIONS):
            row = host.filter(0, 0, QUALIFICATION_CANDIDATES)
            if row["control"]:
                raise RuntimeError("XTEA qualification control unexpectedly matched")
            timings.append(float(row["gpu_seconds"]))
        identity = host.identity
    throughputs = [QUALIFICATION_CANDIDATES / seconds for seconds in timings]
    minimum = min(throughputs)
    capacity = minimum * QUALIFICATION_BUDGET_SECONDS / QUALIFICATION_SAFETY_FACTOR
    eligible = [
        width
        for width in range(MIN_WIDTH, MAX_WIDTH + 1)
        if (1 << width) <= capacity
    ]
    if not eligible:
        raise RuntimeError("XTEA qualification did not clear the minimum width")
    selected = max(eligible)
    payload = {
        "schema": "xtea-metal-qualification-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_XTEA_METAL_QUALIFIED",
        "algorithm": {
            "name": "Extended Tiny Encryption Algorithm (XTEA)",
            "cycles": 32,
            "branch_updates": 64,
            "complete_standard_round_count": True,
            "key_bits": 128,
            "plaintext_blocks": 2,
            "filter_bits": 128,
        },
        "anchors": {
            "qualification_source_sha256": _file_sha256(Path(__file__)),
            "family_framework_sha256": _file_sha256(FRAMEWORK_SOURCE),
            "native_source_sha256": _file_sha256(NATIVE_SOURCE),
        },
        "published_reference_gate": references,
        "metal_mapping_gate": mapping,
        "native_build": build,
        "metal_identity": identity,
        "benchmark": {
            "candidate_count_per_repetition": QUALIFICATION_CANDIDATES,
            "repetitions": QUALIFICATION_REPETITIONS,
            "gpu_seconds": timings,
            "candidates_per_gpu_second": throughputs,
            "minimum_candidates_per_gpu_second": minimum,
            "median_candidates_per_gpu_second": statistics.median(throughputs),
            "budget_seconds": QUALIFICATION_BUDGET_SECONDS,
            "safety_factor": QUALIFICATION_SAFETY_FACTOR,
        },
        "selection": {
            "eligible_widths": eligible,
            "selected_width": selected,
            "projected_seconds_at_minimum_throughput": (1 << selected) / minimum,
            "production_challenge_generated": False,
        },
    }
    _atomic_json(output, payload)
    return payload


def freeze_protocol(
    *, qualification_path: Path, expected_qualification_sha256: str, output: Path
) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"XTEA protocol already exists: {output}")
    if _file_sha256(qualification_path) != expected_qualification_sha256:
        raise RuntimeError("XTEA qualification hash differs")
    qualification = json.loads(qualification_path.read_bytes())
    if (
        qualification.get("evidence_stage") != "FULLROUND_XTEA_METAL_QUALIFIED"
        or qualification.get("selection", {}).get("production_challenge_generated")
        is not False
    ):
        raise RuntimeError("XTEA qualification semantic gate failed")
    width = int(qualification["selection"]["selected_width"])
    context = _context(width)
    key = tuple(secrets.randbits(32) for _ in range(4))
    plaintext = tuple(secrets.randbits(32) for _ in range(4))
    target = encrypt_relation(plaintext, key)
    if target != numpy_relation(plaintext, key):
        raise RuntimeError("XTEA target construction references differ")
    control = (target[0] ^ 1, *target[1:])
    known_zeroed = (0, key[1] & ~context["outer_mask"], key[2], key[3])
    challenge = {
        "plaintext_words": list(plaintext),
        "known_key_words_zeroed_residual": list(known_zeroed),
        "unknown_key_bits": width,
        "known_key_bits": 128 - width,
        "unknown_bit_interval": [0, width - 1],
        "unknown_mapping": "key_word0_bits_0_31_then_key_word1_low_bits",
        "target_ciphertext_words": list(target),
        "target_sha256": _sha256(_canonical_bytes(target)),
        "control_ciphertext_words": list(control),
        "control_sha256": _sha256(_canonical_bytes(control)),
        "control_relation": "target_ciphertext_word0_bit0_flipped",
        "secret_assignment_included": False,
        "full_key_included": False,
        "secret_discarded_after_target_construction": True,
    }
    protocol = {
        "schema": "xtea-metal-recovery-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_any_production_candidate_execution",
        "algorithm": {
            "name": "Extended Tiny Encryption Algorithm (XTEA)",
            "cycles": 32,
            "branch_updates": 64,
            "complete_standard_round_count": True,
            "plaintext_blocks": 2,
            "output_bits_compared": 128,
        },
        "anchors": {
            "qualification": {
                "path": str(qualification_path.relative_to(ROOT)),
                "sha256": expected_qualification_sha256,
            },
            "runner_sha256": _file_sha256(Path(__file__)),
            "family_framework_sha256": _file_sha256(FRAMEWORK_SOURCE),
            "native_source_sha256": _file_sha256(NATIVE_SOURCE),
        },
        "challenge": challenge,
        "public_challenge_sha256": _canonical_sha256(challenge),
        "execution": {
            **context,
            "complete_domain_required": True,
            "early_stop_permitted": False,
            "matched_control_same_kernel_and_domain": True,
            "checkpoint_resume_enabled": True,
            "success_evaluated_only_after_complete_domain": True,
        },
        "information_boundary": {
            "qualification_precedes_production_target": True,
            "production_target_frozen_before_candidate_execution": True,
            "secret_assignment_available_to_runner": False,
            "secret_assignment_serialized": False,
        },
    }
    _atomic_json(output, protocol)
    return protocol


def _load_protocol(path: Path, expected_sha256: str) -> dict[str, Any]:
    if _file_sha256(path) != expected_sha256:
        raise RuntimeError("XTEA protocol hash differs")
    protocol = json.loads(path.read_bytes())
    challenge = protocol.get("challenge", {})
    anchors = protocol.get("anchors", {})
    qualification_path = ROOT / anchors.get("qualification", {}).get("path", "")
    if (
        protocol.get("schema") != "xtea-metal-recovery-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_before_any_production_candidate_execution"
        or protocol.get("public_challenge_sha256") != _canonical_sha256(challenge)
        or anchors.get("runner_sha256") != _file_sha256(Path(__file__))
        or anchors.get("family_framework_sha256") != _file_sha256(FRAMEWORK_SOURCE)
        or anchors.get("native_source_sha256") != _file_sha256(NATIVE_SOURCE)
        or _file_sha256(qualification_path) != anchors["qualification"]["sha256"]
        or challenge.get("secret_assignment_included") is not False
        or challenge.get("full_key_included") is not False
    ):
        raise RuntimeError("XTEA frozen protocol gate failed")
    _context(int(challenge["unknown_key_bits"]))
    return protocol


def _challenge_values(
    challenge: Mapping[str, Any]
) -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    values = tuple(
        tuple(int(word) for word in challenge[name])
        for name in (
            "known_key_words_zeroed_residual",
            "plaintext_words",
            "target_ciphertext_words",
            "control_ciphertext_words",
        )
    )
    if any(len(value) != 4 for value in values) or any(
        not 0 <= word <= MASK32 for value in values for word in value
    ):
        raise RuntimeError("XTEA challenge word boundary differs")
    return values


def _post_freeze_mapping_gate(
    host: MetalTEAHost, protocol: Mapping[str, Any]
) -> dict[str, Any]:
    challenge = protocol["challenge"]
    width = int(challenge["unknown_key_bits"])
    known, plaintext, target, control = _challenge_values(challenge)
    host.configure(
        target=target,
        control=control,
        known_zeroed_key=known,
        plaintext_words=plaintext,
        width=width,
        algorithm="xtea",
    )
    rows = []
    for assignment in (0, 1, (1 << 32) - 1, 1 << 32, (1 << width) - 1):
        observed = host.blocks(assignment >> 32, assignment & MASK32, 1)[0]
        key = apply_assignment(known, assignment, width)
        if observed != encrypt_relation(plaintext, key) or observed != numpy_relation(plaintext, key):
            raise RuntimeError("XTEA post-freeze mapping gate failed")
        rows.append(
            {"assignment": assignment, "output_sha256": _sha256(_canonical_bytes(observed))}
        )
    return {"rows": rows, "scalar_numpy_metal_exact": True}


def _checkpoint_fingerprint(
    protocol_sha256: str, protocol: Mapping[str, Any]
) -> dict[str, Any]:
    width = int(protocol["challenge"]["unknown_key_bits"])
    context = _context(width)
    return {
        "schema": "xtea-complete-domain-checkpoint-v1",
        "protocol_sha256": protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "width": width,
        "logical_candidate_count": context["logical_candidates"],
        "stream_candidate_count": STREAM_CANDIDATES,
        "candidate_encoding": "combined=(key_word1_low_bits<<32)|key_word0",
    }


def _confirm(
    protocol: Mapping[str, Any], assignment: int, expected: Sequence[int], relation: str
) -> dict[str, Any]:
    challenge = protocol["challenge"]
    width = int(challenge["unknown_key_bits"])
    known, plaintext, _, _ = _challenge_values(challenge)
    key = apply_assignment(known, assignment, width)
    scalar = encrypt_relation(plaintext, key)
    independent = numpy_relation(plaintext, key)
    expected_tuple = tuple(int(word) for word in expected)
    return {
        "assignment": assignment,
        "relation": relation,
        "recovered_key_words": list(key),
        "recovered_key_words_hex": [f"{word:08x}" for word in key],
        "scalar_output_sha256": _sha256(_canonical_bytes(scalar)),
        "independent_numpy_output_sha256": _sha256(_canonical_bytes(independent)),
        "scalar_numpy_identity": scalar == independent,
        "complete_128_bit_match": scalar == independent == expected_tuple,
        "output_bits_checked": 128,
    }


def enumerate_domain(
    *,
    host: MetalTEAHost,
    protocol: Mapping[str, Any],
    protocol_sha256: str,
    checkpoint_path: Path,
    resume: bool,
    checkpoint_fingerprint_fn: Any = _checkpoint_fingerprint,
    confirm_fn: Any = _confirm,
    challenge_values_fn: Any = _challenge_values,
    attempt_id: str = ATTEMPT_ID,
    label: str = "XTEA",
) -> dict[str, Any]:
    width = int(protocol["challenge"]["unknown_key_bits"])
    context = _context(width)
    fingerprint = checkpoint_fingerprint_fn(protocol_sha256, protocol)
    next_assignment = 0
    factual: list[int] = []
    control: list[int] = []
    gpu_seconds = 0.0
    if checkpoint_path.exists() and not resume:
        raise FileExistsError(f"{label} checkpoint exists; pass --resume")
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_bytes())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError(f"{label} checkpoint fingerprint differs")
        next_assignment = int(checkpoint["next_assignment"])
        factual = [int(value) for value in checkpoint["factual_filtered"]]
        control = [int(value) for value in checkpoint["control_filtered"]]
        gpu_seconds = float(checkpoint["gpu_seconds"])
        if (
            next_assignment % STREAM_CANDIDATES
            or not 0 <= next_assignment <= context["logical_candidates"]
            or any(not 0 <= value < next_assignment for value in factual + control)
        ):
            raise RuntimeError(f"{label} checkpoint progress differs")
    resumed = next_assignment
    started = time.perf_counter()
    while next_assignment < context["logical_candidates"]:
        outer = next_assignment >> 32
        first = next_assignment & MASK32
        count = min(
            STREAM_CANDIDATES,
            (1 << 32) - first,
            context["logical_candidates"] - next_assignment,
        )
        row = host.filter(outer, first, count)
        for name, destination in (("factual", factual), ("control", control)):
            for inner in row[name]:
                combined = (outer << 32) | int(inner)
                if not next_assignment <= combined < next_assignment + count:
                    raise RuntimeError(f"{label} {name} candidate is outside batch")
                destination.append(combined)
            if len(destination) != len(set(destination)):
                raise RuntimeError(f"{label} duplicate {name} candidate")
        gpu_seconds += float(row["gpu_seconds"])
        next_assignment += count
        _atomic_json(
            checkpoint_path,
            {
                **fingerprint,
                "next_assignment": next_assignment,
                "factual_filtered": factual,
                "control_filtered": control,
                "gpu_seconds": gpu_seconds,
                "complete_domain_executed": next_assignment == context["logical_candidates"],
                "early_stop_used": False,
                "success_evaluated_before_complete_domain": False,
            },
        )
        if next_assignment % (1 << 34) == 0:
            print(
                json.dumps(
                    {
                        "attempt_id": attempt_id,
                        "next_assignment": next_assignment,
                        "logical_candidates": context["logical_candidates"],
                        "progress": next_assignment / context["logical_candidates"],
                        "gpu_seconds": gpu_seconds,
                        "factual_filters": len(factual),
                        "control_filters": len(control),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
    _, _, target, control_target = challenge_values_fn(protocol["challenge"])
    factual_confirmations = [
        confirm_fn(protocol, value, target, "factual") for value in factual
    ]
    control_confirmations = [
        confirm_fn(protocol, value, control_target, "control") for value in control
    ]
    factual_full = [row["assignment"] for row in factual_confirmations if row["complete_128_bit_match"]]
    control_full = [row["assignment"] for row in control_confirmations if row["complete_128_bit_match"]]
    complete = next_assignment == context["logical_candidates"]
    return {
        "unknown_key_bits": width,
        "known_key_bits": 128 - width,
        "logical_candidate_count": context["logical_candidates"],
        "executed_assignment_count": next_assignment,
        "resumed_assignment_count": resumed,
        "newly_executed_assignment_count": next_assignment - resumed,
        "complete_domain_executed": complete,
        "early_stop_used": False,
        "success_evaluated_only_after_complete_domain": True,
        "factual_filter_matches": factual,
        "control_filter_matches": control,
        "factual_confirmations": factual_confirmations,
        "control_confirmations": control_confirmations,
        "factual_full_matches": factual_full,
        "control_full_matches": control_full,
        "unique_exact_assignment": complete and len(factual) == 1 and factual_full == factual,
        "control_target_rejected": complete and not control and not control_full,
        "gpu_seconds": gpu_seconds,
        "volatile_wall_seconds": time.perf_counter() - started,
        "volatile_candidates_per_gpu_second": next_assignment / gpu_seconds if gpu_seconds else None,
    }


def build_causal(
    *, path: Path, payload: Mapping[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = FAMILY._load_dotcausal(dotcausal_src)
    execution = payload["execution"]
    width = int(execution["unknown_key_bits"])
    logical = int(execution["logical_candidate_count"])
    recovered = f"XTEA:unique_verified_W{width}_fullround_residual"
    writer = CausalWriter(api_id="xteakr1")
    writer._rules = []
    writer.add_rule(
        name="complete_domain_plus_independent_confirmation",
        description="Complete full-round XTEA residual enumeration plus scalar and independent NumPy confirmation establishes the recovered assignment.",
        pattern=["complete_domain_enumeration", "two_reference_confirmation"],
        conclusion="verified_residual_key_recovery",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="matched_control_separation",
        description="The same complete search returns zero models for the one-bit control relation.",
        pattern=["same_complete_search", "zero_control_models"],
        conclusion="target_specific_recovery",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="XTEA:pre_target_Metal_qualification",
        mechanism="published_reference_plus_scalar_NumPy_Metal_mapping_gates",
        outcome="XTEA:qualified_fullround_enumerator",
        confidence=1.0,
        source=payload["qualification_sha256"],
        quantification="32 cycles; 64 branch updates; 128-bit two-block relation",
        evidence=json.dumps(payload["mapping_gate"], sort_keys=True),
        domain="XTEA implementation equivalence",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"XTEA:frozen_public_W{width}_relation",
        mechanism="complete_domain_enumeration",
        outcome="XTEA:factual_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{logical} assignments; no early stop",
        evidence=json.dumps(execution["factual_filter_matches"]),
        domain="full-round residual-key enumeration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="XTEA:factual_candidate_set",
        mechanism="two_reference_confirmation",
        outcome=recovered,
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="128 output bits; scalar plus independent NumPy",
        evidence=json.dumps(execution["factual_confirmations"], sort_keys=True),
        domain="independent key confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="XTEA:one_bit_control_relation",
        mechanism="same_complete_search",
        outcome="XTEA:control_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{logical} assignments; identical kernel",
        evidence=json.dumps(execution["control_filter_matches"]),
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="XTEA:control_candidate_set",
        mechanism="zero_control_models",
        outcome="XTEA:control_relation_rejected",
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="zero exact control assignments",
        evidence=json.dumps(execution["control_confirmations"], sort_keys=True),
        domain="matched negative control",
        quality_score=1.0,
    )

    def inferred(**kwargs: Any) -> None:
        try:
            writer.add_triplet(**kwargs, is_inferred=True)
        except TypeError:
            index = writer.add_triplet(**kwargs)
            writer._triplets[index]["is_inferred"] = True

    inferred(
        trigger=f"XTEA:frozen_public_W{width}_relation",
        mechanism="verified_complete_enumeration_and_confirmation_chain",
        outcome=recovered,
        confidence=1.0,
        source="materialized:complete_domain_plus_independent_confirmation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after complete execution and confirmation.",
        domain="AI-native retained inference",
        quality_score=1.0,
    )
    inferred(
        trigger="XTEA:one_bit_control_relation",
        mechanism="verified_matched_control_chain",
        outcome="XTEA:control_relation_rejected",
        confidence=1.0,
        source="materialized:matched_control_separation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after the identical complete control search.",
        domain="AI-native retained inference",
        quality_score=1.0,
    )
    writer.add_cluster(
        name="XTEA verified recovery chain",
        entities=[f"XTEA:frozen_public_W{width}_relation", "complete_domain_enumeration", "XTEA:factual_candidate_set", "two_reference_confirmation", recovered],
    )
    writer.add_cluster(
        name="XTEA matched control chain",
        entities=["XTEA:one_bit_control_relation", "same_complete_search", "XTEA:control_candidate_set", "zero_control_models", "XTEA:control_relation_rejected"],
    )
    writer.add_gap(
        subject=recovered,
        predicate="next_required_gain",
        expected_object_type=f"prospectively_selected_strict_subset_of_W{width}_domain",
        confidence=1.0,
        suggested_queries=[f"Which frozen operator ranks a held-out W{width} XTEA region early?"],
    )
    temporary = path.with_name(f".{path.name}.tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    writer_stats = writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    gaps = list(reader._gaps)
    if (
        reader.api_id != "xteakr1"
        or len(reader._triplets) != 7
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(gaps) != 1
    ):
        raise RuntimeError("XTEA authentic Causal readback gate failed")
    return {
        "path": _artifact_path(path),
        "sha256": _file_sha256(path),
        "reader_source": source,
        "writer_stats": writer_stats,
        "api_id": reader.api_id,
        "triplets": len(reader._triplets),
        "rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": gaps,
    }


def execute(
    *, protocol_path: Path, expected_protocol_sha256: str, result_path: Path, checkpoint_path: Path, causal_path: Path, report_path: Path, build_dir: Path, dotcausal_src: Path, resume: bool
) -> dict[str, Any]:
    if result_path.exists() or causal_path.exists():
        raise FileExistsError("XTEA final result already exists")
    protocol = _load_protocol(protocol_path, expected_protocol_sha256)
    qualification_path = ROOT / protocol["anchors"]["qualification"]["path"]
    qualification_sha256 = protocol["anchors"]["qualification"]["sha256"]
    reference_gate()
    executable, build = FAMILY._compile_native(build_dir)
    with MetalTEAHost(executable) as host:
        mapping = _post_freeze_mapping_gate(host, protocol)
        execution = enumerate_domain(
            host=host,
            protocol=protocol,
            protocol_sha256=expected_protocol_sha256,
            checkpoint_path=checkpoint_path,
            resume=resume,
        )
        identity = host.identity
    if (
        execution["complete_domain_executed"] is not True
        or execution["unique_exact_assignment"] is not True
        or execution["control_target_rejected"] is not True
    ):
        raise RuntimeError("XTEA full-domain recovery headline gate failed")
    payload: dict[str, Any] = {
        "schema": "xtea-metal-recovery-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_XTEA_COMPLETE_DOMAIN_RECOVERY_CONFIRMED",
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "qualification_sha256": qualification_sha256,
        "qualification_path": str(qualification_path.relative_to(ROOT)),
        "anchors": {
            "runner_sha256": _file_sha256(Path(__file__)),
            "family_framework_sha256": _file_sha256(FRAMEWORK_SOURCE),
            "native_source_sha256": _file_sha256(NATIVE_SOURCE),
            "native_executable_sha256": build["executable_sha256"],
        },
        "native_build": build,
        "metal_identity": identity,
        "mapping_gate": mapping,
        "execution": execution,
    }
    payload["execution_sha256"] = _canonical_sha256(
        {key: value for key, value in execution.items() if not key.startswith("volatile_")}
    )
    payload["confirmation_sha256"] = _canonical_sha256(
        {"factual": execution["factual_confirmations"], "control": execution["control_confirmations"]}
    )
    causal = build_causal(path=causal_path, payload=payload, dotcausal_src=dotcausal_src)
    payload["authentic_causal"] = causal
    _atomic_json(result_path, payload)
    report = f"""# XTEAKR1 — Full-round XTEA W{execution['unknown_key_bits']} residual-key recovery

- Complete logical domain: **{execution['logical_candidate_count']:,} assignments**
- Complete standard XTEA execution: **32/32 cycles; 64/64 branch updates**
- Two-block ciphertext relation checked: **128/128 bits**
- Exact factual assignments: **{execution['factual_full_matches']}**
- Exact one-bit control assignments: **{execution['control_full_matches']}**
- GPU seconds: **{execution['gpu_seconds']:.6f}**
- Early stop: **False**
- Scalar and independent NumPy confirmation: **exact**
- Authentic Causal SHA-256: `{causal['sha256']}`
"""
    _atomic_bytes(report_path, report.encode())
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--qualify", action="store_true")
    modes.add_argument("--freeze", action="store_true")
    modes.add_argument("--analyze", action="store_true")
    modes.add_argument("--run", action="store_true")
    parser.add_argument("--qualification", type=Path, default=DEFAULT_QUALIFICATION)
    parser.add_argument("--expected-qualification-sha256")
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--result", type=Path, default=DEFAULT_RESULT)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--causal", type=Path, default=DEFAULT_CAUSAL)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    if args.qualify:
        payload = qualify(output=args.qualification, build_dir=args.build_dir)
        output = {
            "qualification": str(args.qualification),
            "qualification_sha256": _file_sha256(args.qualification),
            "selected_width": payload["selection"]["selected_width"],
            "minimum_candidates_per_gpu_second": payload["benchmark"]["minimum_candidates_per_gpu_second"],
        }
    elif args.freeze:
        if not args.expected_qualification_sha256:
            parser.error("--freeze requires --expected-qualification-sha256")
        payload = freeze_protocol(
            qualification_path=args.qualification,
            expected_qualification_sha256=args.expected_qualification_sha256,
            output=args.protocol,
        )
        output = {
            "protocol": str(args.protocol),
            "protocol_sha256": _file_sha256(args.protocol),
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "unknown_key_bits": payload["challenge"]["unknown_key_bits"],
        }
    else:
        if not args.expected_protocol_sha256:
            parser.error("--analyze/--run requires --expected-protocol-sha256")
        protocol = _load_protocol(args.protocol, args.expected_protocol_sha256)
        if args.analyze:
            output = {
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": args.expected_protocol_sha256,
                "public_challenge_sha256": protocol["public_challenge_sha256"],
                "unknown_key_bits": protocol["challenge"]["unknown_key_bits"],
                "logical_candidate_count": protocol["execution"]["logical_candidates"],
                "candidate_execution_started": False,
            }
        else:
            payload = execute(
                protocol_path=args.protocol,
                expected_protocol_sha256=args.expected_protocol_sha256,
                result_path=args.result,
                checkpoint_path=args.checkpoint,
                causal_path=args.causal,
                report_path=args.report,
                build_dir=args.build_dir,
                dotcausal_src=args.dotcausal_src,
                resume=args.resume,
            )
            output = {
                "result": str(args.result),
                "result_sha256": _file_sha256(args.result),
                "causal_sha256": payload["authentic_causal"]["sha256"],
                "evidence_stage": payload["evidence_stage"],
                "factual_full_matches": payload["execution"]["factual_full_matches"],
                "control_full_matches": payload["execution"]["control_full_matches"],
            }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
