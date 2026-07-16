#!/usr/bin/env python3
"""Qualify and execute a complete full-round SipHash-2-4 residual-key search."""

from __future__ import annotations

import argparse
import importlib.util
import json
import secrets
import statistics
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
FRAMEWORK_SOURCE = Path(__file__).with_name("tea_metal_record.py")
ENGINE_SOURCE = Path(__file__).with_name("xtea_metal_record.py")


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


FAMILY = _load(FRAMEWORK_SOURCE, "siphash_tea_family_framework")
ENGINE = _load(ENGINE_SOURCE, "siphash_complete_domain_engine")

ATTEMPT_ID = "SIPKR1"
NATIVE_SOURCE = FAMILY.NATIVE_SOURCE
DEFAULT_DOTCAUSAL_SRC = FAMILY.DEFAULT_DOTCAUSAL_SRC
DEFAULT_BUILD = ROOT / "research/build/siphash24_metal_v1"
DEFAULT_QUALIFICATION = ROOT / "research/results/v1/siphash24_metal_qualification_v1.json"
DEFAULT_PROTOCOL = ROOT / "research/configs/siphash24_metal_recovery_v1.json"
DEFAULT_RESULT = ROOT / "research/results/v1/siphash24_metal_recovery_v1.json"
DEFAULT_CHECKPOINT = ROOT / "research/results/v1/siphash24_metal_recovery_v1.checkpoint.json"
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = ROOT / "research/reports/FULLROUND_SIPHASH24_METAL_RECOVERY_V1.md"

MASK32 = FAMILY.MASK32
MASK64 = (1 << 64) - 1
STREAM_CANDIDATES = FAMILY.STREAM_CANDIDATES
QUALIFICATION_CANDIDATES = FAMILY.QUALIFICATION_CANDIDATES
QUALIFICATION_REPETITIONS = FAMILY.QUALIFICATION_REPETITIONS
QUALIFICATION_BUDGET_SECONDS = FAMILY.QUALIFICATION_BUDGET_SECONDS
QUALIFICATION_SAFETY_FACTOR = FAMILY.QUALIFICATION_SAFETY_FACTOR
MIN_WIDTH = FAMILY.MIN_WIDTH
MAX_WIDTH = FAMILY.MAX_WIDTH
OFFICIAL_EMPTY = 0x726FDB47DD0E0E31
OFFICIAL_LENGTH8 = 0x93F5F5799A932462

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


def _rotl64(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & MASK64


def _sipround(state: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    value0, value1, value2, value3 = state
    value0 = (value0 + value1) & MASK64
    value1 = _rotl64(value1, 13) ^ value0
    value0 = _rotl64(value0, 32)
    value2 = (value2 + value3) & MASK64
    value3 = _rotl64(value3, 16) ^ value2
    value0 = (value0 + value3) & MASK64
    value3 = _rotl64(value3, 21) ^ value0
    value2 = (value2 + value1) & MASK64
    value1 = _rotl64(value1, 17) ^ value2
    value2 = _rotl64(value2, 32)
    return value0, value1, value2, value3


def siphash24_bytes(key: bytes, data: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("SipHash-2-4 requires a 16-byte key")
    key0 = int.from_bytes(key[:8], "little")
    key1 = int.from_bytes(key[8:], "little")
    state = (
        key0 ^ 0x736F6D6570736575,
        key1 ^ 0x646F72616E646F6D,
        key0 ^ 0x6C7967656E657261,
        key1 ^ 0x7465646279746573,
    )
    end = len(data) - len(data) % 8
    for offset in range(0, end, 8):
        message = int.from_bytes(data[offset : offset + 8], "little")
        state = (*state[:3], state[3] ^ message)
        state = _sipround(_sipround(state))
        state = (state[0] ^ message, *state[1:])
    last = (len(data) & 0xFF) << 56
    for index, byte in enumerate(data[end:]):
        last |= byte << (8 * index)
    state = (*state[:3], state[3] ^ last)
    state = _sipround(_sipround(state))
    state = (state[0] ^ last, state[1], state[2] ^ 0xFF, state[3])
    for _ in range(4):
        state = _sipround(state)
    return (state[0] ^ state[1] ^ state[2] ^ state[3]).to_bytes(8, "little")


def _key_bytes(key_words: Sequence[int]) -> bytes:
    if len(key_words) != 4:
        raise ValueError("SipHash key requires four little-endian uint32 words")
    return b"".join((int(word) & MASK32).to_bytes(4, "little") for word in key_words)


def scalar_hash8(message_words: Sequence[int], key_words: Sequence[int]) -> tuple[int, int]:
    if len(message_words) != 2:
        raise ValueError("SIPKR1 messages contain exactly eight bytes")
    message = b"".join(
        (int(word) & MASK32).to_bytes(4, "little") for word in message_words
    )
    output = siphash24_bytes(_key_bytes(key_words), message)
    return int.from_bytes(output[:4], "little"), int.from_bytes(output[4:], "little")


def _numpy_rotl(value: np.ndarray, shift: int) -> np.ndarray:
    return (value << np.uint64(shift)) | (value >> np.uint64(64 - shift))


def numpy_hash8(message_words: Sequence[int], key_words: Sequence[int]) -> tuple[int, int]:
    if len(message_words) != 2 or len(key_words) != 4:
        raise ValueError("SipHash NumPy boundary differs")
    key0 = np.uint64((int(key_words[1]) << 32) | int(key_words[0]))
    key1 = np.uint64((int(key_words[3]) << 32) | int(key_words[2]))
    message = np.uint64((int(message_words[1]) << 32) | int(message_words[0]))
    state = np.asarray(
        [
            key0 ^ np.uint64(0x736F6D6570736575),
            key1 ^ np.uint64(0x646F72616E646F6D),
            key0 ^ np.uint64(0x6C7967656E657261),
            key1 ^ np.uint64(0x7465646279746573),
        ],
        dtype=np.uint64,
    )

    def round_in_place() -> None:
        with np.errstate(over="ignore"):
            state[0] += state[1]
            state[1] = _numpy_rotl(state[1:2], 13)[0] ^ state[0]
            state[0] = _numpy_rotl(state[0:1], 32)[0]
            state[2] += state[3]
            state[3] = _numpy_rotl(state[3:4], 16)[0] ^ state[2]
            state[0] += state[3]
            state[3] = _numpy_rotl(state[3:4], 21)[0] ^ state[0]
            state[2] += state[1]
            state[1] = _numpy_rotl(state[1:2], 17)[0] ^ state[2]
            state[2] = _numpy_rotl(state[2:3], 32)[0]

    state[3] ^= message
    round_in_place()
    round_in_place()
    state[0] ^= message
    last = np.uint64(8 << 56)
    state[3] ^= last
    round_in_place()
    round_in_place()
    state[0] ^= last
    state[2] ^= np.uint64(0xFF)
    for _ in range(4):
        round_in_place()
    output = int(state[0] ^ state[1] ^ state[2] ^ state[3])
    return output & MASK32, output >> 32


def reference_gate() -> dict[str, Any]:
    official_key = bytes(range(16))
    empty = int.from_bytes(siphash24_bytes(official_key, b""), "little")
    length8 = int.from_bytes(siphash24_bytes(official_key, bytes(range(8))), "little")
    if empty != OFFICIAL_EMPTY or length8 != OFFICIAL_LENGTH8:
        raise RuntimeError("SipHash-2-4 official vector gate failed")
    rows = []
    for index in range(8):
        key_words = tuple(
            (0x10203040 * (index + word + 1) + 0x13579BDF * word) & MASK32
            for word in range(4)
        )
        message = (
            (0x89ABCDEF ^ (0x01010101 * index)) & MASK32,
            (0x76543210 + 0x1020304 * index) & MASK32,
        )
        scalar = scalar_hash8(message, key_words)
        independent = numpy_hash8(message, key_words)
        if scalar != independent:
            raise RuntimeError("SipHash scalar/NumPy reference gate failed")
        rows.append(
            {
                "case": index,
                "key_words": list(key_words),
                "message_words": list(message),
                "output_words": list(scalar),
                "scalar_numpy_exact": True,
            }
        )
    return {
        "reference": "SipHash reference vectors for key bytes 00..0f",
        "official_empty_expected_uint64": OFFICIAL_EMPTY,
        "official_empty_observed_uint64": empty,
        "official_length8_expected_uint64": OFFICIAL_LENGTH8,
        "official_length8_observed_uint64": length8,
        "official_vectors_exact": True,
        "cross_reference_rows": rows,
        "all_exact": True,
    }


def hash_relation(
    message_words: Sequence[int], key_words: Sequence[int]
) -> tuple[int, int, int, int]:
    if len(message_words) != 4:
        raise ValueError("SIPKR1 requires exactly two eight-byte messages")
    return (*scalar_hash8(message_words[:2], key_words), *scalar_hash8(message_words[2:], key_words))


def numpy_relation(
    message_words: Sequence[int], key_words: Sequence[int]
) -> tuple[int, int, int, int]:
    if len(message_words) != 4:
        raise ValueError("SIPKR1 requires exactly two eight-byte messages")
    return (*numpy_hash8(message_words[:2], key_words), *numpy_hash8(message_words[2:], key_words))


def _configure_reference(host: MetalTEAHost, *, width: int) -> None:
    messages = (0x03020100, 0x07060504, 0xA3A2A1A0, 0xA7A6A5A4)
    key_words = (0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C)
    target = hash_relation(messages, key_words)
    context = _context(width)
    known = (0, key_words[1] & ~context["outer_mask"], key_words[2], key_words[3])
    host.configure(
        target=target,
        control=(target[0] ^ 1, *target[1:]),
        known_zeroed_key=known,
        plaintext_words=messages,
        width=width,
        algorithm="siphash24",
    )


def _metal_mapping_gate(host: MetalTEAHost, *, width: int) -> dict[str, Any]:
    context = _context(width)
    messages = (0x03020100, 0x07060504, 0xA3A2A1A0, 0xA7A6A5A4)
    key_words = (0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C)
    known = (0, key_words[1] & ~context["outer_mask"], key_words[2], key_words[3])
    target = hash_relation(messages, key_words)
    host.configure(
        target=target,
        control=(target[0] ^ 1, *target[1:]),
        known_zeroed_key=known,
        plaintext_words=messages,
        width=width,
        algorithm="siphash24",
    )
    rows = []
    for assignment in (0, 1, (1 << 32) - 1, 1 << 32, (1 << width) - 1):
        observed = host.blocks(assignment >> 32, assignment & MASK32, 1)[0]
        key = apply_assignment(known, assignment, width)
        scalar = hash_relation(messages, key)
        independent = numpy_relation(messages, key)
        if observed != scalar or observed != independent:
            raise RuntimeError("SipHash Metal residual mapping gate failed")
        rows.append(
            {
                "assignment": assignment,
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
        raise FileExistsError(f"SipHash qualification already exists: {output}")
    references = reference_gate()
    executable, build = FAMILY._compile_native(build_dir)
    with MetalTEAHost(executable) as host:
        mapping = _metal_mapping_gate(host, width=MAX_WIDTH)
        _configure_reference(host, width=MAX_WIDTH)
        timings = []
        for _ in range(QUALIFICATION_REPETITIONS):
            row = host.filter(0, 0, QUALIFICATION_CANDIDATES)
            if row["control"]:
                raise RuntimeError("SipHash qualification control unexpectedly matched")
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
        raise RuntimeError("SipHash qualification did not clear the minimum width")
    selected = max(eligible)
    payload = {
        "schema": "siphash24-metal-qualification-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_SIPHASH24_METAL_QUALIFIED",
        "algorithm": {
            "name": "SipHash-2-4",
            "compression_rounds_per_message_word": 2,
            "finalization_rounds": 4,
            "complete_standard_round_count": True,
            "key_bits": 128,
            "messages": 2,
            "message_bytes_each": 8,
            "filter_bits": 128,
        },
        "anchors": {
            "qualification_source_sha256": _file_sha256(Path(__file__)),
            "family_framework_sha256": _file_sha256(FRAMEWORK_SOURCE),
            "complete_domain_engine_sha256": _file_sha256(ENGINE_SOURCE),
            "native_source_sha256": _file_sha256(NATIVE_SOURCE),
        },
        "official_reference_gate": references,
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
        raise FileExistsError(f"SipHash protocol already exists: {output}")
    if _file_sha256(qualification_path) != expected_qualification_sha256:
        raise RuntimeError("SipHash qualification hash differs")
    qualification = json.loads(qualification_path.read_bytes())
    if (
        qualification.get("evidence_stage") != "FULLROUND_SIPHASH24_METAL_QUALIFIED"
        or qualification.get("selection", {}).get("production_challenge_generated")
        is not False
    ):
        raise RuntimeError("SipHash qualification semantic gate failed")
    width = int(qualification["selection"]["selected_width"])
    context = _context(width)
    key = tuple(secrets.randbits(32) for _ in range(4))
    messages = tuple(secrets.randbits(32) for _ in range(4))
    target = hash_relation(messages, key)
    if target != numpy_relation(messages, key):
        raise RuntimeError("SipHash target construction references differ")
    control = (target[0] ^ 1, *target[1:])
    known = (0, key[1] & ~context["outer_mask"], key[2], key[3])
    challenge = {
        "message_words": list(messages),
        "message_lengths_bytes": [8, 8],
        "known_key_words_zeroed_residual": list(known),
        "unknown_key_bits": width,
        "known_key_bits": 128 - width,
        "unknown_bit_interval": [0, width - 1],
        "unknown_mapping": "key_k0_low_bits_across_two_little_endian_uint32_words",
        "target_hash_words": list(target),
        "target_sha256": _sha256(_canonical_bytes(target)),
        "control_hash_words": list(control),
        "control_sha256": _sha256(_canonical_bytes(control)),
        "control_relation": "first_hash_word_bit0_flipped",
        "secret_assignment_included": False,
        "full_key_included": False,
        "secret_discarded_after_target_construction": True,
    }
    protocol = {
        "schema": "siphash24-metal-recovery-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_any_production_candidate_execution",
        "algorithm": {
            "name": "SipHash-2-4",
            "compression_rounds_per_message_word": 2,
            "finalization_rounds": 4,
            "complete_standard_round_count": True,
            "messages": 2,
            "output_bits_compared": 128,
        },
        "anchors": {
            "qualification": {
                "path": str(qualification_path.relative_to(ROOT)),
                "sha256": expected_qualification_sha256,
            },
            "runner_sha256": _file_sha256(Path(__file__)),
            "family_framework_sha256": _file_sha256(FRAMEWORK_SOURCE),
            "complete_domain_engine_sha256": _file_sha256(ENGINE_SOURCE),
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
        raise RuntimeError("SipHash protocol hash differs")
    protocol = json.loads(path.read_bytes())
    challenge = protocol.get("challenge", {})
    anchors = protocol.get("anchors", {})
    qualification_path = ROOT / anchors.get("qualification", {}).get("path", "")
    if (
        protocol.get("schema") != "siphash24-metal-recovery-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_before_any_production_candidate_execution"
        or protocol.get("public_challenge_sha256") != _canonical_sha256(challenge)
        or anchors.get("runner_sha256") != _file_sha256(Path(__file__))
        or anchors.get("family_framework_sha256") != _file_sha256(FRAMEWORK_SOURCE)
        or anchors.get("complete_domain_engine_sha256") != _file_sha256(ENGINE_SOURCE)
        or anchors.get("native_source_sha256") != _file_sha256(NATIVE_SOURCE)
        or _file_sha256(qualification_path) != anchors["qualification"]["sha256"]
        or challenge.get("secret_assignment_included") is not False
        or challenge.get("full_key_included") is not False
    ):
        raise RuntimeError("SipHash frozen protocol gate failed")
    _context(int(challenge["unknown_key_bits"]))
    return protocol


def _challenge_values(
    challenge: Mapping[str, Any]
) -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    values = tuple(
        tuple(int(word) for word in challenge[name])
        for name in (
            "known_key_words_zeroed_residual",
            "message_words",
            "target_hash_words",
            "control_hash_words",
        )
    )
    if any(len(value) != 4 for value in values) or any(
        not 0 <= word <= MASK32 for value in values for word in value
    ):
        raise RuntimeError("SipHash challenge word boundary differs")
    return values


def _post_freeze_mapping_gate(
    host: MetalTEAHost, protocol: Mapping[str, Any]
) -> dict[str, Any]:
    challenge = protocol["challenge"]
    width = int(challenge["unknown_key_bits"])
    known, messages, target, control = _challenge_values(challenge)
    host.configure(
        target=target,
        control=control,
        known_zeroed_key=known,
        plaintext_words=messages,
        width=width,
        algorithm="siphash24",
    )
    rows = []
    for assignment in (0, 1, (1 << 32) - 1, 1 << 32, (1 << width) - 1):
        observed = host.blocks(assignment >> 32, assignment & MASK32, 1)[0]
        key = apply_assignment(known, assignment, width)
        if observed != hash_relation(messages, key) or observed != numpy_relation(messages, key):
            raise RuntimeError("SipHash post-freeze mapping gate failed")
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
        "schema": "siphash24-complete-domain-checkpoint-v1",
        "protocol_sha256": protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "width": width,
        "logical_candidate_count": context["logical_candidates"],
        "stream_candidate_count": STREAM_CANDIDATES,
        "candidate_encoding": "combined=(key_k0_high_low_bits<<32)|key_k0_low32",
    }


def _confirm(
    protocol: Mapping[str, Any], assignment: int, expected: Sequence[int], relation: str
) -> dict[str, Any]:
    challenge = protocol["challenge"]
    width = int(challenge["unknown_key_bits"])
    known, messages, _, _ = _challenge_values(challenge)
    key = apply_assignment(known, assignment, width)
    scalar = hash_relation(messages, key)
    independent = numpy_relation(messages, key)
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


def build_causal(
    *, path: Path, payload: Mapping[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = FAMILY._load_dotcausal(dotcausal_src)
    execution = payload["execution"]
    width = int(execution["unknown_key_bits"])
    logical = int(execution["logical_candidate_count"])
    recovered = f"SipHash24:unique_verified_W{width}_fullround_residual"
    writer = CausalWriter(api_id="sipkr1")
    writer._rules = []
    writer.add_rule(
        name="complete_domain_plus_independent_confirmation",
        description="Complete SipHash-2-4 residual enumeration plus scalar and independent NumPy confirmation establishes the recovered assignment.",
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
        trigger="SipHash24:pre_target_Metal_qualification",
        mechanism="official_vectors_plus_scalar_NumPy_Metal_mapping_gates",
        outcome="SipHash24:qualified_fullround_enumerator",
        confidence=1.0,
        source=payload["qualification_sha256"],
        quantification="SipHash-2-4; two 64-bit messages; 128-bit relation",
        evidence=json.dumps(payload["mapping_gate"], sort_keys=True),
        domain="SipHash implementation equivalence",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"SipHash24:frozen_public_W{width}_relation",
        mechanism="complete_domain_enumeration",
        outcome="SipHash24:factual_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{logical} assignments; no early stop",
        evidence=json.dumps(execution["factual_filter_matches"]),
        domain="full-round residual-key enumeration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="SipHash24:factual_candidate_set",
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
        trigger="SipHash24:one_bit_control_relation",
        mechanism="same_complete_search",
        outcome="SipHash24:control_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{logical} assignments; identical kernel",
        evidence=json.dumps(execution["control_filter_matches"]),
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="SipHash24:control_candidate_set",
        mechanism="zero_control_models",
        outcome="SipHash24:control_relation_rejected",
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="zero exact control assignments",
        evidence=json.dumps(execution["control_confirmations"], sort_keys=True),
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"SipHash24:frozen_public_W{width}_relation",
        mechanism="verified_complete_enumeration_and_confirmation_chain",
        outcome=recovered,
        confidence=1.0,
        source="materialized:complete_domain_plus_independent_confirmation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after complete execution and confirmation.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_triplet(
        trigger="SipHash24:one_bit_control_relation",
        mechanism="verified_matched_control_chain",
        outcome="SipHash24:control_relation_rejected",
        confidence=1.0,
        source="materialized:matched_control_separation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after the identical complete control search.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="SipHash-2-4 verified recovery chain",
        entities=[f"SipHash24:frozen_public_W{width}_relation", "complete_domain_enumeration", "SipHash24:factual_candidate_set", "two_reference_confirmation", recovered],
    )
    writer.add_cluster(
        name="SipHash-2-4 matched control chain",
        entities=["SipHash24:one_bit_control_relation", "same_complete_search", "SipHash24:control_candidate_set", "zero_control_models", "SipHash24:control_relation_rejected"],
    )
    writer.add_gap(
        subject=recovered,
        predicate="next_required_gain",
        expected_object_type=f"prospectively_selected_strict_subset_of_W{width}_domain",
        confidence=1.0,
        suggested_queries=[f"Which frozen operator ranks a held-out W{width} SipHash region early?"],
    )
    temporary = path.with_name(f".{path.name}.tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    writer_stats = writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    gaps = list(reader._gaps)
    if (
        reader.api_id != "sipkr1"
        or len(reader._triplets) != 7
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(gaps) != 1
    ):
        raise RuntimeError("SipHash authentic Causal readback gate failed")
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
        raise FileExistsError("SipHash final result already exists")
    protocol = _load_protocol(protocol_path, expected_protocol_sha256)
    qualification_path = ROOT / protocol["anchors"]["qualification"]["path"]
    qualification_sha256 = protocol["anchors"]["qualification"]["sha256"]
    reference_gate()
    executable, build = FAMILY._compile_native(build_dir)
    with MetalTEAHost(executable) as host:
        mapping = _post_freeze_mapping_gate(host, protocol)
        execution = ENGINE.enumerate_domain(
            host=host,
            protocol=protocol,
            protocol_sha256=expected_protocol_sha256,
            checkpoint_path=checkpoint_path,
            resume=resume,
            checkpoint_fingerprint_fn=_checkpoint_fingerprint,
            confirm_fn=_confirm,
            challenge_values_fn=_challenge_values,
            attempt_id=ATTEMPT_ID,
            label="SipHash24",
        )
        identity = host.identity
    if (
        execution["complete_domain_executed"] is not True
        or execution["unique_exact_assignment"] is not True
        or execution["control_target_rejected"] is not True
    ):
        raise RuntimeError("SipHash full-domain recovery headline gate failed")
    payload: dict[str, Any] = {
        "schema": "siphash24-metal-recovery-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_SIPHASH24_COMPLETE_DOMAIN_RECOVERY_CONFIRMED",
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "qualification_sha256": qualification_sha256,
        "qualification_path": str(qualification_path.relative_to(ROOT)),
        "anchors": {
            "runner_sha256": _file_sha256(Path(__file__)),
            "family_framework_sha256": _file_sha256(FRAMEWORK_SOURCE),
            "complete_domain_engine_sha256": _file_sha256(ENGINE_SOURCE),
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
    report_text = f"""# SIPKR1 — Full-round SipHash-2-4 W{execution['unknown_key_bits']} residual-key recovery

- Complete logical domain: **{execution['logical_candidate_count']:,} assignments**
- Complete standard SipHash execution: **2 compression + 4 finalization rounds**
- Two-message hash relation checked: **128/128 bits**
- Exact factual assignments: **{execution['factual_full_matches']}**
- Exact one-bit control assignments: **{execution['control_full_matches']}**
- GPU seconds: **{execution['gpu_seconds']:.6f}**
- Early stop: **False**
- Scalar and independent NumPy confirmation: **exact**
- Authentic Causal SHA-256: `{causal['sha256']}`
"""
    _atomic_bytes(report_path, report_text.encode())
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
