#!/usr/bin/env python3
"""Prospective full-round ChaCha20 W43 residual-key record on Apple Metal."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import secrets
import struct
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.chacha20_rfc8439_reference import (
    RFC8439_SECTION_2_3_2_BLOCK,
    RFC8439_SECTION_2_3_2_COUNTER,
    RFC8439_SECTION_2_3_2_KEY,
    RFC8439_SECTION_2_3_2_NONCE,
    chacha20_block,
    rfc8439_section_2_3_2_kat,
)

ROOT = Path(__file__).parents[2]


def _load_sibling(filename: str, name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ANCHOR = _load_sibling(
    "chacha20_round20_a223_w40_metal_transfer.py",
    "chacha20_w43_a225_anchor",
)
A184 = ANCHOR.A184
A223 = ANCHOR.A223

ATTEMPT_ID = "CHACHA20KR43"
SCHEMA = "chacha20-round20-w43-metal-record-result-v1"
PROTOCOL_SCHEMA = "chacha20-round20-w43-metal-record-protocol-v1"
QUALIFICATION_SCHEMA = "chacha20-round20-w43-metal-record-qualification-v1"
DESIGN_SCHEMA = "chacha20-round20-w43-metal-record-design-v1"
DESIGN_SHA256 = "1b8b9aac076787ec4d4f7f06108e4b82ac7e70c6f494ee8cd9d05c2148bc92ff"

DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
DEFAULT_DESIGN = ROOT / "research/configs/chacha20_round20_w43_metal_record_design_v1.json"
DEFAULT_QUALIFICATION = ROOT / "research/results/v1/chacha20_round20_w43_metal_qualification_v1.json"
DEFAULT_PROTOCOL = ROOT / "research/configs/chacha20_round20_w43_metal_record_v1.json"
DEFAULT_RESULT = ROOT / "research/results/v1/chacha20_round20_w43_metal_record_v1.json"
DEFAULT_CHECKPOINT = ROOT / "research/results/v1/chacha20_round20_w43_metal_record_v1.checkpoint.json"
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = ROOT / "research/reports/FULLROUND_CHACHA20_W43_METAL_RECORD_V1.md"
DEFAULT_BUILD = ROOT / "research/build/chacha20_round20_w43_metal_v1"

WIDTH = 43
WORD0_BITS = 32
WORD1_LOW_BITS = 11
KNOWN_KEY_BITS = 256 - WIDTH
OUTER_SLICES = 1 << WORD1_LOW_BITS
INNER_CANDIDATES = 1 << WORD0_BITS
DOMAIN_SIZE = 1 << WIDTH
STREAM_CANDIDATES = A184.STREAM_CANDIDATES
RESULT_CAPACITY = A184.RESULT_CAPACITY
BLOCK_COUNT = 8
FILTER_WORDS = 2
QUALIFICATION_CANDIDATES = 1 << 28
QUALIFICATION_REPETITIONS = 3
QUALIFICATION_SAFETY_FACTOR = 1.25
QUALIFICATION_BUDGET_SECONDS = 10_800.0
MASK32 = 0xFFFFFFFF


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _artifact_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_bytes(
        path,
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n",
    )


def _words(raw: bytes) -> list[int]:
    if len(raw) % 4:
        raise ValueError("word input must be a multiple of four bytes")
    return list(struct.unpack(f"<{len(raw) // 4}I", raw))


def _word_bytes(words: Sequence[int]) -> bytes:
    return struct.pack(f"<{len(words)}I", *(int(word) & MASK32 for word in words))


def _load_design(path: Path) -> dict[str, Any]:
    if _file_sha256(path) != DESIGN_SHA256:
        raise RuntimeError("ChaCha20 W43 frozen design hash differs")
    design = json.loads(path.read_bytes())
    execution = design.get("execution", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema") != DESIGN_SCHEMA
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_before_qualification_and_before_generation_of_the_fresh_production_challenge"
        or execution.get("rounds") != 20
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("known_key_bits") != KNOWN_KEY_BITS
        or execution.get("public_output_blocks") != BLOCK_COUNT
        or execution.get("complete_candidate_domain") != DOMAIN_SIZE
        or execution.get("complete_domain_required") is not True
        or execution.get("early_stop") is not False
        or boundary.get("fresh_assignment_not_stored_in_protocol_source_or_checkpoint")
        is not True
    ):
        raise RuntimeError("ChaCha20 W43 frozen design semantic gate failed")
    return design


def apply_assignment(known_zeroed_key_words: Sequence[int], assignment: int) -> list[int]:
    if len(known_zeroed_key_words) != 8:
        raise ValueError("ChaCha20 requires eight key words")
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("assignment is outside the W43 residual domain")
    key = [int(word) & MASK32 for word in known_zeroed_key_words]
    if key[0] != 0 or key[1] & ((1 << WORD1_LOW_BITS) - 1):
        raise ValueError("known key does not zero the W43 residual interval")
    key[0] = assignment & MASK32
    key[1] |= assignment >> WORD0_BITS
    return key


def _initial(
    known_zeroed_key_words: Sequence[int],
    counter: int,
    nonce_words: Sequence[int],
    outer: int,
) -> np.ndarray:
    if not 0 <= outer < OUTER_SLICES:
        raise ValueError("outer slice is outside the 11-bit domain")
    key = apply_assignment(known_zeroed_key_words, outer << WORD0_BITS)
    initial = np.zeros(16, dtype=np.uint32)
    initial[:4] = np.asarray(ANCHOR.A119.CONSTANTS, dtype=np.uint32)
    initial[4:12] = np.asarray(key, dtype=np.uint32)
    initial[12] = np.uint32(counter)
    initial[13:16] = np.asarray(nonce_words, dtype=np.uint32)
    return initial


def _reference_outputs(
    key_words: Sequence[int], counter_start: int, nonce_words: Sequence[int]
) -> list[list[int]]:
    key = _word_bytes(key_words)
    nonce = _word_bytes(nonce_words)
    return [
        _words(
            chacha20_block(
                key=key,
                counter=(counter_start + block) & MASK32,
                nonce=nonce,
            )
        )
        for block in range(BLOCK_COUNT)
    ]


def reference_gate() -> dict[str, Any]:
    if not rfc8439_section_2_3_2_kat():
        raise RuntimeError("RFC 8439 Section 2.3.2 gate failed")
    key_words = _words(RFC8439_SECTION_2_3_2_KEY)
    nonce_words = _words(RFC8439_SECTION_2_3_2_NONCE)
    independent_words = A223.P1._chacha_block(
        key_words=key_words,
        counter=RFC8439_SECTION_2_3_2_COUNTER,
        nonce_words=nonce_words,
        rounds=20,
    )
    expected_words = _words(RFC8439_SECTION_2_3_2_BLOCK)
    if independent_words != expected_words:
        raise RuntimeError("independent ChaCha20 implementation differs from RFC 8439")
    return {
        "reference": "RFC_8439_Section_2.3.2",
        "rounds": 20,
        "feedforward": True,
        "output_bits_checked": 512,
        "pure_python_exact": True,
        "independent_word_reference_exact": True,
        "output_sha256": _sha256(RFC8439_SECTION_2_3_2_BLOCK),
    }


def _mapping_gate(
    host: Any,
    *,
    known_zeroed_key_words: Sequence[int],
    counter: int,
    nonce_words: Sequence[int],
) -> dict[str, Any]:
    first = 0x2468AC00
    count = 8
    target_offset = 3
    rows: list[dict[str, Any]] = []
    for outer in (0, 0x3FF, 0x7FF):
        initial = _initial(known_zeroed_key_words, counter, nonce_words, outer)
        expected = []
        for word0 in range(first, first + count):
            key_words = apply_assignment(
                known_zeroed_key_words,
                (outer << WORD0_BITS) | word0,
            )
            expected.append(
                _reference_outputs(key_words, counter, nonce_words)[0]
            )
        expected_array = np.asarray(expected, dtype=np.uint32)
        target = expected_array[target_offset].copy()
        control = target.copy()
        control[0] ^= np.uint32(1)
        host.configure(initial, target, control)
        observed = host.blocks(first, count)
        filtered = host.filter(first, count)
        if (
            not np.array_equal(observed, expected_array)
            or filtered["factual"] != [first + target_offset]
            or filtered["control"] != []
        ):
            raise RuntimeError("ChaCha20 W43 Metal mapping gate failed")
        rows.append(
            {
                "outer11": outer,
                "first_key_word0": first,
                "candidate_count": count,
                "factual_key_word0": first + target_offset,
                "complete_output_bits_checked": count * 512,
                "output_sha256": _sha256(
                    observed.astype("<u4", copy=False).tobytes()
                ),
            }
        )
    return {
        "rows": rows,
        "logical_candidates_checked": len(rows) * count,
        "complete_output_bits_checked": len(rows) * count * 512,
        "official_reference_and_Metal_exact": True,
    }


def _qualification_material() -> tuple[list[int], int, list[int]]:
    raw = hashlib.shake_256(b"CHACHA20KR43|qualification|public").digest(48)
    words = _words(raw)
    key = words[:8]
    key[0] = 0
    key[1] &= ~((1 << WORD1_LOW_BITS) - 1)
    return key, words[8], words[9:12]


def qualify(
    *, design_path: Path, output: Path, build_dir: Path, swiftc: str
) -> dict[str, Any]:
    design = _load_design(design_path)
    reference = reference_gate()
    known_key, counter, nonce = _qualification_material()
    executable, build = A184._A181._compile_native(build_dir, swiftc)
    target_words = _reference_outputs(known_key, counter, nonce)[0]
    control_words = target_words.copy()
    control_words[0] ^= 1
    host = A184.SliceMetalHost(
        executable,
        _initial(known_key, counter, nonce, 0),
        np.asarray(target_words, dtype=np.uint32),
        np.asarray(control_words, dtype=np.uint32),
    )
    try:
        mapping = _mapping_gate(
            host,
            known_zeroed_key_words=known_key,
            counter=counter,
            nonce_words=nonce,
        )
        host.configure(
            _initial(known_key, counter, nonce, 0),
            np.asarray(target_words, dtype=np.uint32),
            np.asarray(control_words, dtype=np.uint32),
        )
        rates = []
        benchmark_rows = []
        for repetition in range(QUALIFICATION_REPETITIONS):
            row = host.filter(0, QUALIFICATION_CANDIDATES)
            gpu_seconds = float(row["gpu_seconds"])
            rate = QUALIFICATION_CANDIDATES / gpu_seconds
            rates.append(rate)
            benchmark_rows.append(
                {
                    "repetition": repetition,
                    "candidate_count": QUALIFICATION_CANDIDATES,
                    "gpu_seconds": gpu_seconds,
                    "candidates_per_gpu_second": rate,
                    "factual_matches": row["factual"],
                    "control_matches": row["control"],
                }
            )
        identity = host.identity
    finally:
        host.close()
    minimum_rate = min(rates)
    projected_seconds = DOMAIN_SIZE / minimum_rate
    safety_seconds = projected_seconds * QUALIFICATION_SAFETY_FACTOR
    if safety_seconds > QUALIFICATION_BUDGET_SECONDS:
        raise RuntimeError(
            "ChaCha20 W43 qualification does not fit the frozen launch budget"
        )
    payload = {
        "schema": QUALIFICATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "qualification_state": "complete_before_production_challenge_generation",
        "design_sha256": DESIGN_SHA256,
        "design_execution_sha256": _canonical_sha256(design["execution"]),
        "reference_gate": reference,
        "mapping_gate": mapping,
        "native_build": build,
        "metal_identity": identity,
        "benchmark": {
            "rows": benchmark_rows,
            "minimum_candidates_per_gpu_second": minimum_rate,
            "projected_complete_domain_seconds": projected_seconds,
            "safety_factor": QUALIFICATION_SAFETY_FACTOR,
            "safety_adjusted_projected_seconds": safety_seconds,
            "maximum_projected_seconds": QUALIFICATION_BUDGET_SECONDS,
        },
        "selection": {
            "selected_width": WIDTH,
            "logical_candidate_count": DOMAIN_SIZE,
            "launch_approved": True,
        },
        "production_challenge_generated": False,
    }
    _atomic_json(output, payload)
    return payload


def _challenge_from_assignment(*, label: str, assignment: int) -> dict[str, Any]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("assignment is outside W43")
    derived = hashlib.shake_256(label.encode("utf-8")).digest(48)
    words = _words(derived)
    known_key = words[:8]
    known_key[0] = 0
    known_key[1] &= ~((1 << WORD1_LOW_BITS) - 1)
    counter = words[8]
    nonce_words = words[9:12]
    full_key = apply_assignment(known_key, assignment)
    targets = _reference_outputs(full_key, counter, nonce_words)
    target_hashes = [_sha256(_word_bytes(block)) for block in targets]
    control = targets[0].copy()
    control[0] ^= 1
    return {
        "challenge_id": "chacha20-r20-w43-fresh-v1",
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward": True,
        "known_material_derivation_label": label,
        "known_material_derivation_sha256": _sha256(derived),
        "known_zeroed_key_words": known_key,
        "known_key_bits": KNOWN_KEY_BITS,
        "unknown_key_bits": WIDTH,
        "unknown_layout": "key_word0_all32_plus_key_word1_low11",
        "unknown_assignment_included": False,
        "counter_start": counter,
        "nonce_words": nonce_words,
        "target_words": targets,
        "target_block_sha256": target_hashes,
        "control_target_words": control,
        "control_target_block_sha256": _sha256(_word_bytes(control)),
        "public_output_blocks": BLOCK_COUNT,
        "public_output_bits": BLOCK_COUNT * 512,
        "filter_words": FILTER_WORDS,
        "filter_bits": FILTER_WORDS * 32,
    }


def _validate_challenge(challenge: Mapping[str, Any]) -> None:
    if (
        challenge.get("challenge_id") != "chacha20-r20-w43-fresh-v1"
        or challenge.get("primitive") != "RFC8439_ChaCha20_block_function"
        or challenge.get("rounds") != 20
        or challenge.get("feedforward") is not True
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("known_key_bits") != KNOWN_KEY_BITS
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("public_output_blocks") != BLOCK_COUNT
        or challenge.get("public_output_bits") != BLOCK_COUNT * 512
        or challenge.get("filter_words") != FILTER_WORDS
        or len(challenge.get("known_zeroed_key_words", [])) != 8
        or len(challenge.get("nonce_words", [])) != 3
        or len(challenge.get("target_words", [])) != BLOCK_COUNT
        or any(len(block) != 16 for block in challenge.get("target_words", []))
    ):
        raise RuntimeError("ChaCha20 W43 public challenge shape differs")
    label = str(challenge["known_material_derivation_label"])
    derived = hashlib.shake_256(label.encode("utf-8")).digest(48)
    words = _words(derived)
    expected_key = words[:8]
    expected_key[0] = 0
    expected_key[1] &= ~((1 << WORD1_LOW_BITS) - 1)
    targets = [[int(word) & MASK32 for word in block] for block in challenge["target_words"]]
    control = [int(word) & MASK32 for word in challenge["control_target_words"]]
    if (
        _sha256(derived) != challenge["known_material_derivation_sha256"]
        or expected_key != challenge["known_zeroed_key_words"]
        or words[8] != challenge["counter_start"]
        or words[9:12] != challenge["nonce_words"]
        or expected_key[0] != 0
        or expected_key[1] & ((1 << WORD1_LOW_BITS) - 1)
        or [_sha256(_word_bytes(block)) for block in targets]
        != challenge["target_block_sha256"]
        or control[0] != (targets[0][0] ^ 1)
        or control[1:] != targets[0][1:]
        or _sha256(_word_bytes(control)) != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("ChaCha20 W43 public challenge identity gate failed")


def _execution_plan() -> dict[str, Any]:
    return {
        "rounds": 20,
        "feedforward": True,
        "unknown_key_bits": WIDTH,
        "known_key_bits": KNOWN_KEY_BITS,
        "logical_candidate_count": DOMAIN_SIZE,
        "outer_slice_count": OUTER_SLICES,
        "inner_candidates_per_slice": INNER_CANDIDATES,
        "stream_candidates": STREAM_CANDIDATES,
        "stream_batch_count": DOMAIN_SIZE // STREAM_CANDIDATES,
        "filter_output_bits": FILTER_WORDS * 32,
        "public_output_blocks": BLOCK_COUNT,
        "public_output_bits": BLOCK_COUNT * 512,
        "complete_domain_required": True,
        "early_stop_used": False,
        "checkpoint_resume_enabled": True,
        "matched_one_bit_control_required": True,
        "full_confirmation": "RFC8439_byte_reference_plus_independent_word_reference_all_4096_bits",
    }


def freeze_protocol(
    *,
    design_path: Path,
    qualification_path: Path,
    expected_qualification_sha256: str,
    output: Path,
) -> dict[str, Any]:
    _load_design(design_path)
    if _file_sha256(qualification_path) != expected_qualification_sha256:
        raise RuntimeError("ChaCha20 W43 qualification hash differs")
    qualification = json.loads(qualification_path.read_bytes())
    if (
        qualification.get("schema") != QUALIFICATION_SCHEMA
        or qualification.get("attempt_id") != ATTEMPT_ID
        or qualification.get("qualification_state")
        != "complete_before_production_challenge_generation"
        or qualification.get("selection", {}).get("selected_width") != WIDTH
        or qualification.get("selection", {}).get("launch_approved") is not True
        or qualification.get("production_challenge_generated") is not False
    ):
        raise RuntimeError("ChaCha20 W43 qualification semantic gate failed")
    label = f"CHACHA20KR43|fresh|{secrets.token_hex(32)}"
    assignment = secrets.randbits(WIDTH)
    challenge = _challenge_from_assignment(label=label, assignment=assignment)
    del assignment
    plan = _execution_plan()
    payload = {
        "schema": PROTOCOL_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_after_qualification_before_candidate_execution",
        "anchors": {
            "design": {
                "path": _artifact_path(design_path),
                "sha256": DESIGN_SHA256,
            },
            "qualification": {
                "path": _artifact_path(qualification_path),
                "sha256": expected_qualification_sha256,
            },
            "runner_sha256_at_freeze": _file_sha256(Path(__file__)),
            "native_source_sha256": A184.NATIVE_SOURCE_SHA256,
        },
        "challenge": challenge,
        "public_challenge_sha256": _canonical_sha256(challenge),
        "execution": plan,
        "execution_sha256": _canonical_sha256(plan),
        "information_boundary": {
            "fresh_assignment_generated_only_to_materialize_public_outputs": True,
            "fresh_assignment_stored": False,
            "candidate_outcomes_used_before_freeze": False,
            "complete_domain_required": True,
            "success_evaluated_only_after_complete_domain": True,
        },
    }
    _atomic_json(output, payload)
    return payload


def _load_protocol(path: Path, expected_sha256: str) -> dict[str, Any]:
    if _file_sha256(path) != expected_sha256:
        raise RuntimeError("ChaCha20 W43 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_qualification_before_candidate_execution"
        or protocol.get("anchors", {}).get("design", {}).get("sha256")
        != DESIGN_SHA256
        or protocol.get("anchors", {}).get("native_source_sha256")
        != A184.NATIVE_SOURCE_SHA256
        or protocol.get("anchors", {}).get("runner_sha256_at_freeze")
        != _file_sha256(Path(__file__))
        or protocol.get("execution") != _execution_plan()
        or protocol.get("execution_sha256") != _canonical_sha256(_execution_plan())
        or protocol.get("information_boundary", {}).get("fresh_assignment_stored")
        is not False
    ):
        raise RuntimeError("ChaCha20 W43 frozen protocol semantic gate failed")
    _validate_challenge(protocol["challenge"])
    if _canonical_sha256(protocol["challenge"]) != protocol["public_challenge_sha256"]:
        raise RuntimeError("ChaCha20 W43 public challenge hash differs")
    return protocol


def _checkpoint_fingerprint(
    protocol_sha256: str, protocol: Mapping[str, Any], domain_size: int
) -> dict[str, Any]:
    return {
        "schema": "chacha20-round20-w43-metal-record-checkpoint-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "native_source_sha256": A184.NATIVE_SOURCE_SHA256,
        "domain_size": domain_size,
        "stream_candidates": STREAM_CANDIDATES,
    }


def enumerate_domain(
    *,
    host: Any,
    protocol: Mapping[str, Any],
    protocol_sha256: str,
    checkpoint_path: Path,
    resume: bool,
    domain_size: int = DOMAIN_SIZE,
    stream_candidates: int = STREAM_CANDIDATES,
) -> dict[str, Any]:
    if domain_size < 1 or domain_size > DOMAIN_SIZE:
        raise ValueError("domain_size is outside W43")
    if stream_candidates < 1 or stream_candidates > STREAM_CANDIDATES:
        raise ValueError("stream_candidates is outside the native batch boundary")
    challenge = protocol["challenge"]
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    fingerprint = _checkpoint_fingerprint(protocol_sha256, protocol, domain_size)
    fingerprint["stream_candidates"] = stream_candidates
    next_assignment = 0
    factual: list[int] = []
    controls: list[int] = []
    gpu_seconds = 0.0
    if checkpoint_path.exists() and not resume:
        raise FileExistsError("ChaCha20 W43 checkpoint exists; pass --resume")
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_bytes())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("ChaCha20 W43 checkpoint fingerprint differs")
        next_assignment = int(checkpoint["next_assignment"])
        factual = [int(value) for value in checkpoint["factual_filtered"]]
        controls = [int(value) for value in checkpoint["control_filtered"]]
        gpu_seconds = float(checkpoint["gpu_seconds"])
        if (
            next_assignment % stream_candidates
            or not 0 <= next_assignment <= domain_size
            or any(not 0 <= value < next_assignment for value in factual + controls)
        ):
            raise RuntimeError("ChaCha20 W43 checkpoint progress differs")
    resumed = next_assignment
    configured_outer: int | None = None
    started = time.perf_counter()
    while next_assignment < domain_size:
        outer = next_assignment >> WORD0_BITS
        first = next_assignment & MASK32
        count = min(
            stream_candidates,
            INNER_CANDIDATES - first,
            domain_size - next_assignment,
        )
        if configured_outer != outer:
            host.configure(
                _initial(
                    challenge["known_zeroed_key_words"],
                    int(challenge["counter_start"]),
                    challenge["nonce_words"],
                    outer,
                ),
                target,
                control,
            )
            configured_outer = outer
        row = host.filter(first, count)
        for name, destination in (("factual", factual), ("control", controls)):
            for inner in row[name]:
                combined = (outer << WORD0_BITS) | int(inner)
                if not next_assignment <= combined < next_assignment + count:
                    raise RuntimeError(
                        f"ChaCha20 W43 {name} candidate is outside its batch"
                    )
                destination.append(combined)
            if len(destination) != len(set(destination)):
                raise RuntimeError(f"ChaCha20 W43 duplicate {name} candidate")
        gpu_seconds += float(row.get("gpu_seconds", 0.0))
        next_assignment += count
        _atomic_json(
            checkpoint_path,
            {
                **fingerprint,
                "next_assignment": next_assignment,
                "factual_filtered": factual,
                "control_filtered": controls,
                "gpu_seconds": gpu_seconds,
                "complete_domain_executed": next_assignment == domain_size,
                "early_stop_used": False,
                "success_evaluated_before_complete_domain": False,
            },
        )
        if next_assignment % (1 << 34) == 0 or next_assignment == domain_size:
            print(
                json.dumps(
                    {
                        "attempt_id": ATTEMPT_ID,
                        "next_assignment": next_assignment,
                        "logical_candidates": domain_size,
                        "progress": next_assignment / domain_size,
                        "gpu_seconds": gpu_seconds,
                        "factual_filters": len(factual),
                        "control_filters": len(controls),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
    return {
        "unknown_key_bits": WIDTH if domain_size == DOMAIN_SIZE else None,
        "known_key_bits": KNOWN_KEY_BITS if domain_size == DOMAIN_SIZE else None,
        "logical_candidate_count": domain_size,
        "executed_assignment_count": next_assignment,
        "resumed_assignment_count": resumed,
        "newly_executed_assignment_count": next_assignment - resumed,
        "complete_domain_executed": next_assignment == domain_size,
        "early_stop_used": False,
        "success_evaluated_only_after_complete_domain": True,
        "factual_filter_matches": factual,
        "control_filter_matches": controls,
        "gpu_seconds": gpu_seconds,
        "volatile_wall_seconds": time.perf_counter() - started,
    }


def _confirm(protocol: Mapping[str, Any], assignment: int) -> dict[str, Any]:
    challenge = protocol["challenge"]
    key_words = apply_assignment(challenge["known_zeroed_key_words"], assignment)
    target_words = challenge["target_words"]
    byte_outputs = _reference_outputs(
        key_words,
        int(challenge["counter_start"]),
        challenge["nonce_words"],
    )
    word_outputs = [
        A223.P1._chacha_block(
            key_words=key_words,
            counter=(int(challenge["counter_start"]) + block) & MASK32,
            nonce_words=challenge["nonce_words"],
            rounds=20,
        )
        for block in range(BLOCK_COUNT)
    ]
    byte_matches = [
        observed == expected
        for observed, expected in zip(byte_outputs, target_words, strict=True)
    ]
    word_matches = [
        observed == expected
        for observed, expected in zip(word_outputs, target_words, strict=True)
    ]
    return {
        "assignment": assignment,
        "recovered_key_words": key_words,
        "recovered_key_words_hex": [f"{word:08x}" for word in key_words],
        "byte_reference_block_matches": byte_matches,
        "word_reference_block_matches": word_matches,
        "all_blocks_match": all(byte_matches) and all(word_matches),
        "output_bits_checked_per_reference": BLOCK_COUNT * 512,
        "total_cross_implementation_output_bits_checked": BLOCK_COUNT * 512 * 2,
        "byte_reference_sha256": [
            _sha256(_word_bytes(block)) for block in byte_outputs
        ],
        "word_reference_sha256": [
            _sha256(_word_bytes(block)) for block in word_outputs
        ],
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    source = str(dotcausal_src.resolve())
    if source not in sys.path:
        sys.path.insert(0, source)
    module = importlib.import_module("dotcausal.io")
    io_path = Path(inspect.getsourcefile(module) or "")
    return module.CausalWriter, module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(io_path),
        "io_sha256": _file_sha256(io_path),
    }


def build_causal(
    *, path: Path, payload: Mapping[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = _load_dotcausal(dotcausal_src)
    execution = payload["execution"]
    recovered = "ChaCha20:unique_verified_W43_fullround_residual"
    writer = CausalWriter(api_id="c20kr43")
    writer._rules = []
    writer.add_rule(
        name="complete_domain_plus_independent_confirmation",
        description="Complete standard ChaCha20 W43 residual enumeration plus two independent 4096-bit confirmations establishes the recovered assignment.",
        pattern=["complete_domain_enumeration", "dual_4096_bit_confirmation"],
        conclusion="verified_residual_key_recovery",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="matched_control_separation",
        description="The identical full search returns zero models for the one-bit control relation.",
        pattern=["same_complete_search", "zero_control_models"],
        conclusion="target_specific_recovery",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="ChaCha20:pre_target_Metal_qualification",
        mechanism="RFC8439_plus_independent_word_and_Metal_mapping_gates",
        outcome="ChaCha20:qualified_W43_fullround_enumerator",
        confidence=1.0,
        source=payload["qualification_sha256"],
        quantification="20 rounds plus feed-forward; 512-bit block function",
        evidence=json.dumps(payload["mapping_gate"], sort_keys=True),
        domain="ChaCha20 implementation equivalence",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="ChaCha20:frozen_public_W43_relation",
        mechanism="complete_domain_enumeration",
        outcome="ChaCha20:factual_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{DOMAIN_SIZE} assignments; no early stop",
        evidence=json.dumps(execution["factual_filter_matches"]),
        domain="full-round residual-key enumeration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="ChaCha20:factual_candidate_set",
        mechanism="dual_4096_bit_confirmation",
        outcome=recovered,
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="eight blocks; RFC byte reference plus independent word reference",
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="independent key confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="ChaCha20:one_bit_control_relation",
        mechanism="same_complete_search",
        outcome="ChaCha20:control_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{DOMAIN_SIZE} assignments; identical kernel",
        evidence=json.dumps(execution["control_filter_matches"]),
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="ChaCha20:control_candidate_set",
        mechanism="zero_control_models",
        outcome="ChaCha20:control_relation_rejected",
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="zero exact control assignments",
        evidence="[]",
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="ChaCha20:frozen_public_W43_relation",
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
        trigger="ChaCha20:one_bit_control_relation",
        mechanism="verified_matched_control_chain",
        outcome="ChaCha20:control_relation_rejected",
        confidence=1.0,
        source="materialized:matched_control_separation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after the identical complete control search.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="ChaCha20 W43 verified recovery chain",
        entities=[
            "ChaCha20:frozen_public_W43_relation",
            "complete_domain_enumeration",
            "ChaCha20:factual_candidate_set",
            "dual_4096_bit_confirmation",
            recovered,
        ],
    )
    writer.add_cluster(
        name="ChaCha20 W43 matched control chain",
        entities=[
            "ChaCha20:one_bit_control_relation",
            "same_complete_search",
            "ChaCha20:control_candidate_set",
            "zero_control_models",
            "ChaCha20:control_relation_rejected",
        ],
    )
    writer.add_gap(
        subject=recovered,
        predicate="next_required_gain",
        expected_object_type="prospectively_selected_strict_subset_of_W43_domain",
        confidence=1.0,
        suggested_queries=[
            "Which frozen Causal operator ranks a held-out ChaCha20 W43 region early?"
        ],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    writer_stats = writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    if (
        reader.api_id != "c20kr43"
        or len(reader._triplets) != 7
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("ChaCha20 W43 authentic Causal readback gate failed")
    return {
        "path": _artifact_path(path),
        "sha256": _file_sha256(path),
        "reader_source": source,
        "writer_stats": writer_stats,
        "api_id": reader.api_id,
        "triplets": len(reader._triplets),
        "rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": list(reader._gaps),
    }


def execute(
    *,
    protocol_path: Path,
    expected_protocol_sha256: str,
    result_path: Path,
    checkpoint_path: Path,
    causal_path: Path,
    report_path: Path,
    build_dir: Path,
    dotcausal_src: Path,
    swiftc: str,
    resume: bool,
) -> dict[str, Any]:
    if result_path.exists() or causal_path.exists():
        raise FileExistsError("ChaCha20 W43 final result already exists")
    protocol = _load_protocol(protocol_path, expected_protocol_sha256)
    challenge = protocol["challenge"]
    qualification_path = ROOT / protocol["anchors"]["qualification"]["path"]
    qualification_sha256 = protocol["anchors"]["qualification"]["sha256"]
    if _file_sha256(qualification_path) != qualification_sha256:
        raise RuntimeError("ChaCha20 W43 qualification anchor differs")
    reference = reference_gate()
    executable, build = A184._A181._compile_native(build_dir, swiftc)
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    host = A184.SliceMetalHost(
        executable,
        _initial(
            challenge["known_zeroed_key_words"],
            int(challenge["counter_start"]),
            challenge["nonce_words"],
            0,
        ),
        target,
        control,
    )
    try:
        mapping = _mapping_gate(
            host,
            known_zeroed_key_words=challenge["known_zeroed_key_words"],
            counter=int(challenge["counter_start"]),
            nonce_words=challenge["nonce_words"],
        )
        execution = enumerate_domain(
            host=host,
            protocol=protocol,
            protocol_sha256=expected_protocol_sha256,
            checkpoint_path=checkpoint_path,
            resume=resume,
        )
        identity = host.identity
    finally:
        host.close()
    if (
        execution["complete_domain_executed"] is not True
        or len(execution["factual_filter_matches"]) != 1
        or execution["control_filter_matches"] != []
    ):
        raise RuntimeError("ChaCha20 W43 complete-domain filter headline gate failed")
    confirmation = _confirm(protocol, execution["factual_filter_matches"][0])
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("ChaCha20 W43 independent confirmation failed")
    execution["factual_full_matches"] = [confirmation["assignment"]]
    execution["control_full_matches"] = []
    execution["unique_exact_assignment"] = True
    execution["control_target_rejected"] = True
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_CHACHA20_W43_COMPLETE_DOMAIN_RECOVERY_CONFIRMED",
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "qualification_sha256": qualification_sha256,
        "anchors": {
            "design_sha256": DESIGN_SHA256,
            "runner_sha256": _file_sha256(Path(__file__)),
            "native_source_sha256": _file_sha256(Path(A184._A181.__file__).with_name(A184.NATIVE_SOURCE_FILENAME)),
            "native_executable_sha256": build["executable_sha256"],
        },
        "reference_gate": reference,
        "native_build": build,
        "metal_identity": identity,
        "mapping_gate": mapping,
        "execution": execution,
        "confirmation": confirmation,
    }
    payload["execution_sha256"] = _canonical_sha256(
        {
            key: value
            for key, value in execution.items()
            if not key.startswith("volatile_")
        }
    )
    payload["confirmation_sha256"] = _canonical_sha256(confirmation)
    payload["authentic_causal"] = build_causal(
        path=causal_path,
        payload=payload,
        dotcausal_src=dotcausal_src,
    )
    _atomic_json(result_path, payload)
    report = f"""# CHACHA20KR43 — Full-round ChaCha20 W43 residual-key recovery

- Complete logical domain: **{DOMAIN_SIZE:,} assignments**
- Complete standard ChaCha20 execution: **20/20 rounds plus feed-forward**
- Public relation: **eight 512-bit output blocks**
- Exact factual assignments: **{execution['factual_full_matches']}**
- Exact one-bit control assignments: **[]**
- GPU seconds: **{execution['gpu_seconds']:.6f}**
- Early stop: **False**
- RFC byte and independent word confirmations: **8,192 checked output bits**
- Authentic Causal SHA-256: `{payload['authentic_causal']['sha256']}`
"""
    _atomic_bytes(report_path, report.encode("utf-8"))
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--qualify", action="store_true")
    modes.add_argument("--freeze", action="store_true")
    modes.add_argument("--analyze", action="store_true")
    modes.add_argument("--run", action="store_true")
    parser.add_argument("--design", type=Path, default=DEFAULT_DESIGN)
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
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    if args.qualify:
        payload = qualify(
            design_path=args.design,
            output=args.qualification,
            build_dir=args.build_dir,
            swiftc=args.swiftc,
        )
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
            design_path=args.design,
            qualification_path=args.qualification,
            expected_qualification_sha256=args.expected_qualification_sha256,
            output=args.protocol,
        )
        output = {
            "protocol": str(args.protocol),
            "protocol_sha256": _file_sha256(args.protocol),
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "unknown_key_bits": WIDTH,
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
                "unknown_key_bits": WIDTH,
                "logical_candidate_count": DOMAIN_SIZE,
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
                swiftc=args.swiftc,
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
