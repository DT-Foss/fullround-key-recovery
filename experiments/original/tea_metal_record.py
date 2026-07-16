#!/usr/bin/env python3
"""Qualify and execute a complete full-round TEA residual-key search."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import os
import secrets
import select
import shutil
import statistics
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
ATTEMPT_ID = "TEAKR1"
NATIVE_VERSION = "tea-metal-native-v1"
NATIVE_SOURCE = Path(__file__).with_name("tea_metal_native.swift")
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
DEFAULT_BUILD = ROOT / "research/build/tea_metal_v1"
DEFAULT_QUALIFICATION = ROOT / "research/results/v1/tea_metal_qualification_v1.json"
DEFAULT_PROTOCOL = ROOT / "research/configs/tea_metal_recovery_v1.json"
DEFAULT_RESULT = ROOT / "research/results/v1/tea_metal_recovery_v1.json"
DEFAULT_CHECKPOINT = ROOT / "research/results/v1/tea_metal_recovery_v1.checkpoint.json"
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = ROOT / "research/reports/FULLROUND_TEA_METAL_RECOVERY_V1.md"

MASK32 = 0xFFFFFFFF
DELTA = 0x9E3779B9
ZERO_REFERENCE_CIPHERTEXT = (0x41EA3A0A, 0x94BAA940)
STREAM_CANDIDATES = 1 << 28
QUALIFICATION_CANDIDATES = 1 << 25
QUALIFICATION_REPETITIONS = 3
QUALIFICATION_BUDGET_SECONDS = 10_800.0
QUALIFICATION_SAFETY_FACTOR = 1.25
MIN_WIDTH = 36
MAX_WIDTH = 43
RESULT_CAPACITY = 64


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _artifact_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


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


def scalar_encrypt(
    plaintext: Sequence[int], key: Sequence[int]
) -> tuple[int, int]:
    """Encrypt one TEA block with the published 32-cycle reference semantics."""
    if len(plaintext) != 2 or len(key) != 4:
        raise ValueError("TEA requires two plaintext words and four key words")
    value0, value1 = (int(word) & MASK32 for word in plaintext)
    key0, key1, key2, key3 = (int(word) & MASK32 for word in key)
    running_sum = 0
    for _ in range(32):
        running_sum = (running_sum + DELTA) & MASK32
        mix0 = (
            ((((value1 << 4) & MASK32) + key0) & MASK32)
            ^ ((value1 + running_sum) & MASK32)
            ^ (((value1 >> 5) + key1) & MASK32)
        )
        value0 = (value0 + mix0) & MASK32
        mix1 = (
            ((((value0 << 4) & MASK32) + key2) & MASK32)
            ^ ((value0 + running_sum) & MASK32)
            ^ (((value0 >> 5) + key3) & MASK32)
        )
        value1 = (value1 + mix1) & MASK32
    return value0, value1


def scalar_decrypt(
    ciphertext: Sequence[int], key: Sequence[int]
) -> tuple[int, int]:
    if len(ciphertext) != 2 or len(key) != 4:
        raise ValueError("TEA requires two ciphertext words and four key words")
    value0, value1 = (int(word) & MASK32 for word in ciphertext)
    key0, key1, key2, key3 = (int(word) & MASK32 for word in key)
    running_sum = (DELTA * 32) & MASK32
    for _ in range(32):
        mix1 = (
            ((((value0 << 4) & MASK32) + key2) & MASK32)
            ^ ((value0 + running_sum) & MASK32)
            ^ (((value0 >> 5) + key3) & MASK32)
        )
        value1 = (value1 - mix1) & MASK32
        mix0 = (
            ((((value1 << 4) & MASK32) + key0) & MASK32)
            ^ ((value1 + running_sum) & MASK32)
            ^ (((value1 >> 5) + key1) & MASK32)
        )
        value0 = (value0 - mix0) & MASK32
        running_sum = (running_sum - DELTA) & MASK32
    return value0, value1


def numpy_encrypt(
    plaintext: Sequence[int], key: Sequence[int]
) -> tuple[int, int]:
    """Independent NumPy uint64-lane formulation of the TEA recurrence."""
    if len(plaintext) != 2 or len(key) != 4:
        raise ValueError("TEA requires two plaintext words and four key words")
    values = np.asarray([int(word) & MASK32 for word in plaintext], dtype=np.uint64)
    keys = np.asarray([int(word) & MASK32 for word in key], dtype=np.uint64)
    mask = np.uint64(MASK32)
    running_sum = np.uint64(0)
    delta = np.uint64(DELTA)
    for _ in range(32):
        running_sum = (running_sum + delta) & mask
        values[0] = (
            values[0]
            + (
                (((values[1] << np.uint64(4)) & mask) + keys[0])
                ^ (values[1] + running_sum)
                ^ ((values[1] >> np.uint64(5)) + keys[1])
            )
        ) & mask
        values[1] = (
            values[1]
            + (
                (((values[0] << np.uint64(4)) & mask) + keys[2])
                ^ (values[0] + running_sum)
                ^ ((values[0] >> np.uint64(5)) + keys[3])
            )
        ) & mask
    return int(values[0]), int(values[1])


def reference_gate() -> dict[str, Any]:
    zero = scalar_encrypt((0, 0), (0, 0, 0, 0))
    zero_numpy = numpy_encrypt((0, 0), (0, 0, 0, 0))
    if zero != ZERO_REFERENCE_CIPHERTEXT or zero_numpy != zero:
        raise RuntimeError("TEA published-reference zero vector gate failed")
    rows = []
    for index in range(8):
        plaintext = (
            (0x10203040 * (index + 1)) & MASK32,
            (0x89ABCDEF ^ (0x01010101 * index)) & MASK32,
        )
        key = tuple(
            (0x13579BDF * (index + word + 1) + 0x2468ACE0 * word) & MASK32
            for word in range(4)
        )
        scalar = scalar_encrypt(plaintext, key)
        independent = numpy_encrypt(plaintext, key)
        decrypted = scalar_decrypt(scalar, key)
        if scalar != independent or decrypted != plaintext:
            raise RuntimeError("TEA independent-reference gate failed")
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
        "reference": "Wheeler and Needham TEA 32-cycle reference routine",
        "zero_key_zero_plaintext_ciphertext": list(ZERO_REFERENCE_CIPHERTEXT),
        "zero_vector_exact": True,
        "cross_reference_rows": rows,
        "all_exact": True,
    }


def encrypt_relation(
    plaintext_words: Sequence[int], key_words: Sequence[int]
) -> tuple[int, int, int, int]:
    if len(plaintext_words) != 4:
        raise ValueError("TEAKR1 requires exactly two plaintext blocks")
    first = scalar_encrypt(plaintext_words[:2], key_words)
    second = scalar_encrypt(plaintext_words[2:], key_words)
    return (*first, *second)


def numpy_relation(
    plaintext_words: Sequence[int], key_words: Sequence[int]
) -> tuple[int, int, int, int]:
    if len(plaintext_words) != 4:
        raise ValueError("TEAKR1 requires exactly two plaintext blocks")
    first = numpy_encrypt(plaintext_words[:2], key_words)
    second = numpy_encrypt(plaintext_words[2:], key_words)
    return (*first, *second)


def apply_assignment(
    known_zeroed_key: Sequence[int], assignment: int, width: int
) -> tuple[int, int, int, int]:
    context = _context(width)
    if len(known_zeroed_key) != 4:
        raise ValueError("TEA key must contain four words")
    if not 0 <= assignment < context["logical_candidates"]:
        raise ValueError("assignment is outside residual domain")
    known = tuple(int(word) & MASK32 for word in known_zeroed_key)
    if known[0] != 0 or known[1] & context["outer_mask"]:
        raise ValueError("known key does not zero the residual interval")
    return (
        assignment & MASK32,
        known[1] | ((assignment >> 32) & context["outer_mask"]),
        known[2],
        known[3],
    )


def _context(width: int) -> dict[str, int]:
    if not MIN_WIDTH <= width <= MAX_WIDTH:
        raise ValueError(f"TEAKR1 width must be in {MIN_WIDTH}..{MAX_WIDTH}")
    outer_bits = width - 32
    return {
        "width": width,
        "known_key_bits": 128 - width,
        "outer_bits": outer_bits,
        "outer_count": 1 << outer_bits,
        "outer_mask": (1 << outer_bits) - 1,
        "inner_count": 1 << 32,
        "logical_candidates": 1 << width,
        "stream_candidates": STREAM_CANDIDATES,
    }


def _compile_native(build_dir: Path, swiftc: str = "swiftc") -> tuple[Path, dict[str, Any]]:
    compiler = shutil.which(swiftc)
    if compiler is None:
        raise FileNotFoundError(f"Swift compiler not found: {swiftc}")
    source_sha256 = _file_sha256(NATIVE_SOURCE)
    build_dir.mkdir(parents=True, exist_ok=True)
    output = build_dir / f"tea_metal_{source_sha256[:16]}"
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.unlink(missing_ok=True)
    flags = ["-O", "-whole-module-optimization", "-warnings-as-errors"]
    completed = subprocess.run(
        [compiler, *flags, str(NATIVE_SOURCE), "-o", str(temporary)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError("TEA Swift/Metal compilation failed: " + completed.stderr)
    temporary.replace(output)
    compiler_version = subprocess.run(
        [compiler, "--version"], check=True, capture_output=True, text=True
    ).stdout.splitlines()[0]
    return output, {
        "source_sha256": source_sha256,
        "executable_sha256": _file_sha256(output),
        "compiler_version": compiler_version,
        "flags": flags,
    }


class MetalTEAHost:
    def __init__(self, executable: Path, *, deadline: float | None = None):
        self.process = subprocess.Popen(
            [str(executable.resolve())],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.deadline = deadline
        ready = self._read()
        metal = ready.get("metal", {})
        if (
            ready.get("op") != "ready"
            or ready.get("version") != NATIVE_VERSION
            or not str(metal.get("device", "")).startswith("Apple")
            or metal.get("shader_runtime_compiled") is not True
            or metal.get("tea_cycles") != 32
            or metal.get("tea_feistel_updates") != 64
            or metal.get("algorithms") != ["tea", "xtea", "siphash24"]
            or metal.get("plaintext_blocks") != 2
            or metal.get("output_words_compared") != 4
        ):
            self.close(force=True)
            raise RuntimeError("TEA Metal host identity gate failed")
        self.identity = ready

    def _read(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                self.close(force=True)
                raise TimeoutError("TEA Metal host deadline expired")
            readable, _, _ = select.select([self.process.stdout], [], [], remaining)
            if not readable:
                self.close(force=True)
                raise TimeoutError("TEA Metal host exceeded deadline")
        line = self.process.stdout.readline()
        if not line:
            assert self.process.stderr is not None
            raise RuntimeError(
                "TEA Metal host closed unexpectedly: "
                + self.process.stderr.read().strip()
            )
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("TEA Metal host returned a non-object")
        return value

    def _request(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError("TEA Metal host is not running")
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        )
        self.process.stdin.flush()
        return self._read()

    def configure(
        self,
        *,
        target: Sequence[int],
        control: Sequence[int],
        known_zeroed_key: Sequence[int],
        plaintext_words: Sequence[int],
        width: int,
        algorithm: str = "tea",
    ) -> None:
        context = _context(width)
        algorithm_codes = {"tea": 0, "xtea": 1, "siphash24": 2}
        if algorithm not in algorithm_codes:
            raise ValueError("algorithm must be tea, xtea, or siphash24")
        if not all(len(value) == expected for value, expected in (
            (target, 4),
            (control, 4),
            (known_zeroed_key, 4),
            (plaintext_words, 4),
        )):
            raise ValueError("TEAKR1 configuration boundary differs")
        response = self._request(
            {
                "op": "configure",
                "target": [int(word) & MASK32 for word in target],
                "control": [int(word) & MASK32 for word in control],
                "known_key": [int(word) & MASK32 for word in known_zeroed_key],
                "plaintext": [int(word) & MASK32 for word in plaintext_words],
                "algorithm": algorithm_codes[algorithm],
                "key_word1_unknown_mask": context["outer_mask"],
            }
        )
        if (
            response.get("op") != "configured"
            or response.get("algorithm") != algorithm
            or response.get("algorithm_code") != algorithm_codes[algorithm]
            or response.get("cycles") != 32
            or response.get("feistel_updates") != 64
            or response.get("plaintext_blocks") != 2
            or response.get("filter_words") != 4
            or response.get("complete_128_bit_relation_comparison") is not True
        ):
            raise RuntimeError("TEA Metal configuration gate failed")

    def blocks(self, outer: int, first: int, count: int) -> list[tuple[int, ...]]:
        response = self._request(
            {"op": "blocks", "outer": outer, "first": first, "count": count}
        )
        words = response.get("words")
        if (
            response.get("op") != "blocks"
            or response.get("outer") != outer
            or response.get("first") != first
            or response.get("count") != count
            or not isinstance(words, list)
            or len(words) != count * 4
        ):
            raise RuntimeError("TEA Metal blocks response gate failed")
        return [
            tuple(int(word) for word in words[index * 4 : (index + 1) * 4])
            for index in range(count)
        ]

    def filter(self, outer: int, first: int, count: int) -> dict[str, Any]:
        response = self._request(
            {
                "op": "filter",
                "outer": outer,
                "first": first,
                "count": count,
                "capacity": RESULT_CAPACITY,
            }
        )
        if (
            response.get("op") != "filter"
            or response.get("outer") != outer
            or response.get("first") != first
            or response.get("count") != count
            or not isinstance(response.get("factual"), list)
            or not isinstance(response.get("control"), list)
            or float(response.get("gpu_seconds", -1)) < 0
        ):
            raise RuntimeError("TEA Metal filter response gate failed")
        return response

    def close(self, *, force: bool = False) -> None:
        if self.process.poll() is None and not force:
            try:
                self._request({"op": "quit"})
            except Exception:
                force = True
        if force and self.process.poll() is None:
            self.process.kill()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

    def __enter__(self) -> MetalTEAHost:
        return self

    def __exit__(self, *_: object) -> None:
        self.close(force=False)


def _configure_reference(host: MetalTEAHost, *, width: int) -> None:
    plaintext = (0, 0, 0x01234567, 0x89ABCDEF)
    key = (0, 0, 0, 0)
    target = encrypt_relation(plaintext, key)
    control = (target[0] ^ 1, *target[1:])
    host.configure(
        target=target,
        control=control,
        known_zeroed_key=key,
        plaintext_words=plaintext,
        width=width,
    )


def _metal_mapping_gate(host: MetalTEAHost, *, width: int) -> dict[str, Any]:
    context = _context(width)
    plaintext = (0, 0, 0x01234567, 0x89ABCDEF)
    zeroed = (0, 0, 0, 0)
    _configure_reference(host, width=width)
    assignments = [0, 1, (1 << 32) - 1, 1 << 32, (1 << width) - 1]
    rows = []
    for assignment in assignments:
        outer = assignment >> 32
        inner = assignment & MASK32
        observed = host.blocks(outer, inner, 1)[0]
        key = apply_assignment(zeroed, assignment, width)
        scalar = encrypt_relation(plaintext, key)
        independent = numpy_relation(plaintext, key)
        if observed != scalar or observed != independent:
            raise RuntimeError("TEA Metal residual mapping gate failed")
        rows.append(
            {
                "assignment": assignment,
                "outer": outer,
                "inner": inner,
                "output_words": list(observed),
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
        raise FileExistsError(f"TEA qualification already exists: {output}")
    references = reference_gate()
    executable, build = _compile_native(build_dir)
    with MetalTEAHost(executable) as host:
        mapping = _metal_mapping_gate(host, width=MAX_WIDTH)
        _configure_reference(host, width=MAX_WIDTH)
        timings = []
        for _ in range(QUALIFICATION_REPETITIONS):
            row = host.filter(0, 0, QUALIFICATION_CANDIDATES)
            if row["control"]:
                raise RuntimeError("TEA qualification control unexpectedly matched")
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
        raise RuntimeError("TEA qualification did not clear the minimum width")
    selected = max(eligible)
    payload = {
        "schema": "tea-metal-qualification-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_TEA_METAL_QUALIFIED",
        "algorithm": {
            "name": "Tiny Encryption Algorithm (TEA)",
            "cycles": 32,
            "feistel_updates": 64,
            "complete_standard_round_count": True,
            "key_bits": 128,
            "plaintext_blocks": 2,
            "filter_bits": 128,
        },
        "anchors": {
            "qualification_source_sha256": _file_sha256(Path(__file__)),
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
    *,
    qualification_path: Path,
    expected_qualification_sha256: str,
    output: Path,
) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"TEA protocol already exists: {output}")
    if _file_sha256(qualification_path) != expected_qualification_sha256:
        raise RuntimeError("TEA qualification hash differs")
    qualification = json.loads(qualification_path.read_bytes())
    if (
        qualification.get("evidence_stage") != "FULLROUND_TEA_METAL_QUALIFIED"
        or qualification.get("selection", {}).get("production_challenge_generated")
        is not False
    ):
        raise RuntimeError("TEA qualification semantic gate failed")
    width = int(qualification["selection"]["selected_width"])
    context = _context(width)
    key = tuple(secrets.randbits(32) for _ in range(4))
    plaintext = tuple(secrets.randbits(32) for _ in range(4))
    target = encrypt_relation(plaintext, key)
    if target != numpy_relation(plaintext, key):
        raise RuntimeError("TEA target construction references differ")
    control = (target[0] ^ 1, *target[1:])
    known_zeroed = (
        0,
        key[1] & ~context["outer_mask"],
        key[2],
        key[3],
    )
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
        "schema": "tea-metal-recovery-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_any_production_candidate_execution",
        "algorithm": {
            "name": "Tiny Encryption Algorithm (TEA)",
            "cycles": 32,
            "feistel_updates": 64,
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
        raise RuntimeError("TEA protocol hash differs")
    protocol = json.loads(path.read_bytes())
    challenge = protocol.get("challenge", {})
    anchors = protocol.get("anchors", {})
    qualification_path = ROOT / anchors.get("qualification", {}).get("path", "")
    if (
        protocol.get("schema") != "tea-metal-recovery-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_before_any_production_candidate_execution"
        or protocol.get("public_challenge_sha256") != _canonical_sha256(challenge)
        or anchors.get("runner_sha256") != _file_sha256(Path(__file__))
        or anchors.get("native_source_sha256") != _file_sha256(NATIVE_SOURCE)
        or _file_sha256(qualification_path) != anchors["qualification"]["sha256"]
        or challenge.get("secret_assignment_included") is not False
        or challenge.get("full_key_included") is not False
    ):
        raise RuntimeError("TEA frozen protocol gate failed")
    _context(int(challenge["unknown_key_bits"]))
    return protocol


def _challenge_values(
    challenge: Mapping[str, Any]
) -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    known = tuple(int(word) for word in challenge["known_key_words_zeroed_residual"])
    plaintext = tuple(int(word) for word in challenge["plaintext_words"])
    target = tuple(int(word) for word in challenge["target_ciphertext_words"])
    control = tuple(int(word) for word in challenge["control_ciphertext_words"])
    if not all(len(value) == 4 for value in (known, plaintext, target, control)):
        raise RuntimeError("TEA challenge word boundary differs")
    if any(not 0 <= word <= MASK32 for value in (known, plaintext, target, control) for word in value):
        raise RuntimeError("TEA challenge word range differs")
    return known, plaintext, target, control


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
    )
    assignments = [0, 1, (1 << 32) - 1, 1 << 32, (1 << width) - 1]
    rows = []
    for assignment in assignments:
        observed = host.blocks(assignment >> 32, assignment & MASK32, 1)[0]
        key = apply_assignment(known, assignment, width)
        scalar = encrypt_relation(plaintext, key)
        independent = numpy_relation(plaintext, key)
        if observed != scalar or observed != independent:
            raise RuntimeError("TEA post-freeze mapping gate failed")
        rows.append(
            {
                "assignment": assignment,
                "output_sha256": _sha256(_canonical_bytes(observed)),
            }
        )
    return {"rows": rows, "scalar_numpy_metal_exact": True}


def _checkpoint_fingerprint(
    protocol_sha256: str, protocol: Mapping[str, Any]
) -> dict[str, Any]:
    width = int(protocol["challenge"]["unknown_key_bits"])
    context = _context(width)
    return {
        "schema": "tea-complete-domain-checkpoint-v1",
        "protocol_sha256": protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "width": width,
        "logical_candidate_count": context["logical_candidates"],
        "stream_candidate_count": context["stream_candidates"],
        "candidate_encoding": "combined=(key_word1_low_bits<<32)|key_word0",
    }


def _confirm(
    protocol: Mapping[str, Any],
    assignment: int,
    expected: Sequence[int],
    relation: str,
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
) -> dict[str, Any]:
    width = int(protocol["challenge"]["unknown_key_bits"])
    context = _context(width)
    fingerprint = _checkpoint_fingerprint(protocol_sha256, protocol)
    next_assignment = 0
    factual: list[int] = []
    control: list[int] = []
    gpu_seconds = 0.0
    if checkpoint_path.exists() and not resume:
        raise FileExistsError("TEA checkpoint exists; pass --resume")
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_bytes())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("TEA checkpoint fingerprint differs")
        next_assignment = int(checkpoint["next_assignment"])
        factual = [int(value) for value in checkpoint["factual_filtered"]]
        control = [int(value) for value in checkpoint["control_filtered"]]
        gpu_seconds = float(checkpoint["gpu_seconds"])
        if (
            next_assignment % STREAM_CANDIDATES
            or not 0 <= next_assignment <= context["logical_candidates"]
            or any(not 0 <= value < next_assignment for value in factual + control)
        ):
            raise RuntimeError("TEA checkpoint progress differs")
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
                    raise RuntimeError(f"TEA {name} candidate is outside batch")
                destination.append(combined)
            if len(destination) != len(set(destination)):
                raise RuntimeError(f"TEA duplicate {name} candidate")
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
                "complete_domain_executed": next_assignment
                == context["logical_candidates"],
                "early_stop_used": False,
                "success_evaluated_before_complete_domain": False,
            },
        )
        if next_assignment % (1 << 34) == 0:
            print(
                json.dumps(
                    {
                        "attempt_id": ATTEMPT_ID,
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
    _, _, target, control_target = _challenge_values(protocol["challenge"])
    factual_confirmations = [
        _confirm(protocol, assignment, target, "factual") for assignment in factual
    ]
    control_confirmations = [
        _confirm(protocol, assignment, control_target, "control")
        for assignment in control
    ]
    factual_full = [
        row["assignment"]
        for row in factual_confirmations
        if row["complete_128_bit_match"]
    ]
    control_full = [
        row["assignment"]
        for row in control_confirmations
        if row["complete_128_bit_match"]
    ]
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
        "unique_exact_assignment": complete
        and len(factual) == 1
        and factual_full == factual,
        "control_target_rejected": complete and not control and not control_full,
        "gpu_seconds": gpu_seconds,
        "volatile_wall_seconds": time.perf_counter() - started,
        "volatile_candidates_per_gpu_second": (
            next_assignment / gpu_seconds if gpu_seconds else None
        ),
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("authoritative dotcausal.io is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(module.CausalReader) or "")
    return module.CausalWriter, module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": _file_sha256(source),
    }


def build_causal(
    *, path: Path, payload: Mapping[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = _load_dotcausal(dotcausal_src)
    execution = payload["execution"]
    width = int(execution["unknown_key_bits"])
    logical = int(execution["logical_candidate_count"])
    recovered = f"TEA:unique_verified_W{width}_fullround_residual"
    writer = CausalWriter(api_id="teakr1")
    writer._rules = []
    writer.add_rule(
        name="complete_domain_plus_independent_confirmation",
        description="Complete full-round TEA residual enumeration plus scalar and independent NumPy confirmation establishes the recovered assignment.",
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
        trigger="TEA:pre_target_Metal_qualification",
        mechanism="published_reference_plus_scalar_NumPy_Metal_mapping_gates",
        outcome="TEA:qualified_fullround_enumerator",
        confidence=1.0,
        source=payload["qualification_sha256"],
        quantification="32 cycles; 64 Feistel updates; 128-bit two-block relation",
        evidence=json.dumps(payload["mapping_gate"], sort_keys=True),
        domain="TEA implementation equivalence",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"TEA:frozen_public_W{width}_relation",
        mechanism="complete_domain_enumeration",
        outcome="TEA:factual_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{logical} assignments; no early stop",
        evidence=json.dumps(execution["factual_filter_matches"]),
        domain="full-round residual-key enumeration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="TEA:factual_candidate_set",
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
        trigger="TEA:one_bit_control_relation",
        mechanism="same_complete_search",
        outcome="TEA:control_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{logical} assignments; identical kernel",
        evidence=json.dumps(execution["control_filter_matches"]),
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="TEA:control_candidate_set",
        mechanism="zero_control_models",
        outcome="TEA:control_relation_rejected",
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
        trigger=f"TEA:frozen_public_W{width}_relation",
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
        trigger="TEA:one_bit_control_relation",
        mechanism="verified_matched_control_chain",
        outcome="TEA:control_relation_rejected",
        confidence=1.0,
        source="materialized:matched_control_separation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after the identical complete control search.",
        domain="AI-native retained inference",
        quality_score=1.0,
    )
    writer.add_cluster(
        name="TEA verified recovery chain",
        entities=[
            f"TEA:frozen_public_W{width}_relation",
            "complete_domain_enumeration",
            "TEA:factual_candidate_set",
            "two_reference_confirmation",
            recovered,
        ],
    )
    writer.add_cluster(
        name="TEA matched control chain",
        entities=[
            "TEA:one_bit_control_relation",
            "same_complete_search",
            "TEA:control_candidate_set",
            "zero_control_models",
            "TEA:control_relation_rejected",
        ],
    )
    writer.add_gap(
        subject=recovered,
        predicate="next_required_gain",
        expected_object_type=f"prospectively_selected_strict_subset_of_W{width}_domain",
        confidence=1.0,
        suggested_queries=[
            f"Which frozen operator ranks a held-out W{width} TEA region early?"
        ],
    )
    temporary = path.with_name(f".{path.name}.tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    writer_stats = writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    gaps = list(reader._gaps)
    if (
        reader.api_id != "teakr1"
        or len(reader._triplets) != 7
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(gaps) != 1
    ):
        raise RuntimeError("TEA authentic Causal readback gate failed")
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
    *,
    protocol_path: Path,
    expected_protocol_sha256: str,
    result_path: Path,
    checkpoint_path: Path,
    causal_path: Path,
    report_path: Path,
    build_dir: Path,
    dotcausal_src: Path,
    resume: bool,
) -> dict[str, Any]:
    if result_path.exists() or causal_path.exists():
        raise FileExistsError("TEA final result already exists")
    protocol = _load_protocol(protocol_path, expected_protocol_sha256)
    qualification_path = ROOT / protocol["anchors"]["qualification"]["path"]
    qualification_sha256 = protocol["anchors"]["qualification"]["sha256"]
    reference_gate()
    executable, build = _compile_native(build_dir)
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
        raise RuntimeError("TEA full-domain recovery headline gate failed")
    payload: dict[str, Any] = {
        "schema": "tea-metal-recovery-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_TEA_COMPLETE_DOMAIN_RECOVERY_CONFIRMED",
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "qualification_sha256": qualification_sha256,
        "qualification_path": str(qualification_path.relative_to(ROOT)),
        "anchors": {
            "runner_sha256": _file_sha256(Path(__file__)),
            "native_source_sha256": _file_sha256(NATIVE_SOURCE),
            "native_executable_sha256": build["executable_sha256"],
        },
        "native_build": build,
        "metal_identity": identity,
        "mapping_gate": mapping,
        "execution": execution,
    }
    payload["execution_sha256"] = _canonical_sha256(
        {
            key: value
            for key, value in execution.items()
            if not key.startswith("volatile_")
        }
    )
    payload["confirmation_sha256"] = _canonical_sha256(
        {
            "factual": execution["factual_confirmations"],
            "control": execution["control_confirmations"],
        }
    )
    causal = build_causal(path=causal_path, payload=payload, dotcausal_src=dotcausal_src)
    payload["authentic_causal"] = causal
    _atomic_json(result_path, payload)
    report = f"""# TEAKR1 — Full-round TEA W{execution['unknown_key_bits']} residual-key recovery

- Complete logical domain: **{execution['logical_candidate_count']:,} assignments**
- Complete standard TEA execution: **32/32 cycles; 64/64 Feistel updates**
- Two-block ciphertext relation checked: **128/128 bits**
- Exact factual assignments: **{execution['factual_full_matches']}**
- Exact one-bit control assignments: **{execution['control_full_matches']}**
- GPU seconds: **{execution['gpu_seconds']:.6f}**
- Early stop: **False**
- Scalar and independent NumPy confirmation: **exact**
- Authentic Causal SHA-256: `{causal['sha256']}`
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
        print(
            json.dumps(
                {
                    "qualification": str(args.qualification),
                    "qualification_sha256": _file_sha256(args.qualification),
                    "selected_width": payload["selection"]["selected_width"],
                    "minimum_candidates_per_gpu_second": payload["benchmark"][
                        "minimum_candidates_per_gpu_second"
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    if args.freeze:
        if not args.expected_qualification_sha256:
            parser.error("--freeze requires --expected-qualification-sha256")
        payload = freeze_protocol(
            qualification_path=args.qualification,
            expected_qualification_sha256=args.expected_qualification_sha256,
            output=args.protocol,
        )
        print(
            json.dumps(
                {
                    "protocol": str(args.protocol),
                    "protocol_sha256": _file_sha256(args.protocol),
                    "public_challenge_sha256": payload["public_challenge_sha256"],
                    "unknown_key_bits": payload["challenge"]["unknown_key_bits"],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    if not args.expected_protocol_sha256:
        parser.error("--analyze/--run requires --expected-protocol-sha256")
    protocol = _load_protocol(args.protocol, args.expected_protocol_sha256)
    if args.analyze:
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "protocol_sha256": args.expected_protocol_sha256,
                    "public_challenge_sha256": protocol["public_challenge_sha256"],
                    "unknown_key_bits": protocol["challenge"]["unknown_key_bits"],
                    "logical_candidate_count": protocol["execution"][
                        "logical_candidates"
                    ],
                    "candidate_execution_started": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
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
    print(
        json.dumps(
            {
                "result": str(args.result),
                "result_sha256": _file_sha256(args.result),
                "causal_sha256": payload["authentic_causal"]["sha256"],
                "evidence_stage": payload["evidence_stage"],
                "factual_full_matches": payload["execution"]["factual_full_matches"],
                "control_full_matches": payload["execution"]["control_full_matches"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
