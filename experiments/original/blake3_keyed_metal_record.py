#!/usr/bin/env python3
"""Qualify and execute a complete full-round keyed-BLAKE3 residual-key search."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
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
ATTEMPT_ID = "B3KR1"
NATIVE_VERSION = "blake3-keyed-metal-native-v1"
NATIVE_SOURCE = Path(__file__).with_name("blake3_keyed_metal_native.swift")
NUMPY_REFERENCE = Path(__file__).with_name("blake3_fullcompression_reader.py")
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
DEFAULT_BUILD = ROOT / "research/build/blake3_keyed_metal_v1"
DEFAULT_QUALIFICATION = (
    ROOT / "research/results/v1/blake3_keyed_metal_qualification_v1.json"
)
DEFAULT_PROTOCOL = ROOT / "research/configs/blake3_keyed_metal_recovery_v1.json"
DEFAULT_RESULT = ROOT / "research/results/v1/blake3_keyed_metal_recovery_v1.json"
DEFAULT_CHECKPOINT = (
    ROOT / "research/results/v1/blake3_keyed_metal_recovery_v1.checkpoint.json"
)
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = ROOT / "research/reports/FULLROUND_BLAKE3_KEYED_METAL_RECOVERY_V1.md"

MASK32 = 0xFFFFFFFF
IV = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]
MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
ROOT_FLAG = 1 << 3
KEYED_HASH = 1 << 4
KEYED_ROOT_FLAGS = CHUNK_START | CHUNK_END | ROOT_FLAG | KEYED_HASH
OFFICIAL_KEY = b"whats the Elvish word for friend"
OFFICIAL_KEYED_32 = {
    0: "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
    1: "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
    63: "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae",
    64: "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6",
}
STREAM_CANDIDATES = 1 << 29
QUALIFICATION_CANDIDATES = 1 << 26
QUALIFICATION_REPETITIONS = 3
QUALIFICATION_BUDGET_SECONDS = 10_800.0
QUALIFICATION_SAFETY_FACTOR = 1.25
MIN_WIDTH = 38
MAX_WIDTH = 43
RESULT_CAPACITY = 64


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


def _ror32(value: int, shift: int) -> int:
    return ((value >> shift) | (value << (32 - shift))) & MASK32


def _g(
    state: list[int],
    a: int,
    b: int,
    c: int,
    d: int,
    message_x: int,
    message_y: int,
) -> None:
    state[a] = (state[a] + state[b] + message_x) & MASK32
    state[d] = _ror32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _ror32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + message_y) & MASK32
    state[d] = _ror32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _ror32(state[b] ^ state[c], 7)


def _round(state: list[int], message: list[int]) -> None:
    _g(state, 0, 4, 8, 12, message[0], message[1])
    _g(state, 1, 5, 9, 13, message[2], message[3])
    _g(state, 2, 6, 10, 14, message[4], message[5])
    _g(state, 3, 7, 11, 15, message[6], message[7])
    _g(state, 0, 5, 10, 15, message[8], message[9])
    _g(state, 1, 6, 11, 12, message[10], message[11])
    _g(state, 2, 7, 8, 13, message[12], message[13])
    _g(state, 3, 4, 9, 14, message[14], message[15])


def _words32(raw: bytes, count: int) -> list[int]:
    if len(raw) != count * 4:
        raise ValueError(f"expected {count * 4} bytes")
    return [
        int.from_bytes(raw[offset : offset + 4], "little")
        for offset in range(0, len(raw), 4)
    ]


def _word_bytes(words: Sequence[int]) -> bytes:
    return b"".join(int(word).to_bytes(4, "little") for word in words)


def scalar_keyed_root(key: bytes, message: bytes) -> bytes:
    """Return BLAKE3's first 256 keyed-root bits for one message block."""
    if len(key) != 32:
        raise ValueError("BLAKE3 keyed mode requires a 32-byte key")
    if len(message) > 64:
        raise ValueError("B3KR1 accepts a single message block")
    cv = _words32(key, 8)
    block = message + b"\x00" * (64 - len(message))
    message_words = _words32(block, 16)
    state = cv + IV[:4] + [0, 0, len(message), KEYED_ROOT_FLAGS]
    schedule = list(message_words)
    for round_index in range(7):
        _round(state, schedule)
        if round_index != 6:
            schedule = [schedule[index] for index in MSG_PERMUTATION]
    return _word_bytes([state[index] ^ state[index + 8] for index in range(8)])


def _load_numpy_reference() -> Any:
    spec = importlib.util.spec_from_file_location(
        "b3kr1_independent_numpy_reference", NUMPY_REFERENCE
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load independent BLAKE3 NumPy reference")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def numpy_keyed_root(key: bytes, message: bytes) -> bytes:
    module = _load_numpy_reference()
    cv = np.frombuffer(key, dtype="<u4").astype(np.uint32).reshape(1, 8)
    block = message + b"\x00" * (64 - len(message))
    block_words = np.frombuffer(block, dtype="<u4").astype(np.uint32).reshape(1, 16)
    output = module._compress(
        cv,
        block_words,
        np.asarray([0], dtype=np.uint64),
        np.asarray([len(message)], dtype=np.uint32),
        np.asarray([KEYED_ROOT_FLAGS], dtype=np.uint32),
    )
    return output[0, :8].astype("<u4", copy=False).tobytes()


def official_kat_gate() -> dict[str, Any]:
    if len(OFFICIAL_KEY) != 32:
        raise RuntimeError("official BLAKE3 keyed test key differs")
    rows = []
    for length, expected in OFFICIAL_KEYED_32.items():
        message = bytes(index % 251 for index in range(length))
        scalar = scalar_keyed_root(OFFICIAL_KEY, message).hex()
        independent = numpy_keyed_root(OFFICIAL_KEY, message).hex()
        if scalar != independent or scalar != expected:
            raise RuntimeError(f"BLAKE3 keyed KAT failed for input length {length}")
        rows.append(
            {
                "input_len": length,
                "expected_32_hex": expected,
                "scalar_32_hex": scalar,
                "independent_numpy_32_hex": independent,
                "exact": True,
            }
        )
    return {
        "source": "BLAKE3-team/BLAKE3 test_vectors/test_vectors.json",
        "official_key_ascii": OFFICIAL_KEY.decode("ascii"),
        "rows": rows,
        "all_exact": True,
    }


def apply_assignment(known_zeroed_key: bytes, assignment: int, width: int) -> bytes:
    if len(known_zeroed_key) != 32 or not 32 < width <= 48:
        raise ValueError("B3KR1 residual mapping requires 33..48 bits")
    if not 0 <= assignment < 1 << width:
        raise ValueError("assignment is outside residual domain")
    mask = (1 << width) - 1
    known = int.from_bytes(known_zeroed_key, "little")
    if known & mask:
        raise ValueError("known key does not zero the residual interval")
    return ((known | assignment).to_bytes(32, "little"))


def _context(width: int) -> dict[str, int]:
    if not MIN_WIDTH <= width <= MAX_WIDTH:
        raise ValueError(f"B3KR1 width must be in {MIN_WIDTH}..{MAX_WIDTH}")
    outer_bits = width - 32
    return {
        "width": width,
        "known_key_bits": 256 - width,
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
    output = build_dir / f"blake3_keyed_metal_{source_sha256[:16]}"
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
        raise RuntimeError("BLAKE3 Swift/Metal compilation failed: " + completed.stderr)
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


class MetalBlake3Host:
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
            or metal.get("blake3_rounds") != 7
            or metal.get("keyed_root_output_words_compared") != 8
        ):
            self.close(force=True)
            raise RuntimeError("BLAKE3 Metal host identity gate failed")
        self.identity = ready

    def _read(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                self.close(force=True)
                raise TimeoutError("BLAKE3 Metal host deadline expired")
            readable, _, _ = select.select([self.process.stdout], [], [], remaining)
            if not readable:
                self.close(force=True)
                raise TimeoutError("BLAKE3 Metal host exceeded deadline")
        line = self.process.stdout.readline()
        if not line:
            assert self.process.stderr is not None
            raise RuntimeError(
                "BLAKE3 Metal host closed unexpectedly: "
                + self.process.stderr.read().strip()
            )
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("BLAKE3 Metal host returned a non-object")
        return value

    def _request(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError("BLAKE3 Metal host is not running")
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        )
        self.process.stdin.flush()
        return self._read()

    def configure(
        self,
        *,
        target: bytes,
        control: bytes,
        known_zeroed_key: bytes,
        message: bytes,
        width: int,
    ) -> None:
        context = _context(width)
        if len(target) != 32 or len(control) != 32 or len(message) > 64:
            raise ValueError("B3KR1 configuration boundary differs")
        key_words = _words32(known_zeroed_key, 8)
        block = message + b"\x00" * (64 - len(message))
        response = self._request(
            {
                "op": "configure",
                "target": _words32(target, 8),
                "control": _words32(control, 8),
                "key_words_2_to_7": key_words[2:],
                "key_word1_known": key_words[1],
                "key_word1_unknown_mask": context["outer_mask"],
                "block_words": _words32(block, 16),
                "block_len": len(message),
                "flags": KEYED_ROOT_FLAGS,
            }
        )
        if (
            response.get("op") != "configured"
            or response.get("rounds") != 7
            or response.get("filter_words") != 8
            or response.get("complete_256_bit_output_comparison") is not True
        ):
            raise RuntimeError("BLAKE3 Metal configuration gate failed")

    def blocks(self, outer: int, first: int, count: int) -> list[bytes]:
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
            or len(words) != count * 8
        ):
            raise RuntimeError("BLAKE3 Metal blocks response gate failed")
        return [_word_bytes(words[index * 8 : (index + 1) * 8]) for index in range(count)]

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
            raise RuntimeError("BLAKE3 Metal filter response gate failed")
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

    def __enter__(self) -> MetalBlake3Host:
        return self

    def __exit__(self, *_: object) -> None:
        self.close(force=False)


def _configure_official(host: MetalBlake3Host, *, width: int, message: bytes) -> None:
    target = scalar_keyed_root(OFFICIAL_KEY, message)
    control = bytearray(target)
    control[0] ^= 1
    mask = (1 << width) - 1
    zeroed = (int.from_bytes(OFFICIAL_KEY, "little") & ~mask).to_bytes(32, "little")
    host.configure(
        target=target,
        control=bytes(control),
        known_zeroed_key=zeroed,
        message=message,
        width=width,
    )


def _metal_mapping_gate(host: MetalBlake3Host, *, width: int) -> dict[str, Any]:
    context = _context(width)
    message = bytes(index % 251 for index in range(64))
    _configure_official(host, width=width, message=message)
    zeroed = (
        int.from_bytes(OFFICIAL_KEY, "little") & ~((1 << width) - 1)
    ).to_bytes(32, "little")
    assignments = [0, 1, (1 << 32) - 1, 1 << 32, (1 << width) - 1]
    rows = []
    for assignment in assignments:
        outer = assignment >> 32
        inner = assignment & MASK32
        observed = host.blocks(outer, inner, 1)[0]
        key = apply_assignment(zeroed, assignment, width)
        scalar = scalar_keyed_root(key, message)
        independent = numpy_keyed_root(key, message)
        if observed != scalar or observed != independent:
            raise RuntimeError("BLAKE3 Metal residual mapping gate failed")
        rows.append(
            {
                "assignment": assignment,
                "outer": outer,
                "inner": inner,
                "output_sha256": _sha256(observed),
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
        raise FileExistsError(f"BLAKE3 qualification already exists: {output}")
    kat = official_kat_gate()
    executable, build = _compile_native(build_dir)
    benchmark_message = bytes(index % 251 for index in range(64))
    with MetalBlake3Host(executable) as host:
        mapping = _metal_mapping_gate(host, width=MAX_WIDTH)
        _configure_official(host, width=MAX_WIDTH, message=benchmark_message)
        timings = []
        for _ in range(QUALIFICATION_REPETITIONS):
            row = host.filter(0, 0, QUALIFICATION_CANDIDATES)
            if row["control"]:
                raise RuntimeError("BLAKE3 qualification control unexpectedly matched")
            timings.append(float(row["gpu_seconds"]))
        identity = host.identity
    throughputs = [QUALIFICATION_CANDIDATES / seconds for seconds in timings]
    minimum = min(throughputs)
    capacity = minimum * QUALIFICATION_BUDGET_SECONDS / QUALIFICATION_SAFETY_FACTOR
    selected = max(
        width
        for width in range(MIN_WIDTH, MAX_WIDTH + 1)
        if (1 << width) <= capacity
    )
    payload = {
        "schema": "blake3-keyed-metal-qualification-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_KEYED_BLAKE3_METAL_QUALIFIED",
        "algorithm": {
            "name": "BLAKE3 keyed hash",
            "rounds": 7,
            "mode": "single_block_keyed_root_output",
            "key_bits": 256,
            "filter_bits": 256,
        },
        "anchors": {
            "qualification_source_sha256": _file_sha256(Path(__file__)),
            "native_source_sha256": _file_sha256(NATIVE_SOURCE),
            "independent_numpy_reference_sha256": _file_sha256(NUMPY_REFERENCE),
        },
        "official_keyed_kat_gate": kat,
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
            "eligible_widths": list(range(MIN_WIDTH, MAX_WIDTH + 1)),
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
        raise FileExistsError(f"BLAKE3 protocol already exists: {output}")
    if _file_sha256(qualification_path) != expected_qualification_sha256:
        raise RuntimeError("BLAKE3 qualification hash differs")
    qualification = json.loads(qualification_path.read_bytes())
    if (
        qualification.get("evidence_stage") != "FULLROUND_KEYED_BLAKE3_METAL_QUALIFIED"
        or qualification.get("selection", {}).get("production_challenge_generated")
        is not False
    ):
        raise RuntimeError("BLAKE3 qualification semantic gate failed")
    width = int(qualification["selection"]["selected_width"])
    context = _context(width)
    key = secrets.token_bytes(32)
    message_length = 64
    message = secrets.token_bytes(message_length)
    target = scalar_keyed_root(key, message)
    if target != numpy_keyed_root(key, message):
        raise RuntimeError("BLAKE3 target construction references differ")
    control = bytearray(target)
    control[0] ^= 1
    mask = (1 << width) - 1
    known_zeroed = (int.from_bytes(key, "little") & ~mask).to_bytes(32, "little")
    challenge = {
        "message_hex": message.hex(),
        "message_length": message_length,
        "known_key_zeroed_residual_hex": known_zeroed.hex(),
        "unknown_key_bits": width,
        "known_key_bits": 256 - width,
        "unknown_bit_interval": [0, width - 1],
        "bit_numbering": "little_endian_bit0_upward_across_key_words",
        "target_256_hex": target.hex(),
        "target_sha256": _sha256(target),
        "control_256_hex": bytes(control).hex(),
        "control_sha256": _sha256(bytes(control)),
        "control_relation": "target_output_bit0_flipped",
        "secret_assignment_included": False,
        "full_key_included": False,
        "secret_discarded_after_target_construction": True,
    }
    protocol = {
        "schema": "blake3-keyed-metal-recovery-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_any_production_candidate_execution",
        "algorithm": {
            "name": "BLAKE3 keyed hash",
            "rounds": 7,
            "flags": KEYED_ROOT_FLAGS,
            "complete_standard_round_count": True,
            "output_bits_compared": 256,
        },
        "anchors": {
            "qualification": {
                "path": str(qualification_path.relative_to(ROOT)),
                "sha256": expected_qualification_sha256,
            },
            "runner_sha256": _file_sha256(Path(__file__)),
            "native_source_sha256": _file_sha256(NATIVE_SOURCE),
            "independent_numpy_reference_sha256": _file_sha256(NUMPY_REFERENCE),
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
        raise RuntimeError("BLAKE3 protocol hash differs")
    protocol = json.loads(path.read_bytes())
    challenge = protocol.get("challenge", {})
    anchors = protocol.get("anchors", {})
    qualification_path = ROOT / anchors.get("qualification", {}).get("path", "")
    if (
        protocol.get("schema") != "blake3-keyed-metal-recovery-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_before_any_production_candidate_execution"
        or protocol.get("public_challenge_sha256") != _canonical_sha256(challenge)
        or anchors.get("runner_sha256") != _file_sha256(Path(__file__))
        or anchors.get("native_source_sha256") != _file_sha256(NATIVE_SOURCE)
        or anchors.get("independent_numpy_reference_sha256")
        != _file_sha256(NUMPY_REFERENCE)
        or _file_sha256(qualification_path) != anchors["qualification"]["sha256"]
        or challenge.get("secret_assignment_included") is not False
        or challenge.get("full_key_included") is not False
    ):
        raise RuntimeError("BLAKE3 frozen protocol gate failed")
    _context(int(challenge["unknown_key_bits"]))
    return protocol


def _challenge_bytes(challenge: Mapping[str, Any]) -> tuple[bytes, bytes, bytes, bytes]:
    known = bytes.fromhex(str(challenge["known_key_zeroed_residual_hex"]))
    message = bytes.fromhex(str(challenge["message_hex"]))
    target = bytes.fromhex(str(challenge["target_256_hex"]))
    control = bytes.fromhex(str(challenge["control_256_hex"]))
    if len(known) != 32 or len(message) > 64 or len(target) != 32 or len(control) != 32:
        raise RuntimeError("BLAKE3 challenge byte boundary differs")
    return known, message, target, control


def _post_freeze_mapping_gate(
    host: MetalBlake3Host, protocol: Mapping[str, Any]
) -> dict[str, Any]:
    challenge = protocol["challenge"]
    width = int(challenge["unknown_key_bits"])
    known, message, target, control = _challenge_bytes(challenge)
    host.configure(
        target=target,
        control=control,
        known_zeroed_key=known,
        message=message,
        width=width,
    )
    assignments = [0, 1, (1 << 32) - 1, 1 << 32, (1 << width) - 1]
    rows = []
    for assignment in assignments:
        observed = host.blocks(assignment >> 32, assignment & MASK32, 1)[0]
        key = apply_assignment(known, assignment, width)
        scalar = scalar_keyed_root(key, message)
        independent = numpy_keyed_root(key, message)
        if observed != scalar or observed != independent:
            raise RuntimeError("BLAKE3 post-freeze mapping gate failed")
        rows.append({"assignment": assignment, "output_sha256": _sha256(observed)})
    return {"rows": rows, "scalar_numpy_metal_exact": True}


def _checkpoint_fingerprint(protocol_sha256: str, protocol: Mapping[str, Any]) -> dict[str, Any]:
    width = int(protocol["challenge"]["unknown_key_bits"])
    context = _context(width)
    return {
        "schema": "blake3-keyed-complete-domain-checkpoint-v1",
        "protocol_sha256": protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "width": width,
        "logical_candidate_count": context["logical_candidates"],
        "stream_candidate_count": context["stream_candidates"],
        "candidate_encoding": "combined=(outer_key_word1_low_bits<<32)|inner_key_word0",
    }


def _confirm(
    protocol: Mapping[str, Any], assignment: int, expected: bytes, relation: str
) -> dict[str, Any]:
    challenge = protocol["challenge"]
    width = int(challenge["unknown_key_bits"])
    known, message, _, _ = _challenge_bytes(challenge)
    key = apply_assignment(known, assignment, width)
    scalar = scalar_keyed_root(key, message)
    independent = numpy_keyed_root(key, message)
    return {
        "assignment": assignment,
        "relation": relation,
        "recovered_key_hex": key.hex(),
        "scalar_output_sha256": _sha256(scalar),
        "independent_numpy_output_sha256": _sha256(independent),
        "scalar_numpy_identity": scalar == independent,
        "complete_256_bit_match": scalar == independent == expected,
        "output_bits_checked": 256,
    }


def enumerate_domain(
    *,
    host: MetalBlake3Host,
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
        raise FileExistsError("BLAKE3 checkpoint exists; pass --resume")
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_bytes())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("BLAKE3 checkpoint fingerprint differs")
        next_assignment = int(checkpoint["next_assignment"])
        factual = [int(value) for value in checkpoint["factual_filtered"]]
        control = [int(value) for value in checkpoint["control_filtered"]]
        gpu_seconds = float(checkpoint["gpu_seconds"])
        if (
            next_assignment % STREAM_CANDIDATES
            or not 0 <= next_assignment <= context["logical_candidates"]
            or any(not 0 <= value < next_assignment for value in factual + control)
        ):
            raise RuntimeError("BLAKE3 checkpoint progress differs")
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
                    raise RuntimeError(f"BLAKE3 {name} candidate is outside batch")
                destination.append(combined)
            if len(destination) != len(set(destination)):
                raise RuntimeError(f"BLAKE3 duplicate {name} candidate")
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
        if next_assignment % (1 << 35) == 0:
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
    _, _, target, control_target = _challenge_bytes(protocol["challenge"])
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
        if row["complete_256_bit_match"]
    ]
    control_full = [
        row["assignment"]
        for row in control_confirmations
        if row["complete_256_bit_match"]
    ]
    complete = next_assignment == context["logical_candidates"]
    return {
        "unknown_key_bits": width,
        "known_key_bits": 256 - width,
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
    recovered = f"BLAKE3:unique_verified_W{width}_keyed_residual"
    writer = CausalWriter(api_id="b3kr1")
    writer._rules = []
    writer.add_rule(
        name="complete_domain_plus_independent_confirmation",
        description="Complete keyed-BLAKE3 residual enumeration plus scalar and independent NumPy confirmation establishes the recovered assignment.",
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
        trigger="BLAKE3:pre_target_Metal_qualification",
        mechanism="official_keyed_KAT_plus_scalar_NumPy_Metal_mapping_gates",
        outcome="BLAKE3:qualified_fullround_keyed_enumerator",
        confidence=1.0,
        source=payload["qualification_sha256"],
        quantification="7 rounds; 256-bit keyed root output; exact boundary mapping",
        evidence=json.dumps(payload["mapping_gate"], sort_keys=True),
        domain="BLAKE3 implementation equivalence",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"BLAKE3:frozen_public_W{width}_keyed_relation",
        mechanism="complete_domain_enumeration",
        outcome="BLAKE3:factual_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{logical} assignments; no early stop",
        evidence=json.dumps(execution["factual_filter_matches"]),
        domain="full-round residual-key enumeration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="BLAKE3:factual_candidate_set",
        mechanism="two_reference_confirmation",
        outcome=recovered,
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="256 output bits; scalar plus independent NumPy",
        evidence=json.dumps(execution["factual_confirmations"], sort_keys=True),
        domain="independent key confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="BLAKE3:one_bit_control_relation",
        mechanism="same_complete_search",
        outcome="BLAKE3:control_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{logical} assignments; identical kernel",
        evidence=json.dumps(execution["control_filter_matches"]),
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="BLAKE3:control_candidate_set",
        mechanism="zero_control_models",
        outcome="BLAKE3:control_relation_rejected",
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
        trigger=f"BLAKE3:frozen_public_W{width}_keyed_relation",
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
        trigger="BLAKE3:one_bit_control_relation",
        mechanism="verified_matched_control_chain",
        outcome="BLAKE3:control_relation_rejected",
        confidence=1.0,
        source="materialized:matched_control_separation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after the identical complete control search.",
        domain="AI-native retained inference",
        quality_score=1.0,
    )
    writer.add_cluster(
        name="BLAKE3 verified recovery chain",
        entities=[
            f"BLAKE3:frozen_public_W{width}_keyed_relation",
            "complete_domain_enumeration",
            "BLAKE3:factual_candidate_set",
            "two_reference_confirmation",
            recovered,
        ],
    )
    writer.add_cluster(
        name="BLAKE3 matched control chain",
        entities=[
            "BLAKE3:one_bit_control_relation",
            "same_complete_search",
            "BLAKE3:control_candidate_set",
            "zero_control_models",
            "BLAKE3:control_relation_rejected",
        ],
    )
    writer.add_gap(
        subject=recovered,
        predicate="next_required_gain",
        expected_object_type=f"prospectively_selected_strict_subset_of_W{width}_domain",
        confidence=1.0,
        suggested_queries=[
            f"Which frozen operator ranks a held-out W{width} keyed region early?"
        ],
    )
    temporary = path.with_name(f".{path.name}.tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    writer_stats = writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    gaps = list(reader._gaps)
    if (
        reader.api_id != "b3kr1"
        or len(reader._triplets) != 7
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(gaps) != 1
    ):
        raise RuntimeError("BLAKE3 authentic Causal readback gate failed")
    return {
        "path": str(path.relative_to(ROOT)),
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
        raise FileExistsError("BLAKE3 final result already exists")
    protocol = _load_protocol(protocol_path, expected_protocol_sha256)
    qualification_path = ROOT / protocol["anchors"]["qualification"]["path"]
    qualification_sha256 = protocol["anchors"]["qualification"]["sha256"]
    official_kat_gate()
    executable, build = _compile_native(build_dir)
    with MetalBlake3Host(executable) as host:
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
        raise RuntimeError("BLAKE3 full-domain recovery headline gate failed")
    payload: dict[str, Any] = {
        "schema": "blake3-keyed-metal-recovery-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_KEYED_BLAKE3_COMPLETE_DOMAIN_RECOVERY_CONFIRMED",
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "qualification_sha256": qualification_sha256,
        "qualification_path": str(qualification_path.relative_to(ROOT)),
        "anchors": {
            "runner_sha256": _file_sha256(Path(__file__)),
            "native_source_sha256": _file_sha256(NATIVE_SOURCE),
            "native_executable_sha256": build["executable_sha256"],
            "independent_numpy_reference_sha256": _file_sha256(NUMPY_REFERENCE),
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
    report = f"""# B3KR1 — Full-round keyed-BLAKE3 W{execution['unknown_key_bits']} residual-key recovery

- Complete logical domain: **{execution['logical_candidate_count']:,} assignments**
- Complete standard BLAKE3 rounds: **7/7**
- Keyed root output checked: **256/256 bits**
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
