#!/usr/bin/env python3
"""Pre-target semantic and throughput qualification for Salsa20/20 Metal.

Running this file is the only operation that invokes Metal.  Importing it is
side-effect free, selects no production secret, and freezes no challenge.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import select
import shutil
import statistics
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from arx_carry_leak.salsa20_reference import (
    BERNSTEIN_REFERENCE_SHA256,
    BERNSTEIN_REFERENCE_URL,
    ROUNDS,
    SPEC_256_EXPANSION_KAT,
    SPECIFICATION_PDF_SHA256,
    SPECIFICATION_URL,
    block,
    verify_specification_kats,
)

ATTEMPT_ID = "A263"
RECOVERY_ATTEMPT_ID = "A264"
SCHEMA = "salsa20-20-metal-qualification-v1"
STAGE = "SALSA20_20_METAL_PRE_TARGET_QUALIFICATION"
NATIVE_SOURCE_FILENAME = "salsa20_20_metal_native.swift"
NATIVE_VERSION = "salsa20-20-metal-native-v1"
REFERENCE_SOURCE_FILENAME = "salsa20_reference.py"
PROTOCOL_FACTORY_FILENAME = "salsa20_20_metal_protocol_factory.py"
RECOVERY_SOURCE_FILENAME = "salsa20_20_metal_recovery.py"
METAL_EVIDENCE_LEDGER_SCHEMA = "salsa20-20-metal-evidence-ledger-v1"
METAL_EVIDENCE_PRODUCER = "salsa20_20_metal_qualification.run"
MAX_HOST_RECORD_BYTES = 16 * 1024 * 1024
RESULT_CAPACITY = 64
DEFAULT_BENCHMARK_CANDIDATES = 1 << 26
DEFAULT_REPEATS = 3
MAX_BENCHMARK_CANDIDATES = 1 << 26
MAX_BENCHMARK_REPEATS = 3
QUALIFICATION_METAL_WALL_CAP_SECONDS = 110.0
# Retained alias for callers that used the original name.  The enforced cap is
# host-lifetime wall time, not accumulated GPU command time.
QUALIFICATION_GPU_WALL_CAP_SECONDS = QUALIFICATION_METAL_WALL_CAP_SECONDS
MAX_COMPLETE_DOMAIN_SECONDS = 2 * 60 * 60
MIN_RESIDUAL_WIDTH = 32
MAX_RESIDUAL_WIDTH = 64
MIN_STREAM_CANDIDATES = 1 << 16
MAX_STREAM_CANDIDATES = 1 << 30
FULL_ROUNDS = ROUNDS
QUALIFICATION_NONCE = bytes.fromhex("0011223344556677")
QUALIFICATION_COUNTER = 0xFFEEDDCCBBAA9988
QUALIFICATION_KEY_WORDS_1_TO_7 = [
    0x10213243,
    0x54657687,
    0x98A9BACB,
    0xDCEDFE0F,
    0x11223344,
    0x55667788,
    0x99AABBCC,
]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_sha256(value: Any) -> str:
    return _sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    )


def _is_sha256_hex(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _bytes_to_words(raw: bytes) -> list[int]:
    if len(raw) % 4:
        raise ValueError("Salsa20 byte sequence is not word aligned")
    return [int.from_bytes(raw[offset : offset + 4], "little") for offset in range(0, len(raw), 4)]


def _key(candidate: int, words_1_to_7: Sequence[int]) -> bytes:
    if candidate < 0 or candidate > 0xFFFFFFFF or len(words_1_to_7) != 7:
        raise ValueError("Salsa20 qualification key mapping differs")
    words = [candidate, *[int(value) for value in words_1_to_7]]
    if any(value < 0 or value > 0xFFFFFFFF for value in words):
        raise ValueError("Salsa20 key words must fit uint32")
    return b"".join(value.to_bytes(4, "little") for value in words)


def _scalar_words(
    candidate: int,
    words_1_to_7: Sequence[int],
    nonce: bytes,
    counter: int,
) -> list[int]:
    return _bytes_to_words(block(_key(candidate, words_1_to_7), nonce, counter))


def _compile_native(build_dir: Path, swiftc: str) -> tuple[Path, dict[str, Any]]:
    source = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    source_sha256 = _file_sha256(source)
    compiler = shutil.which(swiftc)
    if compiler is None:
        raise FileNotFoundError(f"Swift compiler not found: {swiftc}")
    build_dir.mkdir(parents=True, exist_ok=True)
    executable = build_dir / f"salsa20_20_metal_{source_sha256[:16]}"
    temporary = executable.with_name(f".{executable.name}.tmp")
    temporary.unlink(missing_ok=True)
    flags = ["-O", "-whole-module-optimization", "-warnings-as-errors"]
    command = [
        compiler,
        *flags,
        "-framework",
        "Foundation",
        "-framework",
        "CoreFoundation",
        "-framework",
        "Metal",
        str(source),
        "-o",
        str(temporary),
    ]
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("Salsa20 Swift/Metal host compilation failed: " + result.stderr.strip())
    temporary.replace(executable)
    compiler_version = subprocess.run(
        [compiler, "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()[0]
    return executable, {
        "source": str(source),
        "source_sha256": source_sha256,
        "executable": str(executable),
        "executable_sha256": _file_sha256(executable),
        "compiler": compiler,
        "compiler_version": compiler_version,
        "selected_flags": flags,
        "warnings_as_errors": True,
        "compile_command": command,
    }


class MetalSalsa2020Host:
    """Persistent JSON-lines wrapper around the native Swift/Metal process."""

    def __init__(
        self,
        executable: Path,
        *,
        deadline_monotonic: float | None = None,
    ) -> None:
        self.process = subprocess.Popen(
            [str(executable.resolve())],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.deadline_monotonic = deadline_monotonic
        self.total_gpu_seconds = 0.0
        self._stdout_buffer = b""
        try:
            ready = self._read()
            metal = ready.get("metal", {})
            if (
                ready.get("op") != "ready"
                or ready.get("version") != NATIVE_VERSION
                or not str(metal.get("device", "")).startswith("Apple")
                or int(metal.get("filter_execution_width", 0)) <= 0
                or metal.get("shader_runtime_compiled") is not True
                or metal.get("salsa20_rounds") != FULL_ROUNDS
                or metal.get("complete_block_words") != 16
            ):
                raise RuntimeError("Salsa20 native host identity gate failed")
        except BaseException:
            self.close(force=True)
            raise
        self.ready = ready
        self.identity = metal

    def set_wall_deadline(self, seconds_from_now: float) -> None:
        if seconds_from_now <= 0:
            raise ValueError("Salsa20 Metal wall deadline must be positive")
        proposed = time.monotonic() + seconds_from_now
        if self.deadline_monotonic is None:
            self.deadline_monotonic = proposed
        else:
            self.deadline_monotonic = min(self.deadline_monotonic, proposed)

    def _read(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        while b"\n" not in self._stdout_buffer:
            remaining = None
            if self.deadline_monotonic is not None:
                remaining = self.deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    self.close(force=True)
                    raise TimeoutError("Salsa20 Metal qualification wall cap expired")
            readable, _, _ = select.select([self.process.stdout], [], [], remaining)
            if not readable:
                self.close(force=True)
                raise TimeoutError("Salsa20 Metal qualification exceeded its wall cap")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                if self.process.poll() is None:
                    self.process.kill()
                    self.process.wait(timeout=5)
                stderr = ""
                if self.process.stderr is not None:
                    stderr = self.process.stderr.read()
                raise RuntimeError(f"Salsa20 native host ended: {stderr.strip()}")
            self._stdout_buffer += chunk
            if len(self._stdout_buffer) > MAX_HOST_RECORD_BYTES:
                self.close(force=True)
                raise RuntimeError("Salsa20 native host record exceeded its size cap")
        raw_line, self._stdout_buffer = self._stdout_buffer.split(b"\n", 1)
        payload = json.loads(raw_line.decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("Salsa20 native response is not an object")
        if "gpu_seconds" in payload:
            elapsed = float(payload["gpu_seconds"])
            if not math.isfinite(elapsed) or elapsed < 0:
                raise RuntimeError("Salsa20 native host returned invalid GPU time")
            self.total_gpu_seconds += elapsed
        return payload

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError("Salsa20 native host is not running")
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(payload, sort_keys=True) + "\n")
        self.process.stdin.flush()
        return self._read()

    def configure(
        self,
        *,
        target: Sequence[int],
        control: Sequence[int],
        key_words_1_to_7: Sequence[int],
        nonce: Sequence[int],
        counter: Sequence[int],
    ) -> dict[str, Any]:
        response = self._request(
            {
                "op": "configure",
                "target": list(target),
                "control": list(control),
                "key_words_1_to_7": list(key_words_1_to_7),
                "nonce": list(nonce),
                "counter": list(counter),
            }
        )
        if response.get("op") != "configured":
            raise RuntimeError("Salsa20 native configure failed")
        return response

    def blocks(self, first: int, count: int) -> dict[str, Any]:
        response = self._request({"op": "blocks", "first": first, "count": count})
        if response.get("op") != "blocks":
            raise RuntimeError("Salsa20 native block request failed")
        return response

    def filter(self, first: int, count: int) -> dict[str, Any]:
        response = self._request(
            {
                "op": "filter",
                "first": first,
                "count": count,
                "capacity": RESULT_CAPACITY,
            }
        )
        if response.get("op") != "filter":
            raise RuntimeError("Salsa20 native filter request failed")
        return response

    def close(self, *, force: bool = False) -> None:
        if self.process.poll() is not None:
            return
        if not force:
            try:
                force = self._request({"op": "quit"}).get("op") != "quit"
            except (BrokenPipeError, RuntimeError, TimeoutError):
                force = True
        if force:
            self.process.kill()
        else:
            assert self.process.stdin is not None
            self.process.stdin.close()
        try:
            code = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            code = self.process.wait(timeout=5)
        if not force and code != 0:
            raise RuntimeError("Salsa20 native host exit failed")

    def __enter__(self) -> MetalSalsa2020Host:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _one_bit_control(target: Sequence[int]) -> list[int]:
    control = list(target)
    if len(control) != 16:
        raise ValueError("Salsa20 target must contain one complete block")
    control[-1] ^= 1
    return control


def _specification_kat_gate(host: MetalSalsa2020Host) -> dict[str, Any]:
    scalar_rows = verify_specification_kats()
    if not all(row["pass"] is True for row in scalar_rows):
        raise RuntimeError("Salsa20 scalar specification KAT failed")
    vector = SPEC_256_EXPANSION_KAT
    key_words = _bytes_to_words(bytes.fromhex(vector.key_hex))
    input16 = bytes.fromhex(vector.input_hex)
    nonce = _bytes_to_words(input16[:8])
    counter = _bytes_to_words(input16[8:])
    expected = _bytes_to_words(bytes.fromhex(vector.output_hex))
    host.configure(
        target=expected,
        control=_one_bit_control(expected),
        key_words_1_to_7=key_words[1:],
        nonce=nonce,
        counter=counter,
    )
    native = host.blocks(key_words[0], 1)
    actual = native["words"]
    if actual != expected:
        raise RuntimeError("Salsa20 Metal specification KAT failed")
    return {
        "primary_specification_url": SPECIFICATION_URL,
        "primary_specification_pdf_sha256": SPECIFICATION_PDF_SHA256,
        "bernstein_reference_url": BERNSTEIN_REFERENCE_URL,
        "bernstein_reference_sha256": BERNSTEIN_REFERENCE_SHA256,
        "scalar_vectors": scalar_rows,
        "metal_256_bit_expansion_vector": {
            "expected_words": expected,
            "actual_words": actual,
            "exact_cpu_metal_identity": True,
            "gpu_seconds": native["gpu_seconds"],
        },
        "all_specification_kat_gates_passed": True,
    }


def _cross_implementation_gate(host: MetalSalsa2020Host) -> dict[str, Any]:
    first = 0x10203040
    count = 8
    expected = [
        word
        for candidate in range(first, first + count)
        for word in _scalar_words(
            candidate,
            QUALIFICATION_KEY_WORDS_1_TO_7,
            QUALIFICATION_NONCE,
            QUALIFICATION_COUNTER,
        )
    ]
    target = expected[:16]
    host.configure(
        target=target,
        control=_one_bit_control(target),
        key_words_1_to_7=QUALIFICATION_KEY_WORDS_1_TO_7,
        nonce=_bytes_to_words(QUALIFICATION_NONCE),
        counter=[
            QUALIFICATION_COUNTER & 0xFFFFFFFF,
            QUALIFICATION_COUNTER >> 32,
        ],
    )
    native = host.blocks(first, count)
    if native["words"] != expected:
        raise RuntimeError("Salsa20 CPU/Metal cross-implementation gate failed")
    return {
        "candidate_first": first,
        "candidate_count": count,
        "compared_words": count * 16,
        "compared_bits": count * 512,
        "exact_cpu_metal_identity": True,
        "cpu_words_sha256": _sha256(b"".join(word.to_bytes(4, "little") for word in expected)),
        "gpu_seconds": native["gpu_seconds"],
    }


def _boundary_mapping_gate(host: MetalSalsa2020Host) -> dict[str, Any]:
    candidates = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]
    rows = []
    for candidate in candidates:
        expected = _scalar_words(
            candidate,
            QUALIFICATION_KEY_WORDS_1_TO_7,
            QUALIFICATION_NONCE,
            QUALIFICATION_COUNTER,
        )
        host.configure(
            target=expected,
            control=_one_bit_control(expected),
            key_words_1_to_7=QUALIFICATION_KEY_WORDS_1_TO_7,
            nonce=_bytes_to_words(QUALIFICATION_NONCE),
            counter=[
                QUALIFICATION_COUNTER & 0xFFFFFFFF,
                QUALIFICATION_COUNTER >> 32,
            ],
        )
        native = host.blocks(candidate, 1)
        exact = native["words"] == expected
        rows.append(
            {
                "candidate": candidate,
                "exact_cpu_metal_identity": exact,
                "output_sha256": _sha256(b"".join(word.to_bytes(4, "little") for word in expected)),
                "gpu_seconds": native["gpu_seconds"],
            }
        )
    if not all(row["exact_cpu_metal_identity"] for row in rows):
        raise RuntimeError("Salsa20 uint32 boundary mapping gate failed")
    return {
        "boundary_candidates": rows,
        "exact_boundary_identity": True,
        "candidate_word_mapping": "candidate_is_key_word_0_little_endian",
        "outer_slice_mapping": "outer_slice_ors_into_low_bits_of_key_word_1",
    }


def _validate_benchmark_budget(candidate_count: int, repeats: int) -> int:
    if candidate_count < 1 or candidate_count > MAX_BENCHMARK_CANDIDATES:
        raise ValueError(f"benchmark candidate count must be in 1...{MAX_BENCHMARK_CANDIDATES}")
    if repeats < 1 or repeats > MAX_BENCHMARK_REPEATS:
        raise ValueError(f"benchmark repeats must be in 1...{MAX_BENCHMARK_REPEATS}")
    return candidate_count * repeats


def _benchmark(host: MetalSalsa2020Host, *, candidate_count: int, repeats: int) -> dict[str, Any]:
    _validate_benchmark_budget(candidate_count, repeats)
    target = _scalar_words(
        0xF1234567,
        QUALIFICATION_KEY_WORDS_1_TO_7,
        QUALIFICATION_NONCE,
        QUALIFICATION_COUNTER,
    )
    host.configure(
        target=target,
        control=_one_bit_control(target),
        key_words_1_to_7=QUALIFICATION_KEY_WORDS_1_TO_7,
        nonce=_bytes_to_words(QUALIFICATION_NONCE),
        counter=[
            QUALIFICATION_COUNTER & 0xFFFFFFFF,
            QUALIFICATION_COUNTER >> 32,
        ],
    )
    rows = []
    for _ in range(repeats):
        started = time.perf_counter()
        response = host.filter(0, candidate_count)
        wall_seconds = time.perf_counter() - started
        gpu_seconds = float(response["gpu_seconds"])
        if gpu_seconds <= 0 or wall_seconds <= 0:
            raise RuntimeError("Salsa20 Metal benchmark returned nonpositive time")
        if response["factual"] or response["control"]:
            raise RuntimeError("Salsa20 benchmark relation unexpectedly matched")
        rows.append(
            {
                "candidate_count": candidate_count,
                "gpu_seconds": gpu_seconds,
                "end_to_end_wall_seconds": wall_seconds,
                "gpu_candidates_per_second": candidate_count / gpu_seconds,
                "end_to_end_candidates_per_second": candidate_count / wall_seconds,
                "factual_matches": list(response["factual"]),
                "control_matches": list(response["control"]),
            }
        )
    wall_throughputs = [row["end_to_end_candidates_per_second"] for row in rows]
    gpu_throughputs = [row["gpu_candidates_per_second"] for row in rows]
    minimum = min(wall_throughputs)
    stream = _recommended_stream_count(minimum)
    return {
        "rows": rows,
        "candidate_count_per_repeat": candidate_count,
        "repeat_count": repeats,
        "minimum_end_to_end_candidates_per_second": minimum,
        "median_end_to_end_candidates_per_second": statistics.median(wall_throughputs),
        "minimum_gpu_candidates_per_second": min(gpu_throughputs),
        "median_gpu_candidates_per_second": statistics.median(gpu_throughputs),
        "recommended_stream_candidate_count": stream,
        "recommended_stream_seconds_at_minimum": stream / minimum,
        "projected_complete_domain_seconds_at_minimum": {
            str(width): (2**width) / minimum
            for width in range(MIN_RESIDUAL_WIDTH, MAX_RESIDUAL_WIDTH + 1)
        },
        "maximum_candidate_evaluations": MAX_BENCHMARK_CANDIDATES * MAX_BENCHMARK_REPEATS,
        "timed_relation_bits": 512,
        "volatile_performance_only_not_recovery_evidence": True,
    }


def _recommended_stream_count(minimum_throughput: float) -> int:
    desired = max(MIN_STREAM_CANDIDATES, int(minimum_throughput * 0.5))
    power = 1 << max(0, int(math.floor(math.log2(desired))))
    return min(MAX_STREAM_CANDIDATES, max(MIN_STREAM_CANDIDATES, power))


def _launch_gate(benchmark: dict[str, Any]) -> dict[str, Any]:
    minimum = float(benchmark["minimum_end_to_end_candidates_per_second"])
    affordable = int(math.floor(math.log2(minimum * MAX_COMPLETE_DOMAIN_SECONDS)))
    selected_width = min(MAX_RESIDUAL_WIDTH, max(MIN_RESIDUAL_WIDTH, affordable))
    projected = (1 << selected_width) / minimum
    selected_stream = int(benchmark["recommended_stream_candidate_count"])
    return {
        "selected_width": selected_width,
        "selected_stream_candidate_count": selected_stream,
        "projected_selected_width_seconds_at_observed_minimum": projected,
        "projection_rate_basis": "minimum_end_to_end_candidates_per_second",
        "maximum_complete_domain_seconds": MAX_COMPLETE_DOMAIN_SECONDS,
        "selected_width_under_two_hours": projected <= MAX_COMPLETE_DOMAIN_SECONDS,
        "parameters_safe_for_post_review_freeze": projected <= MAX_COMPLETE_DOMAIN_SECONDS,
        "full_domain_launch_authorized": False,
        "requires_explicit_root_review_before_protocol_freeze": True,
        "requires_separate_explicit_execution_acknowledgement": True,
    }


def _build_metal_evidence_ledger(
    *,
    content_anchors_sha256: str,
    native_build: dict[str, Any],
    host_ready: dict[str, Any],
    kat_gate: dict[str, Any],
    cross_gate: dict[str, Any],
    boundary_gate: dict[str, Any],
    benchmark: dict[str, Any],
    launch_gate: dict[str, Any],
    resource_cap: dict[str, Any],
) -> dict[str, Any]:
    """Bind the actual Metal transcript and every derived launch parameter."""

    return {
        "schema": METAL_EVIDENCE_LEDGER_SCHEMA,
        "producer": METAL_EVIDENCE_PRODUCER,
        "provenance_scope": "semantic_execution_provenance_not_hardware_attestation",
        "content_anchors_sha256": content_anchors_sha256,
        "native_build_record": native_build,
        "native_source_sha256": native_build["source_sha256"],
        "native_executable_sha256": native_build["executable_sha256"],
        "raw_host_ready_device_record": host_ready,
        "specification_kat_gate": kat_gate,
        "cross_implementation_gate": cross_gate,
        "boundary_mapping_gate": boundary_gate,
        "benchmark": benchmark,
        "launch_gate": launch_gate,
        "qualification_resource_cap": resource_cap,
        "semantic_bindings": {
            "official_rounds": FULL_ROUNDS,
            "full_output_bits": 512,
            "candidate_word_mapping": "candidate_is_key_word_0_little_endian",
            "width_projection_rate_basis": ("minimum_end_to_end_candidates_per_second"),
            "deadline_covers_process_startup_and_every_read": True,
            "future_production_target_absent": True,
        },
    }


def _expected_cross_static() -> dict[str, Any]:
    first = 0x10203040
    count = 8
    expected = [
        word
        for candidate in range(first, first + count)
        for word in _scalar_words(
            candidate,
            QUALIFICATION_KEY_WORDS_1_TO_7,
            QUALIFICATION_NONCE,
            QUALIFICATION_COUNTER,
        )
    ]
    return {
        "candidate_first": first,
        "candidate_count": count,
        "compared_words": count * 16,
        "compared_bits": count * 512,
        "exact_cpu_metal_identity": True,
        "cpu_words_sha256": _sha256(b"".join(word.to_bytes(4, "little") for word in expected)),
    }


def _expected_boundary_static() -> list[dict[str, Any]]:
    rows = []
    for candidate in [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]:
        expected = _scalar_words(
            candidate,
            QUALIFICATION_KEY_WORDS_1_TO_7,
            QUALIFICATION_NONCE,
            QUALIFICATION_COUNTER,
        )
        rows.append(
            {
                "candidate": candidate,
                "exact_cpu_metal_identity": True,
                "output_sha256": _sha256(b"".join(word.to_bytes(4, "little") for word in expected)),
            }
        )
    return rows


def validate_metal_evidence_ledger(payload: dict[str, Any]) -> str:
    """Recompute and validate actual Metal evidence before target selection."""

    try:
        ledger = payload["metal_evidence_ledger"]
        claimed_sha256 = payload["metal_evidence_ledger_sha256"]
        content_anchors = payload["content_anchors"]
        native_build = payload["native_build"]
        host_ready = payload["host_ready_record"]
        kat = payload["specification_kat_gate"]
        cross = payload["cross_implementation_gate"]
        boundary = payload["boundary_mapping_gate"]
        benchmark = payload["benchmark"]
        launch = payload["launch_gate"]
        resource = payload["qualification_resource_cap"]
        if (
            payload.get("schema") != SCHEMA
            or payload.get("attempt_id") != ATTEMPT_ID
            or payload.get("recovery_attempt_id") != RECOVERY_ATTEMPT_ID
            or payload.get("evidence_stage") != STAGE
            or payload.get("metal_executed") is not True
            or payload.get("full_domain_launched") is not False
            or not isinstance(ledger, dict)
            or ledger.get("schema") != METAL_EVIDENCE_LEDGER_SCHEMA
            or ledger.get("producer") != METAL_EVIDENCE_PRODUCER
            or claimed_sha256 != _canonical_sha256(ledger)
            or payload.get("content_anchors_sha256") != _canonical_sha256(content_anchors)
        ):
            raise ValueError("top-level evidence identity")
        rebuilt = _build_metal_evidence_ledger(
            content_anchors_sha256=payload["content_anchors_sha256"],
            native_build=native_build,
            host_ready=host_ready,
            kat_gate=kat,
            cross_gate=cross,
            boundary_gate=boundary,
            benchmark=benchmark,
            launch_gate=launch,
            resource_cap=resource,
        )
        if ledger != rebuilt:
            raise ValueError("ledger recomputation")
        if (
            native_build.get("source_sha256")
            != content_anchors.get("native_source", {}).get("sha256")
            or native_build.get("source") != content_anchors.get("native_source", {}).get("path")
            or not _is_sha256_hex(native_build.get("executable_sha256"))
            or native_build.get("selected_flags")
            != ["-O", "-whole-module-optimization", "-warnings-as-errors"]
            or native_build.get("warnings_as_errors") is not True
            or not str(native_build.get("compiler_version", "")).strip()
        ):
            raise ValueError("native build provenance")

        metal = host_ready["metal"]
        if (
            host_ready.get("op") != "ready"
            or host_ready.get("version") != NATIVE_VERSION
            or not str(metal.get("device", "")).startswith("Apple")
            or int(metal.get("filter_execution_width", 0)) <= 0
            or metal.get("shader_runtime_compiled") is not True
            or metal.get("salsa20_rounds") != FULL_ROUNDS
            or metal.get("complete_block_words") != 16
            or payload.get("host_identity") != metal
        ):
            raise ValueError("host identity")

        vector = SPEC_256_EXPANSION_KAT
        expected_words = _bytes_to_words(bytes.fromhex(vector.output_hex))
        metal_vector = kat["metal_256_bit_expansion_vector"]
        vector_gpu_seconds = float(metal_vector["gpu_seconds"])
        if (
            kat.get("scalar_vectors") != verify_specification_kats()
            or kat.get("primary_specification_url") != SPECIFICATION_URL
            or kat.get("primary_specification_pdf_sha256") != SPECIFICATION_PDF_SHA256
            or kat.get("bernstein_reference_url") != BERNSTEIN_REFERENCE_URL
            or kat.get("bernstein_reference_sha256") != BERNSTEIN_REFERENCE_SHA256
            or metal_vector.get("expected_words") != expected_words
            or metal_vector.get("actual_words") != expected_words
            or metal_vector.get("exact_cpu_metal_identity") is not True
            or not math.isfinite(vector_gpu_seconds)
            or vector_gpu_seconds < 0
            or kat.get("all_specification_kat_gates_passed") is not True
        ):
            raise ValueError("official KAT evidence")

        expected_cross = _expected_cross_static()
        cross_gpu_seconds = float(cross["gpu_seconds"])
        if (
            {key: cross.get(key) for key in expected_cross} != expected_cross
            or not math.isfinite(cross_gpu_seconds)
            or cross_gpu_seconds < 0
        ):
            raise ValueError("cross evidence")
        expected_boundary = _expected_boundary_static()
        observed_boundary = boundary["boundary_candidates"]
        if (
            len(observed_boundary) != len(expected_boundary)
            or boundary.get("exact_boundary_identity") is not True
            or boundary.get("candidate_word_mapping") != "candidate_is_key_word_0_little_endian"
            or boundary.get("outer_slice_mapping") != "outer_slice_ors_into_low_bits_of_key_word_1"
        ):
            raise ValueError("boundary evidence")
        boundary_gpu_seconds = 0.0
        for actual, expected in zip(observed_boundary, expected_boundary, strict=True):
            elapsed = float(actual["gpu_seconds"])
            if (
                {key: actual.get(key) for key in expected} != expected
                or not math.isfinite(elapsed)
                or elapsed < 0
            ):
                raise ValueError("boundary row")
            boundary_gpu_seconds += elapsed

        candidate_count = int(benchmark["candidate_count_per_repeat"])
        repeats = int(benchmark["repeat_count"])
        permitted = _validate_benchmark_budget(candidate_count, repeats)
        rows = benchmark["rows"]
        if len(rows) != repeats:
            raise ValueError("benchmark row count")
        wall_rates = []
        gpu_rates = []
        benchmark_gpu_seconds = 0.0
        benchmark_wall_seconds = 0.0
        for row in rows:
            gpu_seconds = float(row["gpu_seconds"])
            wall_seconds = float(row["end_to_end_wall_seconds"])
            gpu_rate = candidate_count / gpu_seconds
            wall_rate = candidate_count / wall_seconds
            if (
                row.get("candidate_count") != candidate_count
                or not all(
                    math.isfinite(value)
                    for value in (gpu_seconds, wall_seconds, gpu_rate, wall_rate)
                )
                or gpu_seconds <= 0
                or wall_seconds <= 0
                or gpu_seconds > wall_seconds
                or not math.isclose(float(row["gpu_candidates_per_second"]), gpu_rate)
                or not math.isclose(float(row["end_to_end_candidates_per_second"]), wall_rate)
                or row.get("factual_matches") != []
                or row.get("control_matches") != []
            ):
                raise ValueError("benchmark row")
            wall_rates.append(wall_rate)
            gpu_rates.append(gpu_rate)
            benchmark_gpu_seconds += gpu_seconds
            benchmark_wall_seconds += wall_seconds
        minimum = min(wall_rates)
        stream = _recommended_stream_count(minimum)
        projections = benchmark["projected_complete_domain_seconds_at_minimum"]
        if (
            benchmark.get("maximum_candidate_evaluations")
            != MAX_BENCHMARK_CANDIDATES * MAX_BENCHMARK_REPEATS
            or permitted != candidate_count * repeats
            or not math.isclose(
                float(benchmark["minimum_end_to_end_candidates_per_second"]),
                minimum,
            )
            or not math.isclose(
                float(benchmark["median_end_to_end_candidates_per_second"]),
                statistics.median(wall_rates),
            )
            or not math.isclose(
                float(benchmark["minimum_gpu_candidates_per_second"]),
                min(gpu_rates),
            )
            or not math.isclose(
                float(benchmark["median_gpu_candidates_per_second"]),
                statistics.median(gpu_rates),
            )
            or benchmark.get("recommended_stream_candidate_count") != stream
            or not math.isclose(
                float(benchmark["recommended_stream_seconds_at_minimum"]),
                stream / minimum,
            )
            or set(projections)
            != {str(width) for width in range(MIN_RESIDUAL_WIDTH, MAX_RESIDUAL_WIDTH + 1)}
            or any(
                not math.isclose(float(projections[str(width)]), (2**width) / minimum)
                for width in range(MIN_RESIDUAL_WIDTH, MAX_RESIDUAL_WIDTH + 1)
            )
            or benchmark.get("timed_relation_bits") != 512
            or benchmark.get("volatile_performance_only_not_recovery_evidence") is not True
            or launch != _launch_gate(benchmark)
            or launch.get("projection_rate_basis") != "minimum_end_to_end_candidates_per_second"
        ):
            raise ValueError("benchmark derivation")

        started = float(resource["host_lifetime_started_monotonic"])
        deadline = float(resource["absolute_deadline_monotonic"])
        finished = float(resource["host_lifetime_finished_monotonic"])
        actual_wall = float(resource["actual_wall_seconds_host_lifetime"])
        reported_gpu = float(resource["reported_total_gpu_seconds"])
        recorded_gpu = (
            vector_gpu_seconds + cross_gpu_seconds + boundary_gpu_seconds + benchmark_gpu_seconds
        )
        if (
            not all(
                math.isfinite(value)
                for value in (started, deadline, finished, actual_wall, reported_gpu)
            )
            or started < 0
            or started > finished
            or actual_wall < benchmark_wall_seconds
            or reported_gpu + 1e-12 < recorded_gpu
            or reported_gpu > actual_wall
            or not math.isclose(deadline - started, QUALIFICATION_METAL_WALL_CAP_SECONDS)
            or not math.isclose(finished - started, actual_wall)
            or finished > deadline + 2.0
            or resource.get("wall_deadline_seconds") != QUALIFICATION_METAL_WALL_CAP_SECONDS
            or resource.get("maximum_benchmark_candidates_per_repeat") != MAX_BENCHMARK_CANDIDATES
            or resource.get("maximum_benchmark_repeats") != MAX_BENCHMARK_REPEATS
            or resource.get("subprocess_killed_on_deadline") is not True
            or resource.get("deadline_covers_ready_wait") is not True
            or resource.get("deadline_covers_every_response_wait") is not True
            or resource.get("constructor_cleanup_on_startup_failure") is not True
            or resource.get("cannot_occupy_gpu_for_two_minutes") is not True
        ):
            raise ValueError("deadline provenance")
    except (KeyError, TypeError, ValueError, OverflowError, ZeroDivisionError) as error:
        raise RuntimeError("Salsa20 Metal evidence ledger consistency gate failed") from error
    return str(claimed_sha256)


def run(
    *,
    output: Path,
    build_dir: Path,
    swiftc: str,
    benchmark_candidates: int,
    repeats: int,
) -> dict[str, Any]:
    _validate_benchmark_budget(benchmark_candidates, repeats)
    executable, native_build = _compile_native(build_dir, swiftc)
    started = time.monotonic()
    absolute_deadline = started + QUALIFICATION_METAL_WALL_CAP_SECONDS
    host = MetalSalsa2020Host(
        executable,
        deadline_monotonic=absolute_deadline,
    )
    try:
        kat_gate = _specification_kat_gate(host)
        cross_gate = _cross_implementation_gate(host)
        boundary_gate = _boundary_mapping_gate(host)
        benchmark = _benchmark(host, candidate_count=benchmark_candidates, repeats=repeats)
        host_ready = host.ready
        host_identity = host.identity
        reported_gpu_seconds = host.total_gpu_seconds
    finally:
        host.close()
    finished = time.monotonic()
    wall_seconds = finished - started
    if wall_seconds > QUALIFICATION_METAL_WALL_CAP_SECONDS + 2.0:
        raise RuntimeError("Salsa20 qualification exceeded its enforced Metal wall cap")
    launch = _launch_gate(benchmark)
    if launch["parameters_safe_for_post_review_freeze"] is not True:
        raise RuntimeError("Salsa20 qualification found no safe residual width")
    root = Path(__file__).parents[2]
    reference = root / "src" / "arx_carry_leak" / REFERENCE_SOURCE_FILENAME
    factory = Path(__file__).with_name(PROTOCOL_FACTORY_FILENAME)
    recovery = Path(__file__).with_name(RECOVERY_SOURCE_FILENAME)
    content_anchors = {
        "qualification_source": {
            "path": str(Path(__file__)),
            "sha256": _file_sha256(Path(__file__)),
        },
        "native_source": {
            "path": native_build["source"],
            "sha256": native_build["source_sha256"],
        },
        "cpu_reference": {
            "path": str(reference),
            "sha256": _file_sha256(reference),
        },
        "protocol_factory": {
            "path": str(factory),
            "sha256": _file_sha256(factory),
        },
        "recovery_source": {
            "path": str(recovery),
            "sha256": _file_sha256(recovery),
        },
        "primary_specification": {
            "url": SPECIFICATION_URL,
            "pdf_sha256": SPECIFICATION_PDF_SHA256,
        },
        "bernstein_reference": {
            "url": BERNSTEIN_REFERENCE_URL,
            "sha256": BERNSTEIN_REFERENCE_SHA256,
        },
    }
    resource_cap = {
        "wall_deadline_seconds": QUALIFICATION_METAL_WALL_CAP_SECONDS,
        "gpu_wall_cap_seconds": QUALIFICATION_METAL_WALL_CAP_SECONDS,
        "host_lifetime_started_monotonic": started,
        "absolute_deadline_monotonic": absolute_deadline,
        "host_lifetime_finished_monotonic": finished,
        "actual_wall_seconds_host_lifetime": wall_seconds,
        "reported_total_gpu_seconds": reported_gpu_seconds,
        "maximum_benchmark_candidates_per_repeat": MAX_BENCHMARK_CANDIDATES,
        "maximum_benchmark_repeats": MAX_BENCHMARK_REPEATS,
        "max_candidates_per_repeat": MAX_BENCHMARK_CANDIDATES,
        "max_repeats": MAX_BENCHMARK_REPEATS,
        "subprocess_killed_on_deadline": True,
        "deadline_covers_ready_wait": True,
        "deadline_covers_every_response_wait": True,
        "constructor_cleanup_on_startup_failure": True,
        "cannot_occupy_gpu_for_two_minutes": True,
    }
    payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "recovery_attempt_id": RECOVERY_ATTEMPT_ID,
        "evidence_stage": STAGE,
        "algorithm": {
            "name": "Salsa20/20",
            "rounds": FULL_ROUNDS,
            "key_bits": 256,
            "nonce_bits": 64,
            "counter_bits": 64,
            "output_block_bits": 512,
            "byte_semantics": "Bernstein_little_endian",
        },
        "content_anchors": content_anchors,
        "content_anchors_sha256": _canonical_sha256(content_anchors),
        "specification_kat_gate": kat_gate,
        "cross_implementation_gate": cross_gate,
        "boundary_mapping_gate": boundary_gate,
        "benchmark": benchmark,
        "qualification_resource_cap": resource_cap,
        "launch_gate": launch,
        "native_build": native_build,
        "host_ready_record": host_ready,
        "host_identity": host_identity,
        "host_platform": platform.platform(),
        "information_boundary": {
            "production_target_selected": False,
            "production_secret_generated": False,
            "production_protocol_frozen": False,
            "full_domain_launched": False,
            "benchmark_independent_of_future_production_target": True,
        },
        "metal_executed": True,
        "full_domain_launched": False,
    }
    ledger = _build_metal_evidence_ledger(
        content_anchors_sha256=payload["content_anchors_sha256"],
        native_build=native_build,
        host_ready=host_ready,
        kat_gate=kat_gate,
        cross_gate=cross_gate,
        boundary_gate=boundary_gate,
        benchmark=benchmark,
        launch_gate=launch,
        resource_cap=resource_cap,
    )
    payload["metal_evidence_ledger"] = ledger
    payload["metal_evidence_ledger_sha256"] = _canonical_sha256(ledger)
    validate_metal_evidence_ledger(payload)
    _atomic_json(output, payload)
    reopened = json.loads(output.read_text())
    if reopened != payload:
        raise RuntimeError("Salsa20 qualification artifact reopen gate failed")
    return {
        "output": str(output),
        "sha256": _file_sha256(output),
        "selected_width": launch["selected_width"],
        "selected_stream_candidate_count": launch["selected_stream_candidate_count"],
        "production_challenge_frozen": False,
        "full_domain_launched": False,
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).parents[2]
    parser.add_argument(
        "--metal",
        action="store_true",
        help="run the capped pre-target Metal qualification",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root
        / "research"
        / "results"
        / "v1"
        / "salsa20_20_metal_a263_qualification_v1.json",
    )
    parser.add_argument("--build-dir", type=Path, default=root / "build" / "salsa20_20_a263")
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument("--benchmark-candidates", type=int, default=DEFAULT_BENCHMARK_CANDIDATES)
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    args = parser.parse_args(argv)
    if not args.metal:
        raise RuntimeError("Salsa20 qualification requires explicit --metal")
    print(
        json.dumps(
            run(
                output=args.output,
                build_dir=args.build_dir,
                swiftc=args.swiftc,
                benchmark_candidates=args.benchmark_candidates,
                repeats=args.repeats,
            ),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
