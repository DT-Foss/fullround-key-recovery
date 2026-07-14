#!/usr/bin/env python3
"""A255: qualify the standardized Ascon-AEAD128 Metal record factory.

This pre-target stage may run only pinned KATs, deterministic mapping checks,
and a capped throughput benchmark.  It never generates, freezes, or searches a
production A256 challenge.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import select
import shutil
import statistics
import struct
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from arx_carry_leak.ascon_aead128_reference import (
    OFFICIAL_KAT_COMMIT,
    OFFICIAL_KAT_FILE_SHA256,
    OFFICIAL_KAT_URL,
    OFFICIAL_KATS,
    ORIENTATION_SENTINEL_COUNT,
    SP800_232_PDF_SHA256,
    SP800_232_URL,
    encrypt_combined,
    verify_official_kats,
    verify_orientation_sentinel,
)

ATTEMPT_ID = "A255"
SCHEMA = "ascon-aead128-sp800-232-metal-qualification-v1"
NATIVE_SOURCE_FILENAME = "ascon_aead128_metal_native.swift"
NATIVE_VERSION = "ascon-aead128-metal-native-v1"
REFERENCE_SOURCE_FILENAME = "ascon_aead128_reference.py"
MAX_MESSAGE_BYTES = 32
MAX_ASSOCIATED_DATA_BYTES = 32
MAX_OUTPUT_BYTES = MAX_MESSAGE_BYTES + 16
OUTPUT_WORDS = MAX_OUTPUT_BYTES // 4
RESULT_CAPACITY = 64
DEFAULT_BENCHMARK_CANDIDATES = 1 << 26
DEFAULT_REPEATS = 3
MAX_BENCHMARK_CANDIDATES = 1 << 26
MAX_BENCHMARK_REPEATS = 3
BENCHMARK_WARMUP_CANDIDATES = 1 << 20
QUALIFICATION_GPU_WALL_CAP_SECONDS = 110.0
MAX_COMPLETE_DOMAIN_SECONDS = 2 * 60 * 60
MAX_SUPPORTED_RESIDUAL_WIDTH = 64
STREAM_TARGET_SECONDS = 15.0
MIN_STREAM_CANDIDATES = 1 << 16
MAX_STREAM_CANDIDATES = 1 << 30
QUALIFICATION_MESSAGE = bytes(range(0x20, 0x40))
QUALIFICATION_ASSOCIATED_DATA = bytes(range(0x30, 0x41))
QUALIFICATION_NONCE = bytes(range(0xA0, 0xB0))


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


def _bytes_to_words(raw: bytes, word_count: int) -> list[int]:
    if len(raw) > word_count * 4:
        raise ValueError("byte string does not fit requested uint32 word count")
    padded = raw + bytes(word_count * 4 - len(raw))
    return list(struct.unpack(f"<{word_count}I", padded))


def _words_to_bytes(words: list[int], length: int) -> bytes:
    return struct.pack(f"<{len(words)}I", *words)[:length]


def _key_from_words(candidate: int, key_words_1_to_3: Sequence[int]) -> bytes:
    if candidate < 0 or candidate > 0xFFFFFFFF:
        raise ValueError("candidate must fit uint32")
    if len(key_words_1_to_3) != 3:
        raise ValueError("key_words_1_to_3 must contain three words")
    words = [candidate, *(int(value) for value in key_words_1_to_3)]
    if any(value < 0 or value > 0xFFFFFFFF for value in words):
        raise ValueError("all key words must fit uint32")
    return struct.pack("<4I", *words)


def _scalar_output(
    candidate: int,
    key_words_1_to_3: Sequence[int],
    *,
    message: bytes = QUALIFICATION_MESSAGE,
    associated_data: bytes = QUALIFICATION_ASSOCIATED_DATA,
    nonce: bytes = QUALIFICATION_NONCE,
) -> bytes:
    return encrypt_combined(
        _key_from_words(candidate, key_words_1_to_3),
        nonce,
        associated_data,
        message,
    )


def _compile_native(build_dir: Path, swiftc: str) -> tuple[Path, dict[str, Any]]:
    source = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    source_sha256 = _file_sha256(source)
    compiler = shutil.which(swiftc)
    if compiler is None:
        raise FileNotFoundError(f"Swift compiler not found: {swiftc}")
    build_dir.mkdir(parents=True, exist_ok=True)
    output = build_dir / f"ascon_aead128_metal_{source_sha256[:16]}"
    temporary = output.with_name(f".{output.name}.tmp")
    flags = ["-O", "-whole-module-optimization", "-warnings-as-errors"]
    temporary.unlink(missing_ok=True)
    result = subprocess.run(
        [compiler, *flags, str(source), "-o", str(temporary)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Ascon-AEAD128 Swift/Metal host compilation failed: "
            + result.stderr.strip()
        )
    temporary.replace(output)
    if not output.is_file() or output.stat().st_size == 0:
        raise RuntimeError("Ascon-AEAD128 native build produced no executable")
    compiler_version = subprocess.run(
        [compiler, "--version"], check=True, capture_output=True, text=True
    ).stdout.splitlines()[0]
    return output, {
        "source_filename": source.name,
        "source_sha256": source_sha256,
        "executable_sha256": _file_sha256(output),
        "host_language": "Swift_6",
        "shader_language": "Metal_Shading_Language_runtime_compiled",
        "compiler_version": compiler_version,
        "selected_flags": flags,
        "warnings_as_errors": True,
    }


class MetalAsconAEAD128Host:
    """Persistent JSON-lines client for the Swift/Metal implementation."""

    def __init__(self, executable: Path):
        self.process = subprocess.Popen(
            [str(executable.resolve())],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.deadline_monotonic: float | None = None
        self.total_gpu_seconds = 0.0
        ready = self._read()
        metal = ready.get("metal", {})
        if (
            ready.get("op") != "ready"
            or ready.get("version") != NATIVE_VERSION
            or not str(metal.get("device", "")).startswith("Apple")
            or int(metal.get("filter_execution_width", 0)) <= 0
            or int(metal.get("filter_max_threads_per_group", 0)) < 256
            or metal.get("shader_runtime_compiled") is not True
            or metal.get("sp800_232_little_endian_semantics") is not True
        ):
            self.close(force=True)
            raise RuntimeError("Ascon-AEAD128 Metal host identity gate failed")
        self.identity = ready

    def set_wall_deadline(self, seconds_from_now: float) -> None:
        if seconds_from_now <= 0:
            raise ValueError("Metal wall deadline must be positive")
        self.deadline_monotonic = time.monotonic() + seconds_from_now

    def _read(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        if self.deadline_monotonic is not None:
            remaining = self.deadline_monotonic - time.monotonic()
            if remaining <= 0:
                self.close(force=True)
                raise TimeoutError("A255 Metal qualification wall cap expired")
            readable, _, _ = select.select([self.process.stdout], [], [], remaining)
            if not readable:
                self.close(force=True)
                raise TimeoutError("A255 Metal qualification exceeded its 110 s wall cap")
        line = self.process.stdout.readline()
        if not line:
            assert self.process.stderr is not None
            diagnostics = self.process.stderr.read().strip()
            raise RuntimeError(
                "Ascon-AEAD128 Metal host closed unexpectedly: " + diagnostics
            )
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("Ascon-AEAD128 Metal host returned a non-object")
        if "gpu_seconds" in value:
            gpu_seconds = float(value["gpu_seconds"])
            if gpu_seconds < 0:
                raise RuntimeError("Ascon-AEAD128 Metal host returned negative GPU time")
            self.total_gpu_seconds += gpu_seconds
        return value

    def _request(self, value: dict[str, Any]) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError("Ascon-AEAD128 Metal host is not running")
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        )
        self.process.stdin.flush()
        return self._read()

    def configure(
        self,
        *,
        message: bytes,
        associated_data: bytes,
        nonce: bytes,
        target: bytes,
        control: bytes,
        key_words_1_to_3: Sequence[int],
    ) -> None:
        if len(message) > MAX_MESSAGE_BYTES:
            raise ValueError("A255 message exceeds native qualification capacity")
        if len(associated_data) > MAX_ASSOCIATED_DATA_BYTES:
            raise ValueError("A255 associated data exceeds native qualification capacity")
        if len(nonce) != 16:
            raise ValueError("A255 nonce must contain 16 bytes")
        if len(target) != len(message) + 16 or len(control) != len(target):
            raise ValueError("A255 target/control must contain full ciphertext and tag")
        response = self._request(
            {
                "op": "configure",
                "message_words": _bytes_to_words(message, 8),
                "associated_data_words": _bytes_to_words(associated_data, 8),
                "target_words": _bytes_to_words(target, OUTPUT_WORDS),
                "control_words": _bytes_to_words(control, OUTPUT_WORDS),
                "nonce_words": _bytes_to_words(nonce, 4),
                "key_words_1_to_3": [int(value) for value in key_words_1_to_3],
                "message_length": len(message),
                "associated_data_length": len(associated_data),
            }
        )
        if (
            response.get("op") != "configured"
            or response.get("message_length") != len(message)
            or response.get("associated_data_length") != len(associated_data)
            or response.get("output_length") != len(target)
            or response.get("complete_ciphertext_and_tag_comparison") is not True
        ):
            raise RuntimeError("Ascon-AEAD128 Metal configuration gate failed")

    def encryptions(self, first: int, count: int, output_length: int) -> list[bytes]:
        response = self._request(
            {"op": "encryptions", "first": first, "count": count}
        )
        words = response.get("words", [])
        if (
            response.get("op") != "encryptions"
            or response.get("first") != first
            or response.get("count") != count
            or response.get("output_length") != output_length
            or not isinstance(words, list)
            or len(words) != count * OUTPUT_WORDS
        ):
            raise RuntimeError("Ascon-AEAD128 Metal encryptions response gate failed")
        return [
            _words_to_bytes(
                [int(value) for value in words[index * OUTPUT_WORDS : (index + 1) * OUTPUT_WORDS]],
                output_length,
            )
            for index in range(count)
        ]

    def filter(self, first: int, count: int) -> dict[str, Any]:
        response = self._request(
            {
                "op": "filter",
                "first": first,
                "count": count,
                "capacity": RESULT_CAPACITY,
            }
        )
        if (
            response.get("op") != "filter"
            or response.get("first") != first
            or response.get("count") != count
            or not isinstance(response.get("factual"), list)
            or not isinstance(response.get("control"), list)
            or float(response.get("gpu_seconds", -1.0)) < 0
        ):
            raise RuntimeError("Ascon-AEAD128 Metal filter response gate failed")
        return response

    def close(self, *, force: bool = False) -> None:
        if self.process.poll() is not None:
            return
        if not force:
            try:
                response = self._request({"op": "quit"})
                if response.get("op") != "quit":
                    force = True
            except (RuntimeError, TimeoutError):
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
            assert self.process.stderr is not None
            raise RuntimeError(
                "Ascon-AEAD128 Metal host exit failed: "
                + self.process.stderr.read().strip()
            )


def _one_bit_control(target: bytes) -> bytes:
    if not target:
        raise ValueError("control target cannot be empty")
    control = bytearray(target)
    control[-1] ^= 0x01
    return bytes(control)


def _official_kat_gate(host: MetalAsconAEAD128Host) -> dict[str, Any]:
    scalar_rows = verify_official_kats()
    orientation = verify_orientation_sentinel()
    if (
        len(scalar_rows) != len(OFFICIAL_KATS)
        or not all(row["pass"] is True for row in scalar_rows)
        or orientation["pass"] is not True
        or orientation["official_kat_count"] != ORIENTATION_SENTINEL_COUNT
    ):
        raise RuntimeError("Ascon-AEAD128 scalar official KAT gate failed")
    metal_rows: list[dict[str, Any]] = []
    for vector in OFFICIAL_KATS:
        key_words = _bytes_to_words(vector.key, 4)
        target = vector.combined_ciphertext_tag
        host.configure(
            message=vector.plaintext,
            associated_data=vector.associated_data,
            nonce=vector.nonce,
            target=target,
            control=_one_bit_control(target),
            key_words_1_to_3=key_words[1:],
        )
        observed = host.encryptions(key_words[0], 1, len(target))[0]
        filtered = host.filter(key_words[0], 1)
        if (
            observed != target
            or filtered["factual"] != [key_words[0]]
            or filtered["control"] != []
        ):
            raise RuntimeError(
                f"Ascon-AEAD128 official KAT {vector.count} Metal gate failed"
            )
        metal_rows.append(
            {
                "count": vector.count,
                "message_bytes": len(vector.plaintext),
                "associated_data_bytes": len(vector.associated_data),
                "ciphertext_and_tag_bytes_checked": len(target),
                "combined_sha256": _sha256(observed),
                "exact_cpu_metal_identity": True,
                "one_bit_control_rejected": True,
            }
        )
    return {
        "standard": "NIST_SP_800-232_Ascon-AEAD128",
        "sp800_232_url": SP800_232_URL,
        "sp800_232_pdf_sha256": SP800_232_PDF_SHA256,
        "official_kat_url": OFFICIAL_KAT_URL,
        "official_kat_repository_commit": OFFICIAL_KAT_COMMIT,
        "official_kat_file_sha256": OFFICIAL_KAT_FILE_SHA256,
        "scalar_vectors": scalar_rows,
        "metal_vectors": metal_rows,
        "nonpalindromic_orientation_sentinel": orientation,
        "legacy_endian_semantics_used": False,
        "all_official_kat_gates_passed": True,
    }


def _cross_implementation_gate(host: MetalAsconAEAD128Host) -> dict[str, Any]:
    first = 0x1234FE80
    count = 256
    target_offset = 0x91
    upper = (0x89ABCDEF, 0x10213243, 0x54657687)
    expected = [_scalar_output(first + index, upper) for index in range(count)]
    target = expected[target_offset]
    host.configure(
        message=QUALIFICATION_MESSAGE,
        associated_data=QUALIFICATION_ASSOCIATED_DATA,
        nonce=QUALIFICATION_NONCE,
        target=target,
        control=_one_bit_control(target),
        key_words_1_to_3=upper,
    )
    observed = host.encryptions(first, count, len(target))
    filtered = host.filter(first, count)
    if (
        observed != expected
        or filtered["factual"] != [first + target_offset]
        or filtered["control"] != []
    ):
        raise RuntimeError("Ascon-AEAD128 CPU/Metal cross-implementation gate failed")
    raw = b"".join(observed)
    return {
        "first_candidate": first,
        "candidate_count": count,
        "target_candidate": first + target_offset,
        "message_bytes": len(QUALIFICATION_MESSAGE),
        "associated_data_bytes": len(QUALIFICATION_ASSOCIATED_DATA),
        "ciphertext_and_tag_bits_per_candidate": len(target) * 8,
        "complete_output_bits_checked": len(raw) * 8,
        "outputs_sha256": _sha256(raw),
        "exact_cpu_metal_identity": True,
        "exact_factual_and_control_filter_identity": True,
    }


def _mapping_gate(host: MetalAsconAEAD128Host) -> dict[str, Any]:
    cases = (
        (0x00000000, 0x00000000, 2, 1, "low32_zero_boundary"),
        (0x00000000, 0x0000FFFE, 4, 2, "low16_carry_boundary"),
        (0x00000000, 0x7FFFFFFE, 4, 2, "low32_sign_boundary"),
        (0x00000000, 0xFFFFFFFC, 4, 3, "low32_terminal_boundary"),
        (0x00000001, 0x00000000, 2, 0, "outer_bit_zero_to_one_boundary"),
        (0x80000000, 0x00000000, 2, 1, "outer_word_high_bit_boundary"),
        (0xFFFFFFFF, 0xFFFFFFFE, 2, 0, "full_low64_terminal_boundary"),
    )
    fixed_tail = (0x31415926, 0x53589793)
    rows: list[dict[str, Any]] = []
    for outer_word, first, count, target_offset, label in cases:
        upper = (outer_word, *fixed_tail)
        expected = [_scalar_output(first + index, upper) for index in range(count)]
        target = expected[target_offset]
        host.configure(
            message=QUALIFICATION_MESSAGE,
            associated_data=QUALIFICATION_ASSOCIATED_DATA,
            nonce=QUALIFICATION_NONCE,
            target=target,
            control=_one_bit_control(target),
            key_words_1_to_3=upper,
        )
        observed = host.encryptions(first, count, len(target))
        filtered = host.filter(first, count)
        expected_candidate = first + target_offset
        if (
            observed != expected
            or filtered["factual"] != [expected_candidate]
            or filtered["control"] != []
        ):
            raise RuntimeError(f"Ascon-AEAD128 mapping gate failed at {label}")
        rows.append(
            {
                "label": label,
                "outer_key_word1": outer_word,
                "first_low32_candidate": first,
                "candidate_count": count,
                "target_low32_candidate": expected_candidate,
                "target_combined_low64_assignment": (outer_word << 32)
                | expected_candidate,
                "outputs_sha256": _sha256(b"".join(observed)),
                "exact_cpu_metal_filter_identity": True,
            }
        )
    return {
        "candidate_encoding": (
            "assignment=(outer_key_word1_low_bits<<32)|candidate_key_word0; "
            "all key words and candidate bytes are little-endian"
        ),
        "rows": rows,
        "uint32_boundaries_checked": [
            "0x00000000",
            "0x00010000",
            "0x80000000",
            "0xffffffff",
        ],
        "outer_word_boundaries_checked": [
            "0x00000000",
            "0x00000001",
            "0x80000000",
            "0xffffffff",
        ],
        "complete_ciphertext_and_tag_checked": True,
        "exact_boundary_identity": True,
    }


def _validate_benchmark_budget(candidate_count: int, repeats: int) -> int:
    if candidate_count < 1 or candidate_count > MAX_BENCHMARK_CANDIDATES:
        raise ValueError(
            f"benchmark candidate count must be in 1...{MAX_BENCHMARK_CANDIDATES}"
        )
    if repeats < 1 or repeats > MAX_BENCHMARK_REPEATS:
        raise ValueError(f"benchmark repeats must be in 1...{MAX_BENCHMARK_REPEATS}")
    total = BENCHMARK_WARMUP_CANDIDATES + candidate_count * repeats
    hard_candidate_cap = (
        BENCHMARK_WARMUP_CANDIDATES
        + MAX_BENCHMARK_CANDIDATES * MAX_BENCHMARK_REPEATS
    )
    if total > hard_candidate_cap:
        raise ValueError("benchmark request exceeds the immutable A255 work cap")
    return total


def _recommended_stream_count(minimum_throughput: float) -> int:
    target = max(1, math.floor(minimum_throughput * STREAM_TARGET_SECONDS))
    power_of_two = 1 << math.floor(math.log2(target))
    return min(max(power_of_two, MIN_STREAM_CANDIDATES), MAX_STREAM_CANDIDATES)


def _benchmark(
    host: MetalAsconAEAD128Host,
    *,
    candidate_count: int,
    repeats: int,
) -> dict[str, Any]:
    total_candidate_cap = _validate_benchmark_budget(candidate_count, repeats)
    upper = (0x6EED1234, 0xC001D00D, 0x0BADF00D)
    target_candidate = candidate_count // 2
    target = _scalar_output(target_candidate, upper)
    host.configure(
        message=QUALIFICATION_MESSAGE,
        associated_data=QUALIFICATION_ASSOCIATED_DATA,
        nonce=QUALIFICATION_NONCE,
        target=target,
        control=_one_bit_control(target),
        key_words_1_to_3=upper,
    )
    warmup_count = min(candidate_count, BENCHMARK_WARMUP_CANDIDATES)
    warmup = host.filter(0, warmup_count)
    samples: list[dict[str, Any]] = []
    for _ in range(repeats):
        wall_start = time.perf_counter()
        response = host.filter(0, candidate_count)
        wall_seconds = time.perf_counter() - wall_start
        gpu_seconds = float(response["gpu_seconds"])
        if gpu_seconds <= 0 or wall_seconds <= 0:
            raise RuntimeError("Ascon-AEAD128 benchmark returned zero elapsed time")
        if response["factual"] != [target_candidate] or response["control"] != []:
            raise RuntimeError("Ascon-AEAD128 timed filter correctness gate failed")
        samples.append(
            {
                "candidate_count": candidate_count,
                "gpu_seconds": gpu_seconds,
                "end_to_end_wall_seconds": wall_seconds,
                "gpu_candidates_per_second": candidate_count / gpu_seconds,
                "end_to_end_candidates_per_second": candidate_count / wall_seconds,
                "factual_matches": response["factual"],
                "control_matches": response["control"],
            }
        )
    throughputs = [row["end_to_end_candidates_per_second"] for row in samples]
    gpu_throughputs = [row["gpu_candidates_per_second"] for row in samples]
    minimum = min(throughputs)
    median = statistics.median(throughputs)
    stream_count = _recommended_stream_count(minimum)
    return {
        "candidate_count_per_repeat": candidate_count,
        "repeats": repeats,
        "warmup_candidate_count": warmup_count,
        "maximum_candidate_invocations_permitted": total_candidate_cap,
        "warmup_factual_matches": warmup["factual"],
        "samples": samples,
        "median_candidates_per_second": median,
        "minimum_candidates_per_second": minimum,
        "maximum_candidates_per_second": max(throughputs),
        "median_gpu_candidates_per_second": statistics.median(gpu_throughputs),
        "minimum_gpu_candidates_per_second": min(gpu_throughputs),
        "maximum_gpu_candidates_per_second": max(gpu_throughputs),
        "recommended_stream_candidate_count": stream_count,
        "recommended_stream_target_seconds_at_minimum": stream_count / minimum,
        "projected_complete_domain_seconds": {
            str(width): (2**width) / median for width in range(32, 65)
        },
        "projected_complete_domain_seconds_at_minimum": {
            str(width): (2**width) / minimum for width in range(32, 65)
        },
        "launch_gate_uses_end_to_end_wall_throughput": True,
        "timed_relation_compares_full_32_byte_ciphertext_and_16_byte_tag": True,
        "volatile_performance_only_not_a_recovery_success_rule": True,
    }


def _launch_gate(benchmark: dict[str, Any]) -> dict[str, Any]:
    minimum = float(benchmark["minimum_candidates_per_second"])
    highest_safe_width = math.floor(
        math.log2(minimum * MAX_COMPLETE_DOMAIN_SECONDS)
    )
    selected_width = min(max(highest_safe_width, 0), MAX_SUPPORTED_RESIDUAL_WIDTH)
    projected_seconds = (2**selected_width) / minimum
    gate = {
        "selection_rule": (
            "maximum_supported_integer_width_whose_complete_domain_fits_7200_seconds_"
            "at_minimum_end_to_end_wall_throughput"
        ),
        "maximum_supported_residual_width": MAX_SUPPORTED_RESIDUAL_WIDTH,
        "maximum_complete_domain_seconds": MAX_COMPLETE_DOMAIN_SECONDS,
        "throughput_statistic": "minimum_end_to_end_wall_throughput_of_all_timed_repeats",
        "observed_minimum_candidates_per_second": minimum,
        "highest_safe_integer_width_at_observed_minimum": highest_safe_width,
        "selected_width": selected_width,
        "projected_selected_width_seconds_at_observed_minimum": projected_seconds,
        "selected_width_under_two_hours": projected_seconds
        <= MAX_COMPLETE_DOMAIN_SECONDS,
        "selected_stream_candidate_count": benchmark[
            "recommended_stream_candidate_count"
        ],
        "selected_stream_projected_seconds_at_observed_minimum": benchmark[
            "recommended_stream_target_seconds_at_minimum"
        ],
        "full_domain_launch_authorized": False,
        "authorization_reason": (
            "A255 selects parameters only; A256 remains blocked pending root review, "
            "fresh challenge freeze, content-hash anchoring, and explicit launch acknowledgement"
        ),
    }
    gate["parameters_safe_for_post_review_freeze"] = bool(
        selected_width >= 32 and gate["selected_width_under_two_hours"]
    )
    return gate


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
    qualification_wall_start = time.monotonic()
    host = MetalAsconAEAD128Host(executable)
    host.set_wall_deadline(QUALIFICATION_GPU_WALL_CAP_SECONDS)
    try:
        kat = _official_kat_gate(host)
        cross = _cross_implementation_gate(host)
        mapping = _mapping_gate(host)
        benchmark = _benchmark(
            host, candidate_count=benchmark_candidates, repeats=repeats
        )
        identity = host.identity
        gpu_seconds = host.total_gpu_seconds
    finally:
        host.close()
    wall_seconds = time.monotonic() - qualification_wall_start
    if wall_seconds > QUALIFICATION_GPU_WALL_CAP_SECONDS + 2.0:
        raise RuntimeError("A255 qualification exceeded its enforced Metal wall cap")
    launch = _launch_gate(benchmark)
    reference_source = (
        Path(__file__).parents[2]
        / "src"
        / "arx_carry_leak"
        / REFERENCE_SOURCE_FILENAME
    )
    content_anchors = {
        "qualification_source": {
            "filename": Path(__file__).name,
            "sha256": _file_sha256(Path(__file__)),
        },
        "native_source": {
            "filename": NATIVE_SOURCE_FILENAME,
            "sha256": native_build["source_sha256"],
        },
        "cpu_reference": {
            "filename": REFERENCE_SOURCE_FILENAME,
            "sha256": _file_sha256(reference_source),
        },
        "official_kat": {
            "url": OFFICIAL_KAT_URL,
            "commit": OFFICIAL_KAT_COMMIT,
            "sha256": OFFICIAL_KAT_FILE_SHA256,
        },
        "nist_standard": {
            "url": SP800_232_URL,
            "pdf_sha256": SP800_232_PDF_SHA256,
        },
    }
    payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "ASCON_AEAD128_SP800_232_METAL_PRE_TARGET_QUALIFICATION",
        "scope": (
            "Standardized NIST SP 800-232 Ascon-AEAD128 full encryption and 128-bit "
            "tag implementation qualification plus volatile throughput measurement; "
            "no A256 production challenge was generated, frozen, or searched."
        ),
        "algorithm": {
            "name": "Ascon-AEAD128",
            "standard": "NIST_SP_800-232_August_2025",
            "key_bits": 128,
            "nonce_bits": 128,
            "rate_bits": 128,
            "tag_bits": 128,
            "permutation_rounds_initial_final": 12,
            "permutation_rounds_intermediate": 8,
            "iv_hex_as_uint64": "00001000808c0001",
            "byte_semantics": "SP800-232_little_endian",
            "legacy_submission_endian_semantics": False,
            "candidate_encoding": (
                "candidate=key_uint32_word0_bytes_0_to_3_little_endian; "
                "outer_bits=low_bits_of_key_uint32_word1"
            ),
            "qualification_message_bytes": len(QUALIFICATION_MESSAGE),
            "qualification_associated_data_bytes": len(
                QUALIFICATION_ASSOCIATED_DATA
            ),
            "filter_bits": (len(QUALIFICATION_MESSAGE) + 16) * 8,
        },
        "content_anchors": content_anchors,
        "content_anchors_sha256": _canonical_sha256(content_anchors),
        "native_build": native_build,
        "host_identity": identity,
        "official_kat_gate": kat,
        "cross_implementation_gate": cross,
        "boundary_mapping_gate": mapping,
        "benchmark": benchmark,
        "launch_gate": launch,
        "qualification_resource_cap": {
            "wall_deadline_seconds": QUALIFICATION_GPU_WALL_CAP_SECONDS,
            "actual_wall_seconds_host_lifetime": wall_seconds,
            "reported_total_gpu_seconds": gpu_seconds,
            "maximum_benchmark_candidates_per_repeat": MAX_BENCHMARK_CANDIDATES,
            "maximum_benchmark_repeats": MAX_BENCHMARK_REPEATS,
            "subprocess_killed_on_deadline": True,
            "cannot_occupy_gpu_for_two_minutes": True,
        },
        "information_boundary": {
            "production_target_selected": False,
            "production_unknown_assignment_generated": False,
            "production_protocol_frozen": False,
            "complete_residual_key_domain_executed": False,
            "benchmark_outcome_used_only_to_select_prospective_width_and_batch_size": True,
            "A256_requires_separate_post_review_process": True,
        },
    }
    _atomic_json(output, payload)
    reopened = json.loads(output.read_text())
    if reopened != payload:
        raise RuntimeError("A255 qualification artifact reopen gate failed")
    return {
        "output": str(output),
        "sha256": _file_sha256(output),
        "device": identity["metal"]["device"],
        "median_candidates_per_second": benchmark["median_candidates_per_second"],
        "minimum_candidates_per_second": benchmark["minimum_candidates_per_second"],
        "selected_width": launch["selected_width"],
        "projected_selected_width_seconds_at_minimum": launch[
            "projected_selected_width_seconds_at_observed_minimum"
        ],
        "selected_stream_candidate_count": launch[
            "selected_stream_candidate_count"
        ],
        "qualification_gpu_wall_cap_seconds": QUALIFICATION_GPU_WALL_CAP_SECONDS,
        "production_challenge_frozen": False,
        "full_domain_launched": False,
        "all_qualification_gates_passed": True,
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument(
        "--output",
        type=Path,
        default=research_root
        / "results"
        / "v1"
        / "ascon_aead128_metal_a255_qualification_v1.json",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=research_root / "build" / "ascon_aead128_metal_a255",
    )
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument(
        "--benchmark-candidates",
        type=int,
        default=DEFAULT_BENCHMARK_CANDIDATES,
    )
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    args = parser.parse_args(argv)
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
