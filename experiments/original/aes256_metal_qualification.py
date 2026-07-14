#!/usr/bin/env python3
"""Pre-target qualification for the prospective FIPS-197 AES-256 factory.

The default CLI performs CPU-only KAT, independent-implementation, and endian
mapping checks and writes nothing unless ``--output`` is supplied.  Metal work
requires the explicit ``--metal`` switch and is bounded by immutable candidate,
repeat, and host-lifetime caps.  This module never creates a production target.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import math
import select
import shutil
import statistics
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from arx_carry_leak.aes256_independent import encrypt_blocks_independent
from arx_carry_leak.aes256_reference import (
    FIPS197_KATS,
    FIPS197_URL,
    LOCAL_C_REFERENCE,
    LOCAL_INDEPENDENT_REFERENCE,
    LOCAL_ORIENTATION_KAT,
    NIST_AES_EXAMPLE_VALUES_URL,
    ROUNDS,
    apply_low_residual_bits,
    encrypt_blocks,
    key_words_big_endian,
    verify_fips197_kats,
    verify_orientation_and_schedule_sentinels,
    zero_low_residual_bits,
)

SCHEMA = "aes256-fips197-metal-qualification-v1"
STAGE = "AES256_FIPS197_METAL_PRE_TARGET_QUALIFICATION"
ATTEMPT_ID = "AES256Q1"
NATIVE_SOURCE_FILENAME = "aes256_metal_native.swift"
REFERENCE_SOURCE_FILENAME = "aes256_reference.py"
NATIVE_VERSION = "aes256-fips197-metal-native-v1"
PLAINTEXT_BLOCKS = 2
FILTER_BYTES = PLAINTEXT_BLOCKS * 16
FILTER_BITS = FILTER_BYTES * 8
RESULT_CAPACITY = 64
MIN_RESIDUAL_WIDTH = 32
MAX_RESIDUAL_WIDTH = 64
DEFAULT_BENCHMARK_CANDIDATES = 1 << 22
DEFAULT_REPEATS = 2
MAX_BENCHMARK_CANDIDATES = 1 << 24
MAX_BENCHMARK_REPEATS = 3
BENCHMARK_WARMUP_CANDIDATES = 1 << 18
QUALIFICATION_METAL_WALL_CAP_SECONDS = 90.0
MAX_COMPLETE_DOMAIN_SECONDS = 2 * 60 * 60
STREAM_TARGET_SECONDS = 10.0
MIN_STREAM_CANDIDATES = 1 << 16
MAX_STREAM_CANDIDATES = 1 << 30
QUALIFICATION_PLAINTEXT = bytes(range(32))
QUALIFICATION_KNOWN_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
    "102132435465768798a9bacb00000000"
)
METAL_EVIDENCE_LEDGER_SCHEMA = "aes256-fips197-metal-evidence-ledger-v1"
METAL_EVIDENCE_PRODUCER = (
    "aes256_metal_qualification.run_metal_qualification"
)
METAL_CROSS_FIRST = 0x1234FE80
METAL_CROSS_COUNT = 256
METAL_CROSS_OFFSET = 0x91
METAL_MAPPING_CASES = (
    (0x00000000, 0x00000000, 2, 1, "low32_zero_boundary"),
    (0x00000000, 0x0000FFFE, 4, 2, "low16_carry_boundary"),
    (0x00000000, 0x7FFFFFFE, 4, 2, "low32_sign_boundary"),
    (0x00000000, 0xFFFFFFFC, 4, 3, "low32_terminal_boundary"),
    (0x00000001, 0x00000000, 2, 0, "outer_bit_boundary"),
    (0x80000000, 0x00000000, 2, 1, "outer_high_bit_boundary"),
    (0xFFFFFFFF, 0xFFFFFFFE, 2, 0, "low64_terminal_boundary"),
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


def _is_sha256_hex(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def independent_numpy_source_path() -> Path:
    """Return the exact source file backing the imported NumPy AES oracle."""

    expected = (Path(__file__).parents[2] / LOCAL_INDEPENDENT_REFERENCE).resolve()
    observed = Path(inspect.getsourcefile(encrypt_blocks_independent) or "").resolve()
    if observed != expected or not observed.is_file():
        raise RuntimeError("AES-256 independent NumPy implementation path differs")
    return observed


def independent_numpy_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt whole blocks through the pre-existing independent NumPy AES."""

    raw = bytes(plaintext)
    if not raw or len(raw) % 16:
        raise ValueError("independent AES plaintext must contain whole blocks")
    return encrypt_blocks_independent(key, raw)


def _one_bit_control(target: bytes) -> bytes:
    if len(target) != FILTER_BYTES:
        raise ValueError("AES target must contain exactly two ciphertext blocks")
    control = bytearray(target)
    control[-1] ^= 0x01
    return bytes(control)


def _cpu_kat_gate() -> dict[str, Any]:
    scalar_rows = verify_fips197_kats()
    scalar_sentinels = verify_orientation_and_schedule_sentinels()
    independent_rows: list[dict[str, Any]] = []
    for vector in FIPS197_KATS:
        observed = independent_numpy_encrypt(vector.key, vector.plaintext)
        independent_rows.append(
            {
                "name": vector.name,
                "observed_ciphertext_hex": observed.hex(),
                "expected_ciphertext_hex": vector.ciphertext.hex(),
                "pass": observed == vector.ciphertext,
            }
        )
    local_independent = independent_numpy_encrypt(
        LOCAL_ORIENTATION_KAT.key, LOCAL_ORIENTATION_KAT.plaintext
    )
    if (
        not scalar_rows
        or not all(row["pass"] is True for row in scalar_rows)
        or not all(row["pass"] is True for row in independent_rows)
        or not all(
            row["pass"] is True
            for row in scalar_sentinels["round_key_word_sentinels"].values()
        )
        or scalar_sentinels["orientation_pass"] is not True
        or scalar_sentinels["decrypt_roundtrip_pass"] is not True
        or local_independent != LOCAL_ORIENTATION_KAT.ciphertext
    ):
        raise RuntimeError("AES-256 FIPS-197 CPU KAT gate failed")
    return {
        "standard": "FIPS_197_updated_2023_no_algorithm_change",
        "standard_url": FIPS197_URL,
        "nist_example_values_url": NIST_AES_EXAMPLE_VALUES_URL,
        "scalar_reference_vectors": scalar_rows,
        "independent_numpy_vectors": independent_rows,
        "nonpalindromic_orientation_and_round_key_sentinels": scalar_sentinels,
        "independent_orientation_ciphertext_hex": local_independent.hex(),
        "all_cpu_kats_passed": True,
    }


def _cpu_mapping_gate() -> dict[str, Any]:
    seed_key = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
        "102132435465768798a9bacbdcedfe0f"
    )
    cases = (
        (32, 0x00000000),
        (32, 0x0000FFFF),
        (32, 0x80000000),
        (32, 0xFFFFFFFF),
        (33, (1 << 32) | 0x01234567),
        (40, (0xA5 << 32) | 0x89ABCDEF),
        (64, 0xFEDCBA9876543210),
    )
    rows: list[dict[str, Any]] = []
    for width, assignment in cases:
        known = zero_low_residual_bits(seed_key, width)
        key = apply_low_residual_bits(known, assignment, width)
        words = key_words_big_endian(key)
        scalar = encrypt_blocks(key, QUALIFICATION_PLAINTEXT)
        independent = independent_numpy_encrypt(key, QUALIFICATION_PLAINTEXT)
        if (
            scalar != independent
            or words[7] != (assignment & 0xFFFFFFFF)
            or words[6] & ((1 << (width - 32)) - 1) != assignment >> 32
        ):
            raise RuntimeError(f"AES-256 residual mapping gate failed for width {width}")
        rows.append(
            {
                "width": width,
                "assignment": assignment,
                "key_hex": key.hex(),
                "key_words_big_endian": list(words),
                "inner_candidate_word7": words[7],
                "outer_assignment": assignment >> 32,
                "ciphertext_sha256": _sha256(scalar),
                "exact_scalar_independent_identity": True,
            }
        )
    return {
        "candidate_encoding": (
            "assignment is the contiguous low bits of int.from_bytes(key,'big'); "
            "inner uint32 is FIPS key word7 (bytes 28..31, big-endian); outer bits "
            "are the low bits of FIPS key word6"
        ),
        "assignment_bit0": "key_byte_31_bit_0",
        "inner_candidate_byte_mapping": {
            "key_byte_28": "candidate_bits_31_to_24",
            "key_byte_29": "candidate_bits_23_to_16",
            "key_byte_30": "candidate_bits_15_to_8",
            "key_byte_31": "candidate_bits_7_to_0",
        },
        "rows": rows,
        "exact_boundary_identity": True,
    }


def run_cpu_qualification() -> dict[str, Any]:
    """Run deterministic, non-Metal preparation gates without writing artifacts."""

    root = Path(__file__).parents[2]
    reference = root / "src" / "arx_carry_leak" / REFERENCE_SOURCE_FILENAME
    independent_reference = independent_numpy_source_path()
    native = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    anchors = {
        "qualification_source": {
            "path": str(Path(__file__).relative_to(root)),
            "sha256": _file_sha256(Path(__file__)),
        },
        "native_source": {
            "path": str(native.relative_to(root)),
            "sha256": _file_sha256(native),
        },
        "cpu_reference": {
            "path": str(reference.relative_to(root)),
            "sha256": _file_sha256(reference),
        },
        "local_independent_numpy_reference": {
            "path": LOCAL_INDEPENDENT_REFERENCE,
            "sha256": _file_sha256(independent_reference),
        },
        "local_c_reference_anchor": LOCAL_C_REFERENCE,
        "standard_url": FIPS197_URL,
        "nist_example_values_url": NIST_AES_EXAMPLE_VALUES_URL,
    }
    payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "AES256_FIPS197_CPU_ONLY_FACTORY_PREPARATION",
        "algorithm": {
            "name": "AES-256",
            "standard": "FIPS_197",
            "rounds": ROUNDS,
            "block_bits": 128,
            "key_bits": 256,
            "state_byte_order": "FIPS197_external_column_major",
        },
        "content_anchors": anchors,
        "content_anchors_sha256": _canonical_sha256(anchors),
        "cpu_kat_gate": _cpu_kat_gate(),
        "cpu_boundary_mapping_gate": _cpu_mapping_gate(),
        "metal_executed": False,
        "production_challenge_frozen": False,
        "full_domain_launched": False,
    }
    return payload


def _compile_native(build_dir: Path, swiftc: str) -> tuple[Path, dict[str, Any]]:
    source = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    source_sha256 = _file_sha256(source)
    compiler = shutil.which(swiftc)
    if compiler is None:
        raise FileNotFoundError(f"Swift compiler not found: {swiftc}")
    build_dir.mkdir(parents=True, exist_ok=True)
    output = build_dir / f"aes256_metal_{source_sha256[:16]}"
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.unlink(missing_ok=True)
    flags = ["-O", "-whole-module-optimization", "-warnings-as-errors"]
    result = subprocess.run(
        [compiler, *flags, str(source), "-o", str(temporary)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("AES-256 Swift/Metal host compilation failed: " + result.stderr.strip())
    temporary.replace(output)
    compiler_version = subprocess.run(
        [compiler, "--version"], check=True, capture_output=True, text=True
    ).stdout.splitlines()[0]
    return output, {
        "source_filename": source.name,
        "source_sha256": source_sha256,
        "executable_sha256": _file_sha256(output),
        "compiler_version": compiler_version,
        "selected_flags": flags,
        "warnings_as_errors": True,
    }


class MetalAES256Host:
    """Persistent JSON-lines client for the prospective Swift/Metal host."""

    def __init__(
        self, executable: Path, *, deadline_monotonic: float | None = None
    ):
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
        try:
            ready = self._read()
            metal = ready.get("metal", {})
            if (
                ready.get("op") != "ready"
                or ready.get("version") != NATIVE_VERSION
                or not str(metal.get("device", "")).startswith("Apple")
                or int(metal.get("filter_execution_width", 0)) <= 0
                or metal.get("shader_runtime_compiled") is not True
                or metal.get("fips197_external_byte_order") is not True
                or metal.get("candidate_maps_to_key_bytes_28_through_31_big_endian")
                is not True
                or metal.get("aes256_nk8_subword_i_mod_8_eq_4") is not True
            ):
                raise RuntimeError("AES-256 Metal host identity gate failed")
        except BaseException:
            self.close(force=True)
            raise
        self.identity = ready

    def set_wall_deadline(self, seconds_from_now: float) -> None:
        if seconds_from_now <= 0:
            raise ValueError("Metal wall deadline must be positive")
        proposed = time.monotonic() + seconds_from_now
        if self.deadline_monotonic is None:
            self.deadline_monotonic = proposed
        else:
            self.deadline_monotonic = min(self.deadline_monotonic, proposed)

    def _read(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        if self.deadline_monotonic is not None:
            remaining = self.deadline_monotonic - time.monotonic()
            if remaining <= 0:
                self.close(force=True)
                raise TimeoutError("AES-256 Metal qualification wall cap expired")
            readable, _, _ = select.select([self.process.stdout], [], [], remaining)
            if not readable:
                self.close(force=True)
                raise TimeoutError("AES-256 Metal qualification exceeded its wall cap")
        line = self.process.stdout.readline()
        if not line:
            assert self.process.stderr is not None
            raise RuntimeError(
                "AES-256 Metal host closed unexpectedly: "
                + self.process.stderr.read().strip()
            )
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("AES-256 Metal host returned a non-object")
        if "gpu_seconds" in value:
            elapsed = float(value["gpu_seconds"])
            if elapsed < 0:
                raise RuntimeError("AES-256 Metal host returned negative GPU time")
            self.total_gpu_seconds += elapsed
        return value

    def _request(self, value: dict[str, Any]) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError("AES-256 Metal host is not running")
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        )
        self.process.stdin.flush()
        return self._read()

    def configure(
        self,
        *,
        plaintext: bytes,
        target: bytes,
        control: bytes,
        key_words_0_to_6: Sequence[int],
    ) -> None:
        if len(plaintext) != FILTER_BYTES or len(target) != FILTER_BYTES:
            raise ValueError("AES-256 native relation requires exactly two blocks")
        if len(control) != FILTER_BYTES:
            raise ValueError("AES-256 control must contain exactly two blocks")
        words = [int(value) for value in key_words_0_to_6]
        if len(words) != 7 or any(value < 0 or value > 0xFFFFFFFF for value in words):
            raise ValueError("AES-256 key_words_0_to_6 must be seven uint32 values")
        response = self._request(
            {
                "op": "configure",
                "plaintext": list(plaintext),
                "target": list(target),
                "control": list(control),
                "key_words_0_to_6": words,
            }
        )
        if (
            response.get("op") != "configured"
            or response.get("plaintext_blocks") != PLAINTEXT_BLOCKS
            or response.get("filter_bits") != FILTER_BITS
            or response.get("candidate_key_word") != 7
        ):
            raise RuntimeError("AES-256 Metal configuration gate failed")

    def blocks(self, first: int, count: int) -> list[bytes]:
        response = self._request({"op": "blocks", "first": first, "count": count})
        values = response.get("bytes")
        if (
            response.get("op") != "blocks"
            or response.get("first") != first
            or response.get("count") != count
            or not isinstance(values, list)
            or len(values) != count * FILTER_BYTES
            or any(not isinstance(value, int) or value < 0 or value > 255 for value in values)
        ):
            raise RuntimeError("AES-256 Metal blocks response gate failed")
        return [
            bytes(values[index * FILTER_BYTES : (index + 1) * FILTER_BYTES])
            for index in range(count)
        ]

    def filter(self, first: int, count: int) -> dict[str, Any]:
        response = self._request(
            {"op": "filter", "first": first, "count": count, "capacity": RESULT_CAPACITY}
        )
        if (
            response.get("op") != "filter"
            or response.get("first") != first
            or response.get("count") != count
            or not isinstance(response.get("factual"), list)
            or not isinstance(response.get("control"), list)
            or float(response.get("gpu_seconds", -1)) < 0
        ):
            raise RuntimeError("AES-256 Metal filter response gate failed")
        return response

    def close(self, *, force: bool = False) -> None:
        if self.process.poll() is not None:
            return
        if not force:
            try:
                force = self._request({"op": "quit"}).get("op") != "quit"
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
            raise RuntimeError("AES-256 Metal host exit failed")


def _metal_kat_and_cross_gate(host: MetalAES256Host) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for vector in FIPS197_KATS:
        plaintext = vector.plaintext * 2
        target = vector.ciphertext * 2
        words = key_words_big_endian(vector.key)
        host.configure(
            plaintext=plaintext,
            target=target,
            control=_one_bit_control(target),
            key_words_0_to_6=words[:7],
        )
        outputs = host.blocks(words[7], 1)
        filtered = host.filter(words[7], 1)
        if outputs != [target] or filtered["factual"] != [words[7]] or filtered["control"]:
            raise RuntimeError(f"AES-256 Metal KAT failed for {vector.name}")
        rows.append(
            {
                "name": vector.name,
                "two_block_output_sha256": _sha256(outputs[0]),
                "exact_cpu_metal_identity": True,
                "one_bit_control_rejected": True,
            }
        )

    first = METAL_CROSS_FIRST
    count = METAL_CROSS_COUNT
    offset = METAL_CROSS_OFFSET
    known_words = key_words_big_endian(QUALIFICATION_KNOWN_KEY)
    expected = [
        encrypt_blocks(
            QUALIFICATION_KNOWN_KEY[:28] + (first + index).to_bytes(4, "big"),
            QUALIFICATION_PLAINTEXT,
        )
        for index in range(count)
    ]
    target = expected[offset]
    host.configure(
        plaintext=QUALIFICATION_PLAINTEXT,
        target=target,
        control=_one_bit_control(target),
        key_words_0_to_6=known_words[:7],
    )
    observed = host.blocks(first, count)
    filtered = host.filter(first, count)
    if observed != expected or filtered["factual"] != [first + offset] or filtered["control"]:
        raise RuntimeError("AES-256 CPU/Metal cross-implementation gate failed")
    return {
        "fips197_vectors": rows,
        "cross_candidate_count": count,
        "cross_outputs_sha256": _sha256(b"".join(observed)),
        "exact_cpu_metal_identity": True,
        "exact_factual_control_filter_identity": True,
    }


def _metal_mapping_gate(host: MetalAES256Host) -> dict[str, Any]:
    prefix = bytes.fromhex(
        "00112233445566778899aabbccddeeff1021324354657687"
    )
    rows: list[dict[str, Any]] = []
    for outer, first, count, offset, label in METAL_MAPPING_CASES:
        known_prefix = prefix + outer.to_bytes(4, "big")
        expected = [
            encrypt_blocks(known_prefix + (first + index).to_bytes(4, "big"), QUALIFICATION_PLAINTEXT)
            for index in range(count)
        ]
        target = expected[offset]
        host.configure(
            plaintext=QUALIFICATION_PLAINTEXT,
            target=target,
            control=_one_bit_control(target),
            key_words_0_to_6=key_words_big_endian(known_prefix + bytes(4))[:7],
        )
        observed = host.blocks(first, count)
        filtered = host.filter(first, count)
        candidate = first + offset
        if observed != expected or filtered["factual"] != [candidate] or filtered["control"]:
            raise RuntimeError(f"AES-256 Metal mapping gate failed at {label}")
        rows.append(
            {
                "label": label,
                "outer_word6": outer,
                "target_inner_word7": candidate,
                "combined_low64_assignment": (outer << 32) | candidate,
                "outputs_sha256": _sha256(b"".join(observed)),
                "exact_cpu_metal_identity": True,
            }
        )
    return {"rows": rows, "exact_boundary_identity": True}


def _validate_benchmark_budget(candidate_count: int, repeats: int) -> int:
    if candidate_count < 1 or candidate_count > MAX_BENCHMARK_CANDIDATES:
        raise ValueError(
            f"benchmark candidate count must be in 1...{MAX_BENCHMARK_CANDIDATES}"
        )
    if repeats < 1 or repeats > MAX_BENCHMARK_REPEATS:
        raise ValueError(f"benchmark repeats must be in 1...{MAX_BENCHMARK_REPEATS}")
    return BENCHMARK_WARMUP_CANDIDATES + candidate_count * repeats


def _recommended_stream_count(minimum_throughput: float) -> int:
    target = max(1, math.floor(minimum_throughput * STREAM_TARGET_SECONDS))
    power_of_two = 1 << math.floor(math.log2(target))
    return min(max(power_of_two, MIN_STREAM_CANDIDATES), MAX_STREAM_CANDIDATES)


def _benchmark(
    host: MetalAES256Host, *, candidate_count: int, repeats: int
) -> dict[str, Any]:
    total_cap = _validate_benchmark_budget(candidate_count, repeats)
    target_candidate = candidate_count // 2
    words = key_words_big_endian(QUALIFICATION_KNOWN_KEY)
    target = encrypt_blocks(
        QUALIFICATION_KNOWN_KEY[:28] + target_candidate.to_bytes(4, "big"),
        QUALIFICATION_PLAINTEXT,
    )
    host.configure(
        plaintext=QUALIFICATION_PLAINTEXT,
        target=target,
        control=_one_bit_control(target),
        key_words_0_to_6=words[:7],
    )
    warmup_count = min(candidate_count, BENCHMARK_WARMUP_CANDIDATES)
    warmup = host.filter(0, warmup_count)
    samples: list[dict[str, Any]] = []
    for _ in range(repeats):
        started = time.perf_counter()
        response = host.filter(0, candidate_count)
        wall_seconds = time.perf_counter() - started
        gpu_seconds = float(response["gpu_seconds"])
        if gpu_seconds <= 0 or wall_seconds <= 0:
            raise RuntimeError("AES-256 benchmark returned zero elapsed time")
        if response["factual"] != [target_candidate] or response["control"]:
            raise RuntimeError("AES-256 benchmark correctness gate failed")
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
    minimum = min(throughputs)
    stream = _recommended_stream_count(minimum)
    return {
        "candidate_count_per_repeat": candidate_count,
        "repeats": repeats,
        "warmup_candidate_count": warmup_count,
        "maximum_candidate_invocations_permitted": total_cap,
        "warmup_factual_matches": warmup["factual"],
        "samples": samples,
        "minimum_candidates_per_second": minimum,
        "median_candidates_per_second": statistics.median(throughputs),
        "recommended_stream_candidate_count": stream,
        "recommended_stream_seconds_at_minimum": stream / minimum,
        "projected_complete_domain_seconds_at_minimum": {
            str(width): (2**width) / minimum
            for width in range(MIN_RESIDUAL_WIDTH, MAX_RESIDUAL_WIDTH + 1)
        },
        "timed_relation_bits": FILTER_BITS,
        "volatile_performance_only_not_recovery_evidence": True,
    }


def _launch_gate(benchmark: dict[str, Any]) -> dict[str, Any]:
    minimum = float(benchmark["minimum_candidates_per_second"])
    highest = min(
        math.floor(math.log2(minimum * MAX_COMPLETE_DOMAIN_SECONDS)),
        MAX_RESIDUAL_WIDTH,
    )
    selectable = list(range(MIN_RESIDUAL_WIDTH, max(MIN_RESIDUAL_WIDTH, highest) + 1))
    if highest < MIN_RESIDUAL_WIDTH:
        selectable = []
    selected = highest if selectable else None
    projected = (2**selected) / minimum if selected is not None else None
    return {
        "selection_rule": (
            "maximum integer width in 32...64 whose complete domain fits 7200 "
            "seconds at minimum observed end-to-end wall throughput"
        ),
        "selectable_widths": selectable,
        "selected_width": selected,
        "projected_selected_width_seconds_at_observed_minimum": projected,
        "maximum_complete_domain_seconds": MAX_COMPLETE_DOMAIN_SECONDS,
        "selected_stream_candidate_count": benchmark["recommended_stream_candidate_count"],
        "parameters_safe_for_later_review": selected is not None,
        "full_domain_launch_authorized": False,
    }


def _expected_metal_cross_evidence() -> dict[str, Any]:
    vector_rows = [
        {
            "name": vector.name,
            "two_block_output_sha256": _sha256(vector.ciphertext * 2),
            "exact_cpu_metal_identity": True,
            "one_bit_control_rejected": True,
        }
        for vector in FIPS197_KATS
    ]
    expected = [
        encrypt_blocks(
            QUALIFICATION_KNOWN_KEY[:28] + candidate.to_bytes(4, "big"),
            QUALIFICATION_PLAINTEXT,
        )
        for candidate in range(METAL_CROSS_FIRST, METAL_CROSS_FIRST + METAL_CROSS_COUNT)
    ]
    return {
        "fips197_vectors": vector_rows,
        "cross_candidate_count": METAL_CROSS_COUNT,
        "cross_outputs_sha256": _sha256(b"".join(expected)),
        "exact_cpu_metal_identity": True,
        "exact_factual_control_filter_identity": True,
    }


def _expected_metal_mapping_evidence() -> dict[str, Any]:
    prefix = bytes.fromhex(
        "00112233445566778899aabbccddeeff1021324354657687"
    )
    rows = []
    for outer, first, count, offset, label in METAL_MAPPING_CASES:
        known_prefix = prefix + outer.to_bytes(4, "big")
        outputs = [
            encrypt_blocks(
                known_prefix + (first + index).to_bytes(4, "big"),
                QUALIFICATION_PLAINTEXT,
            )
            for index in range(count)
        ]
        candidate = first + offset
        rows.append(
            {
                "label": label,
                "outer_word6": outer,
                "target_inner_word7": candidate,
                "combined_low64_assignment": (outer << 32) | candidate,
                "outputs_sha256": _sha256(b"".join(outputs)),
                "exact_cpu_metal_identity": True,
            }
        )
    return {"rows": rows, "exact_boundary_identity": True}


def _build_metal_evidence_ledger(
    *,
    cpu_content_anchors_sha256: str,
    native_build: dict[str, Any],
    host_identity: dict[str, Any],
    cross: dict[str, Any],
    mapping: dict[str, Any],
    benchmark: dict[str, Any],
    launch_gate: dict[str, Any],
    resource_cap: dict[str, Any],
) -> dict[str, Any]:
    """Build semantic execution provenance; this is not hardware attestation."""

    return {
        "schema": METAL_EVIDENCE_LEDGER_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "producer_path": METAL_EVIDENCE_PRODUCER,
        "provenance_scope": "semantic_execution_provenance_not_hardware_attestation",
        "cpu_content_anchors_sha256": cpu_content_anchors_sha256,
        "native_build_record": native_build,
        "raw_host_ready_device_record": host_identity,
        "vector_invocation_records": cross,
        "boundary_invocation_records": mapping,
        "timed_run_records": benchmark,
        "selected_throughput_width_derivation": launch_gate,
        "absolute_deadline_timestamps": resource_cap,
    }


def validate_metal_evidence_ledger(payload: dict[str, Any]) -> str:
    """Validate hash-bound semantic Metal provenance, not hardware attestation."""

    ledger = payload.get("metal_evidence_ledger")
    claimed_sha256 = payload.get("metal_evidence_ledger_sha256")
    content_anchors = payload.get("content_anchors")
    content_anchors_sha256 = payload.get("content_anchors_sha256")
    if (
        not isinstance(ledger, dict)
        or not isinstance(content_anchors, dict)
        or not _is_sha256_hex(content_anchors_sha256)
        or content_anchors_sha256 != _canonical_sha256(content_anchors)
        or claimed_sha256 != _canonical_sha256(ledger)
    ):
        raise RuntimeError("AES-256 Metal evidence ledger hash gate failed")
    native_build = payload.get("native_build", {})
    host_identity = payload.get("host_identity", {})
    cross = payload.get("metal_kat_cross_gate", {})
    mapping = payload.get("metal_boundary_mapping_gate", {})
    benchmark = payload.get("benchmark", {})
    launch_gate = payload.get("launch_gate", {})
    resource_cap = payload.get("qualification_resource_cap", {})
    bound_sections = (
        native_build,
        host_identity,
        cross,
        mapping,
        benchmark,
        launch_gate,
        resource_cap,
    )
    if (
        not all(isinstance(section, dict) for section in bound_sections)
        or payload.get("attempt_id") != ATTEMPT_ID
        or payload.get("metal_executed") is not True
        or ledger.get("schema") != METAL_EVIDENCE_LEDGER_SCHEMA
        or ledger.get("attempt_id") != ATTEMPT_ID
        or ledger.get("producer_path") != METAL_EVIDENCE_PRODUCER
        or ledger.get("provenance_scope")
        != "semantic_execution_provenance_not_hardware_attestation"
        or ledger.get("cpu_content_anchors_sha256")
        != payload.get("content_anchors_sha256")
        or ledger.get("native_build_record") != native_build
        or ledger.get("raw_host_ready_device_record") != host_identity
        or ledger.get("vector_invocation_records") != cross
        or ledger.get("boundary_invocation_records") != mapping
        or ledger.get("timed_run_records") != benchmark
        or ledger.get("selected_throughput_width_derivation") != launch_gate
        or ledger.get("absolute_deadline_timestamps") != resource_cap
    ):
        raise RuntimeError("AES-256 Metal evidence ledger binding gate failed")

    metal = host_identity.get("metal", {}) if isinstance(host_identity, dict) else {}
    content_native_sha = (
        payload.get("content_anchors", {}).get("native_source", {}).get("sha256")
    )
    if (
        native_build.get("source_filename") != NATIVE_SOURCE_FILENAME
        or native_build.get("source_sha256") != content_native_sha
        or not _is_sha256_hex(native_build.get("executable_sha256"))
        or native_build.get("selected_flags")
        != ["-O", "-whole-module-optimization", "-warnings-as-errors"]
        or native_build.get("warnings_as_errors") is not True
        or host_identity.get("op") != "ready"
        or host_identity.get("version") != NATIVE_VERSION
        or not str(metal.get("device", "")).startswith("Apple")
        or type(metal.get("filter_execution_width")) is not int
        or metal["filter_execution_width"] <= 0
        or metal.get("shader_runtime_compiled") is not True
        or metal.get("fips197_external_byte_order") is not True
        or metal.get("candidate_maps_to_key_bytes_28_through_31_big_endian") is not True
        or metal.get("aes256_nk8_subword_i_mod_8_eq_4") is not True
        or cross != _expected_metal_cross_evidence()
        or mapping != _expected_metal_mapping_evidence()
    ):
        raise RuntimeError("AES-256 Metal evidence ledger invocation gate failed")

    try:
        candidate_count = benchmark["candidate_count_per_repeat"]
        repeats = benchmark["repeats"]
        if type(candidate_count) is not int or type(repeats) is not int:
            raise ValueError("benchmark integer fields")
        permitted = _validate_benchmark_budget(candidate_count, repeats)
        samples = benchmark["samples"]
        if not isinstance(samples, list) or len(samples) != repeats:
            raise ValueError("sample count")
        throughputs = []
        gpu_sample_seconds = 0.0
        wall_sample_seconds = 0.0
        target_candidate = candidate_count // 2
        for sample in samples:
            if not isinstance(sample, dict):
                raise ValueError("timed sample object")
            gpu_seconds = float(sample["gpu_seconds"])
            wall_seconds = float(sample["end_to_end_wall_seconds"])
            wall_rate = candidate_count / wall_seconds
            gpu_rate = candidate_count / gpu_seconds
            if (
                not all(
                    math.isfinite(value)
                    for value in (gpu_seconds, wall_seconds, wall_rate, gpu_rate)
                )
                or sample.get("candidate_count") != candidate_count
                or gpu_seconds <= 0
                or wall_seconds <= 0
                or gpu_seconds > wall_seconds
                or not math.isclose(
                    float(sample["end_to_end_candidates_per_second"]), wall_rate
                )
                or not math.isclose(
                    float(sample["gpu_candidates_per_second"]), gpu_rate
                )
                or sample.get("factual_matches") != [target_candidate]
                or sample.get("control_matches") != []
            ):
                raise ValueError("timed sample")
            throughputs.append(wall_rate)
            gpu_sample_seconds += gpu_seconds
            wall_sample_seconds += wall_seconds
        minimum = min(throughputs)
        median = statistics.median(throughputs)
        stream = _recommended_stream_count(minimum)
        warmup_count = min(candidate_count, BENCHMARK_WARMUP_CANDIDATES)
        expected_warmup = [target_candidate] if target_candidate < warmup_count else []
        projections = benchmark["projected_complete_domain_seconds_at_minimum"]
        if (
            not isinstance(projections, dict)
            or benchmark.get("warmup_candidate_count") != warmup_count
            or benchmark.get("maximum_candidate_invocations_permitted") != permitted
            or benchmark.get("warmup_factual_matches") != expected_warmup
            or not math.isclose(
                float(benchmark["minimum_candidates_per_second"]), minimum
            )
            or not math.isclose(
                float(benchmark["median_candidates_per_second"]), median
            )
            or benchmark.get("recommended_stream_candidate_count") != stream
            or not math.isclose(
                float(benchmark["recommended_stream_seconds_at_minimum"]),
                stream / minimum,
            )
            or set(projections) != {
                str(width) for width in range(MIN_RESIDUAL_WIDTH, MAX_RESIDUAL_WIDTH + 1)
            }
            or any(
                not math.isclose(float(projections[str(width)]), (2**width) / minimum)
                for width in range(MIN_RESIDUAL_WIDTH, MAX_RESIDUAL_WIDTH + 1)
            )
            or benchmark.get("timed_relation_bits") != FILTER_BITS
            or benchmark.get("volatile_performance_only_not_recovery_evidence") is not True
            or launch_gate != _launch_gate(benchmark)
        ):
            raise ValueError("benchmark derivation")

        started = float(resource_cap["host_lifetime_started_monotonic"])
        deadline = float(resource_cap["absolute_deadline_monotonic"])
        finished = float(resource_cap["host_lifetime_finished_monotonic"])
        actual_wall = float(resource_cap["actual_wall_seconds_host_lifetime"])
        reported_gpu = float(resource_cap["reported_total_gpu_seconds"])
        if (
            not all(
                math.isfinite(value)
                for value in (
                    started,
                    deadline,
                    finished,
                    actual_wall,
                    reported_gpu,
                )
            )
            or started < 0
            or actual_wall < 0
            or reported_gpu < 0
            or started > finished
            or not math.isclose(
                deadline - started, QUALIFICATION_METAL_WALL_CAP_SECONDS
            )
            or not math.isclose(finished - started, actual_wall)
            or finished > deadline + 2.0
            or actual_wall < wall_sample_seconds
            or reported_gpu < gpu_sample_seconds
            or reported_gpu > actual_wall
            or resource_cap.get("wall_deadline_seconds")
            != QUALIFICATION_METAL_WALL_CAP_SECONDS
            or resource_cap.get("maximum_benchmark_candidates_per_repeat")
            != MAX_BENCHMARK_CANDIDATES
            or resource_cap.get("maximum_benchmark_repeats") != MAX_BENCHMARK_REPEATS
            or resource_cap.get("subprocess_killed_on_deadline") is not True
            or resource_cap.get("deadline_covers_ready_wait") is not True
            or resource_cap.get("constructor_cleanup_on_startup_failure") is not True
            or resource_cap.get("cannot_occupy_gpu_for_two_minutes") is not True
        ):
            raise ValueError("deadline provenance")
    except (KeyError, TypeError, ValueError, OverflowError, ZeroDivisionError) as error:
        raise RuntimeError("AES-256 Metal evidence ledger consistency gate failed") from error
    return str(claimed_sha256)


def run_metal_qualification(
    *,
    build_dir: Path,
    swiftc: str,
    benchmark_candidates: int,
    repeats: int,
) -> dict[str, Any]:
    """Run the opt-in, strictly capped Metal stage; never freeze a challenge."""

    _validate_benchmark_budget(benchmark_candidates, repeats)
    cpu = run_cpu_qualification()
    executable, native_build = _compile_native(build_dir, swiftc)
    started = time.monotonic()
    absolute_deadline = started + QUALIFICATION_METAL_WALL_CAP_SECONDS
    host = MetalAES256Host(
        executable, deadline_monotonic=absolute_deadline
    )
    try:
        cross = _metal_kat_and_cross_gate(host)
        mapping = _metal_mapping_gate(host)
        benchmark = _benchmark(
            host, candidate_count=benchmark_candidates, repeats=repeats
        )
        identity = host.identity
        gpu_seconds = host.total_gpu_seconds
    finally:
        host.close()
    finished = time.monotonic()
    wall_seconds = finished - started
    if wall_seconds > QUALIFICATION_METAL_WALL_CAP_SECONDS + 2:
        raise RuntimeError("AES-256 qualification exceeded its enforced Metal wall cap")
    launch_gate = _launch_gate(benchmark)
    resource_cap = {
        "wall_deadline_seconds": QUALIFICATION_METAL_WALL_CAP_SECONDS,
        "host_lifetime_started_monotonic": started,
        "absolute_deadline_monotonic": absolute_deadline,
        "host_lifetime_finished_monotonic": finished,
        "actual_wall_seconds_host_lifetime": wall_seconds,
        "reported_total_gpu_seconds": gpu_seconds,
        "maximum_benchmark_candidates_per_repeat": MAX_BENCHMARK_CANDIDATES,
        "maximum_benchmark_repeats": MAX_BENCHMARK_REPEATS,
        "subprocess_killed_on_deadline": True,
        "deadline_covers_ready_wait": True,
        "constructor_cleanup_on_startup_failure": True,
        "cannot_occupy_gpu_for_two_minutes": True,
    }
    ledger = _build_metal_evidence_ledger(
        cpu_content_anchors_sha256=cpu["content_anchors_sha256"],
        native_build=native_build,
        host_identity=identity,
        cross=cross,
        mapping=mapping,
        benchmark=benchmark,
        launch_gate=launch_gate,
        resource_cap=resource_cap,
    )
    payload = {
        **cpu,
        "evidence_stage": STAGE,
        "native_build": native_build,
        "host_identity": identity,
        "metal_kat_cross_gate": cross,
        "metal_boundary_mapping_gate": mapping,
        "benchmark": benchmark,
        "launch_gate": launch_gate,
        "qualification_resource_cap": resource_cap,
        "metal_evidence_ledger": ledger,
        "metal_evidence_ledger_sha256": _canonical_sha256(ledger),
        "information_boundary": {
            "production_target_selected": False,
            "production_unknown_assignment_generated": False,
            "production_protocol_frozen": False,
            "complete_residual_key_domain_executed": False,
            "benchmark_used_only_for_prospective_width_and_stream_selection": True,
        },
        "metal_executed": True,
    }
    validate_metal_evidence_ledger(payload)
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metal", action="store_true", help="run the capped Metal stage")
    parser.add_argument("--output", type=Path, help="optional artifact path; no default write")
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path(__file__).parents[1] / "build" / "aes256_metal_qualification",
    )
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument(
        "--benchmark-candidates", type=int, default=DEFAULT_BENCHMARK_CANDIDATES
    )
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    args = parser.parse_args(argv)
    payload = (
        run_metal_qualification(
            build_dir=args.build_dir,
            swiftc=args.swiftc,
            benchmark_candidates=args.benchmark_candidates,
            repeats=args.repeats,
        )
        if args.metal
        else run_cpu_qualification()
    )
    if args.output is not None:
        _atomic_json(args.output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
