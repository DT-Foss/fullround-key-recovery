#!/usr/bin/env python3
"""Qualify and benchmark the full-round PRESENT-128 Metal key enumerator.

This module is deliberately separate from any frozen recovery challenge.  It
validates the native implementation and measures throughput without observing
or selecting a production target assignment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import statistics
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.present128_reference import (
    ROUNDS,
    encrypt_int,
    key_parts_to_int,
    key_schedule,
    verify_official_zero_kat,
    verify_orientation_sentinels,
    verify_reference_kats,
    verify_round_key_sentinel,
)

ATTEMPT_ID = "P128Q1"
SCHEMA = "present128-metal-qualification-v1"
NATIVE_SOURCE_FILENAME = "present128_metal_native.swift"
NATIVE_VERSION = "present128-metal-native-v1"
PLAINTEXT_BLOCKS = 2
WORDS_PER_BLOCK = 2
FILTER_WORDS = PLAINTEXT_BLOCKS * WORDS_PER_BLOCK
RESULT_CAPACITY = 64
DEFAULT_BENCHMARK_CANDIDATES = 1 << 25
DEFAULT_REPEATS = 5
MAX_COMPLETE_DOMAIN_SECONDS = 2 * 60 * 60
MAX_SUPPORTED_RESIDUAL_WIDTH = 64
FULL_ROUNDS = ROUNDS
KEY_BITS = 128
REFERENCE_KAT_KEY_PARTS = (0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203)
REFERENCE_KAT_PLAINTEXT = (0x01234567, 0x89ABCDEF)
REFERENCE_KAT_CIPHERTEXT = (0x0E3DCAFF, 0x311F1809)
QUALIFICATION_PLAINTEXT = np.array(
    [*REFERENCE_KAT_PLAINTEXT, 0xFEDCBA98, 0x76543210], dtype=np.uint32
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _compile_native(build_dir: Path, swiftc: str) -> tuple[Path, dict[str, Any]]:
    source = Path(__file__).with_name(NATIVE_SOURCE_FILENAME)
    source_sha = _file_sha256(source)
    compiler = shutil.which(swiftc)
    if compiler is None:
        raise FileNotFoundError(f"Swift compiler not found: {swiftc}")
    build_dir.mkdir(parents=True, exist_ok=True)
    output = build_dir / f"present128_metal_{source_sha[:16]}"
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
            "PRESENT-128 Swift/Metal host compilation failed: " + result.stderr.strip()
        )
    temporary.replace(output)
    if not output.is_file() or output.stat().st_size == 0:
        raise RuntimeError("PRESENT-128 Swift/Metal host build produced no executable")
    version = subprocess.run(
        [compiler, "--version"], check=True, capture_output=True, text=True
    ).stdout.splitlines()[0]
    return output, {
        "source_sha256": source_sha,
        "executable_sha256": _file_sha256(output),
        "host_language": "Swift_6",
        "shader_language": "Metal_Shading_Language_runtime_compiled",
        "compiler_version": version,
        "selected_flags": flags,
        "warnings_as_errors": True,
    }


def _scalar_outputs(
    candidate: int,
    key_mid_low32: int,
    key_mid_high32: int,
    key_high32: int,
    plaintext: np.ndarray = QUALIFICATION_PLAINTEXT,
) -> np.ndarray:
    if plaintext.shape != (FILTER_WORDS,):
        raise ValueError("plaintext must contain four uint32 words")
    high64 = (key_high32 << 32) | key_mid_high32
    round_keys = key_schedule(key_parts_to_int(high64, key_mid_low32, candidate))
    output = np.empty(FILTER_WORDS, dtype=np.uint32)
    for offset in range(0, FILTER_WORDS, WORDS_PER_BLOCK):
        ciphertext = encrypt_int(
            (int(plaintext[offset]) << 32) | int(plaintext[offset + 1]),
            round_keys,
        )
        output[offset] = ciphertext >> 32
        output[offset + 1] = ciphertext & 0xFFFFFFFF
    return output


class MetalPresent128Host:
    def __init__(self, executable: Path):
        self.process = subprocess.Popen(
            [str(executable.resolve())],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        ready = self._read()
        metal = ready.get("metal", {})
        if (
            ready.get("op") != "ready"
            or ready.get("version") != NATIVE_VERSION
            or not str(metal.get("device", "")).startswith("Apple")
            or int(metal.get("filter_execution_width", 0)) <= 0
            or int(metal.get("filter_max_threads_per_group", 0)) < 256
            or metal.get("shader_runtime_compiled") is not True
        ):
            self.close(force=True)
            raise RuntimeError("PRESENT-128 Metal host identity gate failed")
        self.identity = ready

    def _read(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            assert self.process.stderr is not None
            diagnostics = self.process.stderr.read().strip()
            raise RuntimeError("PRESENT-128 Metal host closed unexpectedly: " + diagnostics)
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("PRESENT-128 Metal host returned a non-object")
        return value

    def _request(self, value: dict[str, Any]) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError("PRESENT-128 Metal host is not running")
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        )
        self.process.stdin.flush()
        return self._read()

    def configure(
        self,
        *,
        plaintext: np.ndarray,
        target: np.ndarray,
        control: np.ndarray,
        key_mid_low32: int,
        key_mid_high32: int,
        key_high32: int,
    ) -> None:
        response = self._request(
            {
                "op": "configure",
                "plaintext": [int(value) for value in plaintext],
                "target": [int(value) for value in target],
                "control": [int(value) for value in control],
                "key_high32": key_high32,
                "key_mid_high32": key_mid_high32,
                "key_mid_low32": key_mid_low32,
            }
        )
        if (
            response.get("op") != "configured"
            or response.get("plaintext_blocks") != PLAINTEXT_BLOCKS
            or response.get("filter_words") != FILTER_WORDS
        ):
            raise RuntimeError("PRESENT-128 Metal configuration gate failed")

    def blocks(self, first: int, count: int) -> np.ndarray:
        response = self._request({"op": "blocks", "first": first, "count": count})
        words = np.array(response.get("words", []), dtype=np.uint32)
        if (
            response.get("op") != "blocks"
            or response.get("first") != first
            or response.get("count") != count
            or words.size != count * FILTER_WORDS
        ):
            raise RuntimeError("PRESENT-128 Metal block response gate failed")
        return words.reshape(count, FILTER_WORDS)

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
            or float(response.get("gpu_seconds", -1.0)) < 0.0
        ):
            raise RuntimeError("PRESENT-128 Metal filter response gate failed")
        return response

    def close(self, *, force: bool = False) -> None:
        if self.process.poll() is not None:
            return
        if not force:
            response = self._request({"op": "quit"})
            if response.get("op") != "quit":
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
                "PRESENT-128 Metal host exit failed: " + self.process.stderr.read()
            )


def _kat_gate(host: MetalPresent128Host) -> dict[str, Any]:
    official_zero_kat = verify_official_zero_kat()
    reference_kats = verify_reference_kats()
    schedule_sentinel = verify_round_key_sentinel()
    orientation = verify_orientation_sentinels()
    if (
        official_zero_kat["pass"] is not True
        or len(reference_kats) != 4
        or not all(row["pass"] is True for row in reference_kats)
        or schedule_sentinel["pass"] is not True
        or len(orientation) != 2
        or not all(row["pass"] is True for row in orientation)
    ):
        raise RuntimeError("PRESENT-128 scalar provenance/KAT gate failed")
    candidate, key_mid_low32, key_mid_high32, key_high32 = REFERENCE_KAT_KEY_PARTS
    expected = _scalar_outputs(
        candidate, key_mid_low32, key_mid_high32, key_high32
    )
    control = expected.copy()
    control[-1] ^= np.uint32(1)
    host.configure(
        plaintext=QUALIFICATION_PLAINTEXT,
        target=expected,
        control=control,
        key_mid_low32=key_mid_low32,
        key_mid_high32=key_mid_high32,
        key_high32=key_high32,
    )
    observed = host.blocks(candidate, 1)[0]
    filtered = host.filter(candidate, 1)
    if (
        tuple(int(value) for value in observed[:2]) != REFERENCE_KAT_CIPHERTEXT
        or not np.array_equal(observed, expected)
        or filtered["factual"] != [candidate]
        or filtered["control"] != []
    ):
        raise RuntimeError("PRESENT-128 provenance KAT/Metal equivalence gate failed")
    return {
        "official_zero_scalar_vector": official_zero_kat,
        "reference_scalar_vectors": reference_kats,
        "local_round_key_sentinel": schedule_sentinel,
        "nonpalindromic_orientation_sentinels": orientation,
        "master_key_hex": "000102030405060708090a0b0c0d0e0f",
        "master_key_parts_low32_to_high32": list(REFERENCE_KAT_KEY_PARTS),
        "plaintext_words_big_endian": list(REFERENCE_KAT_PLAINTEXT),
        "expected_ciphertext_words_big_endian": list(REFERENCE_KAT_CIPHERTEXT),
        "actual_ciphertext_words": [int(value) for value in observed[:2]],
        "two_block_scalar_identity": True,
        "candidate_low32": candidate,
        "word_convention": (
            "PRESENT blocks are two big-endian uint32 words; the 128-bit key is "
            "key_high32 || key_mid_high32 || key_mid_low32 || candidate_low32"
        ),
    }


def _cross_gate(host: MetalPresent128Host) -> dict[str, Any]:
    first = 123_456_789
    count = 256
    offset = 73
    key_mid_low32 = 0x89ABCDEF
    key_mid_high32 = 0x13579BDF
    key_high32 = 0x2468ACE0
    expected = np.stack(
        [
            _scalar_outputs(
                candidate, key_mid_low32, key_mid_high32, key_high32
            )
            for candidate in range(first, first + count)
        ]
    )
    target = expected[offset].copy()
    control = target.copy()
    control[-1] ^= np.uint32(1)
    host.configure(
        plaintext=QUALIFICATION_PLAINTEXT,
        target=target,
        control=control,
        key_mid_low32=key_mid_low32,
        key_mid_high32=key_mid_high32,
        key_high32=key_high32,
    )
    observed = host.blocks(first, count)
    filtered = host.filter(first, count)
    if (
        not np.array_equal(observed, expected)
        or filtered["factual"] != [first + offset]
        or filtered["control"] != []
    ):
        raise RuntimeError("PRESENT-128 Metal/scalar cross gate failed")
    return {
        "first_candidate": first,
        "candidate_count": count,
        "complete_output_bits_checked": int(observed.size * 32),
        "target_candidate": first + offset,
        "output_sha256": _sha256(observed.astype("<u4", copy=False).tobytes()),
        "exact_scalar_identity": True,
        "exact_filter_identity": True,
    }


def _boundary_gate(host: MetalPresent128Host) -> dict[str, Any]:
    target_candidate = 0x90210FED
    key_mid_low32 = 0x76543210
    key_mid_high32 = 0xCAFEBABE
    key_high32 = 0xDEADBEEF
    target = _scalar_outputs(
        target_candidate, key_mid_low32, key_mid_high32, key_high32
    )
    control = target.copy()
    control[-1] ^= np.uint32(1)
    host.configure(
        plaintext=QUALIFICATION_PLAINTEXT,
        target=target,
        control=control,
        key_mid_low32=key_mid_low32,
        key_mid_high32=key_mid_high32,
        key_high32=key_high32,
    )
    intervals = [(0, 256), (target_candidate - 128, 256), (2**32 - 256, 256)]
    rows = []
    for first, count in intervals:
        result = host.filter(first, count)
        expected = [target_candidate] if first <= target_candidate < first + count else []
        if result["factual"] != expected or result["control"] != []:
            raise RuntimeError("PRESENT-128 Metal boundary filter gate failed")
        rows.append(
            {
                "first_candidate": first,
                "candidate_count": count,
                "factual_matches": result["factual"],
                "control_matches": result["control"],
            }
        )
    return {
        "target_candidate": target_candidate,
        "intervals": rows,
        "exact_boundary_identity": True,
    }


def _benchmark(
    host: MetalPresent128Host,
    *,
    candidate_count: int,
    repeats: int,
) -> dict[str, Any]:
    if candidate_count < 1 or candidate_count > 2**32 - 1:
        raise ValueError("benchmark candidate count must be in 1...2^32-1")
    if repeats < 1:
        raise ValueError("benchmark repeats must be positive")
    key_mid_low32 = 0x6EED1234
    key_mid_high32 = 0x5EEDFACE
    key_high32 = 0xA5A55A5A
    target = _scalar_outputs(
        0x2468ACE0, key_mid_low32, key_mid_high32, key_high32
    )
    control = target.copy()
    control[-1] ^= np.uint32(1)
    host.configure(
        plaintext=QUALIFICATION_PLAINTEXT,
        target=target,
        control=control,
        key_mid_low32=key_mid_low32,
        key_mid_high32=key_mid_high32,
        key_high32=key_high32,
    )
    # Compile and allocate once before collecting timed samples.
    host.filter(0, min(candidate_count, 1 << 20))
    samples = []
    for _ in range(repeats):
        wall_start = time.perf_counter()
        response = host.filter(0, candidate_count)
        wall_seconds = time.perf_counter() - wall_start
        gpu_seconds = float(response["gpu_seconds"])
        if gpu_seconds <= 0.0 or wall_seconds <= 0.0:
            raise RuntimeError("PRESENT-128 Metal benchmark returned zero elapsed time")
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
    median = statistics.median(throughputs)
    minimum = min(throughputs)
    return {
        "candidate_count_per_repeat": candidate_count,
        "repeats": repeats,
        "samples": samples,
        "median_candidates_per_second": median,
        "minimum_candidates_per_second": minimum,
        "maximum_candidates_per_second": max(throughputs),
        "median_gpu_candidates_per_second": statistics.median(gpu_throughputs),
        "minimum_gpu_candidates_per_second": min(gpu_throughputs),
        "maximum_gpu_candidates_per_second": max(gpu_throughputs),
        "projected_complete_domain_seconds": {
            str(width): (2**width) / median for width in range(32, 65)
        },
        "projected_complete_domain_seconds_at_minimum": {
            str(width): (2**width) / minimum for width in range(32, 65)
        },
        "launch_gate_uses_end_to_end_wall_throughput": True,
        "volatile_performance_only_not_a_recovery_success_rule": True,
    }


def run(
    *,
    output: Path,
    build_dir: Path,
    swiftc: str,
    benchmark_candidates: int,
    repeats: int,
) -> dict[str, Any]:
    executable, build = _compile_native(build_dir, swiftc)
    host = MetalPresent128Host(executable)
    try:
        kat = _kat_gate(host)
        cross = _cross_gate(host)
        boundary = _boundary_gate(host)
        benchmark = _benchmark(
            host, candidate_count=benchmark_candidates, repeats=repeats
        )
        identity = host.identity
    finally:
        host.close()
    minimum_throughput = float(benchmark["minimum_candidates_per_second"])
    highest_safe_width = math.floor(
        math.log2(minimum_throughput * MAX_COMPLETE_DOMAIN_SECONDS)
    )
    selected_width = min(max(highest_safe_width, 0), MAX_SUPPORTED_RESIDUAL_WIDTH)
    projected_selected_width_seconds = (1 << selected_width) / minimum_throughput
    required_candidates_per_second = (
        (1 << selected_width) / MAX_COMPLETE_DOMAIN_SECONDS
    )
    launch_gate = {
        "selection_rule": (
            "maximum_supported_integer_width_whose_complete_domain_fits_7200_seconds_"
            "at_minimum_end_to_end_wall_throughput"
        ),
        "maximum_supported_residual_width": MAX_SUPPORTED_RESIDUAL_WIDTH,
        "maximum_complete_domain_seconds": MAX_COMPLETE_DOMAIN_SECONDS,
        "required_candidates_per_second": required_candidates_per_second,
        "throughput_statistic": "minimum_end_to_end_wall_throughput_of_all_timed_repeats",
        "observed_minimum_candidates_per_second": minimum_throughput,
        "projected_selected_width_seconds_at_observed_minimum": (
            projected_selected_width_seconds
        ),
        "highest_safe_integer_width_at_observed_minimum": highest_safe_width,
        "selected_width": selected_width,
        "selected_width_under_two_hours": (
            projected_selected_width_seconds <= MAX_COMPLETE_DOMAIN_SECONDS
        ),
    }
    launch_gate["full_domain_launch_authorized"] = bool(
        selected_width >= 32 and launch_gate["selected_width_under_two_hours"]
    )
    payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRESENT128_METAL_PRE_TARGET_QUALIFICATION",
        "scope": (
            "All 31 PRESENT-128 SPN rounds plus final K32 whitening implementation "
            "qualification and volatile throughput measurement; no production "
            "recovery target was selected or run."
        ),
        "cipher": {
            "variant": "PRESENT-128",
            "block_bits": 64,
            "master_key_bits": KEY_BITS,
            "rounds": FULL_ROUNDS,
            "final_whitening_key": "K32",
            "key_schedule": (
                "128-bit register rotate-left-61, S-box on both top nibbles, "
                "round-counter XOR into bits 66..62"
            ),
            "references": [
                "Bogdanov_et_al_CHES_2007_DOI_10.1007/978-3-540-74735-2_31",
                "ISO_IEC_29167_11_PRESENT_128",
            ],
            "candidate_encoding": (
                "candidate=master_key_bits_31..0; configured_mid_low32=bits_63..32; "
                "configured_mid_high32=bits_95..64; configured_high32=bits_127..96"
            ),
            "known_plaintext_blocks_per_candidate": PLAINTEXT_BLOCKS,
            "filter_output_bits": FILTER_WORDS * 32,
        },
        "native_build": build,
        "host_identity": identity,
        "provenance_kat_gate": kat,
        "cross_implementation_gate": cross,
        "boundary_filter_gate": boundary,
        "benchmark": benchmark,
        "launch_gate": launch_gate,
        "information_boundary": {
            "production_target_selected": False,
            "production_unknown_assignment_generated": False,
            "complete_residual_key_domain_executed": False,
            "benchmark_outcome_may_select_future_width": True,
        },
    }
    _atomic_json(output, payload)
    reopened = json.loads(output.read_text())
    if reopened != payload:
        raise RuntimeError("PRESENT-128 qualification artifact reopen gate failed")
    return {
        "output": str(output),
        "sha256": _file_sha256(output),
        "device": identity["metal"]["device"],
        "median_candidates_per_second": benchmark["median_candidates_per_second"],
        "minimum_candidates_per_second": benchmark["minimum_candidates_per_second"],
        "launch_gate": launch_gate,
        "projected_complete_domain_seconds": benchmark[
            "projected_complete_domain_seconds"
        ],
        "all_qualification_gates_passed": True,
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument(
        "--output",
        type=Path,
        default=research_root / "results" / "v1" / "present128_metal_qualification_v1.json",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=research_root / "build" / "present128_metal",
    )
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument(
        "--benchmark-candidates", type=int, default=DEFAULT_BENCHMARK_CANDIDATES
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
