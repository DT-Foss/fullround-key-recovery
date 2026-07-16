#!/usr/bin/env python3
"""Prospective full-round Threefish-1024 residual-key recovery on Apple Metal."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import math
import os
import secrets
import shutil
import statistics
import struct
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.ciphers import threefish1024_encrypt

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"

DESIGN = CONFIGS / "threefish1024_metal_record_design_v1.json"
QUALIFICATION = RESULTS / "threefish1024_metal_qualification_v1.json"
PROTOCOL = CONFIGS / "threefish1024_metal_record_v1.json"
RESULT = RESULTS / "threefish1024_metal_record_v1.json"
CHECKPOINT = RESULTS / "threefish1024_metal_record_v1.checkpoint.json"
CAUSAL = RESULTS / "threefish1024_metal_record_v1.causal"
REPORT = REPORTS / "FULLROUND_THREEFISH1024_METAL_RECORD_V1.md"
BUILD = RESEARCH / "build/threefish1024_metal_record"
NATIVE_SOURCE = Path(__file__).with_name("threefish1024_metal_native.swift")
CANONICAL_SOURCE = ROOT / "src/arx_carry_leak/ciphers.py"
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)

ATTEMPT_ID = "TF1024KR1"
DESIGN_SHA256 = "dd6a4a3ebfeae67b51af34f93c31c70e661dff8e8db756e0588ab04cb1c1feb3"
NATIVE_VERSION = "threefish1024-metal-native-v1"
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
C240 = 0x1BD11BDAA9FC1A22
ROUNDS = 80
BLOCK_WORDS = 16
FILTER_WORDS32 = 32
RESULT_CAPACITY = 64
MIN_WIDTH = 32
MAX_WIDTH = 43
MAX_PROJECTED_GPU_SECONDS = 21_600.0
BENCHMARK_CANDIDATES = 1 << 20
BENCHMARK_REPEATS = 5
STREAM_CANDIDATES = 1 << 28
KNOWN_MATERIAL_LABEL = "threefish1024/tf1024kr1/fullround/known-material/v1"
ROTATIONS = (
    (24, 13, 8, 47, 8, 17, 22, 37),
    (38, 19, 10, 55, 49, 18, 23, 52),
    (33, 4, 51, 13, 34, 41, 59, 17),
    (5, 20, 48, 41, 47, 28, 16, 25),
    (41, 9, 37, 31, 12, 47, 44, 30),
    (16, 34, 56, 51, 4, 53, 42, 41),
    (31, 44, 47, 46, 19, 42, 44, 25),
    (9, 48, 35, 52, 23, 31, 37, 20),
)
PERMUTATION = (0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1)
ZERO_KAT = (
    0x04B3053D0A3D5CF0,
    0x0136E0D1C7DD85F7,
    0x067B212F6EA78A5C,
    0x0DA9C10B4C54E1C6,
    0x0F4EC27394CBACF0,
    0x32437F0568EA4FD5,
    0xCFF56D1D7654B49C,
    0xA2D5FB14369B2E7B,
    0x540306B460472E0B,
    0x71C18254BCEA820D,
    0xC36B4068BEAF32C8,
    0xFA4329597A360095,
    0xC4A36C28434A5B9A,
    0xD54331444B1046CF,
    0xDF11834830B2A460,
    0x1E39E8DFE1F7EE4F,
)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def canonical_sha256(value: Any) -> str:
    return sha256(canonical_bytes(value))


def atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, path)


def atomic_json(path: Path, value: Any) -> None:
    atomic_bytes(
        path,
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode()
        + b"\n",
    )


def relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    digest = file_sha256(path)
    if expected is not None and digest != expected:
        raise RuntimeError(f"TF1024KR1 anchor differs: {path}")
    return {"path": relative(path), "sha256": digest}


def halves(words: Sequence[int]) -> np.ndarray:
    output = np.empty(2 * len(words), dtype=np.uint32)
    for index, raw in enumerate(words):
        word = int(raw)
        if word < 0 or word > MASK64:
            raise ValueError("Threefish-1024 word exceeds uint64")
        output[2 * index] = word & MASK32
        output[2 * index + 1] = word >> 32
    return output


def words(halves32: Sequence[int]) -> list[int]:
    if len(halves32) % 2:
        raise ValueError("Threefish-1024 half array has odd length")
    return [
        int(halves32[index]) | (int(halves32[index + 1]) << 32)
        for index in range(0, len(halves32), 2)
    ]


def word_bytes(value: Sequence[int]) -> bytes:
    return struct.pack("<" + "Q" * len(value), *[int(item) & MASK64 for item in value])


def rotl64(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def independent_encrypt(
    plaintext: Sequence[int], key: Sequence[int], tweak: Sequence[int]
) -> list[int]:
    """Second spec transcription: inject before each four-round group."""
    if len(plaintext) != 16 or len(key) != 16 or len(tweak) != 2:
        raise ValueError("independent Threefish-1024 shape differs")
    schedule = [int(value) & MASK64 for value in key]
    parity = C240
    for value in schedule:
        parity ^= value
    schedule.append(parity)
    tweaks = [int(tweak[0]) & MASK64, int(tweak[1]) & MASK64]
    tweaks.append(tweaks[0] ^ tweaks[1])

    def subkey(index: int) -> list[int]:
        row = [schedule[(index + word) % 17] for word in range(16)]
        row[13] = (row[13] + tweaks[index % 3]) & MASK64
        row[14] = (row[14] + tweaks[(index + 1) % 3]) & MASK64
        row[15] = (row[15] + index) & MASK64
        return row

    state = [int(value) & MASK64 for value in plaintext]
    for round_index in range(ROUNDS):
        if round_index % 4 == 0:
            row = subkey(round_index // 4)
            state = [(value + row[index]) & MASK64 for index, value in enumerate(state)]
        mixed = [0] * 16
        for pair, rotation in enumerate(ROTATIONS[round_index % 8]):
            left_index = 2 * pair
            right_index = left_index + 1
            left = (state[left_index] + state[right_index]) & MASK64
            right = rotl64(state[right_index], rotation) ^ left
            mixed[left_index] = left
            mixed[right_index] = right
        state = [mixed[index] for index in PERMUTATION]
    final = subkey(ROUNDS // 4)
    return [(value + final[index]) & MASK64 for index, value in enumerate(state)]


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("TF1024KR1 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    if (
        value.get("schema") != "threefish1024-metal-record-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("primitive_contract", {}).get("rounds") != ROUNDS
        or value.get("information_boundary", {}).get(
            "production_target_exists_at_design_freeze"
        )
        is not False
    ):
        raise RuntimeError("TF1024KR1 design semantics differ")
    return value


def compile_native(build_dir: Path, swiftc: str) -> tuple[Path, dict[str, Any]]:
    source_sha = file_sha256(NATIVE_SOURCE)
    compiler = shutil.which(swiftc)
    if compiler is None:
        raise FileNotFoundError(f"Swift compiler not found: {swiftc}")
    build_dir.mkdir(parents=True, exist_ok=True)
    output = build_dir / f"threefish1024_metal_{source_sha[:16]}"
    if not output.exists():
        temporary = output.with_name(f".{output.name}.tmp")
        temporary.unlink(missing_ok=True)
        flags = ["-O", "-whole-module-optimization", "-warnings-as-errors"]
        completed = subprocess.run(
            [compiler, *flags, str(NATIVE_SOURCE), "-o", str(temporary)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode:
            raise RuntimeError(
                "Threefish-1024 Swift/Metal compilation failed: "
                + completed.stderr.strip()
            )
        os.replace(temporary, output)
    version = subprocess.run(
        [compiler, "--version"], check=True, capture_output=True, text=True
    ).stdout.splitlines()[0]
    return output, {
        "source_sha256": source_sha,
        "executable_sha256": file_sha256(output),
        "compiler_version": version,
        "selected_flags": ["-O", "-whole-module-optimization", "-warnings-as-errors"],
        "warnings_as_errors": True,
    }


class MetalHost:
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
            or metal.get("native_64_bit_integer_arithmetic") is not True
        ):
            self.close(force=True)
            raise RuntimeError("Threefish-1024 Metal identity gate failed")
        self.identity = ready

    def _read(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            assert self.process.stderr is not None
            raise RuntimeError(
                "Threefish-1024 Metal host closed: "
                + self.process.stderr.read().strip()
            )
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("Threefish-1024 Metal response is not an object")
        return value

    def request(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError("Threefish-1024 Metal host is not running")
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n"
        )
        self.process.stdin.flush()
        return self._read()

    def configure(
        self,
        *,
        plaintext: Sequence[int],
        target: Sequence[int],
        control: Sequence[int],
        key: Sequence[int],
        tweak: Sequence[int],
    ) -> None:
        response = self.request(
            {
                "op": "configure",
                "plaintext": [int(value) for value in halves(plaintext)],
                "target": [int(value) for value in halves(target)],
                "control": [int(value) for value in halves(control)],
                "key_words": [int(value) for value in halves(key)],
                "tweak_words": [int(value) for value in halves(tweak)],
            }
        )
        if (
            response.get("op") != "configured"
            or response.get("plaintext_blocks") != 1
            or response.get("filter_words") != FILTER_WORDS32
        ):
            raise RuntimeError("Threefish-1024 Metal configuration gate failed")

    def blocks(self, first: int, count: int) -> tuple[list[list[int]], float]:
        response = self.request({"op": "blocks", "first": first, "count": count})
        raw = response.get("words", [])
        if (
            response.get("op") != "blocks"
            or response.get("first") != first
            or response.get("count") != count
            or len(raw) != count * FILTER_WORDS32
        ):
            raise RuntimeError("Threefish-1024 Metal block gate failed")
        rows = [
            words(raw[offset : offset + FILTER_WORDS32])
            for offset in range(0, len(raw), FILTER_WORDS32)
        ]
        return rows, float(response["gpu_seconds"])

    def filter(self, first: int, count: int) -> dict[str, Any]:
        response = self.request(
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
            or float(response.get("gpu_seconds", -1)) < 0
        ):
            raise RuntimeError("Threefish-1024 Metal filter gate failed")
        return response

    def close(self, *, force: bool = False) -> None:
        if self.process.poll() is None and not force:
            try:
                self.request({"op": "quit"})
            except (BrokenPipeError, RuntimeError):
                force = True
        if force and self.process.poll() is None:
            self.process.kill()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

    def __enter__(self) -> MetalHost:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def key_for_assignment(base_key: Sequence[int], assignment: int, width: int) -> list[int]:
    if width < MIN_WIDTH or width > MAX_WIDTH or assignment not in range(1 << width):
        raise ValueError("Threefish-1024 assignment boundary differs")
    key = [int(value) & MASK64 for value in base_key]
    if len(key) != 16 or key[0] & ((1 << width) - 1):
        raise ValueError("Threefish-1024 base key boundary differs")
    key[0] |= assignment
    return key


def configured_key(base_key: Sequence[int], outer: int, width: int) -> list[int]:
    outer_bits = width - 32
    if outer not in range(1 << outer_bits):
        raise ValueError("Threefish-1024 outer slice differs")
    return key_for_assignment(base_key, outer << 32, width)


def deterministic_material() -> tuple[list[int], list[int], list[int], str]:
    raw = hashlib.shake_256(KNOWN_MATERIAL_LABEL.encode()).digest(34 * 8)
    values = [int.from_bytes(raw[offset : offset + 8], "little") for offset in range(0, len(raw), 8)]
    return values[:16], values[16:18], values[18:34], sha256(raw)


def official_gate() -> dict[str, Any]:
    canonical = threefish1024_encrypt([0] * 16, [0] * 16, [0, 0], ROUNDS)
    independent = independent_encrypt([0] * 16, [0] * 16, [0, 0])
    expected = list(ZERO_KAT)
    if canonical != expected or independent != expected:
        raise RuntimeError("Threefish-1024 official zero KAT failed")
    return {
        "source": "Skein_v1.3_Threefish-1024_zero_KAT",
        "canonical_match": True,
        "independent_match": True,
        "ciphertext_sha256": sha256(word_bytes(expected)),
    }


def qualify(*, output: Path, build_dir: Path, swiftc: str) -> dict[str, Any]:
    if output.exists() or any(
        path.exists() for path in (PROTOCOL, RESULT, CHECKPOINT, CAUSAL, REPORT)
    ):
        raise FileExistsError("TF1024KR1 qualification must precede production")
    load_design()
    kat = official_gate()
    executable, build = compile_native(build_dir, swiftc)
    base_key, tweak, plaintext, material_sha = deterministic_material()
    base_key[0] &= MASK64 ^ MASK32
    target_outside = threefish1024_encrypt(
        plaintext, key_for_assignment(base_key, 0xF0000000, 32), tweak, ROUNDS
    )
    control = list(target_outside)
    control[-1] ^= 1
    with MetalHost(executable) as host:
        host.configure(
            plaintext=[0] * 16,
            target=ZERO_KAT,
            control=[*ZERO_KAT[:-1], ZERO_KAT[-1] ^ 1],
            key=[0] * 16,
            tweak=[0, 0],
        )
        metal_zero, _ = host.blocks(0, 1)
        if metal_zero != [list(ZERO_KAT)]:
            raise RuntimeError("Threefish-1024 Metal official KAT failed")
        host.configure(
            plaintext=plaintext,
            target=target_outside,
            control=control,
            key=base_key,
            tweak=tweak,
        )
        metal_rows, _ = host.blocks(0, 64)
        canonical_rows = [
            threefish1024_encrypt(
                plaintext, key_for_assignment(base_key, candidate, 32), tweak, ROUNDS
            )
            for candidate in range(64)
        ]
        independent_rows = [
            independent_encrypt(
                plaintext, key_for_assignment(base_key, candidate, 32), tweak
            )
            for candidate in range(64)
        ]
        if metal_rows != canonical_rows or canonical_rows != independent_rows:
            raise RuntimeError("Threefish-1024 64-candidate cross gate failed")
        boundary_target = threefish1024_encrypt(
            plaintext, key_for_assignment(base_key, MASK32, 32), tweak, ROUNDS
        )
        boundary_control = list(boundary_target)
        boundary_control[-1] ^= 1
        host.configure(
            plaintext=plaintext,
            target=boundary_target,
            control=boundary_control,
            key=base_key,
            tweak=tweak,
        )
        boundary = host.filter(MASK32 - 1, 2)
        if boundary["factual"] != [MASK32] or boundary["control"]:
            raise RuntimeError("Threefish-1024 uint32 boundary gate failed")
        host.configure(
            plaintext=plaintext,
            target=target_outside,
            control=control,
            key=base_key,
            tweak=tweak,
        )
        samples = []
        for _ in range(BENCHMARK_REPEATS):
            observed = host.filter(0, BENCHMARK_CANDIDATES)
            if observed["factual"] or observed["control"]:
                raise RuntimeError("Threefish-1024 benchmark target entered interval")
            gpu_seconds = float(observed["gpu_seconds"])
            samples.append(
                {
                    "candidate_count": BENCHMARK_CANDIDATES,
                    "gpu_seconds": gpu_seconds,
                    "candidates_per_gpu_second": BENCHMARK_CANDIDATES / gpu_seconds,
                }
            )
        identity = host.identity
    rates = [row["candidates_per_gpu_second"] for row in samples]
    minimum_rate = min(rates)
    eligible = [
        width
        for width in range(MIN_WIDTH, MAX_WIDTH + 1)
        if (1 << width) / minimum_rate <= MAX_PROJECTED_GPU_SECONDS
    ]
    if not eligible:
        raise RuntimeError("Threefish-1024 qualification selected no width")
    selected = max(eligible)
    payload = {
        "schema": "threefish1024-metal-qualification-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "THREEFISH1024_METAL_PRE_TARGET_QUALIFICATION",
        "design_sha256": DESIGN_SHA256,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "runner": anchor(Path(__file__)),
            "native_source": anchor(NATIVE_SOURCE),
            "canonical_source": anchor(CANONICAL_SOURCE),
        },
        "official_kat_gate": {**kat, "Metal_match": True, "all_passed": True},
        "cross_implementation_gate": {
            "candidate_count": 64,
            "canonical_independent_Metal_exact": True,
            "output_bits_checked": 64 * 1024,
            "output_sha256": sha256(b"".join(word_bytes(row) for row in metal_rows)),
        },
        "boundary_filter_gate": {
            "interval": [MASK32 - 1, MASK32],
            "factual": boundary["factual"],
            "control": boundary["control"],
            "exact": True,
        },
        "benchmark": {
            "candidate_count_per_repeat": BENCHMARK_CANDIDATES,
            "repeats": BENCHMARK_REPEATS,
            "samples": samples,
            "minimum_candidates_per_gpu_second": minimum_rate,
            "median_candidates_per_gpu_second": statistics.median(rates),
            "maximum_candidates_per_gpu_second": max(rates),
            "projected_complete_gpu_seconds": {
                str(width): (1 << width) / minimum_rate
                for width in range(MIN_WIDTH, MAX_WIDTH + 1)
            },
            "volatile_performance_only_not_a_success_rule": True,
        },
        "selection": {
            "selected_width": selected,
            "minimum_width": MIN_WIDTH,
            "maximum_width": MAX_WIDTH,
            "maximum_projected_complete_gpu_seconds": MAX_PROJECTED_GPU_SECONDS,
            "selection_rate": "minimum_observed_candidates_per_gpu_second",
        },
        "known_material_sha256": material_sha,
        "native_build": build,
        "metal_identity": identity,
        "information_boundary": {
            "production_target_exists": False,
            "production_assignment_exists": False,
            "candidate_execution_against_production_target": False,
        },
    }
    atomic_json(output, payload)
    return payload


def freeze(*, expected_qualification_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, RESULT, CHECKPOINT, CAUSAL, REPORT)):
        raise FileExistsError("TF1024KR1 production artifacts already exist")
    design = load_design()
    if file_sha256(QUALIFICATION) != expected_qualification_sha256:
        raise RuntimeError("TF1024KR1 qualification hash differs")
    qualification = json.loads(QUALIFICATION.read_bytes())
    width = int(qualification.get("selection", {}).get("selected_width", 0))
    if (
        qualification.get("schema") != "threefish1024-metal-qualification-v1"
        or qualification.get("official_kat_gate", {}).get("all_passed") is not True
        or qualification.get("cross_implementation_gate", {}).get(
            "canonical_independent_Metal_exact"
        )
        is not True
        or qualification.get("boundary_filter_gate", {}).get("exact") is not True
        or qualification.get("information_boundary", {}).get(
            "production_target_exists"
        )
        is not False
        or width not in range(MIN_WIDTH, MAX_WIDTH + 1)
    ):
        raise RuntimeError("TF1024KR1 qualification semantics differ")
    base_key, tweak, plaintext, material_sha = deterministic_material()
    base_key[0] &= MASK64 ^ ((1 << width) - 1)
    assignment = secrets.randbits(width)
    target = threefish1024_encrypt(
        plaintext, key_for_assignment(base_key, assignment, width), tweak, ROUNDS
    )
    control = list(target)
    control[-1] ^= 1
    public = {
        "primitive": "Threefish-1024",
        "rounds": ROUNDS,
        "standard_final_subkey_included": True,
        "plaintext_words": plaintext,
        "target_ciphertext_words": target,
        "control_ciphertext_words": control,
        "target_ciphertext_sha256": sha256(word_bytes(target)),
        "control_ciphertext_sha256": sha256(word_bytes(control)),
        "known_key0_upper_bits": base_key[0],
        "known_key_words_1_through_15": base_key[1:],
        "known_tweak_words": tweak,
        "known_material_derivation_label": KNOWN_MATERIAL_LABEL,
        "known_material_derivation_sha256": material_sha,
        "unknown_key_bits": width,
        "known_key_bits": 1024 - width,
        "candidate_encoding": "assignment=(outer_key0_bits<<32)|key0_low32",
        "unknown_assignment_included": False,
        "unknown_assignment_value_included": False,
        "full_key_included": False,
        "secret_used_only_for_target_construction": True,
        "secret_discarded_after_target_construction": True,
    }
    del assignment
    outer_bits = width - 32
    plan = {
        "logical_candidate_count": 1 << width,
        "inner_candidate_count_per_slice": 1 << 32,
        "outer_bits": outer_bits,
        "outer_slice_count": 1 << outer_bits,
        "stream_candidate_count": STREAM_CANDIDATES,
        "stream_batch_count": (1 << width) // STREAM_CANDIDATES,
        "complete_domain_required": True,
        "early_stop_forbidden": True,
        "success_evaluated_only_after_complete_domain": True,
        "checkpoint_resume_enabled": True,
        "matched_control_same_kernel_and_domain": True,
        "confirmation": "canonical_plus_independent_all_1024_output_bits",
    }
    payload = {
        "schema": "threefish1024-metal-record-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "fresh_target_and_complete_execution_contract_frozen_before_candidate_zero",
        "design": design,
        "qualification_sha256": expected_qualification_sha256,
        "public_challenge": public,
        "public_challenge_sha256": canonical_sha256(public),
        "execution": plan,
        "execution_sha256": canonical_sha256(plan),
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "qualification": anchor(QUALIFICATION, expected_qualification_sha256),
            "runner": anchor(Path(__file__)),
            "native_source": anchor(NATIVE_SOURCE),
            "canonical_source": anchor(CANONICAL_SOURCE),
        },
        "information_boundary": {
            "assignment_absent": True,
            "all_secret_fields_absent": True,
            "candidate_execution_started": False,
            "target_frozen_after_pre_target_qualification": True,
            "success_rule_frozen": True,
        },
    }
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("TF1024KR1 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    public = value.get("public_challenge", {})
    forbidden = {
        "assignment",
        "unknown_assignment",
        "unknown_assignment_value",
        "full_key",
        "full_key_words",
        "secret_key",
    }
    if (
        value.get("schema") != "threefish1024-metal-record-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("information_boundary", {}).get("assignment_absent") is not True
        or bool(forbidden & set(public))
        or canonical_sha256(public) != value.get("public_challenge_sha256")
        or canonical_sha256(value.get("execution")) != value.get("execution_sha256")
        or file_sha256(QUALIFICATION) != value.get("qualification_sha256")
        or value.get("anchors", {}).get("runner", {}).get("sha256")
        != file_sha256(Path(__file__))
    ):
        raise RuntimeError("TF1024KR1 protocol semantics differ")
    for row in value["anchors"].values():
        path = ROOT / row["path"] if not Path(row["path"]).is_absolute() else Path(row["path"])
        anchor(path, row["sha256"])
    return value


def challenge_parts(protocol: Mapping[str, Any]) -> tuple[int, list[int], list[int], list[int], list[int], list[int]]:
    public = protocol["public_challenge"]
    width = int(public["unknown_key_bits"])
    base_key = [int(public["known_key0_upper_bits"]), *map(int, public["known_key_words_1_through_15"])]
    return (
        width,
        base_key,
        [int(value) for value in public["known_tweak_words"]],
        [int(value) for value in public["plaintext_words"]],
        [int(value) for value in public["target_ciphertext_words"]],
        [int(value) for value in public["control_ciphertext_words"]],
    )


def mapping_gate(host: MetalHost, protocol: Mapping[str, Any]) -> dict[str, Any]:
    width, base_key, tweak, plaintext, _target, _control = challenge_parts(protocol)
    assignment_set = {0, 1, MASK32, (1 << width) - 1}
    if width > 32:
        assignment_set.add(1 << 32)
    assignments = sorted(assignment_set)
    rows = []
    for assignment in assignments:
        outer, low = divmod(assignment, 1 << 32)
        key = key_for_assignment(base_key, assignment, width)
        target = threefish1024_encrypt(plaintext, key, tweak, ROUNDS)
        independent = independent_encrypt(plaintext, key, tweak)
        if target != independent:
            raise RuntimeError("TF1024KR1 mapping references differ")
        control = list(target)
        control[-1] ^= 1
        host.configure(
            plaintext=plaintext,
            target=target,
            control=control,
            key=configured_key(base_key, outer, width),
            tweak=tweak,
        )
        metal, _ = host.blocks(low, 1)
        if metal != [target]:
            raise RuntimeError("TF1024KR1 Metal mapping differs")
        rows.append({"assignment": assignment, "output_sha256": sha256(word_bytes(target))})
    return {"assignments": assignments, "rows": rows, "canonical_independent_Metal_exact": True}


def checkpoint_base(protocol: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": "threefish1024-metal-record-checkpoint-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": file_sha256(PROTOCOL),
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "domain_size": int(protocol["execution"]["logical_candidate_count"]),
        "next_assignment": 0,
        "factual_filtered": [],
        "control_filtered": [],
        "gpu_seconds": 0.0,
        "complete_domain_executed": False,
        "early_stop_used": False,
        "success_evaluated_before_complete_domain": False,
    }


def enumerate_domain(
    *, host: MetalHost, protocol: Mapping[str, Any], resume: bool
) -> dict[str, Any]:
    width, base_key, tweak, plaintext, target, control = challenge_parts(protocol)
    domain = 1 << width
    if CHECKPOINT.exists():
        if not resume:
            raise FileExistsError("TF1024KR1 checkpoint exists; use --resume")
        state = json.loads(CHECKPOINT.read_bytes())
        expected = checkpoint_base(protocol)
        if any(state.get(key) != expected[key] for key in ("schema", "attempt_id", "protocol_sha256", "public_challenge_sha256", "domain_size")):
            raise RuntimeError("TF1024KR1 checkpoint semantics differ")
    else:
        state = checkpoint_base(protocol)
        atomic_json(CHECKPOINT, state)
    start = int(state["next_assignment"])
    if start < 0 or start > domain or start % STREAM_CANDIDATES:
        raise RuntimeError("TF1024KR1 checkpoint boundary differs")
    factual = [int(value) for value in state["factual_filtered"]]
    control_matches = [int(value) for value in state["control_filtered"]]
    if (
        state.get("early_stop_used") is not False
        or state.get("success_evaluated_before_complete_domain") is not False
        or state.get("complete_domain_executed") != (start == domain)
        or len(factual) != len(set(factual))
        or len(control_matches) != len(set(control_matches))
        or any(value not in range(start) for value in [*factual, *control_matches])
    ):
        raise RuntimeError("TF1024KR1 checkpoint state differs")
    gpu_seconds = float(state["gpu_seconds"])
    started = time.perf_counter()
    current_outer: int | None = None
    for combined in range(start, domain, STREAM_CANDIDATES):
        outer = combined >> 32
        inner = combined & MASK32
        count = min(STREAM_CANDIDATES, (1 << 32) - inner, domain - combined)
        if outer != current_outer:
            host.configure(
                plaintext=plaintext,
                target=target,
                control=control,
                key=configured_key(base_key, outer, width),
                tweak=tweak,
            )
            current_outer = outer
        observed = host.filter(inner, count)
        factual.extend((outer << 32) | int(value) for value in observed["factual"])
        control_matches.extend((outer << 32) | int(value) for value in observed["control"])
        gpu_seconds += float(observed["gpu_seconds"])
        state.update(
            {
                "next_assignment": combined + count,
                "factual_filtered": sorted(factual),
                "control_filtered": sorted(control_matches),
                "gpu_seconds": gpu_seconds,
                "complete_domain_executed": combined + count == domain,
            }
        )
        atomic_json(CHECKPOINT, state)
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "progress": (combined + count) / domain,
                    "next_assignment": combined + count,
                    "logical_candidates": domain,
                    "factual_filters": len(factual),
                    "control_filters": len(control_matches),
                    "gpu_seconds": gpu_seconds,
                },
                sort_keys=True,
            ),
            flush=True,
        )
    if int(state["next_assignment"]) != domain or state["complete_domain_executed"] is not True:
        raise RuntimeError("TF1024KR1 complete-domain gate failed")
    if len(factual) != 1 or control_matches:
        raise RuntimeError("TF1024KR1 candidate cardinality gate failed")
    confirmations = confirm(protocol, factual[0])
    return {
        "unknown_key_bits": width,
        "known_key_bits": 1024 - width,
        "logical_candidate_count": domain,
        "executed_assignment_count": domain,
        "resumed_assignment_count": start,
        "newly_executed_assignment_count": domain - start,
        "complete_domain_executed": True,
        "early_stop_used": False,
        "success_evaluated_only_after_complete_domain": True,
        "factual_filter_matches": factual,
        "factual_full_matches": factual,
        "control_filter_matches": control_matches,
        "control_full_matches": [],
        "unique_exact_assignment": True,
        "control_target_rejected": True,
        "factual_confirmations": [confirmations],
        "control_confirmations": [],
        "gpu_seconds": gpu_seconds,
        "volatile_wall_seconds": time.perf_counter() - started,
        "volatile_candidates_per_gpu_second": domain / gpu_seconds,
    }


def confirm(protocol: Mapping[str, Any], assignment: int) -> dict[str, Any]:
    width, base_key, tweak, plaintext, target, _control = challenge_parts(protocol)
    key = key_for_assignment(base_key, assignment, width)
    canonical = threefish1024_encrypt(plaintext, key, tweak, ROUNDS)
    independent = independent_encrypt(plaintext, key, tweak)
    if canonical != target or independent != target or canonical != independent:
        raise RuntimeError("TF1024KR1 independent full-block confirmation failed")
    return {
        "assignment": assignment,
        "assignment_hex": f"{assignment:0{math.ceil(width / 4)}x}",
        "recovered_key_words": key,
        "recovered_key_words_hex": [f"{value:016x}" for value in key],
        "canonical_output_sha256": sha256(word_bytes(canonical)),
        "independent_output_sha256": sha256(word_bytes(independent)),
        "canonical_independent_identity": True,
        "complete_1024_bit_match": True,
        "output_bits_checked_per_implementation": 1024,
        "cross_implementation_output_bits_checked": 2048,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    # The native format stores exactly eight API-id bytes.  Keep the identifier
    # at that boundary so reopen equality is exact instead of relying on the
    # writer's deterministic truncation.
    writer = CausalWriter(api_id="tf1024k1")
    writer._rules = []
    writer.add_rule(
        name="complete_domain_plus_independent_confirmation",
        description="Complete full-round Threefish-1024 residual enumeration plus two-reference confirmation establishes the recovered assignment.",
        pattern=["complete_domain_enumeration", "two_reference_confirmation"],
        conclusion="verified_residual_key_recovery",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="matched_control_separation",
        description="The identical complete search returns zero models for the one-bit control relation.",
        pattern=["same_complete_search", "zero_control_models"],
        conclusion="target_specific_recovery",
        confidence_modifier=1.0,
    )
    execution = payload["execution"]
    writer.add_triplet(
        trigger="Threefish1024:frozen_public_residual_relation",
        mechanism="complete_80_round_domain_enumeration",
        outcome="Threefish1024:factual_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{execution['logical_candidate_count']} assignments; no early stop",
        evidence=json.dumps(execution["factual_filter_matches"]),
        domain="full-round residual-key enumeration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="Threefish1024:factual_candidate_set",
        mechanism="canonical_plus_independent_confirmation",
        outcome="Threefish1024:unique_verified_fullround_residual",
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="1024 output bits in each of two implementations",
        evidence=json.dumps(execution["factual_confirmations"], sort_keys=True),
        domain="independent key confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="Threefish1024:one_bit_control_relation",
        mechanism="same_complete_search",
        outcome="Threefish1024:control_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{execution['logical_candidate_count']} assignments; identical kernel",
        evidence="[]",
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="Threefish1024:control_candidate_set",
        mechanism="zero_control_models",
        outcome="Threefish1024:control_relation_rejected",
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="zero exact control assignments",
        evidence="[]",
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="Threefish1024:frozen_public_residual_relation",
        mechanism="verified_complete_enumeration_and_confirmation_chain",
        outcome="Threefish1024:unique_verified_fullround_residual",
        confidence=1.0,
        source="materialized:complete_domain_plus_independent_confirmation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after complete execution and confirmation.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_triplet(
        trigger="Threefish1024:one_bit_control_relation",
        mechanism="verified_matched_control_chain",
        outcome="Threefish1024:control_relation_rejected",
        confidence=1.0,
        source="materialized:matched_control_separation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after the identical complete control search.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="Threefish-1024 verified recovery chain",
        entities=[
            "Threefish1024:frozen_public_residual_relation",
            "Threefish1024:factual_candidate_set",
            "Threefish1024:unique_verified_fullround_residual",
        ],
    )
    writer.add_cluster(
        name="Threefish-1024 matched control chain",
        entities=[
            "Threefish1024:one_bit_control_relation",
            "Threefish1024:control_candidate_set",
            "Threefish1024:control_relation_rejected",
        ],
    )
    writer.add_gap(
        subject="Threefish1024:unique_verified_fullround_residual",
        predicate="next_required_gain",
        expected_object_type="prospectively_selected_strict_subset_of_residual_domain",
        confidence=1.0,
        suggested_queries=[
            "Can the full-round F8 fixed-point channel rank a held-out residual region early?"
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    if (
        reader.api_id != "tf1024k1"
        or len(reader._triplets) != 6
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("TF1024KR1 authentic Causal reopen failed")
    source = Path(inspect.getsourcefile(CausalReader) or "")
    return {
        "path": relative(CAUSAL),
        "sha256": file_sha256(CAUSAL),
        "api_id": reader.api_id,
        "triplets": len(reader._triplets),
        "rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": list(reader._gaps),
        "reader_source": anchor(source),
        "writer_stats": stats,
    }


def execute(*, expected_protocol_sha256: str, swiftc: str, resume: bool) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("TF1024KR1 final artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    official_gate()
    executable, build = compile_native(BUILD, swiftc)
    with MetalHost(executable) as host:
        mapping = mapping_gate(host, protocol)
        execution = enumerate_domain(host=host, protocol=protocol, resume=resume)
        identity = host.identity
    payload: dict[str, Any] = {
        "schema": "threefish1024-metal-record-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_THREEFISH1024_COMPLETE_DOMAIN_RECOVERY_CONFIRMED",
        "protocol_sha256": expected_protocol_sha256,
        "qualification_sha256": protocol["qualification_sha256"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "anchors": protocol["anchors"],
        "native_build": build,
        "metal_identity": identity,
        "mapping_gate": mapping,
        "execution": execution,
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            key: value
            for key, value in execution.items()
            if not key.startswith("volatile_") and key != "gpu_seconds"
        }
    )
    payload["confirmation_sha256"] = canonical_sha256(
        {
            "factual": execution["factual_confirmations"],
            "control": execution["control_confirmations"],
        }
    )
    payload["authentic_causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    confirmation = execution["factual_confirmations"][0]
    atomic_bytes(
        REPORT,
        (
            f"# TF1024KR1 — Full-round Threefish-1024 W{execution['unknown_key_bits']} residual-key recovery\n\n"
            f"- Complete logical domain: **{execution['logical_candidate_count']:,} assignments**\n"
            "- Complete standard execution: **80/80 rounds; final subkey included**\n"
            "- Exact factual assignments: **1**\n"
            "- Exact one-bit control assignments: **0**\n"
            "- Canonical and independent confirmation: **1,024/1,024 bits each**\n"
            f"- Recovered assignment: **`{confirmation['assignment_hex']}`**\n"
            f"- Authentic Causal SHA-256: `{payload['authentic_causal']['sha256']}`\n"
        ).encode(),
    )
    CHECKPOINT.unlink(missing_ok=True)
    return payload


def analyze(expected_protocol_sha256: str) -> dict[str, Any]:
    protocol = load_protocol(expected_protocol_sha256)
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "unknown_key_bits": protocol["public_challenge"]["unknown_key_bits"],
        "logical_candidate_count": protocol["execution"]["logical_candidate_count"],
        "candidate_execution_started": CHECKPOINT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--qualify", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--expected-qualification-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--swiftc", default="/usr/bin/swiftc")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.qualify:
        payload = qualify(output=QUALIFICATION, build_dir=BUILD, swiftc=args.swiftc)
        response = {
            "qualification": relative(QUALIFICATION),
            "qualification_sha256": file_sha256(QUALIFICATION),
            "selected_width": payload["selection"]["selected_width"],
            "minimum_candidates_per_gpu_second": payload["benchmark"][
                "minimum_candidates_per_gpu_second"
            ],
        }
    elif args.freeze:
        if not args.expected_qualification_sha256:
            parser.error("--freeze requires --expected-qualification-sha256")
        payload = freeze(
            expected_qualification_sha256=args.expected_qualification_sha256
        )
        response = {
            "protocol": relative(PROTOCOL),
            "protocol_sha256": file_sha256(PROTOCOL),
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "unknown_key_bits": payload["public_challenge"]["unknown_key_bits"],
        }
    else:
        if not args.expected_protocol_sha256:
            parser.error("--analyze/--run requires --expected-protocol-sha256")
        if args.analyze:
            response = analyze(args.expected_protocol_sha256)
        else:
            payload = execute(
                expected_protocol_sha256=args.expected_protocol_sha256,
                swiftc=args.swiftc,
                resume=args.resume,
            )
            response = {
                "result": relative(RESULT),
                "result_sha256": file_sha256(RESULT),
                "causal_sha256": payload["authentic_causal"]["sha256"],
                "evidence_stage": payload["evidence_stage"],
                "factual_full_matches": payload["execution"]["factual_full_matches"],
                "control_full_matches": payload["execution"]["control_full_matches"],
            }
    print(json.dumps(response, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
