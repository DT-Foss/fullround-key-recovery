#!/usr/bin/env python3
"""A304: grouped Metal execution companion for the frozen A302 W43 order."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"

DESIGN = CONFIGS / "chacha20_round20_w43_grouped_engine_a304_design_v1.json"
A302_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w43_calibrated_coarse_numeric_replication_a302.py"
)
NATIVE_SOURCE = RESEARCH / "experiments/chacha20_metal_w43_grouped_native.swift"
A304_TEST = ROOT / "tests/test_chacha20_round20_w43_grouped_engine_a304.py"
A304_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w43_grouped_engine_a304.sh"

PROTOCOL = CONFIGS / "chacha20_round20_w43_grouped_engine_a304_v1.json"
QUALIFICATION = RESULTS / "chacha20_round20_w43_grouped_engine_a304_qualification_v1.json"
RESULT = RESULTS / "chacha20_round20_w43_grouped_engine_a304_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_W43_GROUPED_ENGINE_A304_V1.md"
BUILD = RESEARCH / "build/chacha20_round20_w43_grouped_engine_a304"

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A304"
DESIGN_SHA256 = "7f7e9e1a5d7906aa06e2818f0bc99474839de039815e316cdd7ec01cbcff8d03"
NATIVE_SOURCE_SHA256 = (
    "cfd657be7826ccd25a425cbbb5c7eb4d658ab9dc3fb0521edb34688ef32d319d"
)
A302_PROTOCOL_SHA256 = (
    "9aa1121eb94002aea1a159ed321e5b7369dcad7cd24b4f295fb4239f61cfedcc"
)
A302_PREFLIGHT_SHA256 = (
    "990366ed7199049c9f6b132824215ecf170e8a0f2891eab7ad4ff3b7875cb1ab"
)
A302_ORDER_SHA256 = (
    "eeaa8e2a39e40dc50d46d78a149c8c5bf4e2b68781e2a846e329e2dfc164166d"
)
HOST_VERSION = "chacha20-metal-w43-grouped-v1"
WIDTH = 43
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
OUTER_BITS = 11
CELLS = 1 << PREFIX_BITS
WORD0_PER_GROUP = 1 << WORD0_SUFFIX_BITS
OUTER_SLICES = 1 << OUTER_BITS
GROUP_SIZE = WORD0_PER_GROUP * OUTER_SLICES
DOMAIN_SIZE = 1 << WIDTH
RESULT_CAPACITY = 64


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A304 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A302 = load_module(A302_RUNNER, "a304_a302_common")
W43 = A302.A300.A299.W43
sha256 = A302.sha256
file_sha256 = A302.file_sha256
canonical_sha256 = A302.canonical_sha256
atomic_bytes = A302.atomic_bytes
atomic_json = A302.atomic_json
relative = A302.relative
path_from_ref = A302.path_from_ref
anchor = A302.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A304 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    engine = value.get("engine_contract", {})
    if (
        value.get("schema")
        != "chacha20-round20-w43-grouped-engine-a304-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A302_complete_order_and_before_A302_candidate_discovery"
        or engine.get("candidate_group_size") != GROUP_SIZE
        or engine.get("full_rounds") != 20
        or engine.get("feedforward_included") is not True
        or engine.get("complete_group_before_success_evaluation") is not True
        or boundary.get("A302_candidate_available_at_freeze") is not False
        or boundary.get("A302_filter_outcome_available_at_freeze") is not False
        or boundary.get("A302_prefix_rank_available_at_freeze") is not False
        or boundary.get("engine_changes_frozen_prefix_order") is not False
        or boundary.get("engine_changes_candidate_membership") is not False
    ):
        raise RuntimeError("A304 design semantics differ")
    for path_key, sha_key in (
        ("A302_protocol_path", "A302_protocol_sha256"),
        ("A302_preflight_path", "A302_preflight_sha256"),
        ("A302_order_path", "A302_order_sha256"),
        ("A302_runner_path", "A302_runner_sha256"),
        ("A302_test_path", "A302_test_sha256"),
        ("grouped_native_source_path", "grouped_native_source_sha256"),
    ):
        anchor(path_from_ref(value["source_anchors"][path_key]), value["source_anchors"][sha_key])
    return value


def compile_native(swiftc: str) -> tuple[Path, dict[str, Any]]:
    if file_sha256(NATIVE_SOURCE) != NATIVE_SOURCE_SHA256:
        raise RuntimeError("A304 grouped native source hash differs")
    compiler = shutil.which(swiftc)
    if compiler is None:
        raise FileNotFoundError(f"Swift compiler not found: {swiftc}")
    BUILD.mkdir(parents=True, exist_ok=True)
    executable = BUILD / f"chacha20_w43_grouped_{NATIVE_SOURCE_SHA256[:16]}"
    flags = ["-O", "-whole-module-optimization", "-warnings-as-errors"]
    if not executable.exists():
        temporary = executable.with_name(f".{executable.name}.tmp")
        temporary.unlink(missing_ok=True)
        completed = subprocess.run(
            [compiler, *flags, str(NATIVE_SOURCE), "-o", str(temporary)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                "A304 grouped Swift/Metal compilation failed: "
                + completed.stderr.strip()
            )
        temporary.replace(executable)
    if not executable.is_file() or executable.stat().st_size == 0:
        raise RuntimeError("A304 grouped build produced no executable")
    compiler_version = subprocess.run(
        [compiler, "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()[0]
    return executable, {
        "source_path": relative(NATIVE_SOURCE),
        "source_sha256": NATIVE_SOURCE_SHA256,
        "executable_path": relative(executable),
        "executable_sha256": file_sha256(executable),
        "compiler_version": compiler_version,
        "selected_flags": flags,
        "host_language": "Swift_6",
        "shader_language": "Metal_Shading_Language_runtime_compiled",
    }


class GroupedMetalHost:
    def __init__(
        self,
        executable: Path,
        initial: np.ndarray,
        target: np.ndarray,
        control: np.ndarray,
    ) -> None:
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
            or ready.get("version") != HOST_VERSION
            or not str(metal.get("device", "")).startswith("Apple")
            or metal.get("filter_execution_width") != 32
            or metal.get("filter_max_threads_per_group", 0) < 256
            or metal.get("two_dimensional_candidate_grid") is not True
        ):
            self.close(force=True)
            raise RuntimeError("A304 grouped Metal identity gate failed")
        self.identity = ready
        self.configure(initial, target, control)

    def _read(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            assert self.process.stderr is not None
            diagnostics = self.process.stderr.read().strip()
            raise RuntimeError("A304 grouped Metal host closed: " + diagnostics)
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("A304 grouped Metal host returned a non-object")
        return value

    def _request(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError("A304 grouped Metal host is not running")
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        )
        self.process.stdin.flush()
        return self._read()

    def configure(
        self,
        initial: np.ndarray,
        target: np.ndarray,
        control: np.ndarray,
    ) -> None:
        if int(initial[5]) & (OUTER_SLICES - 1):
            raise ValueError("A304 base initial word1 low bits are not zero")
        response = self._request(
            {
                "op": "configure",
                "initial": [int(value) for value in initial],
                "target": [int(value) for value in target[:2]],
                "control": [int(value) for value in control[:2]],
            }
        )
        if response.get("op") != "configured":
            raise RuntimeError("A304 grouped Metal configuration gate failed")

    @staticmethod
    def _pairs(value: Any, *, name: str) -> list[list[int]]:
        if not isinstance(value, list):
            raise RuntimeError(f"A304 {name} is not a list")
        rows: list[list[int]] = []
        for row in value:
            if (
                not isinstance(row, list)
                or len(row) != 2
                or not all(isinstance(item, int) for item in row)
                or not 0 <= row[0] <= 0xFFFFFFFF
                or not 0 <= row[1] < OUTER_SLICES
            ):
                raise RuntimeError(f"A304 {name} candidate pair differs")
            rows.append(row)
        if rows != sorted(rows, key=lambda row: (row[1], row[0])):
            raise RuntimeError(f"A304 {name} candidate order differs")
        if len({tuple(row) for row in rows}) != len(rows):
            raise RuntimeError(f"A304 {name} contains duplicate candidate pairs")
        return rows

    def filter_group(
        self,
        *,
        first_word0: int,
        word0_count: int,
        outer_first: int = 0,
        outer_count: int = OUTER_SLICES,
    ) -> dict[str, Any]:
        response = self._request(
            {
                "op": "filter_group",
                "first_word0": first_word0,
                "word0_count": word0_count,
                "outer_first": outer_first,
                "outer_count": outer_count,
                "capacity": RESULT_CAPACITY,
            }
        )
        expected = word0_count * outer_count
        if (
            response.get("op") != "filter_group"
            or response.get("first_word0") != first_word0
            or response.get("word0_count") != word0_count
            or response.get("outer_first") != outer_first
            or response.get("outer_count") != outer_count
            or response.get("logical_candidates") != expected
        ):
            raise RuntimeError("A304 grouped filter response gate failed")
        response["factual"] = self._pairs(response.get("factual"), name="factual")
        response["control"] = self._pairs(response.get("control"), name="control")
        return response

    def blocks_group(
        self,
        *,
        first_word0: int,
        word0_count: int,
        outer_first: int,
        outer_count: int,
    ) -> np.ndarray:
        response = self._request(
            {
                "op": "blocks_group",
                "first_word0": first_word0,
                "word0_count": word0_count,
                "outer_first": outer_first,
                "outer_count": outer_count,
            }
        )
        words = np.asarray(response.get("words", []), dtype=np.uint32)
        if (
            response.get("op") != "blocks_group"
            or response.get("first_word0") != first_word0
            or response.get("word0_count") != word0_count
            or response.get("outer_first") != outer_first
            or response.get("outer_count") != outer_count
            or words.size != outer_count * word0_count * 16
        ):
            raise RuntimeError("A304 grouped blocks response gate failed")
        return words.reshape(outer_count, word0_count, 16)

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
                "A304 grouped Metal host exit failed: "
                + self.process.stderr.read().strip()
            )


def _scalar_blocks(
    *, challenge: Mapping[str, Any], outer: int, first_word0: int, count: int
) -> np.ndarray:
    initial = W43._initial(  # noqa: SLF001
        challenge["known_zeroed_key_words"],
        int(challenge["counter_start"]),
        challenge["nonce_words"],
        outer,
    )
    scalar = np.repeat(initial.reshape(1, 16), count, axis=0)
    scalar[:, 4] = np.arange(first_word0, first_word0 + count, dtype=np.uint32)
    return (W43.ANCHOR.A119._core(scalar.copy(), 20) + scalar).astype(  # noqa: SLF001
        np.uint32
    )


def freeze() -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, QUALIFICATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A304 artifacts already exist")
    design = load_design()
    a302_protocol, _a302_preflight, a302_order = A302.load_order(
        A302_PROTOCOL_SHA256,
        A302_PREFLIGHT_SHA256,
        A302_ORDER_SHA256,
    )
    if A302.RESULT.exists() or A302.CAUSAL.exists():
        raise RuntimeError("A302 candidate result existed before A304 protocol freeze")
    payload = {
        "schema": "chacha20-round20-w43-grouped-engine-a304-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_grouped_candidate_execution",
        "design_sha256": DESIGN_SHA256,
        "public_challenge_sha256": a302_protocol["public_challenge_sha256"],
        "engine_contract": design["engine_contract"],
        "qualification_contract": design["qualification_contract"],
        "information_boundary": design["information_boundary"],
        "source_order": {
            "attempt_id": "A302",
            "protocol_sha256": A302_PROTOCOL_SHA256,
            "preflight_sha256": A302_PREFLIGHT_SHA256,
            "order_sha256": A302_ORDER_SHA256,
            "portfolio_order_uint16be_sha256": a302_order[
                "portfolio_order_uint16be_sha256"
            ],
            "prefix_cells": len(a302_order["portfolio_order"]),
        },
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "A302_protocol": {
                "path": relative(A302.PROTOCOL),
                "sha256": A302_PROTOCOL_SHA256,
            },
            "A302_preflight": {
                "path": relative(A302.PREFLIGHT),
                "sha256": A302_PREFLIGHT_SHA256,
            },
            "A302_order": {
                "path": relative(A302.ORDER),
                "sha256": A302_ORDER_SHA256,
            },
            "A302_runner": {
                "path": relative(A302_RUNNER),
                "sha256": file_sha256(A302_RUNNER),
            },
            "grouped_native_source": {
                "path": relative(NATIVE_SOURCE),
                "sha256": NATIVE_SOURCE_SHA256,
            },
            "A304_runner": {
                "path": relative(Path(__file__)),
                "sha256": file_sha256(Path(__file__)),
            },
            "A304_test": {
                "path": relative(A304_TEST),
                "sha256": file_sha256(A304_TEST),
            },
            "A304_reproducer": {
                "path": relative(A304_REPRO),
                "sha256": file_sha256(A304_REPRO),
            },
        },
        "candidate_execution_started": False,
        "unknown_assignment_available_to_runner": False,
    }
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_protocol_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A304 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-grouped-engine-a304-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state") != "frozen_before_grouped_candidate_execution"
        or value.get("candidate_execution_started") is not False
        or value.get("unknown_assignment_available_to_runner") is not False
        or value.get("source_order", {}).get("order_sha256") != A302_ORDER_SHA256
        or value.get("engine_contract", {}).get("candidate_group_size") != GROUP_SIZE
    ):
        raise RuntimeError("A304 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    a302_protocol, _preflight, order_value = A302.load_order(
        A302_PROTOCOL_SHA256,
        A302_PREFLIGHT_SHA256,
        A302_ORDER_SHA256,
    )
    if a302_protocol["public_challenge_sha256"] != value["public_challenge_sha256"]:
        raise RuntimeError("A304 public challenge anchor differs")
    return value, order_value


def qualify(*, expected_protocol_sha256: str, swiftc: str) -> dict[str, Any]:
    if QUALIFICATION.exists():
        raise FileExistsError("A304 qualification already exists")
    protocol, _order = load_protocol(expected_protocol_sha256)
    a302_protocol = json.loads(A302.PROTOCOL.read_bytes())
    challenge = a302_protocol["public_challenge"]
    reference = W43.reference_gate()
    executable, build = compile_native(swiftc)
    base = W43._initial(  # noqa: SLF001
        challenge["known_zeroed_key_words"],
        int(challenge["counter_start"]),
        challenge["nonce_words"],
        0,
    )
    placeholder = np.asarray([0, 0], dtype=np.uint32)
    grouped = GroupedMetalHost(executable, base, placeholder, placeholder)
    legacy_build_dir = BUILD / "legacy_equivalence"
    legacy_executable, legacy_build = W43.A184._A181._compile_native(  # noqa: SLF001
        legacy_build_dir, swiftc
    )
    legacy = W43.A184.SliceMetalHost(
        legacy_executable,
        base,
        placeholder,
        placeholder,
    )
    full_block_rows: list[dict[str, Any]] = []
    first_word0 = 0x12345000
    count = 33
    try:
        for outer in (0, 1, 1023, 2047):
            expected = _scalar_blocks(
                challenge=challenge,
                outer=outer,
                first_word0=first_word0,
                count=count,
            )
            observed = grouped.blocks_group(
                first_word0=first_word0,
                word0_count=count,
                outer_first=outer,
                outer_count=1,
            )[0]
            initial = W43._initial(  # noqa: SLF001
                challenge["known_zeroed_key_words"],
                int(challenge["counter_start"]),
                challenge["nonce_words"],
                outer,
            )
            legacy.configure(initial, placeholder, placeholder)
            legacy_observed = legacy.blocks(first_word0, count)
            if not np.array_equal(observed, expected) or not np.array_equal(
                legacy_observed, expected
            ):
                raise RuntimeError("A304 full-block cross-engine gate failed")
            full_block_rows.append(
                {
                    "outer": outer,
                    "first_word0": first_word0,
                    "word0_count": count,
                    "complete_output_bits_checked": count * 512,
                    "output_sha256": hashlib.sha256(
                        expected.astype("<u4").tobytes()
                    ).hexdigest(),
                    "grouped_equals_scalar": True,
                    "legacy_equals_scalar": True,
                }
            )

        filter_outer_first = 37
        filter_outer_count = 4
        filter_first = 0x34567000
        filter_count = 257
        target_outer = filter_outer_first + 2
        target_offset = 73
        expected_target = _scalar_blocks(
            challenge=challenge,
            outer=target_outer,
            first_word0=filter_first,
            count=filter_count,
        )[target_offset]
        control = expected_target.copy()
        control[0] ^= np.uint32(1)
        grouped.configure(base, expected_target, control)
        filtered = grouped.filter_group(
            first_word0=filter_first,
            word0_count=filter_count,
            outer_first=filter_outer_first,
            outer_count=filter_outer_count,
        )
        expected_pair = [filter_first + target_offset, target_outer]
        if filtered["factual"] != [expected_pair] or filtered["control"] != []:
            raise RuntimeError("A304 grouped synthetic filter gate failed")
        grouped_identity = grouped.identity
        legacy_identity = legacy.identity
    finally:
        grouped.close()
        legacy.close()

    payload = {
        "schema": "chacha20-round20-w43-grouped-engine-a304-qualification-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "GROUPED_W43_ENGINE_EXACTLY_QUALIFIED_BEFORE_CANDIDATE_EXECUTION",
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "production_target_used": False,
        "unknown_assignment_used": False,
        "reference_gate": reference,
        "grouped_build": build,
        "legacy_build": legacy_build,
        "grouped_identity": grouped_identity,
        "legacy_identity": legacy_identity,
        "full_block_cross_engine_rows": full_block_rows,
        "total_full_block_bits_checked": sum(
            row["complete_output_bits_checked"] for row in full_block_rows
        ),
        "synthetic_filter_gate": {
            "first_word0": filter_first,
            "word0_count": filter_count,
            "outer_first": filter_outer_first,
            "outer_count": filter_outer_count,
            "logical_candidates": filter_count * filter_outer_count,
            "expected_factual_pair": expected_pair,
            "observed_factual_pairs": filtered["factual"],
            "observed_control_pairs": filtered["control"],
            "exact": True,
        },
        "information_boundary": protocol["information_boundary"],
    }
    payload["qualification_sha256"] = canonical_sha256(
        {
            "reference_gate": reference,
            "grouped_build": build,
            "legacy_build": legacy_build,
            "full_block_cross_engine_rows": full_block_rows,
            "synthetic_filter_gate": payload["synthetic_filter_gate"],
            "production_target_used": False,
        }
    )
    atomic_json(QUALIFICATION, payload)
    return payload


def load_qualification(
    expected_protocol_sha256: str, expected_qualification_sha256: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    protocol, order = load_protocol(expected_protocol_sha256)
    if file_sha256(QUALIFICATION) != expected_qualification_sha256:
        raise RuntimeError("A304 qualification artifact hash differs")
    value = json.loads(QUALIFICATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-grouped-engine-a304-qualification-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("production_target_used") is not False
        or value.get("unknown_assignment_used") is not False
        or value.get("total_full_block_bits_checked") != 4 * 33 * 512
        or value.get("synthetic_filter_gate", {}).get("exact") is not True
        or value.get("synthetic_filter_gate", {}).get("observed_control_pairs") != []
    ):
        raise RuntimeError("A304 qualification semantics differ")
    anchor(
        path_from_ref(value["grouped_build"]["executable_path"]),
        value["grouped_build"]["executable_sha256"],
    )
    return protocol, order, value


def ordered_discovery(
    *, host: GroupedMetalHost, challenge: Mapping[str, Any], order: Sequence[int]
) -> dict[str, Any]:
    values = [int(value) for value in order]
    if len(values) != CELLS or set(values) != set(range(CELLS)):
        raise ValueError("A304 prefix order is not an exact 4096-cell cover")
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    base = W43._initial(  # noqa: SLF001
        challenge["known_zeroed_key_words"],
        int(challenge["counter_start"]),
        challenge["nonce_words"],
        0,
    )
    host.configure(base, target, control)
    factual: list[int] = []
    controls: list[int] = []
    gpu_seconds = 0.0
    started = time.perf_counter()
    for group_index, prefix in enumerate(values):
        first_word0 = prefix << WORD0_SUFFIX_BITS
        observed = host.filter_group(
            first_word0=first_word0,
            word0_count=WORD0_PER_GROUP,
            outer_first=0,
            outer_count=OUTER_SLICES,
        )
        group_factual = [
            (int(outer) << 32) | int(word0)
            for word0, outer in observed["factual"]
        ]
        group_controls = [
            (int(outer) << 32) | int(word0)
            for word0, outer in observed["control"]
        ]
        factual.extend(group_factual)
        controls.extend(group_controls)
        gpu_seconds += float(observed["gpu_seconds"])
        if not group_factual:
            continue
        if len(group_factual) != 1:
            raise RuntimeError("A304 prefix group produced multiple factual filters")
        candidate = group_factual[0]
        if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
            raise RuntimeError("A304 factual candidate prefix differs")
        groups = group_index + 1
        executed = groups * GROUP_SIZE
        return {
            "candidate": candidate,
            "candidate_hex": f"{candidate:011x}",
            "key_word0": candidate & 0xFFFFFFFF,
            "key_word1_low11": candidate >> 32,
            "fine_prefix12": prefix,
            "fine_prefix12_hex": f"{prefix:03x}",
            "source_operator_attempt": "A302",
            "execution_engine_attempt": ATTEMPT_ID,
            "executed_prefix_groups": groups,
            "executed_group_dispatches": groups,
            "executed_outer_slices": groups * OUTER_SLICES,
            "executed_assignments": executed,
            "executed_assignments_upper_bound": executed,
            "complete_domain_assignments": DOMAIN_SIZE,
            "complete_group_execution_before_stop": True,
            "early_stop_inside_group": False,
            "strict_subset_of_complete_domain": groups < CELLS,
            "search_gain_bits": math.log2(CELLS / groups),
            "factual_filter_candidates": factual,
            "matched_control_candidates": len(controls),
            "control_filter_candidates": controls,
            "gpu_seconds": gpu_seconds,
            "volatile_wall_seconds": time.perf_counter() - started,
        }
    raise RuntimeError("A304 exact frozen order exhausted without a factual filter")


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A304:confirmed_grouped_A302_W43_recovery"
    writer = CausalWriter(api_id="a304w43")
    writer._rules = []
    writer.add_rule(
        name="grouped_execution_equivalence",
        description="A two-dimensional Metal grid executes exactly the same 2^31 candidates in every frozen A302 prefix group before success is evaluated.",
        pattern=["A302_frozen_prefix_order", "A304_exact_grouped_execution"],
        conclusion="A304_execution_equivalent_prefix_search",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="grouped_filter_to_confirmed_recovery",
        description="The sole factual two-word filter is confirmed across eight complete blocks by two independent ChaCha20 implementations.",
        pattern=["A304_execution_equivalent_prefix_search", "dual_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A302:frozen_coarse_numeric_W43_order",
        mechanism="A304:two_dimensional_word0_x_word1_low11_Metal_grid",
        outcome="A304:execution_equivalent_prefix_search",
        confidence=1.0,
        source=payload["qualification_artifact_sha256"],
        quantification=json.dumps(payload["engine_efficiency"], sort_keys=True),
        evidence=json.dumps(payload["qualification_gate"], sort_keys=True),
        domain="AI-native execution-equivalent ChaCha20-R20 W43 search",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A304:execution_equivalent_prefix_search",
        mechanism="complete_prefix_group_filter_plus_dual_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="confirmed full-round ChaCha20 W43 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A302:frozen_coarse_numeric_W43_order",
        mechanism="materialized_A302_order_A304_execution_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A304_grouped_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A304 grouped W43 recovery",
        entities=[
            "A302:frozen_coarse_numeric_W43_order",
            "A304:execution_equivalent_prefix_search",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="grouped_three_operator_W43_recovery_or_wider_residual_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the grouped engine preserve the A300 three-operator strict-subset gain on its fresh W43 target?"
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a304w43"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A304 authentic Causal reopen gate failed")
    reader_source = Path(inspect.getsourcefile(CausalReader) or "")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(CAUSAL),
        "sha256": file_sha256(CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": anchor(reader_source),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def recover(
    *,
    expected_protocol_sha256: str,
    expected_qualification_sha256: str,
    swiftc: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A304 final artifacts already exist")
    protocol, order_value, qualification = load_qualification(
        expected_protocol_sha256, expected_qualification_sha256
    )
    a302_protocol = json.loads(A302.PROTOCOL.read_bytes())
    challenge = a302_protocol["public_challenge"]
    executable, build = compile_native(swiftc)
    if (
        build["source_sha256"]
        != qualification["grouped_build"]["source_sha256"]
        or build["executable_sha256"]
        != qualification["grouped_build"]["executable_sha256"]
    ):
        raise RuntimeError("A304 production grouped build differs from qualification")
    base = W43._initial(  # noqa: SLF001
        challenge["known_zeroed_key_words"],
        int(challenge["counter_start"]),
        challenge["nonce_words"],
        0,
    )
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    host = GroupedMetalHost(executable, base, target, control)
    try:
        discovery = ordered_discovery(
            host=host,
            challenge=challenge,
            order=[int(value) for value in order_value["portfolio_order"]],
        )
        identity = host.identity
    finally:
        host.close()
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A304 matched one-bit control produced a filter candidate")
    confirmation = W43._confirm(  # noqa: SLF001
        {"challenge": challenge}, int(discovery["candidate"])
    )
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A304 dual independent confirmation failed")
    prefix = int(discovery["fine_prefix12"])
    ranks = A302.rank_analysis(
        prefix=prefix,
        order_value=order_value,
        challenge_sha=protocol["public_challenge_sha256"],
    )
    portfolio_rank = ranks["prefix_ranks_one_based"]["A302_two_operator_portfolio"]
    if portfolio_rank != discovery["executed_prefix_groups"]:
        raise RuntimeError("A304 discovery rank differs from frozen A302 order")
    strict_subset = portfolio_rank < CELLS
    evidence_stage = (
        "FULLROUND_R20_W43_GROUPED_A302_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_W43_GROUPED_A302_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    engine_efficiency = {
        "legacy_JSON_requests_per_prefix_group": OUTER_SLICES * 2,
        "grouped_JSON_requests_per_prefix_group": 1,
        "host_request_reduction_factor": OUTER_SLICES * 2,
        "legacy_filter_dispatches_per_prefix_group": OUTER_SLICES,
        "grouped_filter_dispatches_per_prefix_group": 1,
        "filter_dispatch_reduction_factor": OUTER_SLICES,
        "candidate_membership_identical": True,
        "complete_group_semantics_identical": True,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w43-grouped-engine-a304-result-v1",
        "attempt_id": ATTEMPT_ID,
        "source_operator_attempt": "A302",
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "qualification_artifact_sha256": expected_qualification_sha256,
        "A302_protocol_sha256": A302_PROTOCOL_SHA256,
        "A302_preflight_sha256": A302_PREFLIGHT_SHA256,
        "A302_order_sha256": A302_ORDER_SHA256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "grouped_build": build,
        "metal_identity": identity,
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "full_block_bits_checked": qualification[
                "total_full_block_bits_checked"
            ],
            "synthetic_filter_exact": qualification["synthetic_filter_gate"][
                "exact"
            ],
            "production_target_used": False,
        },
        "engine_efficiency": engine_efficiency,
        "measurement_efficiency": order_value["measurement_efficiency"],
        "portfolio_guarantee": order_value["portfolio_guarantee"],
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "strict_subset_of_complete_domain": strict_subset,
        "information_boundary": protocol["information_boundary"],
        "anchors": protocol["anchors"],
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "discovery": {
                key: value
                for key, value in discovery.items()
                if not key.startswith("volatile_")
            },
            "metal_identity": identity,
            "grouped_build": build,
            "qualification_artifact_sha256": expected_qualification_sha256,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": {
                key: value
                for key, value in discovery.items()
                if not key.startswith("volatile_")
            },
            "rank_analysis": ranks,
            "confirmation": confirmation,
            "engine_efficiency": engine_efficiency,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A304 — grouped Metal execution of the frozen A302 W43 order\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- A302 portfolio prefix rank: **{portfolio_rank} / 4,096**\n"
            f"- Search gain: **{ranks['portfolio_gain_bits_vs_complete_domain']:.6f} bits**\n"
            f"- Executed assignments: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W43 assignment: **0x{int(discovery['candidate']):011x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Frozen operator order: **A302 coarse+numeric, unchanged**\n"
            "- Grouped execution: **one 2D Metal dispatch per complete 2^31 prefix group**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode()
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "native_source_sha256": NATIVE_SOURCE_SHA256,
        "protocol_frozen": PROTOCOL.exists(),
        "qualification_complete": QUALIFICATION.exists(),
        "result_complete": RESULT.exists(),
        "candidate_group_size": GROUP_SIZE,
        "legacy_to_grouped_filter_dispatch_ratio": OUTER_SLICES,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--qualify", action="store_true")
    mode.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-qualification-sha256")
    parser.add_argument("--swiftc", default="/usr/bin/swiftc")
    args = parser.parse_args()
    if args.analyze:
        output = analyze()
    elif args.freeze:
        value = freeze()
        output = {
            "protocol": relative(PROTOCOL),
            "protocol_sha256": file_sha256(PROTOCOL),
            "public_challenge_sha256": value["public_challenge_sha256"],
        }
    else:
        if not args.expected_protocol_sha256:
            parser.error("--qualify/--recover requires --expected-protocol-sha256")
        if args.qualify:
            value = qualify(
                expected_protocol_sha256=args.expected_protocol_sha256,
                swiftc=args.swiftc,
            )
            output = {
                "qualification": relative(QUALIFICATION),
                "qualification_artifact_sha256": file_sha256(QUALIFICATION),
                "qualification_sha256": value["qualification_sha256"],
                "evidence_stage": value["evidence_stage"],
            }
        else:
            if not args.expected_qualification_sha256:
                parser.error("--recover requires --expected-qualification-sha256")
            value = recover(
                expected_protocol_sha256=args.expected_protocol_sha256,
                expected_qualification_sha256=args.expected_qualification_sha256,
                swiftc=args.swiftc,
            )
            output = {
                "result": relative(RESULT),
                "result_sha256": file_sha256(RESULT),
                "causal_sha256": value["causal"]["sha256"],
                "evidence_stage": value["evidence_stage"],
                "rank_analysis": value["rank_analysis"],
            }
    print(json.dumps(output, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
