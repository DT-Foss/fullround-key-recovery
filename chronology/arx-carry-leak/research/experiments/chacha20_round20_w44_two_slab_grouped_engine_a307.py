#!/usr/bin/env python3
"""A307: target-free W44 adapter over the exactly qualified A304 engine."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w44_two_slab_grouped_engine_a307_design_v1.json"
A304_RUNNER = RESEARCH / "experiments/chacha20_round20_w43_grouped_engine_a304.py"
A307_TEST = ROOT / "tests/test_chacha20_round20_w44_two_slab_grouped_engine_a307.py"
A307_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w44_two_slab_grouped_engine_a307.sh"

PROTOCOL = CONFIGS / "chacha20_round20_w44_two_slab_grouped_engine_a307_v1.json"
QUALIFICATION = RESULTS / "chacha20_round20_w44_two_slab_grouped_engine_a307_qualification_v1.json"

ATTEMPT_ID = "A307"
DESIGN_SHA256 = "e72cd5be42e6803cdd0e2616ed04c99a2b901cc0b546663193af7808881276ec"
A304_PROTOCOL_SHA256 = "2b2ea9febb74397437e0c3a772463d9ed46093461d6cc848aa6c77d2c38e7168"
A304_QUALIFICATION_SHA256 = "a9a92f4f8ecceede5dee44a429352ee4bc55e581531145fb5bb8a9606bc96c9c"
A304_RUNNER_SHA256 = "0f00e54a149d3ad896f5e7bb2ac79b55caac371e163c948894a7d1df72e0ec21"
A304_EXECUTABLE_SHA256 = "d1c41a049db90997ada5eba880d1ba2d0787b1d74be499f0a254183f1b577acf"

WIDTH = 44
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
SLAB_BITS = 1
OUTER_LOW_BITS = 11
CELLS = 1 << PREFIX_BITS
WORD0_PER_GROUP = 1 << WORD0_SUFFIX_BITS
OUTER_SLICES = 1 << OUTER_LOW_BITS
SLABS = (0, 1)
SLAB_SIZE = WORD0_PER_GROUP * OUTER_SLICES
GROUP_SIZE = len(SLABS) * SLAB_SIZE
DOMAIN_SIZE = 1 << WIDTH
HOST_REFRESH_GROUPS = 256


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A307 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A304 = load_module(A304_RUNNER, "a307_a304_common")
W43 = A304.W43
file_sha256 = A304.file_sha256
canonical_sha256 = A304.canonical_sha256
atomic_json = A304.atomic_json
relative = A304.relative
path_from_ref = A304.path_from_ref
anchor = A304.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A307 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    engine = value.get("engine_contract", {})
    boundary = value.get("information_boundary", {})
    qualification = value.get("qualification_contract", {})
    if (
        value.get("schema") != "chacha20-round20-w44-two-slab-grouped-engine-a307-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "target_free_W44_engine_adapter_frozen_before_any_W44_production_challenge_or_candidate_exists"
        or engine.get("unknown_key_bits") != WIDTH
        or engine.get("candidate_group_size") != GROUP_SIZE
        or engine.get("slabs") != list(SLABS)
        or engine.get("filter_dispatches_per_W44_prefix_group") != len(SLABS)
        or engine.get("complete_group_before_success_evaluation") is not True
        or engine.get("early_stop_inside_group") is not False
        or engine.get("host_refresh_interval_W44_prefix_groups") != HOST_REFRESH_GROUPS
        or engine.get("full_rounds") != 20
        or engine.get("feedforward_included") is not True
        or qualification.get("complete_W44_group_gate") is not True
        or qualification.get("complete_W44_group_candidates") != GROUP_SIZE
        or boundary.get("W44_production_challenge_available_at_freeze") is not False
        or boundary.get("W44_target_assignment_available_at_freeze") is not False
        or boundary.get("W44_filter_outcome_available_at_freeze") is not False
        or boundary.get("A307_qualification_uses_only_synthetic_targets") is not True
    ):
        raise RuntimeError("A307 design semantics differ")
    sources = value["source_anchors"]
    for path_key, sha_key in (
        ("A304_protocol_path", "A304_protocol_sha256"),
        ("A304_qualification_path", "A304_qualification_sha256"),
        ("A304_runner_path", "A304_runner_sha256"),
        ("grouped_executable_path", "grouped_executable_sha256"),
    ):
        anchor(path_from_ref(sources[path_key]), sources[sha_key])
    return value


def _base_initial(challenge: Mapping[str, Any]) -> np.ndarray:
    initial = W43._initial(  # noqa: SLF001
        challenge["known_zeroed_key_words"],
        int(challenge["counter_start"]),
        challenge["nonce_words"],
        0,
    ).copy()
    initial[5] = np.uint32(int(initial[5]) & 0xFFFFF000)
    return initial


def initial_for_slab(challenge: Mapping[str, Any], slab: int) -> np.ndarray:
    if slab not in SLABS:
        raise ValueError("A307 slab must be zero or one")
    initial = _base_initial(challenge)
    initial[5] = np.uint32(int(initial[5]) | (slab << OUTER_LOW_BITS))
    return initial


def initial_for_outer12(challenge: Mapping[str, Any], outer12: int) -> np.ndarray:
    if not 0 <= outer12 < (1 << (SLAB_BITS + OUTER_LOW_BITS)):
        raise ValueError("A307 word1 low12 value is outside the W44 domain")
    initial = _base_initial(challenge)
    initial[5] = np.uint32(int(initial[5]) | outer12)
    return initial


def encode_assignment(*, word0: int, slab: int, outer_low11: int) -> int:
    if not 0 <= word0 <= 0xFFFFFFFF:
        raise ValueError("A307 word0 exceeds uint32")
    if slab not in SLABS or not 0 <= outer_low11 < OUTER_SLICES:
        raise ValueError("A307 slab/outer pair differs")
    return (((slab << OUTER_LOW_BITS) | outer_low11) << 32) | word0


def decode_assignment(assignment: int) -> dict[str, int]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A307 assignment exceeds W44")
    outer12 = assignment >> 32
    return {
        "word0": assignment & 0xFFFFFFFF,
        "word1_low12": outer12,
        "slab": outer12 >> OUTER_LOW_BITS,
        "outer_low11": outer12 & (OUTER_SLICES - 1),
    }


def scalar_blocks_w44(
    *, challenge: Mapping[str, Any], outer12: int, first_word0: int, count: int
) -> np.ndarray:
    if count <= 0 or first_word0 < 0 or first_word0 + count > 1 << 32:
        raise ValueError("A307 scalar word0 interval differs")
    initial = initial_for_outer12(challenge, outer12)
    scalar = np.repeat(initial.reshape(1, 16), count, axis=0)
    scalar[:, 4] = np.arange(first_word0, first_word0 + count, dtype=np.uint32)
    return (W43.ANCHOR.A119._core(scalar.copy(), 20) + scalar).astype(  # noqa: SLF001
        np.uint32
    )


def filter_complete_prefix(
    *,
    host: Any,
    challenge: Mapping[str, Any],
    prefix: int,
    target: np.ndarray,
    control: np.ndarray,
) -> dict[str, Any]:
    """Execute both complete 2^31 slabs before inspecting either outcome."""
    if not 0 <= prefix < CELLS:
        raise ValueError("A307 prefix is outside the exact 4096-cell cover")
    first_word0 = prefix << WORD0_SUFFIX_BITS
    slab_rows: list[dict[str, Any]] = []
    started = time.perf_counter()
    for slab in SLABS:
        host.configure(initial_for_slab(challenge, slab), target, control)
        observed = host.filter_group(
            first_word0=first_word0,
            word0_count=WORD0_PER_GROUP,
            outer_first=0,
            outer_count=OUTER_SLICES,
        )
        slab_rows.append({"slab": slab, "observed": observed})

    factual: list[int] = []
    controls: list[int] = []
    gpu_seconds = 0.0
    for row in slab_rows:
        slab = int(row["slab"])
        observed = row["observed"]
        factual.extend(
            encode_assignment(word0=int(word0), slab=slab, outer_low11=int(outer))
            for word0, outer in observed["factual"]
        )
        controls.extend(
            encode_assignment(word0=int(word0), slab=slab, outer_low11=int(outer))
            for word0, outer in observed["control"]
        )
        gpu_seconds += float(observed["gpu_seconds"])
    return {
        "prefix": prefix,
        "first_word0": first_word0,
        "factual_candidates": sorted(factual),
        "control_candidates": sorted(controls),
        "slabs_executed": list(SLABS),
        "filter_dispatches": len(SLABS),
        "logical_candidates": GROUP_SIZE,
        "complete_W44_group_before_outcome_evaluation": True,
        "early_stop_inside_group": False,
        "gpu_seconds": gpu_seconds,
        "volatile_wall_seconds": time.perf_counter() - started,
    }


def freeze() -> dict[str, Any]:
    if PROTOCOL.exists() or QUALIFICATION.exists():
        raise FileExistsError("A307 protocol or qualification already exists")
    design = load_design()
    _protocol, _order, a304_qualification = A304.load_qualification(
        A304_PROTOCOL_SHA256,
        A304_QUALIFICATION_SHA256,
    )
    payload = {
        "schema": "chacha20-round20-w44-two-slab-grouped-engine-a307-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "target_free_adapter_frozen_before_any_W44_production_challenge",
        "design_sha256": DESIGN_SHA256,
        "engine_contract": design["engine_contract"],
        "qualification_contract": design["qualification_contract"],
        "information_boundary": design["information_boundary"],
        "source_engine": {
            "attempt_id": "A304",
            "protocol_sha256": A304_PROTOCOL_SHA256,
            "qualification_artifact_sha256": A304_QUALIFICATION_SHA256,
            "qualification_sha256": a304_qualification["qualification_sha256"],
            "executable_sha256": a304_qualification["grouped_build"]["executable_sha256"],
        },
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "A304_protocol": {
                "path": relative(A304.PROTOCOL),
                "sha256": A304_PROTOCOL_SHA256,
            },
            "A304_qualification": {
                "path": relative(A304.QUALIFICATION),
                "sha256": A304_QUALIFICATION_SHA256,
            },
            "A304_runner": {
                "path": relative(A304_RUNNER),
                "sha256": A304_RUNNER_SHA256,
            },
            "grouped_executable": {
                "path": a304_qualification["grouped_build"]["executable_path"],
                "sha256": A304_EXECUTABLE_SHA256,
            },
            "A307_runner": {
                "path": relative(Path(__file__)),
                "sha256": file_sha256(Path(__file__)),
            },
            "A307_test": {
                "path": relative(A307_TEST),
                "sha256": file_sha256(A307_TEST),
            },
            "A307_reproducer": {
                "path": relative(A307_REPRO),
                "sha256": file_sha256(A307_REPRO),
            },
        },
        "production_W44_challenge_available": False,
        "production_W44_candidate_available": False,
        "production_W44_execution_started": False,
    }
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A307 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w44-two-slab-grouped-engine-a307-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "target_free_adapter_frozen_before_any_W44_production_challenge"
        or value.get("production_W44_challenge_available") is not False
        or value.get("production_W44_candidate_available") is not False
        or value.get("production_W44_execution_started") is not False
        or value.get("engine_contract", {}).get("candidate_group_size") != GROUP_SIZE
        or value.get("source_engine", {}).get("executable_sha256") != A304_EXECUTABLE_SHA256
    ):
        raise RuntimeError("A307 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    return value


def qualify(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if QUALIFICATION.exists():
        raise FileExistsError("A307 qualification already exists")
    protocol = load_protocol(expected_protocol_sha256)
    _a304_protocol, _order, a304_qualification = A304.load_qualification(
        A304_PROTOCOL_SHA256,
        A304_QUALIFICATION_SHA256,
    )
    challenge = json.loads(A304.A302.PROTOCOL.read_bytes())["public_challenge"]
    executable = path_from_ref(a304_qualification["grouped_build"]["executable_path"])
    anchor(executable, A304_EXECUTABLE_SHA256)
    placeholder = np.asarray([0, 0], dtype=np.uint32)
    host = A304.GroupedMetalHost(
        executable,
        initial_for_slab(challenge, 0),
        placeholder,
        placeholder,
    )
    boundary_rows: list[dict[str, Any]] = []
    first_word0 = 0x23456000
    count = 17
    try:
        for outer12 in (0, 1, 2047, 2048, 4095):
            slab = outer12 >> OUTER_LOW_BITS
            outer_low11 = outer12 & (OUTER_SLICES - 1)
            host.configure(initial_for_slab(challenge, slab), placeholder, placeholder)
            observed = host.blocks_group(
                first_word0=first_word0,
                word0_count=count,
                outer_first=outer_low11,
                outer_count=1,
            )[0]
            expected = scalar_blocks_w44(
                challenge=challenge,
                outer12=outer12,
                first_word0=first_word0,
                count=count,
            )
            if not np.array_equal(observed, expected):
                raise RuntimeError("A307 W44 boundary scalar identity gate failed")
            boundary_rows.append(
                {
                    "outer12": outer12,
                    "slab": slab,
                    "outer_low11": outer_low11,
                    "word0_count": count,
                    "complete_output_bits_checked": count * 512,
                    "output_sha256": hashlib.sha256(expected.astype("<u4").tobytes()).hexdigest(),
                    "grouped_equals_scalar": True,
                }
            )

        target_prefix = 0x5A3
        target_word0 = (target_prefix << WORD0_SUFFIX_BITS) | 0x13579
        target_outer12 = 0xC37
        target_block = scalar_blocks_w44(
            challenge=challenge,
            outer12=target_outer12,
            first_word0=target_word0,
            count=1,
        )[0]
        control = target_block.copy()
        control[0] ^= np.uint32(1)
        complete = filter_complete_prefix(
            host=host,
            challenge=challenge,
            prefix=target_prefix,
            target=target_block,
            control=control,
        )
        expected_assignment = (target_outer12 << 32) | target_word0
        if complete["factual_candidates"] != [expected_assignment]:
            raise RuntimeError("A307 complete W44 group factual gate failed")
        if complete["control_candidates"] != []:
            raise RuntimeError("A307 complete W44 group control gate failed")
        identity = host.identity
    finally:
        host.close()

    payload = {
        "schema": "chacha20-round20-w44-two-slab-grouped-engine-a307-qualification-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "TARGET_FREE_COMPLETE_W44_GROUP_ENGINE_EXACTLY_QUALIFIED",
        "protocol_sha256": expected_protocol_sha256,
        "production_W44_challenge_used": False,
        "production_W44_candidate_used": False,
        "source_engine_qualification_sha256": a304_qualification["qualification_sha256"],
        "source_executable_sha256": A304_EXECUTABLE_SHA256,
        "metal_identity": identity,
        "boundary_full_block_rows": boundary_rows,
        "total_boundary_output_bits_checked": sum(
            row["complete_output_bits_checked"] for row in boundary_rows
        ),
        "complete_group_gate": {
            key: value for key, value in complete.items() if not key.startswith("volatile_")
        },
        "expected_synthetic_assignment": expected_assignment,
        "expected_synthetic_assignment_hex": f"{expected_assignment:011x}",
        "synthetic_filter_exact": True,
        "matched_control_empty": True,
        "information_boundary": protocol["information_boundary"],
    }
    payload["qualification_sha256"] = canonical_sha256(
        {
            "boundary_full_block_rows": boundary_rows,
            "complete_group_gate": payload["complete_group_gate"],
            "expected_synthetic_assignment": expected_assignment,
            "source_executable_sha256": A304_EXECUTABLE_SHA256,
            "production_W44_challenge_used": False,
        }
    )
    atomic_json(QUALIFICATION, payload)
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "protocol_frozen": PROTOCOL.exists(),
        "qualification_complete": QUALIFICATION.exists(),
        "candidate_group_size": GROUP_SIZE,
        "full_domain_size": DOMAIN_SIZE,
        "slabs_per_prefix_group": len(SLABS),
        "production_target_used": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze", action="store_true")
    action.add_argument("--qualify", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.freeze:
        payload = freeze()
    else:
        if not args.expected_protocol_sha256:
            parser.error("--qualify requires --expected-protocol-sha256")
        payload = qualify(expected_protocol_sha256=args.expected_protocol_sha256)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
