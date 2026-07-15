#!/usr/bin/env python3
"""A305: grouped execution replay of the prospectively frozen A299 W43 order."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
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

DESIGN = CONFIGS / "chacha20_round20_w43_a299_grouped_replay_a305_design_v1.json"
A299_RUNNER = RESEARCH / "experiments/chacha20_round20_w43_fine_selected_channel_transfer_a299.py"
A304_RUNNER = RESEARCH / "experiments/chacha20_round20_w43_grouped_engine_a304.py"
A305_TEST = ROOT / "tests/test_chacha20_round20_w43_a299_grouped_replay_a305.py"
A305_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w43_a299_grouped_replay_a305.sh"

PROTOCOL = CONFIGS / "chacha20_round20_w43_a299_grouped_replay_a305_v1.json"
RESULT = RESULTS / "chacha20_round20_w43_a299_grouped_replay_a305_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_W43_A299_GROUPED_REPLAY_A305_V1.md"

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A305"
DESIGN_SHA256 = "506e9d6e06877e72a69f94f352f13bee1fcb206c311091b7b8221df8eefd4f9f"
A299_PROTOCOL_SHA256 = "fbd4929df140c4de024d1c4367b9cd964a94316cf67dcf8e5a2c0d99f67ab81b"
A299_PREFLIGHT_SHA256 = "fa42610f437516655d65f6beaf7c10b254441b7715657b3fed856438eb1d0ed6"
A299_ORDER_SHA256 = "8369e7b4b421c68b344a3ea4588de350796cdc97216d71d43fc2f960df26af07"
A304_PROTOCOL_SHA256 = "2b2ea9febb74397437e0c3a772463d9ed46093461d6cc848aa6c77d2c38e7168"
A304_QUALIFICATION_SHA256 = "a9a92f4f8ecceede5dee44a429352ee4bc55e581531145fb5bb8a9606bc96c9c"
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
OUTER_SLICES = 1 << 11
CELLS = 1 << PREFIX_BITS
WORD0_PER_GROUP = 1 << WORD0_SUFFIX_BITS
GROUP_SIZE = WORD0_PER_GROUP * OUTER_SLICES
DOMAIN_SIZE = 1 << 43


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A305 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A299 = load_module(A299_RUNNER, "a305_a299_common")
A304 = load_module(A304_RUNNER, "a305_a304_common")
W43 = A299.W43
file_sha256 = A299.file_sha256
canonical_sha256 = A299.canonical_sha256
atomic_bytes = A299.atomic_bytes
atomic_json = A299.atomic_json
relative = A299.relative
path_from_ref = A299.path_from_ref
anchor = A299.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A305 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    execution = value.get("execution_contract", {})
    implementation = value.get("implementation_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w43-a299-grouped-replay-a305-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or execution.get("candidate_group_size") != GROUP_SIZE
        or execution.get("complete_prefix_group_before_success_evaluation")
        is not True
        or execution.get("full_rounds") != 20
        or implementation.get("legacy_failure_signature")
        != "Metal failure: empty buffer allocation failed"
        or implementation.get("new_filter_dispatches_per_prefix_group") != 1
        or boundary.get("A299_order_was_frozen_before_A299_candidate_or_rank_available")
        is not True
        or boundary.get("A305_engine_changes_A299_prefix_order") is not False
        or boundary.get("A305_engine_changes_candidate_membership") is not False
        or boundary.get("A305_candidate_supplied_to_grouped_runner") is not False
        or boundary.get("A305_grouped_execution_started_at_design_freeze")
        is not False
    ):
        raise RuntimeError("A305 design semantics differ")
    for path_key, sha_key in (
        ("A299_protocol_path", "A299_protocol_sha256"),
        ("A299_preflight_path", "A299_preflight_sha256"),
        ("A299_order_path", "A299_order_sha256"),
        ("A299_runner_path", "A299_runner_sha256"),
        ("A299_test_path", "A299_test_sha256"),
        ("A304_protocol_path", "A304_protocol_sha256"),
        ("A304_qualification_path", "A304_qualification_sha256"),
        ("A304_runner_path", "A304_runner_sha256"),
        ("grouped_executable_path", "grouped_executable_sha256"),
    ):
        sources = value["source_anchors"]
        anchor(path_from_ref(sources[path_key]), sources[sha_key])
    return value


def freeze() -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A305 artifacts already exist")
    design = load_design()
    a299_protocol, _preflight, order = A299.load_order(
        A299_PROTOCOL_SHA256,
        A299_PREFLIGHT_SHA256,
        A299_ORDER_SHA256,
    )
    _a304_protocol, _a302_order, qualification = A304.load_qualification(
        A304_PROTOCOL_SHA256,
        A304_QUALIFICATION_SHA256,
    )
    payload = {
        "schema": "chacha20-round20-w43-a299-grouped-replay-a305-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_A305_grouped_candidate_execution",
        "design_sha256": DESIGN_SHA256,
        "public_challenge_sha256": a299_protocol["public_challenge_sha256"],
        "source_order": {
            "attempt_id": "A299",
            "protocol_sha256": A299_PROTOCOL_SHA256,
            "preflight_sha256": A299_PREFLIGHT_SHA256,
            "order_sha256": A299_ORDER_SHA256,
            "complete_order_uint16be_sha256": order["fine_readout"][
                "complete_order_uint16be_sha256"
            ],
            "prefix_cells": len(order["fine_readout"]["complete_order"]),
        },
        "grouped_engine": {
            "attempt_id": "A304",
            "protocol_sha256": A304_PROTOCOL_SHA256,
            "qualification_artifact_sha256": A304_QUALIFICATION_SHA256,
            "qualification_sha256": qualification["qualification_sha256"],
            "executable_sha256": qualification["grouped_build"][
                "executable_sha256"
            ],
        },
        "execution_contract": design["execution_contract"],
        "implementation_boundary": design["implementation_boundary"],
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "A299_protocol": {
                "path": relative(A299.PROTOCOL),
                "sha256": A299_PROTOCOL_SHA256,
            },
            "A299_preflight": {
                "path": relative(A299.PREFLIGHT),
                "sha256": A299_PREFLIGHT_SHA256,
            },
            "A299_order": {
                "path": relative(A299.ORDER),
                "sha256": A299_ORDER_SHA256,
            },
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
                "sha256": file_sha256(A304_RUNNER),
            },
            "A305_runner": {
                "path": relative(Path(__file__)),
                "sha256": file_sha256(Path(__file__)),
            },
            "A305_test": {
                "path": relative(A305_TEST),
                "sha256": file_sha256(A305_TEST),
            },
            "A305_reproducer": {
                "path": relative(A305_REPRO),
                "sha256": file_sha256(A305_REPRO),
            },
        },
        "candidate_execution_started": False,
        "candidate_assignment_supplied_to_runner": False,
    }
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_protocol_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A305 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-a299-grouped-replay-a305-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "frozen_before_A305_grouped_candidate_execution"
        or value.get("candidate_execution_started") is not False
        or value.get("candidate_assignment_supplied_to_runner") is not False
        or value.get("source_order", {}).get("order_sha256") != A299_ORDER_SHA256
        or value.get("grouped_engine", {}).get("qualification_artifact_sha256")
        != A304_QUALIFICATION_SHA256
    ):
        raise RuntimeError("A305 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    a299_protocol, _preflight, order = A299.load_order(
        A299_PROTOCOL_SHA256,
        A299_PREFLIGHT_SHA256,
        A299_ORDER_SHA256,
    )
    if value["public_challenge_sha256"] != a299_protocol["public_challenge_sha256"]:
        raise RuntimeError("A305 public challenge anchor differs")
    return value, order


def ordered_discovery(
    *,
    host: A304.GroupedMetalHost,
    challenge: Mapping[str, Any],
    order: Sequence[int],
) -> dict[str, Any]:
    values = [int(value) for value in order]
    if len(values) != CELLS or set(values) != set(range(CELLS)):
        raise ValueError("A305 A299 prefix order is not an exact cover")
    base = W43._initial(  # noqa: SLF001
        challenge["known_zeroed_key_words"],
        int(challenge["counter_start"]),
        challenge["nonce_words"],
        0,
    )
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    host.configure(base, target, control)
    factual: list[int] = []
    controls: list[int] = []
    gpu_seconds = 0.0
    started = time.perf_counter()
    for group_index, prefix in enumerate(values):
        observed = host.filter_group(
            first_word0=prefix << WORD0_SUFFIX_BITS,
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
            raise RuntimeError("A305 complete prefix group produced multiple factual filters")
        candidate = group_factual[0]
        if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
            raise RuntimeError("A305 candidate prefix differs")
        groups = group_index + 1
        executed = groups * GROUP_SIZE
        return {
            "candidate": candidate,
            "candidate_hex": f"{candidate:011x}",
            "key_word0": candidate & 0xFFFFFFFF,
            "key_word1_low11": candidate >> 32,
            "fine_prefix12": prefix,
            "fine_prefix12_hex": f"{prefix:03x}",
            "source_operator_attempt": "A299",
            "execution_engine_attempt": "A304",
            "execution_replay_attempt": ATTEMPT_ID,
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
    raise RuntimeError("A305 exact A299 order exhausted without a factual filter")


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A305:confirmed_grouped_A299_W43_recovery"
    writer = CausalWriter(api_id="a305w43")
    writer._rules = []
    writer.add_rule(
        name="A299_order_to_grouped_execution_equivalence",
        description="The prospectively frozen A299 prefix order is executed unchanged while A304 maps every complete 2^31-member group to one two-dimensional Metal grid.",
        pattern=["A299_frozen_fine_order", "A304_complete_group_grid"],
        conclusion="A305_execution_equivalent_A299_search",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="grouped_A299_filter_to_confirmed_recovery",
        description="The sole factual two-word filter is confirmed across eight complete blocks by independent byte and word ChaCha20 implementations.",
        pattern=["A305_execution_equivalent_A299_search", "dual_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A299:prospectively_frozen_fine_W43_order",
        mechanism="A304:complete_word0_x_word1_low11_grouped_Metal_execution",
        outcome="A305:execution_equivalent_A299_search",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification=json.dumps(payload["engine_efficiency"], sort_keys=True),
        evidence=json.dumps(payload["implementation_boundary"], sort_keys=True),
        domain="AI-native full-round ChaCha20 W43 search execution",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A305:execution_equivalent_A299_search",
        mechanism="complete_prefix_groups_plus_dual_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="confirmed full-round ChaCha20 W43 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A299:prospectively_frozen_fine_W43_order",
        mechanism="materialized_A299_order_A304_execution_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A305_grouped_A299_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A305 grouped A299 W43 recovery",
        entities=[
            "A299:prospectively_frozen_fine_W43_order",
            "A305:execution_equivalent_A299_search",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_grouped_W43_replication_or_wider_residual_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the prospectively frozen A302 or A300 operator portfolio retain strict-subset gain under grouped W43 execution?"
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
        reader.api_id != "a305w43"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A305 authentic Causal reopen gate failed")
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


def recover(*, expected_protocol_sha256: str, swiftc: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A305 final artifacts already exist")
    protocol, order_value = load_protocol(expected_protocol_sha256)
    _a304_protocol, _a302_order, qualification = A304.load_qualification(
        A304_PROTOCOL_SHA256,
        A304_QUALIFICATION_SHA256,
    )
    a299_protocol = json.loads(A299.PROTOCOL.read_bytes())
    challenge = a299_protocol["public_challenge"]
    executable, build = A304.compile_native(swiftc)
    if (
        build["source_sha256"] != qualification["grouped_build"]["source_sha256"]
        or build["executable_sha256"]
        != qualification["grouped_build"]["executable_sha256"]
    ):
        raise RuntimeError("A305 grouped build differs from A304 qualification")
    base = W43._initial(  # noqa: SLF001
        challenge["known_zeroed_key_words"],
        int(challenge["counter_start"]),
        challenge["nonce_words"],
        0,
    )
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    host = A304.GroupedMetalHost(executable, base, target, control)
    try:
        discovery = ordered_discovery(
            host=host,
            challenge=challenge,
            order=[int(value) for value in order_value["fine_readout"]["complete_order"]],
        )
        identity = host.identity
    finally:
        host.close()
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A305 matched control produced a candidate")
    confirmation = W43._confirm(  # noqa: SLF001
        {"challenge": challenge}, int(discovery["candidate"])
    )
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A305 dual independent confirmation failed")
    ranks = A299.rank_analysis(
        discovery=discovery,
        order_value=order_value,
        challenge_sha=protocol["public_challenge_sha256"],
    )
    rank = ranks["prefix_ranks_one_based"]["A299_fine_selected_channel"]
    if rank != discovery["executed_prefix_groups"]:
        raise RuntimeError("A305 discovery rank differs from A299 order")
    strict_subset = rank < CELLS
    evidence_stage = (
        "FULLROUND_R20_W43_A299_GROUPED_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_W43_A299_GROUPED_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    engine_efficiency = {
        "legacy_host_JSON_requests_per_prefix_group": OUTER_SLICES * 2,
        "grouped_host_JSON_requests_per_prefix_group": 1,
        "host_request_reduction_factor": OUTER_SLICES * 2,
        "legacy_filter_dispatches_per_prefix_group": OUTER_SLICES,
        "grouped_filter_dispatches_per_prefix_group": 1,
        "filter_dispatch_reduction_factor": OUTER_SLICES,
        "candidate_membership_identical": True,
        "complete_group_semantics_identical": True,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w43-a299-grouped-replay-a305-result-v1",
        "attempt_id": ATTEMPT_ID,
        "source_operator_attempt": "A299",
        "grouped_engine_attempt": "A304",
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "A299_protocol_sha256": A299_PROTOCOL_SHA256,
        "A299_preflight_sha256": A299_PREFLIGHT_SHA256,
        "A299_order_sha256": A299_ORDER_SHA256,
        "A304_protocol_sha256": A304_PROTOCOL_SHA256,
        "A304_qualification_artifact_sha256": A304_QUALIFICATION_SHA256,
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
        "implementation_boundary": protocol["implementation_boundary"],
        "engine_efficiency": engine_efficiency,
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
            "A304_qualification_artifact_sha256": A304_QUALIFICATION_SHA256,
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
            "implementation_boundary": payload["implementation_boundary"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A305 — grouped execution replay of the frozen A299 W43 order\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Frozen A299 fine-prefix rank: **{rank} / 4,096**\n"
            f"- Search gain: **{ranks['A299_gain_bits_vs_complete_domain']:.6f} bits**\n"
            f"- Executed assignments: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W43 assignment: **0x{int(discovery['candidate']):011x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- A299 prefix order: **unchanged and prospectively frozen before rank reveal**\n"
            "- A304 grouped execution: **one complete 2^31-candidate Metal grid per prefix**\n"
            "- Matched one-bit control: **zero candidates**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode()
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "protocol_frozen": PROTOCOL.exists(),
        "result_complete": RESULT.exists(),
        "source_order": "A299",
        "grouped_engine": "A304",
        "candidate_group_size": GROUP_SIZE,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
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
            parser.error("--recover requires --expected-protocol-sha256")
        value = recover(
            expected_protocol_sha256=args.expected_protocol_sha256,
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
