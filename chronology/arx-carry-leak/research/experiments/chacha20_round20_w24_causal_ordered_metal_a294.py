#!/usr/bin/env python3
"""Prospective Causal-ordered full-round ChaCha20 W24 recovery (A294)."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import struct
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.chacha20_rfc8439_reference import (
    chacha20_block as byte_reference_block,
)
from arx_carry_leak.chacha20_rfc8439_reference import (
    rfc8439_section_2_3_2_kat,
)

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"

DESIGN = CONFIGS / "chacha20_round20_w24_causal_ordered_metal_a294_design_v1.json"
A287_PROTOCOL = CONFIGS / "chacha20_round20_w24_global_portfolio_a287_v1.json"
A291_RESULT = RESULTS / "chacha20_round20_w24_selected_channel_transfer_a291_v1.json"
A291_CAUSAL = RESULTS / "chacha20_round20_w24_selected_channel_transfer_a291_v1.causal"
A293_PROTOCOL = CONFIGS / "chacha20_round20_w24_causal_refinement_a293_v1.json"
A287_RUNNER = RESEARCH / "experiments/chacha20_round20_w24_global_portfolio_a287.py"
METAL_ANCHOR = RESEARCH / "experiments/chacha20_round20_a223_w40_metal_transfer.py"
ROOT_REFERENCE = RESEARCH / "experiments/chacha20_round20_multitarget_root_confirm.py"

PROTOCOL = CONFIGS / "chacha20_round20_w24_causal_ordered_metal_a294_v1.json"
RESULT = RESULTS / "chacha20_round20_w24_causal_ordered_metal_a294_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_W24_CAUSAL_ORDERED_METAL_A294_V1.md"
BUILD = RESEARCH / "build/chacha20_round20_w24_causal_ordered_metal_a294"

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A294"
DESIGN_SHA256 = "8836312a190faea1d6a037b7e39945c2581358a2af0a1ae6711e74b78543efc7"
WIDTH = 24
PREFIX_BITS = 12
SUFFIX_BITS = 12
PREFIX_CELLS = 1 << PREFIX_BITS
GROUP_SIZE = 1 << SUFFIX_BITS
DOMAIN_SIZE = 1 << WIDTH
BLOCKS = 8
OUTPUT_BITS = BLOCKS * 512
MASK32 = 0xFFFFFFFF


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_sha256(value: Any) -> str:
    return sha256(canonical_bytes(value))


def atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def atomic_json(path: Path, value: Any) -> None:
    atomic_bytes(
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


def relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:
        return str(resolved)


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    digest = file_sha256(path)
    if expected is not None and digest != expected:
        raise RuntimeError(f"A294 anchor differs: {path}")
    return {"path": relative(path), "sha256": digest}


def word_bytes(words: Sequence[int]) -> bytes:
    return struct.pack(f"<{len(words)}I", *(int(word) & MASK32 for word in words))


def fine_order(a291: Mapping[str, Any]) -> list[int]:
    coarse = [int(value) for value in a291["analysis"]["complete_cell_order"]]
    gray4 = [value ^ (value >> 1) for value in range(16)]
    order = [(prefix << 4) | suffix for prefix in coarse for suffix in gray4]
    if len(order) != PREFIX_CELLS or set(order) != set(range(PREFIX_CELLS)):
        raise RuntimeError("A294 Causal fine order is not an exact cover")
    return order


def public_hash_order(public_challenge_sha256: str) -> list[int]:
    seed = bytes.fromhex(public_challenge_sha256)
    order = sorted(
        range(PREFIX_CELLS),
        key=lambda value: hashlib.sha256(
            b"A294|public-hash-control|" + seed + value.to_bytes(2, "big")
        ).digest(),
    )
    if len(order) != PREFIX_CELLS or set(order) != set(range(PREFIX_CELLS)):
        raise RuntimeError("A294 public hash order is not an exact cover")
    return order


def initial_state(challenge: Mapping[str, Any], constants: Sequence[int]) -> np.ndarray:
    key = [int(value) & MASK32 for value in challenge["known_key_value_words"]]
    if len(key) != 8 or key[0] & ((1 << WIDTH) - 1):
        raise RuntimeError("A294 known key does not zero the W24 interval")
    state = np.zeros(16, dtype=np.uint32)
    state[:4] = np.asarray(constants, dtype=np.uint32)
    state[4:12] = np.asarray(key, dtype=np.uint32)
    state[12] = np.uint32(int(challenge["counter_start"]))
    state[13:16] = np.asarray(challenge["nonce_words"], dtype=np.uint32)
    return state


def _load_frozen_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A294 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    if (
        design.get("schema")
        != "chacha20-round20-w24-causal-ordered-metal-a294-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A292_and_A293_were_running_before_any_A292_or_A293_result_model_or_target_prefix_existed"
        or design.get("information_boundary", {}).get(
            "secret_assignment_available_to_design_or_runner"
        )
        is not False
    ):
        raise RuntimeError("A294 design semantics differ")
    frozen = design["frozen_inputs"]
    anchor(A287_PROTOCOL, frozen["A287_protocol_sha256"])
    anchor(A291_RESULT, frozen["A291_result_sha256"])
    anchor(A291_CAUSAL, frozen["A291_Causal_sha256"])
    anchor(A293_PROTOCOL, frozen["A293_protocol_sha256"])
    a287 = json.loads(A287_PROTOCOL.read_bytes())
    a291 = json.loads(A291_RESULT.read_bytes())
    if (
        a287.get("attempt_id") != "A287"
        or a287.get("public_challenge_sha256")
        != frozen["A287_public_challenge_sha256"]
        or canonical_sha256(a287.get("public_challenge"))
        != frozen["A287_public_challenge_sha256"]
        or a287.get("information_boundary", {}).get(
            "ephemeral_secret_available_to_preflight_or_runner"
        )
        is not False
        or a291.get("attempt_id") != "A291"
        or a291.get("analysis", {}).get("complete_cell_order_uint8_sha256")
        != frozen["A291_complete_order_uint8_sha256"]
        or a291.get("analysis", {}).get("target_labels_used") != 0
        or a291.get("analysis", {}).get("model_refits") != 0
    ):
        raise RuntimeError("A294 frozen public challenge or Causal order differs")
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(A291_CAUSAL), verify_integrity=True)
    if (
        reader.api_id != "a291w24"
        or len(reader._gaps) != 1
        or reader._gaps[0].get("expected_object_type")
        != "ranked_W24_partition_recovery_with_16_free_bits_per_cell"
    ):
        raise RuntimeError("A294 authentic A291 Reader gap differs")
    fine_order(a291)
    return design, a287, a291


def execution_plan(a287: Mapping[str, Any], a291: Mapping[str, Any]) -> dict[str, Any]:
    order = fine_order(a291)
    hash_control = public_hash_order(str(a287["public_challenge_sha256"]))
    return {
        "primitive": "standard_ChaCha20_block_function",
        "rounds": 20,
        "feedforward_included": True,
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "public_output_blocks": BLOCKS,
        "public_output_bits": OUTPUT_BITS,
        "filter_bits": 64,
        "prefix_bits": PREFIX_BITS,
        "suffix_bits_per_group": SUFFIX_BITS,
        "candidate_group_count": PREFIX_CELLS,
        "candidate_group_size": GROUP_SIZE,
        "complete_residual_domain": DOMAIN_SIZE,
        "Causal_order": order,
        "Causal_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in order)
        ),
        "numeric_control_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in range(PREFIX_CELLS))
        ),
        "public_hash_control_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in hash_control)
        ),
        "first_factual_filter_match_stops_discovery": True,
        "matched_control_scanned_over_identical_executed_groups": True,
        "confirmation": "two_independent_RFC8439_implementations_all_eight_blocks",
        "counterfactual_prefix_ranks_computed_only_after_confirmation": True,
    }


def freeze_protocol() -> dict[str, Any]:
    if PROTOCOL.exists():
        raise FileExistsError(PROTOCOL)
    design, a287, a291 = _load_frozen_inputs()
    if any(
        path.exists()
        for path in (
            RESULTS / "chacha20_round20_w24_causal_ranked_recovery_a292_v1.json",
            RESULTS / "chacha20_round20_w24_causal_refinement_a293_v1.json",
        )
    ):
        raise RuntimeError("A294 protocol must freeze before A292/A293 results")
    metal = load_module(METAL_ANCHOR, "a294_metal_anchor_freeze")
    plan = execution_plan(a287, a291)
    payload = {
        "schema": "chacha20-round20-w24-causal-ordered-metal-a294-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "Causal_candidate_order_and_native_execution_frozen_before_any_A292_or_A293_outcome",
        "public_challenge": a287["public_challenge"],
        "public_challenge_sha256": a287["public_challenge_sha256"],
        "execution_plan": plan,
        "execution_plan_sha256": canonical_sha256(plan),
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A287_protocol": anchor(A287_PROTOCOL),
            "A291_result": anchor(A291_RESULT),
            "A291_causal": anchor(A291_CAUSAL),
            "A293_protocol": anchor(A293_PROTOCOL),
            "A287_runner": anchor(A287_RUNNER),
            "Metal_anchor": anchor(METAL_ANCHOR),
            "Metal_native_source_sha256": metal.A184.NATIVE_SOURCE_SHA256,
            "root_reference": anchor(ROOT_REFERENCE),
            "byte_reference": anchor(
                Path(inspect.getsourcefile(byte_reference_block) or "")
            ),
            "runner": anchor(Path(__file__)),
        },
        "information_boundary": {
            "secret_assignment_available_to_protocol_or_runner": False,
            "target_prefix_or_model_available_before_order_freeze": False,
            "A292_result_available_at_protocol_freeze": False,
            "A293_result_available_at_protocol_freeze": False,
            "order_or_budget_may_change_after_freeze": False,
            "candidate_filter_outcomes_used_before_freeze": False,
        },
        "design": design,
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "execution_plan": plan,
            "information_boundary": payload["information_boundary"],
            "anchors": payload["anchors"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A294 protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    _, a287, a291 = _load_frozen_inputs()
    if (
        protocol.get("schema")
        != "chacha20-round20-w24-causal-ordered-metal-a294-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "Causal_candidate_order_and_native_execution_frozen_before_any_A292_or_A293_outcome"
        or protocol.get("public_challenge_sha256")
        != a287.get("public_challenge_sha256")
        or canonical_sha256(protocol.get("public_challenge"))
        != protocol.get("public_challenge_sha256")
        or protocol.get("execution_plan") != execution_plan(a287, a291)
        or protocol.get("execution_plan_sha256")
        != canonical_sha256(protocol.get("execution_plan"))
        or protocol.get("anchors", {}).get("runner", {}).get("sha256")
        != file_sha256(Path(__file__))
    ):
        raise RuntimeError("A294 protocol semantics differ")
    for name, row in protocol["anchors"].items():
        if name == "Metal_native_source_sha256":
            continue
        anchor(ROOT / row["path"] if not Path(row["path"]).is_absolute() else Path(row["path"]), row["sha256"])
    return protocol


def mapping_gate(host: Any, challenge: Mapping[str, Any], root_reference: Any) -> dict[str, Any]:
    known = [int(value) for value in challenge["known_key_value_words"]]
    prefix = 0x5A3
    candidate = prefix << SUFFIX_BITS | 0x7B1
    key = [known[0] | candidate, *known[1:]]
    target = root_reference.chacha20_block(
        key, int(challenge["counter_start"]), challenge["nonce_words"]
    )
    control = list(target)
    control[0] ^= 1
    metal = load_module(METAL_ANCHOR, "a294_metal_anchor_mapping")
    host.configure(
        initial_state(challenge, metal.A119.CONSTANTS),
        np.asarray(target, dtype=np.uint32),
        np.asarray(control, dtype=np.uint32),
    )
    start = known[0] | (prefix << SUFFIX_BITS)
    observed = host.filter(start, GROUP_SIZE)
    if observed["factual"] != [known[0] | candidate] or observed["control"]:
        raise RuntimeError("A294 Metal mapping gate failed")
    return {
        "public_synthetic_prefix12": prefix,
        "public_synthetic_suffix12": 0x7B1,
        "candidate_group_size": GROUP_SIZE,
        "factual_match_exact": True,
        "control_matches": 0,
        "gpu_seconds": float(observed["gpu_seconds"]),
    }


def ordered_discovery(
    *,
    host: Any,
    challenge: Mapping[str, Any],
    order: Sequence[int],
) -> dict[str, Any]:
    known_high = int(challenge["known_key_value_words"][0])
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    metal = load_module(METAL_ANCHOR, "a294_metal_anchor_discovery")
    host.configure(
        initial_state(challenge, metal.A119.CONSTANTS), target, control
    )
    gpu_seconds = 0.0
    for index, prefix in enumerate(order):
        start = known_high | (int(prefix) << SUFFIX_BITS)
        observed = host.filter(start, GROUP_SIZE)
        gpu_seconds += float(observed["gpu_seconds"])
        if observed["control"]:
            raise RuntimeError("A294 matched control produced a candidate")
        factual = [int(value) for value in observed["factual"]]
        if not factual:
            continue
        if len(factual) != 1:
            raise RuntimeError("A294 prefix group produced multiple filter matches")
        word0 = factual[0]
        candidate = word0 & ((1 << WIDTH) - 1)
        if candidate >> SUFFIX_BITS != int(prefix):
            raise RuntimeError("A294 recovered candidate prefix differs")
        groups = index + 1
        return {
            "candidate_low24": candidate,
            "candidate_low24_hex": f"{candidate:06x}",
            "matched_full_key_word0": word0,
            "discovery_prefix12": int(prefix),
            "discovery_prefix12_hex": f"{int(prefix):03x}",
            "Causal_prefix_rank_one_based": groups,
            "executed_prefix_groups": groups,
            "executed_assignments_upper_bound": groups * GROUP_SIZE,
            "complete_domain_assignments": DOMAIN_SIZE,
            "strict_subset_of_complete_domain": groups < PREFIX_CELLS,
            "search_gain_bits": math.log2(DOMAIN_SIZE / (groups * GROUP_SIZE)),
            "matched_control_candidates": 0,
            "gpu_seconds": gpu_seconds,
        }
    raise RuntimeError("A294 exact Causal order exhausted without a factual match")


def confirm(
    discovery: Mapping[str, Any], challenge: Mapping[str, Any], root_reference: Any
) -> dict[str, Any]:
    candidate = int(discovery["candidate_low24"])
    key_words = [
        int(challenge["known_key_value_words"][0]) | candidate,
        *[int(word) for word in challenge["known_key_value_words"][1:]],
    ]
    root_blocks = [
        root_reference.chacha20_block(
            key_words,
            (int(challenge["counter_start"]) + block) & MASK32,
            challenge["nonce_words"],
        )
        for block in range(BLOCKS)
    ]
    key_bytes = word_bytes(key_words)
    nonce_bytes = word_bytes(challenge["nonce_words"])
    byte_blocks = [
        list(
            struct.unpack(
                "<16I",
                byte_reference_block(
                    key=key_bytes,
                    counter=(int(challenge["counter_start"]) + block) & MASK32,
                    nonce=nonce_bytes,
                ),
            )
        )
        for block in range(BLOCKS)
    ]
    target = [[int(word) for word in row] for row in challenge["target_words"]]
    if root_blocks != target or byte_blocks != target or root_blocks != byte_blocks:
        raise RuntimeError("A294 dual independent 4096-bit confirmation failed")
    hashes = [sha256(word_bytes(row)) for row in root_blocks]
    if hashes != challenge["target_block_sha256"]:
        raise RuntimeError("A294 confirmed block hashes differ")
    return {
        "recovered_unknown_low24": candidate,
        "recovered_unknown_low24_hex": f"{candidate:06x}",
        "recovered_full_key_word0": key_words[0],
        "root_operation_reference_all_eight_blocks_match": True,
        "independent_byte_reference_all_eight_blocks_match": True,
        "cross_implementation_blocks_match": True,
        "output_bits_checked_per_implementation": OUTPUT_BITS,
        "cross_implementation_output_bits_checked": OUTPUT_BITS * 2,
        "block_sha256": hashes,
        "one_bit_control_rejected_over_discovery_subset": True,
    }


def rank_analysis(
    discovery: Mapping[str, Any], protocol: Mapping[str, Any]
) -> dict[str, Any]:
    prefix = int(discovery["discovery_prefix12"])
    causal = [int(value) for value in protocol["execution_plan"]["Causal_order"]]
    numeric = list(range(PREFIX_CELLS))
    hashed = public_hash_order(str(protocol["public_challenge_sha256"]))
    ranks = {
        "Causal": causal.index(prefix) + 1,
        "numeric": numeric.index(prefix) + 1,
        "public_hash_control": hashed.index(prefix) + 1,
    }
    return {
        "prefix12": prefix,
        "prefix_ranks_one_based": ranks,
        "assignment_upper_bounds": {
            name: rank * GROUP_SIZE for name, rank in ranks.items()
        },
        "Causal_gain_bits_vs_complete_domain": math.log2(
            DOMAIN_SIZE / (ranks["Causal"] * GROUP_SIZE)
        ),
        "Causal_speedup_vs_numeric_rank": ranks["numeric"] / ranks["Causal"],
        "Causal_speedup_vs_public_hash_rank": (
            ranks["public_hash_control"] / ranks["Causal"]
        ),
        "counterfactual_ranks_computed_after_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    reader_source = Path(inspect.getsourcefile(CausalReader) or "")
    terminal = "A294:confirmed_Causal_ordered_strict_subset_W24_recovery"
    writer = CausalWriter(api_id="a294w24")
    writer._rules = []
    writer.add_rule(
        name="frozen_selected_channel_order_to_direct_discovery",
        description="The frozen zero-refit A291 Reader order selects exact W24 candidate groups before any recovered model or target prefix exists.",
        pattern=["A291_frozen_Causal_order", "A294_ordered_candidate_groups"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="filter_discovery_to_dual_full_confirmation",
        description="A factual filter candidate is retained only after two independent implementations reproduce all eight standard ChaCha20 output blocks.",
        pattern=["A294_filter_candidate", "dual_4096_bit_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A291:zero_refit_complete_W24_Causal_order",
        mechanism="extend_each_coarse_cell_by_reflected_Gray4_and_scan_exact_candidate_groups",
        outcome="A294:target_blind_ordered_candidate_discovery",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="AI-native Causal ordered full-round ChaCha20 search",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A294:target_blind_ordered_candidate_discovery",
        mechanism="two_independent_RFC8439_recomputations_over_all_eight_blocks",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification="8192 cross-implementation checked bits; matched control rejected",
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="independent full-round recovery confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A291:zero_refit_complete_W24_Causal_order",
        mechanism="materialized_prospective_order_plus_discovery_plus_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A291_order_plus_A294_execution",
        quantification="AI-native exact closure retained in-file",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A294 Causal-ordered ChaCha20-R20 W24 recovery",
        entities=[
            "A291:zero_refit_complete_W24_Causal_order",
            "A294:target_blind_ordered_candidate_discovery",
            terminal,
        ],
    )
    positive_controls = (
        payload["rank_analysis"]["Causal_speedup_vs_numeric_rank"] > 1
        and payload["rank_analysis"]["Causal_speedup_vs_public_hash_rank"] > 1
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospective_multitarget_Causal_search_gain_replication_or_W28_transfer"
            if positive_controls
            else "fine_grained_selected_channel_subprefix_order"
        ),
        confidence=1.0,
        suggested_queries=(
            ["Does the frozen Causal discovery gain replicate on fresh targets or widen to W28?"]
            if positive_controls
            else ["Which selected channel orders the four unresolved subprefix bits directly?"]
        ),
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
        reader.version != 1
        or reader.api_id != "a294w24"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A294 authentic Causal gate failed")
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


def execute(expected_protocol_sha256: str, swiftc: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A294 result already exists")
    protocol = load_protocol(expected_protocol_sha256)
    if not rfc8439_section_2_3_2_kat():
        raise RuntimeError("A294 RFC 8439 gate failed")
    metal = load_module(METAL_ANCHOR, "a294_metal_anchor_run")
    root_reference = load_module(ROOT_REFERENCE, "a294_root_reference_run")
    if root_reference.rfc8439_kat().get("exact") is not True:
        raise RuntimeError("A294 independent RFC 8439 gate failed")
    executable, build = metal.A184._A181._compile_native(BUILD, swiftc)
    challenge = protocol["public_challenge"]
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    host = metal.A184.SliceMetalHost(
        executable,
        initial_state(challenge, metal.A119.CONSTANTS),
        target,
        control,
    )
    try:
        mapping = mapping_gate(host, challenge, root_reference)
        discovery = ordered_discovery(
            host=host,
            challenge=challenge,
            order=protocol["execution_plan"]["Causal_order"],
        )
        metal_identity = host.identity
    finally:
        host.close()
    confirmation = confirm(discovery, challenge, root_reference)
    ranks = rank_analysis(discovery, protocol)
    if not discovery["strict_subset_of_complete_domain"]:
        raise RuntimeError("A294 discovery did not cross the frozen strict-subset gate")
    evidence_stage = "FULLROUND_R20_W24_CAUSAL_ORDERED_STRICT_SUBSET_RECOVERY_CONFIRMED"
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w24-causal-ordered-metal-a294-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "native_build": build,
        "metal_identity": metal_identity,
        "mapping_gate": mapping,
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "information_boundary": {
            "secret_assignment_available_to_runner": False,
            "target_prefix_or_model_available_before_order_freeze": False,
            "A292_or_A293_outcome_used_to_select_order_or_budget": False,
            "candidate_groups_executed_until_first_factual_filter_match": True,
            "complete_candidate_domain_enumeration_used": False,
            "counterfactual_ranks_computed_only_after_confirmation": True,
        },
        "anchors": protocol["anchors"],
    }
    payload["execution_sha256"] = canonical_sha256(
        {"mapping_gate": mapping, "discovery": discovery, "metal_identity": metal_identity}
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": discovery,
            "rank_analysis": ranks,
            "confirmation": confirmation,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    lines = [
        "# A294 — Causal-ordered ChaCha20-R20 W24 recovery",
        "",
        f"Evidence stage: **{evidence_stage}**",
        "",
        f"- Causal prefix rank: **{ranks['prefix_ranks_one_based']['Causal']} / {PREFIX_CELLS}**",
        f"- Executed assignment upper bound: **{discovery['executed_assignments_upper_bound']:,} / {DOMAIN_SIZE:,}**",
        f"- Search gain: **{discovery['search_gain_bits']:.6f} bits**",
        f"- Numeric/hash rank speedups: **{ranks['Causal_speedup_vs_numeric_rank']:.6f}x / {ranks['Causal_speedup_vs_public_hash_rank']:.6f}x**",
        f"- Recovered low 24 bits: **0x{confirmation['recovered_unknown_low24_hex']}**",
        "- Standard ChaCha20 rounds plus feed-forward: **20**",
        "- Dual independent confirmation: **8,192 checked bits**",
        "- Complete-domain enumeration used for discovery: **no**",
        "",
        f"Result SHA-256: `{file_sha256(RESULT) if RESULT.exists() else 'written-after-report'}`",
    ]
    atomic_bytes(REPORT, ("\n".join(lines) + "\n").encode("utf-8"))
    return payload


def analyze(expected_protocol_sha256: str) -> dict[str, Any]:
    protocol = load_protocol(expected_protocol_sha256)
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "candidate_groups": PREFIX_CELLS,
        "candidate_group_size": GROUP_SIZE,
        "complete_domain": DOMAIN_SIZE,
        "Causal_order_sha256": protocol["execution_plan"][
            "Causal_order_uint16be_sha256"
        ],
        "secret_assignment_available": False,
        "target_prefix_available": False,
        "GPU_execution_started": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--swiftc", default="/usr/bin/swiftc")
    args = parser.parse_args()
    if args.freeze:
        payload = freeze_protocol()
        print(file_sha256(PROTOCOL))
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if not args.expected_protocol_sha256:
        parser.error("--expected-protocol-sha256 is required for --analyze/--run")
    payload = (
        execute(args.expected_protocol_sha256, args.swiftc)
        if args.run
        else analyze(args.expected_protocol_sha256)
    )
    if args.run:
        print(file_sha256(RESULT))
        print(file_sha256(CAUSAL))
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
