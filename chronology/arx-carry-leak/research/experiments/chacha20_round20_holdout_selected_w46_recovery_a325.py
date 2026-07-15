#!/usr/bin/env python3
"""A325: transfer the A321-selected prefix operator unchanged to fresh W46."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import secrets
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_holdout_selected_w46_recovery_a325_design_v1.json"
IMPLEMENTATION_COMMITMENT = CONFIGS / "chacha20_round20_holdout_selected_w46_recovery_a325_implementation_commitment_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
CAUSAL = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.causal"
REPORT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.md"
PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"

A321_RUNNER = RESEARCH / "experiments/chacha20_round20_holdout_selected_w45_operator_a321.py"
A314_RUNNER = RESEARCH / "experiments/chacha20_round20_w45_fine_band_recovery_a314.py"
A324_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_eight_slab_grouped_engine_a324.py"
A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A325_TEST = ROOT / "tests/test_chacha20_round20_holdout_selected_w46_recovery_a325.py"
A325_REPRO = ROOT / "scripts/reproduce_chacha20_round20_holdout_selected_w46_recovery_a325.sh"

ATTEMPT_ID = "A325"
DESIGN_SHA256 = "de0262a09388a613d3fda288dcb4211c92be246d43d3ccb89dca16b71d2a9c6b"
A321_DESIGN_SHA256 = "3db5966ca254f8a5342399445d992db672fd0e9e5d40bc8ad401b0ae8cbd1e92"
A321_RUNNER_SHA256 = "61fd8e3c9635eab8cb166d8c9008df08b0cc067764f9c64da5042fa18726ef52"
A314_RUNNER_SHA256 = "f85ed4e7ae7acbd71f06aeca54609e278a1d26e16f9fbddf94e154a3b5f005f0"
A324_DESIGN_SHA256 = "9a307d00c898a325a792ea1850a8a04d5ad8c7a6e4038e9938ee0e99d3507078"
A324_PROTOCOL_SHA256 = "a787285d547e4eaaeffd808c35fcaa3f44df2ce2bd01dece67cd6f4ceb550694"
A324_RUNNER_SHA256 = "d286102bfcdf5ec4902c7e7240aa6b4ba6c9edd486933b58cbc895355b0c0f4b"

WIDTH = 46
KNOWN_KEY_BITS = 256 - WIDTH
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
WORD1_LOW_BITS = 14
CELLS = 1 << PREFIX_BITS
BLOCK_COUNT = 8
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
HOST_REFRESH_GROUPS = 64
MASK32 = 0xFFFFFFFF


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A325 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A321 = load_module(A321_RUNNER, "a325_a321_common")
A314 = load_module(A314_RUNNER, "a325_a314_common")
A324 = load_module(A324_RUNNER, "a325_a324_common")
W43 = A314.W43
file_sha256 = A314.file_sha256
canonical_sha256 = A314.canonical_sha256
sha256 = A314.sha256
atomic_json = A314.atomic_json
atomic_bytes = A314.atomic_bytes
relative = A314.relative
path_from_ref = A314.path_from_ref
anchor = A314.anchor
DOTCAUSAL_SRC = A314.DOTCAUSAL_SRC


def _exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A325 {label} is not an exact 4,096-cell cover")
    return order


def _order_sha(values: Sequence[int]) -> str:
    return sha256(b"".join(int(value).to_bytes(2, "big") for value in values))


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A325 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    transfer = value.get("order_transfer_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-holdout-selected-w46-recovery-a325-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_while_A313_recovery_is_running_before_A321_selection_A324_qualification_any_W46_challenge_or_A322_result_exists"
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("slabs_per_prefix_group") != 8
        or execution.get("host_refresh_interval_prefix_groups")
        != HOST_REFRESH_GROUPS
        or transfer.get("parameter_refit_at_W46") is not False
        or transfer.get("W46_protocol_must_freeze_before_A322_result") is not True
        or boundary.get("A313_result_available_at_design_freeze") is not False
        or boundary.get("A321_selected_operator_available_at_design_freeze") is not False
        or boundary.get("A322_result_available_at_design_freeze") is not False
        or boundary.get("W46_challenge_available_at_design_freeze") is not False
        or boundary.get("target_labels_used_for_W46_order_selection") != 0
    ):
        raise RuntimeError("A325 frozen design semantics differ")
    anchors = value["source_anchors"]
    for key, source_path in anchors.items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(source_path),
                anchors[key.removesuffix("_path") + "_sha256"],
            )
    return value


def load_implementation_commitment() -> dict[str, Any]:
    value = json.loads(IMPLEMENTATION_COMMITMENT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-holdout-selected-w46-recovery-a325-implementation-commitment-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_while_A313_recovery_is_running_before_A313_A321_A322_or_W46_outcomes"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A313_result_available_at_commitment") is not False
        or value.get("A321_selection_available_at_commitment") is not False
        or value.get("A322_result_available_at_commitment") is not False
        or value.get("W46_challenge_available_at_commitment") is not False
    ):
        raise RuntimeError("A325 implementation commitment semantics differ")
    expected = {
        "design": DESIGN,
        "runner": Path(__file__),
        "test": A325_TEST,
        "reproducer": A325_REPRO,
    }
    for name, path in expected.items():
        row = value.get("anchors", {}).get(name, {})
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A325 implementation commitment {name} hash differs")
    return value


def load_a324_qualification(expected_sha256: str) -> dict[str, Any]:
    A324.load_protocol(A324_PROTOCOL_SHA256)
    if file_sha256(A324.QUALIFICATION) != expected_sha256:
        raise RuntimeError("A325 A324 qualification artifact hash differs")
    value = json.loads(A324.QUALIFICATION.read_bytes())
    group = value.get("complete_group_gate", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-eight-slab-grouped-engine-a324-qualification-v1"
        or value.get("protocol_sha256") != A324_PROTOCOL_SHA256
        or value.get("production_W46_challenge_used") is not False
        or value.get("production_W46_candidate_used") is not False
        or value.get("synthetic_filter_exact") is not True
        or value.get("matched_control_empty") is not True
        or group.get("logical_candidates") != GROUP_SIZE
        or group.get("complete_W46_group_before_outcome_evaluation") is not True
        or group.get("slabs_executed") != list(range(8))
        or group.get("control_candidates") != []
    ):
        raise RuntimeError("A325 A324 qualification semantics differ")
    return value


def apply_assignment(known_zeroed_key_words: Sequence[int], assignment: int) -> list[int]:
    if len(known_zeroed_key_words) != 8:
        raise ValueError("A325 requires eight ChaCha20 key words")
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A325 assignment exceeds W46")
    key = [int(word) & MASK32 for word in known_zeroed_key_words]
    if key[0] != 0 or key[1] & 0x3FFF:
        raise ValueError("A325 known key does not zero the W46 interval")
    key[0] = assignment & MASK32
    key[1] |= assignment >> 32
    return key


def challenge_from_assignment(*, label: str, assignment: int) -> dict[str, Any]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A325 assignment exceeds W46")
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = W43._words(derived)  # noqa: SLF001
    known = words[:8]
    known[0] = 0
    known[1] &= 0xFFFFC000
    counter = words[8]
    nonce = words[9:12]
    full_key = apply_assignment(known, assignment)
    targets = W43._reference_outputs(full_key, counter, nonce)  # noqa: SLF001
    hashes = [sha256(W43._word_bytes(block)) for block in targets]  # noqa: SLF001
    control = [int(value) for value in targets[0]]
    control[0] ^= 1
    return {
        "challenge_id": "chacha20-r20-w46-a325-fresh-v1",
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward": True,
        "known_material_derivation_label": label,
        "known_material_derivation_sha256": sha256(derived),
        "known_zeroed_key_words": [int(value) for value in known],
        "known_key_bits": KNOWN_KEY_BITS,
        "unknown_key_bits": WIDTH,
        "unknown_layout": "key_word0_all32_plus_key_word1_low14",
        "unknown_assignment_included": False,
        "counter_start": int(counter),
        "nonce_words": [int(value) for value in nonce],
        "target_words": [[int(value) for value in block] for block in targets],
        "target_block_sha256": hashes,
        "control_target_words": control,
        "control_target_block_sha256": sha256(W43._word_bytes(control)),  # noqa: SLF001
        "public_output_blocks": BLOCK_COUNT,
        "public_output_bits": BLOCK_COUNT * 512,
        "filter_words": 2,
        "filter_bits": 64,
    }


def validate_challenge(challenge: Mapping[str, Any]) -> None:
    if (
        challenge.get("challenge_id") != "chacha20-r20-w46-a325-fresh-v1"
        or challenge.get("primitive") != "RFC8439_ChaCha20_block_function"
        or challenge.get("rounds") != 20
        or challenge.get("feedforward") is not True
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("known_key_bits") != KNOWN_KEY_BITS
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("public_output_blocks") != BLOCK_COUNT
        or len(challenge.get("known_zeroed_key_words", [])) != 8
        or len(challenge.get("nonce_words", [])) != 3
        or len(challenge.get("target_words", [])) != BLOCK_COUNT
        or any(len(block) != 16 for block in challenge.get("target_words", []))
    ):
        raise RuntimeError("A325 public challenge shape differs")
    label = str(challenge["known_material_derivation_label"])
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = W43._words(derived)  # noqa: SLF001
    expected_key = words[:8]
    expected_key[0] = 0
    expected_key[1] &= 0xFFFFC000
    targets = [[int(word) & MASK32 for word in block] for block in challenge["target_words"]]
    control = [int(word) & MASK32 for word in challenge["control_target_words"]]
    if (
        sha256(derived) != challenge["known_material_derivation_sha256"]
        or expected_key != challenge["known_zeroed_key_words"]
        or words[8] != challenge["counter_start"]
        or words[9:12] != challenge["nonce_words"]
        or expected_key[0] != 0
        or expected_key[1] & 0x3FFF
        or [sha256(W43._word_bytes(block)) for block in targets]  # noqa: SLF001
        != challenge["target_block_sha256"]
        or control[0] != (targets[0][0] ^ 1)
        or control[1:] != targets[0][1:]
        or sha256(W43._word_bytes(control))  # noqa: SLF001
        != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("A325 public challenge identity differs")


def fresh_challenge() -> dict[str, Any]:
    label = f"A325|fresh|{secrets.token_hex(32)}"
    assignment = secrets.randbits(WIDTH)
    challenge = challenge_from_assignment(label=label, assignment=assignment)
    del assignment
    validate_challenge(challenge)
    return challenge


def materialize(
    *, expected_a321_commitment_sha256: str, expected_a324_qualification_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, RESULT, CAUSAL, REPORT, PROGRESS)):
        raise FileExistsError("A325 artifacts already exist")
    if A322_RESULT.exists():
        raise RuntimeError("A325 protocol must freeze before any A322 result exists")
    design = load_design()
    _implementation_commitment = load_implementation_commitment()
    a321_commitment, a321_order = A321.load_frozen(expected_a321_commitment_sha256)
    qualification = load_a324_qualification(expected_a324_qualification_sha256)
    selected_order = _exact_order(
        a321_order["selected_W45_order"], "A321 selected order copied to W46"
    )
    selected_hash = _order_sha(selected_order)
    if selected_hash != a321_order["selection"]["selected_W45_order_uint16be_sha256"]:
        raise RuntimeError("A325 copied order hash differs from A321")
    challenge = fresh_challenge()
    public_sha = canonical_sha256(challenge)
    boundary = {
        **design["information_boundary"],
        "A313_result_used_only_through_frozen_A321_selection": True,
        "A324_qualification_verified_before_W46_challenge_generation": True,
        "A322_result_available_at_protocol_freeze": False,
        "W46_assignment_absent_from_protocol": True,
        "W46_candidate_or_prefix_rank_available_at_protocol_freeze": False,
        "target_labels_used_for_W46_order_selection": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-holdout-selected-w46-recovery-a325-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "fresh_W46_target_and_unchanged_A321_order_frozen_before_A322_or_W46_result",
        "design_sha256": DESIGN_SHA256,
        "A325_implementation_commitment_sha256": file_sha256(
            IMPLEMENTATION_COMMITMENT
        ),
        "A321_commitment_sha256": expected_a321_commitment_sha256,
        "A321_order_sha256": a321_commitment["order_sha256"],
        "A324_qualification_sha256": expected_a324_qualification_sha256,
        "A324_semantic_qualification_sha256": qualification["qualification_sha256"],
        "selected_operator": a321_order["selection"]["selected_operator"],
        "selected_family": a321_order["selection"]["selected_family"],
        "selected_A313_calibration_rank_one_based": a321_order["selection"][
            "selected_calibration_rank_one_based"
        ],
        "selected_W46_order_uint16be_sha256": selected_hash,
        "selected_W46_order": selected_order,
        "public_challenge": challenge,
        "public_challenge_sha256": public_sha,
        "execution_contract": design["execution_contract"],
        "order_transfer_contract": design["order_transfer_contract"],
        "information_boundary": boundary,
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "A325_implementation_commitment": {
                "path": relative(IMPLEMENTATION_COMMITMENT),
                "sha256": file_sha256(IMPLEMENTATION_COMMITMENT),
            },
            "A321_design": {
                "path": relative(A321.DESIGN),
                "sha256": A321_DESIGN_SHA256,
            },
            "A321_commitment": {
                "path": relative(A321.COMMITMENT),
                "sha256": expected_a321_commitment_sha256,
            },
            "A321_order": {
                "path": relative(A321.ORDER),
                "sha256": a321_commitment["order_sha256"],
            },
            "A324_protocol": {
                "path": relative(A324.PROTOCOL),
                "sha256": A324_PROTOCOL_SHA256,
            },
            "A324_qualification": {
                "path": relative(A324.QUALIFICATION),
                "sha256": expected_a324_qualification_sha256,
            },
            "A325_runner": {
                "path": relative(Path(__file__)),
                "sha256": file_sha256(Path(__file__)),
            },
            "A325_test": {
                "path": relative(A325_TEST),
                "sha256": file_sha256(A325_TEST),
            },
            "A325_reproducer": {
                "path": relative(A325_REPRO),
                "sha256": file_sha256(A325_REPRO),
            },
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "A325_implementation_commitment_sha256": file_sha256(
                IMPLEMENTATION_COMMITMENT
            ),
            "A321_commitment_sha256": expected_a321_commitment_sha256,
            "A324_qualification_sha256": expected_a324_qualification_sha256,
            "selected_operator": payload["selected_operator"],
            "selected_W46_order_uint16be_sha256": selected_hash,
            "public_challenge_sha256": public_sha,
            "execution_contract": payload["execution_contract"],
            "information_boundary": boundary,
        }
    )
    atomic_json(PROTOCOL, payload)
    return {
        "protocol": relative(PROTOCOL),
        "protocol_sha256": file_sha256(PROTOCOL),
        "public_challenge_sha256": public_sha,
        "selected_operator": payload["selected_operator"],
        "selected_W46_order_uint16be_sha256": selected_hash,
    }


def load_protocol(expected_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A325 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-holdout-selected-w46-recovery-a325-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "fresh_W46_target_and_unchanged_A321_order_frozen_before_A322_or_W46_result"
        or value.get("information_boundary", {}).get(
            "A322_result_available_at_protocol_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get(
            "W46_assignment_absent_from_protocol"
        )
        is not True
        or canonical_sha256(value.get("public_challenge"))
        != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A325 frozen protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    _commitment, selected = A321.load_frozen(value["A321_commitment_sha256"])
    order = _exact_order(value["selected_W46_order"], "protocol order")
    if (
        order != selected["selected_W45_order"]
        or _order_sha(order) != value["selected_W46_order_uint16be_sha256"]
        or value["selected_operator"] != selected["selection"]["selected_operator"]
    ):
        raise RuntimeError("A325 transferred order reconstruction differs")
    validate_challenge(value["public_challenge"])
    return value


def confirm(challenge: Mapping[str, Any], assignment: int) -> dict[str, Any]:
    key_words = apply_assignment(challenge["known_zeroed_key_words"], assignment)
    target_words = challenge["target_words"]
    byte_outputs = W43._reference_outputs(  # noqa: SLF001
        key_words,
        int(challenge["counter_start"]),
        challenge["nonce_words"],
    )
    word_outputs = [
        W43.A223.P1._chacha_block(  # noqa: SLF001
            key_words=key_words,
            counter=(int(challenge["counter_start"]) + block) & MASK32,
            nonce_words=challenge["nonce_words"],
            rounds=20,
        )
        for block in range(BLOCK_COUNT)
    ]
    byte_matches = [
        observed == expected
        for observed, expected in zip(byte_outputs, target_words, strict=True)
    ]
    word_matches = [
        observed == expected
        for observed, expected in zip(word_outputs, target_words, strict=True)
    ]
    return {
        "assignment": assignment,
        "recovered_key_words": key_words,
        "recovered_key_words_hex": [f"{word:08x}" for word in key_words],
        "byte_reference_block_matches": byte_matches,
        "word_reference_block_matches": word_matches,
        "all_blocks_match": all(byte_matches) and all(word_matches),
        "output_bits_checked_per_reference": BLOCK_COUNT * 512,
        "total_cross_implementation_output_bits_checked": BLOCK_COUNT * 512 * 2,
        "byte_reference_sha256": [
            sha256(W43._word_bytes(block)) for block in byte_outputs  # noqa: SLF001
        ],
        "word_reference_sha256": [
            sha256(W43._word_bytes(block)) for block in word_outputs  # noqa: SLF001
        ],
    }


def transferred_orders() -> dict[str, list[int]]:
    orders = {
        row["name"]: _exact_order(row["W45_order"], row["name"])
        for row in A321.candidate_pairs()
    }
    a314 = json.loads(A314.ORDER.read_bytes())
    orders["A314_three_arm_portfolio"] = _exact_order(
        a314["portfolio_order"], "A314 baseline"
    )
    return orders


def rank_panel(*, prefix: int, selected_operator: str) -> dict[str, Any]:
    orders = transferred_orders()
    if selected_operator not in A321.CANDIDATE_NAMES:
        raise ValueError("A325 selected operator is outside frozen A321 candidates")
    ranks = {name: order.index(prefix) + 1 for name, order in orders.items()}
    selected_rank = ranks[selected_operator]
    baseline_rank = ranks["A314_three_arm_portfolio"]
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "selected_operator": selected_operator,
        "prefix_ranks_one_based": ranks,
        "selected_rank_one_based": selected_rank,
        "A314_baseline_rank_one_based": baseline_rank,
        "selected_gain_bits_vs_complete_prefix_domain": math.log2(CELLS / selected_rank),
        "selected_speed_factor_vs_A314_baseline": baseline_rank / selected_rank,
        "selected_rank_computed_only_after_independent_confirmation": True,
    }


def ordered_discovery(
    *,
    host_factory: Callable[[], Any],
    challenge: Mapping[str, Any],
    order: Sequence[int],
    start_group: int = 0,
    prior_gpu_seconds: float = 0.0,
    prior_host_instances: int = 0,
    progress_callback: Callable[[Mapping[str, Any]], None] | None = None,
) -> dict[str, Any]:
    values = _exact_order(order, "recovery order")
    if not 0 <= start_group < CELLS:
        raise ValueError("A325 resume group lies outside the prefix cover")
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    host: Any | None = None
    host_instances = prior_host_instances
    gpu_seconds = prior_gpu_seconds
    started = time.perf_counter()
    try:
        for group_index in range(start_group, CELLS):
            prefix = values[group_index]
            if group_index == start_group or group_index % HOST_REFRESH_GROUPS == 0:
                if host is not None:
                    host.close()
                host = host_factory()
                host_instances += 1
            observed = A324.filter_complete_prefix(
                host=host,
                challenge=challenge,
                prefix=prefix,
                target=target,
                control=control,
            )
            factual = [int(value) for value in observed["factual_candidates"]]
            controls = [int(value) for value in observed["control_candidates"]]
            gpu_seconds += float(observed["gpu_seconds"])
            groups = group_index + 1
            if controls:
                raise RuntimeError("A325 matched control produced a candidate")
            if not factual:
                if progress_callback is not None:
                    progress_callback(
                        {
                            "status": "running",
                            "executed_prefix_groups": groups,
                            "complete_prefix_groups": CELLS,
                            "executed_assignments": groups * GROUP_SIZE,
                            "complete_domain_assignments": DOMAIN_SIZE,
                            "matched_control_candidates": 0,
                            "factual_filter_candidates": 0,
                            "gpu_seconds": gpu_seconds,
                            "host_instances": host_instances,
                            "last_completed_prefix12": prefix,
                        }
                    )
                continue
            if len(factual) != 1:
                raise RuntimeError("A325 complete W46 group produced multiple filters")
            candidate = factual[0]
            if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
                raise RuntimeError("A325 candidate prefix differs")
            found = {
                "candidate": candidate,
                "candidate_hex": f"{candidate:012x}",
                "key_word0": candidate & MASK32,
                "key_word1_low14": candidate >> 32,
                "prefix12": prefix,
                "prefix12_hex": f"{prefix:03x}",
                "executed_prefix_groups": groups,
                "executed_group_dispatches": groups * 8,
                "executed_assignments": groups * GROUP_SIZE,
                "complete_domain_assignments": DOMAIN_SIZE,
                "complete_W46_group_execution_before_stop": True,
                "early_stop_inside_group": False,
                "strict_subset_of_complete_domain": groups < CELLS,
                "search_gain_bits": math.log2(CELLS / groups),
                "factual_filter_candidates": factual,
                "matched_control_candidates": 0,
                "control_filter_candidates": [],
                "host_refresh_interval_prefix_groups": HOST_REFRESH_GROUPS,
                "host_instances": host_instances,
                "gpu_seconds": gpu_seconds,
                "volatile_wall_seconds": time.perf_counter() - started,
            }
            if progress_callback is not None:
                progress_callback({"status": "candidate_found", **found})
            return found
    finally:
        if host is not None:
            host.close()
    raise RuntimeError("A325 exact frozen order exhausted without a factual filter")


def _load_resume(
    *, protocol_sha256: str, order_sha256: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-holdout-selected-w46-recovery-a325-progress-v1"
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("selected_W46_order_uint16be_sha256") != order_sha256
        or value.get("A324_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A325 progress fingerprint differs")
    if value.get("status") == "candidate_found":
        return 0, 0.0, 0, {key: val for key, val in value.items() if key not in {
            "schema", "attempt_id", "protocol_sha256", "selected_operator",
            "selected_W46_order_uint16be_sha256", "A324_qualification_sha256", "status"
        }}
    completed = int(value.get("executed_prefix_groups", -1))
    if not 0 <= completed < CELLS or value.get("factual_filter_candidates") != 0:
        raise RuntimeError("A325 resumable progress state differs")
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A325:confirmed_holdout_selected_fullround_W46_recovery"
    writer = CausalWriter(api_id="a325w46")
    writer._rules = []
    writer.add_rule(
        name="W44_holdout_selected_order_to_unchanged_fresh_W46_search",
        description="The exact A321-selected W45 prefix order is copied unchanged to a fresh W46 challenge and every selected prefix executes eight complete slabs.",
        pattern=["A321_frozen_holdout_selected_order", "A324_exact_W46_group_engine"],
        conclusion="A325_sole_factual_W46_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="factual_W46_model_to_dual_fullround_confirmation",
        description="Independent byte and word implementations confirm the recovered 46-bit assignment across eight complete blocks.",
        pattern=["A325_sole_factual_W46_model", "dual_eight_block_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A321:frozen_holdout_selected_order",
        mechanism="unchanged_cross_width_copy_plus_eight_complete_slabs_per_prefix",
        outcome="A325:sole_factual_W46_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="holdout-selected full-round ChaCha20 W46 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A325:sole_factual_W46_model",
        mechanism="dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W46 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A321:frozen_holdout_selected_order",
        mechanism="materialized_unchanged_W46_transfer_recovery_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A325_holdout_selected_W46_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A325 unchanged holdout-selected W46 recovery",
        entities=[
            "A321:frozen_holdout_selected_order",
            "A325:sole_factual_W46_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_W46_replication_or_W47_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does unchanged holdout-selected concentration replicate on another W46 target or transfer to W47?"
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
        reader.api_id != "a325w46"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A325 authentic Causal reopen gate failed")
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
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def recover(
    *, expected_protocol_sha256: str, expected_a324_qualification_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A325 result artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    qualification = load_a324_qualification(expected_a324_qualification_sha256)
    if protocol["A324_qualification_sha256"] != expected_a324_qualification_sha256:
        raise RuntimeError("A325 protocol qualification anchor differs")
    challenge = protocol["public_challenge"]
    a324_protocol = A324.load_protocol(A324_PROTOCOL_SHA256)
    executable_row = a324_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A324.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            PROGRESS,
            {
                "schema": "chacha20-round20-holdout-selected-w46-recovery-a325-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": expected_protocol_sha256,
                "selected_operator": protocol["selected_operator"],
                "selected_W46_order_uint16be_sha256": protocol[
                    "selected_W46_order_uint16be_sha256"
                ],
                "A324_qualification_sha256": expected_a324_qualification_sha256,
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed_discovery = _load_resume(
        protocol_sha256=expected_protocol_sha256,
        order_sha256=protocol["selected_W46_order_uint16be_sha256"],
        qualification_sha256=expected_a324_qualification_sha256,
    )
    discovery = completed_discovery or ordered_discovery(
        host_factory=host_factory,
        challenge=challenge,
        order=protocol["selected_W46_order"],
        start_group=start,
        prior_gpu_seconds=prior_gpu,
        prior_host_instances=prior_hosts,
        progress_callback=write_progress,
    )
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A325 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A325 dual independent confirmation failed")
    ranks = rank_panel(
        prefix=int(discovery["prefix12"]),
        selected_operator=protocol["selected_operator"],
    )
    if ranks["selected_rank_one_based"] != discovery["executed_prefix_groups"]:
        raise RuntimeError("A325 discovery rank differs from selected order")
    strict_subset = discovery["executed_prefix_groups"] < CELLS
    evidence_stage = (
        "FULLROUND_R20_UNCHANGED_HOLDOUT_SELECTED_W46_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_UNCHANGED_HOLDOUT_SELECTED_W46_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-holdout-selected-w46-recovery-a325-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "A321_commitment_sha256": protocol["A321_commitment_sha256"],
        "A324_qualification_sha256": expected_a324_qualification_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "selected_operator": protocol["selected_operator"],
        "selected_family": protocol["selected_family"],
        "selected_A313_calibration_rank_one_based": protocol[
            "selected_A313_calibration_rank_one_based"
        ],
        "selected_W46_order_uint16be_sha256": protocol[
            "selected_W46_order_uint16be_sha256"
        ],
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W46_group_candidates": qualification["complete_group_gate"][
                "logical_candidates"
            ],
            "synthetic_filter_exact": qualification["synthetic_filter_exact"],
            "production_target_used": False,
        },
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "strict_subset_of_complete_domain": strict_subset,
        "information_boundary": protocol["information_boundary"],
        "anchors": protocol["anchors"],
    }
    stable_discovery = {
        key: value for key, value in discovery.items() if not key.startswith("volatile_")
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "selected_operator": protocol["selected_operator"],
            "selected_W46_order_uint16be_sha256": protocol[
                "selected_W46_order_uint16be_sha256"
            ],
            "discovery": stable_discovery,
            "A324_qualification_sha256": expected_a324_qualification_sha256,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
            "rank_analysis": ranks,
            "confirmation": confirmation,
            "qualification_gate": payload["qualification_gate"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A325 — unchanged holdout-selected full-round ChaCha20 W46 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Operator selected on independent W44 holdout: **{protocol['selected_operator']}**\n"
            f"- W46 execution rank: **{ranks['selected_rank_one_based']} / 4,096**\n"
            f"- Complete candidate evaluations: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W46 assignment: **0x{candidate:012x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every prefix: **eight complete 2^31 slabs before outcome evaluation**\n"
            "- Matched one-bit control: **zero candidates**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    response: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_commitment_frozen": IMPLEMENTATION_COMMITMENT.exists(),
        "A321_selection_complete": A321.ORDER.exists(),
        "A324_qualification_complete": A324.QUALIFICATION.exists(),
        "A322_result_complete": A322_RESULT.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "result_complete": RESULT.exists(),
        "progress_exists": PROGRESS.exists(),
    }
    if PROTOCOL.exists():
        response["protocol_sha256"] = file_sha256(PROTOCOL)
        protocol = json.loads(PROTOCOL.read_bytes())
        response["selected_operator"] = protocol["selected_operator"]
        response["public_challenge_sha256"] = protocol["public_challenge_sha256"]
    if PROGRESS.exists():
        response["progress"] = json.loads(PROGRESS.read_bytes())
    if RESULT.exists():
        response["result_sha256"] = file_sha256(RESULT)
        response["evidence_stage"] = json.loads(RESULT.read_bytes())["evidence_stage"]
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--materialize", action="store_true")
    action.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-a321-commitment-sha256")
    parser.add_argument("--expected-a324-qualification-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.materialize:
        if not args.expected_a321_commitment_sha256 or not args.expected_a324_qualification_sha256:
            parser.error(
                "--materialize requires --expected-a321-commitment-sha256 and --expected-a324-qualification-sha256"
            )
        payload = materialize(
            expected_a321_commitment_sha256=args.expected_a321_commitment_sha256,
            expected_a324_qualification_sha256=args.expected_a324_qualification_sha256,
        )
    else:
        if not args.expected_protocol_sha256 or not args.expected_a324_qualification_sha256:
            parser.error(
                "--recover requires --expected-protocol-sha256 and --expected-a324-qualification-sha256"
            )
        payload = recover(
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_a324_qualification_sha256=args.expected_a324_qualification_sha256,
        )
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
