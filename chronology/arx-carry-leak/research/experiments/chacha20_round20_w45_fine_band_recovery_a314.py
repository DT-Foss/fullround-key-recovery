#!/usr/bin/env python3
"""A314: fresh full-round ChaCha20 W45 fine-band recovery pipeline."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import math
import os
import secrets
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from fractions import Fraction
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"

DESIGN = CONFIGS / "chacha20_round20_w45_fine_band_recovery_a314_design_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w45_fine_band_recovery_a314_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_w45_fine_band_recovery_a314_preflight_v1.json"
COARSE = RESULTS / "chacha20_round20_w45_fine_band_recovery_a314_coarse_v1.json.zst"
ORDER = RESULTS / "chacha20_round20_w45_fine_band_recovery_a314_order_v1.json"
ORDER_CAUSAL = RESULTS / "chacha20_round20_w45_fine_band_recovery_a314_order_v1.causal"
ORDER_REPORT = REPORTS / "CHACHA20_ROUND20_W45_FINE_BAND_A314_ORDER_V1.md"
RESULT = RESULTS / "chacha20_round20_w45_fine_band_recovery_a314_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w45_fine_band_recovery_a314_v1.causal"
PROGRESS = RESULTS / "chacha20_round20_w45_fine_band_recovery_a314_progress_v1.json"
REPORT = REPORTS / "CHACHA20_ROUND20_W45_FINE_BAND_RECOVERY_A314_V1.md"
ARTIFACTS = RESEARCH / "artifacts/a314_chacha20_r20_w45_fine_band"
BUILD = RESEARCH / "build/chacha20_round20_w45_fine_band_a314"
W45_HELPER_DERIVED = BUILD / "cadical_ranked_variable_prefix_reverse_w45_derived.cpp"
W45_HELPER_BINARY = BUILD / "cadical_ranked_variable_prefix_reverse_w45"

A308_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_calibrated_coarse_numeric_a308.py"
A311_RUNNER = RESEARCH / "experiments/chacha20_round20_w45_four_slab_grouped_engine_a311.py"
A312_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_fine_selected_channel_transfer_a312.py"
A313_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_width_conditioned_fine_portfolio_a313.py"
A314_TEST = ROOT / "tests/test_chacha20_round20_w45_fine_band_recovery_a314.py"
A314_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w45_fine_band_recovery_a314.sh"

ATTEMPT_ID = "A314"
DESIGN_SHA256 = "d0508b7f0d9263620815be797c87444a7d8f10bef2676c25b4ce35630007a7ea"
A308_RUNNER_SHA256 = "c719062aa94500f43d6acae0ad329a06f0dbdd3972875530ee6256b2a98d5aae"
A311_RUNNER_SHA256 = "50786e547d93c5d1d068c83b24ad204be5caba33b3ecd5ccc737fb216763ac7c"
A312_RUNNER_SHA256 = "5adfb16542d37e8928981ff593b873c12c86cc3a1e08f062849738fe7a60037a"
A313_RUNNER_SHA256 = "2e3ef48726395d7c45bdcb859a565f4b9cc511b589aee04bfc8ea05856140484"
A311_PROTOCOL_SHA256 = "b91ee4d153f9ee88d170e333c15c13f1d42a4711b95b1ea069ada8f86816fca6"

WIDTH = 45
KNOWN_KEY_BITS = 256 - WIDTH
PREFIX_BITS = 12
SUFFIX_BITS = WIDTH - PREFIX_BITS
WORD0_SUFFIX_BITS = 20
WORD1_LOW_BITS = 13
CELLS = 1 << PREFIX_BITS
COARSE_CELLS = 1 << 8
LANES = 8
CELLS_PER_LANE = CELLS // LANES
SECONDS_PER_CELL = 5.0
CENTER = 2054
GROUP_SIZE = 1 << SUFFIX_BITS
DOMAIN_SIZE = 1 << WIDTH
BLOCK_COUNT = 8
HOST_REFRESH_GROUPS = 128
ZSTD_LEVEL = 10
MASK32 = 0xFFFFFFFF


def load_module(path: Path, name: str) -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A314 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A308 = load_module(A308_RUNNER, "a314_a308_common")
A311 = load_module(A311_RUNNER, "a314_a311_common")
A312 = load_module(A312_RUNNER, "a314_a312_common")
A313 = load_module(A313_RUNNER, "a314_a313_common")
file_sha256 = A308.file_sha256
canonical_sha256 = A308.canonical_sha256
canonical_bytes = A308.canonical_bytes
atomic_json = A308.atomic_json
atomic_bytes = A308.atomic_bytes
relative = A308.relative
path_from_ref = A308.path_from_ref
anchor = A308.anchor
sha256 = A308.sha256
DOTCAUSAL_SRC = A312.DOTCAUSAL_SRC
W43 = A311.W43


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A314 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    operator = value.get("operator_contract", {})
    fit = operator.get("fit", {})
    if (
        value.get("schema") != "chacha20-round20-w45-fine-band-recovery-a314-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "target_free_W45_end_to_end_fine_band_recovery_pipeline_frozen_before_A311_qualification_any_W45_challenge_or_A312_A313_outcome_exists"
        or fit.get("predicted_W45_fine_rank_nearest_integer") != CENTER
        or fit.get("predicted_W45_fine_rank_numerator") != 560657
        or fit.get("predicted_W45_fine_rank_denominator") != 273
        or operator.get("training_fit_is_not_recomputed_after_A311_A312_A313_or_W45_reveal")
        is not True
        or boundary.get("A311_qualification_available_at_design_freeze") is not False
        or boundary.get("W45_challenge_available_at_design_freeze") is not False
        or boundary.get("W45_secret_or_assignment_available_at_design_freeze") is not False
        or boundary.get("W45_prefix_order_available_at_design_freeze") is not False
        or boundary.get("target_labels_used") != 0
    ):
        raise RuntimeError("A314 design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(path_from_ref(source_path), value["source_anchors"][f"{stem}_sha256"])
    return value


def exact_width_fit(design: Mapping[str, Any]) -> dict[str, Any]:
    rows = A313.confirmed_training_rows(design)
    xs = [Fraction(int(row["unknown_key_bits"])) for row in rows]
    ys = [Fraction(int(row["confirmed_fine_rank_one_based"])) for row in rows]
    x_bar = sum(xs) / len(xs)
    y_bar = sum(ys) / len(ys)
    slope = sum(
        (x - x_bar) * (y - y_bar) for x, y in zip(xs, ys, strict=True)
    ) / sum((x - x_bar) ** 2 for x in xs)
    intercept = y_bar - slope * x_bar
    predicted = intercept + slope * WIDTH
    nearest = math.floor(predicted + Fraction(1, 2))
    if (
        slope != Fraction(-4671, 182)
        or intercept != Fraction(1751899, 546)
        or predicted != Fraction(560657, 273)
        or nearest != CENTER
    ):
        raise RuntimeError("A314 exact W45 width fit differs")
    return {
        "training_rows": rows,
        "slope": {"numerator": slope.numerator, "denominator": slope.denominator},
        "intercept": {
            "numerator": intercept.numerator,
            "denominator": intercept.denominator,
        },
        "predicted_W45_rank": {
            "numerator": predicted.numerator,
            "denominator": predicted.denominator,
            "decimal": float(predicted),
            "nearest_integer": nearest,
        },
    }


def load_a311_qualification(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(A311.QUALIFICATION) != expected_sha256:
        raise RuntimeError("A314 A311 qualification artifact hash differs")
    value = json.loads(A311.QUALIFICATION.read_bytes())
    group = value.get("complete_group_gate", {})
    if (
        value.get("schema")
        != "chacha20-round20-w45-four-slab-grouped-engine-a311-qualification-v1"
        or value.get("protocol_sha256") != A311_PROTOCOL_SHA256
        or value.get("production_W45_challenge_used") is not False
        or value.get("production_W45_candidate_used") is not False
        or value.get("synthetic_filter_exact") is not True
        or value.get("matched_control_empty") is not True
        or group.get("logical_candidates") != GROUP_SIZE
        or group.get("complete_W45_group_before_outcome_evaluation") is not True
        or group.get("slabs_executed") != [0, 1, 2, 3]
    ):
        raise RuntimeError("A314 A311 qualification semantics differ")
    return value


def apply_assignment(known_zeroed_key_words: Sequence[int], assignment: int) -> list[int]:
    if len(known_zeroed_key_words) != 8:
        raise ValueError("A314 requires eight ChaCha20 key words")
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A314 assignment exceeds W45")
    key = [int(word) & MASK32 for word in known_zeroed_key_words]
    if key[0] != 0 or key[1] & 0x1FFF:
        raise ValueError("A314 known key does not zero the W45 interval")
    key[0] = assignment & MASK32
    key[1] |= assignment >> 32
    return key


def challenge_from_assignment(*, label: str, assignment: int) -> dict[str, Any]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A314 assignment exceeds W45")
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = W43._words(derived)  # noqa: SLF001
    known = words[:8]
    known[0] = 0
    known[1] &= 0xFFFFE000
    counter = words[8]
    nonce = words[9:12]
    full_key = apply_assignment(known, assignment)
    targets = W43._reference_outputs(full_key, counter, nonce)  # noqa: SLF001
    hashes = [sha256(W43._word_bytes(block)) for block in targets]  # noqa: SLF001
    control = targets[0].copy()
    control[0] ^= 1
    return {
        "challenge_id": "chacha20-r20-w45-a314-fresh-v1",
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward": True,
        "known_material_derivation_label": label,
        "known_material_derivation_sha256": sha256(derived),
        "known_zeroed_key_words": known,
        "known_key_bits": KNOWN_KEY_BITS,
        "unknown_key_bits": WIDTH,
        "unknown_layout": "key_word0_all32_plus_key_word1_low13",
        "unknown_assignment_included": False,
        "counter_start": counter,
        "nonce_words": nonce,
        "target_words": targets,
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
        challenge.get("challenge_id") != "chacha20-r20-w45-a314-fresh-v1"
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
        raise RuntimeError("A314 public challenge shape differs")
    label = str(challenge["known_material_derivation_label"])
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = W43._words(derived)  # noqa: SLF001
    expected_key = words[:8]
    expected_key[0] = 0
    expected_key[1] &= 0xFFFFE000
    targets = [[int(word) & MASK32 for word in block] for block in challenge["target_words"]]
    control = [int(word) & MASK32 for word in challenge["control_target_words"]]
    if (
        sha256(derived) != challenge["known_material_derivation_sha256"]
        or expected_key != challenge["known_zeroed_key_words"]
        or words[8] != challenge["counter_start"]
        or words[9:12] != challenge["nonce_words"]
        or expected_key[0] != 0
        or expected_key[1] & 0x1FFF
        or [sha256(W43._word_bytes(block)) for block in targets]  # noqa: SLF001
        != challenge["target_block_sha256"]
        or control[0] != (targets[0][0] ^ 1)
        or control[1:] != targets[0][1:]
        or sha256(W43._word_bytes(control))  # noqa: SLF001
        != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("A314 public challenge identity differs")


def fresh_challenge() -> dict[str, Any]:
    label = f"A314|fresh|{secrets.token_hex(32)}"
    assignment = secrets.randbits(WIDTH)
    challenge = challenge_from_assignment(label=label, assignment=assignment)
    del assignment
    validate_challenge(challenge)
    return challenge


def reader_challenge(challenge: Mapping[str, Any], public_challenge_sha256: str) -> dict[str, Any]:
    validate_challenge(challenge)
    return {
        "challenge_id": "a314-reader-view-of-chacha20-r20-w45-fresh-v1",
        "rounds": 20,
        "block_count": BLOCK_COUNT,
        "counter_schedule": "base_plus_block_index_mod_2^32",
        "unknown_key_bits": WIDTH,
        "known_key_bits": KNOWN_KEY_BITS,
        "unknown_global_bit_interval": [0, WIDTH - 1],
        "unknown_bit_numbering": "little_endian_bit0_upward_across_key_words_k0_through_k7",
        "unknown_assignment_included": False,
        "unknown_assignment_value_included": False,
        "full_key_included": False,
        "secret_used_only_for_target_construction": True,
        "secret_discarded_after_target_construction": True,
        "known_key_mask_words": [0, 0xFFFFE000, *([0xFFFFFFFF] * 6)],
        "known_key_value_words": [int(value) for value in challenge["known_zeroed_key_words"]],
        "counter_start": int(challenge["counter_start"]),
        "nonce_words": [int(value) for value in challenge["nonce_words"]],
        "target_words": [[int(value) for value in block] for block in challenge["target_words"]],
        "target_block_sha256": list(challenge["target_block_sha256"]),
        "control_target_words": [int(value) for value in challenge["control_target_words"]],
        "control_target_block_sha256": challenge["control_target_block_sha256"],
        "source_public_challenge_sha256": public_challenge_sha256,
    }


def solver_model_permutation() -> list[int]:
    permutation = [*range(20), *range(32, 45), *range(20, 32)]
    if (
        len(permutation) != WIDTH
        or set(permutation) != set(range(WIDTH))
        or permutation[-PREFIX_BITS:] != list(range(20, 32))
        or list(reversed(permutation[-PREFIX_BITS:])) != list(range(31, 19, -1))
    ):
        raise RuntimeError("A314 W45 solver model permutation differs")
    return permutation


def decode_permuted_candidate(candidate: int) -> int:
    if not 0 <= candidate < DOMAIN_SIZE:
        raise ValueError("A314 permuted candidate lies outside W45")
    result = 0
    for permuted_index, original_coordinate in enumerate(solver_model_permutation()):
        result |= ((candidate >> permuted_index) & 1) << original_coordinate
    return result


def freeze(*, expected_a311_qualification_sha256: str) -> dict[str, Any]:
    outputs = (
        PROTOCOL,
        PREFLIGHT,
        COARSE,
        ORDER,
        ORDER_CAUSAL,
        ORDER_REPORT,
        RESULT,
        CAUSAL,
        PROGRESS,
        REPORT,
    )
    if any(path.exists() for path in outputs) or ARTIFACTS.exists():
        raise FileExistsError("A314 artifacts already exist")
    design = load_design()
    fit = exact_width_fit(design)
    qualification = load_a311_qualification(expected_a311_qualification_sha256)
    if not A314_TEST.exists() or not A314_REPRO.exists():
        raise FileNotFoundError("A314 test and reproducer must precede target generation")
    source_readback = A312.authentic_source_readback()
    challenge = fresh_challenge()
    public_sha = canonical_sha256(challenge)
    adapted = reader_challenge(challenge, public_sha)
    a311_protocol = A311.load_protocol(A311_PROTOCOL_SHA256)
    payload = {
        "schema": "chacha20-round20-w45-fine-band-recovery-a314-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "fresh_W45_target_frozen_after_A311_qualification_before_CNF_measurement_order_or_candidate_discovery",
        "design_sha256": DESIGN_SHA256,
        "A311_qualification_artifact_sha256": expected_a311_qualification_sha256,
        "A311_qualification_sha256": qualification["qualification_sha256"],
        "execution_contract": design["execution_contract"],
        "execution_contract_sha256": canonical_sha256(design["execution_contract"]),
        "exact_width_fit": fit,
        "public_challenge": challenge,
        "public_challenge_sha256": public_sha,
        "reader_challenge": adapted,
        "reader_challenge_sha256": canonical_sha256(adapted),
        "authentic_source_causal_readback": source_readback,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A314_TEST),
            "reproducer": anchor(A314_REPRO),
            "A308_runner": anchor(A308_RUNNER, A308_RUNNER_SHA256),
            "A311_protocol": anchor(A311.PROTOCOL, A311_PROTOCOL_SHA256),
            "A311_qualification": anchor(A311.QUALIFICATION, expected_a311_qualification_sha256),
            "A311_runner": anchor(A311_RUNNER, A311_RUNNER_SHA256),
            "A311_grouped_executable": a311_protocol["anchors"]["grouped_executable"],
            "A312_runner": anchor(A312_RUNNER, A312_RUNNER_SHA256),
            "A313_runner": anchor(A313_RUNNER, A313_RUNNER_SHA256),
            "A295_result": anchor(A312.A295_RESULT, A312.A295_RESULT_SHA256),
            "A295_causal": anchor(A312.A295_CAUSAL, A312.A295_CAUSAL_SHA256),
            "A305_result": anchor(A312.A305_RESULT, A312.A305_RESULT_SHA256),
            "A305_causal": anchor(A312.A305_CAUSAL, A312.A305_CAUSAL_SHA256),
            "CausalReader": source_readback["reader_source"],
        },
        "information_boundary": {
            **design["information_boundary"],
            "A311_qualification_verified_before_target_generation": True,
            "assignment_absent_from_protocol": True,
            "target_key_label_available": False,
            "candidate_filter_outcome_available": False,
            "measurement_or_order_available": False,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "A311_qualification_artifact_sha256": expected_a311_qualification_sha256,
            "execution_contract": payload["execution_contract"],
            "exact_width_fit": fit,
            "public_challenge_sha256": public_sha,
            "reader_challenge_sha256": payload["reader_challenge_sha256"],
            "authentic_source_causal_readback": source_readback,
            "information_boundary": payload["information_boundary"],
            "anchors": payload["anchors"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A314 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w45-fine-band-recovery-a314-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "fresh_W45_target_frozen_after_A311_qualification_before_CNF_measurement_order_or_candidate_discovery"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("exact_width_fit", {}).get("predicted_W45_rank", {}).get(
            "nearest_integer"
        )
        != CENTER
        or canonical_sha256(value.get("public_challenge")) != value.get("public_challenge_sha256")
        or canonical_sha256(value.get("reader_challenge")) != value.get("reader_challenge_sha256")
        or value.get("information_boundary", {}).get("assignment_absent_from_protocol") is not True
    ):
        raise RuntimeError("A314 protocol semantics differ")
    validate_challenge(value["public_challenge"])
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_a311_qualification(value["A311_qualification_artifact_sha256"])
    return value


def export_reader_cnf_w45(*, a223: Any, config: dict[str, Any], challenge: dict[str, Any]) -> dict[str, Any]:
    original = a223._source_formula  # noqa: SLF001

    def corrected_source_formula(source_challenge: dict[str, Any], *, width: int) -> str:
        return A312.A299.correct_non_nibble_known_word_literal(
            original(source_challenge, width=width), source_challenge, width
        )

    try:
        a223._source_formula = corrected_source_formula  # noqa: SLF001
        return A308.A302.A300.A299.A297.A296.export_reader_cnf(
            a223=a223,
            config=config,
            identifier="target",
            challenge=challenge,
            width=WIDTH,
        )
    finally:
        a223._source_formula = original  # noqa: SLF001


def preflight(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A314 preflight artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    a223 = load_module(A308.A302.A300.A299.A297.A223_SOURCE, "a314_a223_preflight")
    config = json.loads(A308.A302.A300.A299.A297.A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    a296 = A308.A302.A300.A299.A297.A296
    original_artifacts = a296.ARTIFACTS
    try:
        a296.ARTIFACTS = ARTIFACTS / "preflight"
        row = export_reader_cnf_w45(
            a223=a223,
            config=config,
            challenge=protocol["reader_challenge"],
        )
    finally:
        a296.ARTIFACTS = original_artifacts
    mapping = [int(value) for value in row["source_one_literals_bit0_upward"]]
    if len(mapping) != WIDTH or len({abs(value) for value in mapping}) != WIDTH:
        raise RuntimeError("A314 W45 source literal mapping differs")
    coarse_view = [*mapping[:12], *mapping[24:32]]
    row["synthetic_reader_mapping"] = coarse_view
    row["synthetic_reader_mapping_sha256"] = canonical_sha256(coarse_view)
    row["coarse_partition_coordinates_high_to_low"] = list(range(31, 23, -1))
    row["fine_partition_coordinates_high_to_low"] = list(range(31, 19, -1))
    row["diagnostic_model_view_coordinates"] = [*range(12), *range(24, 32)]
    row["solver_model_permutation"] = solver_model_permutation()
    row["solver_model_permutation_sha256"] = canonical_sha256(row["solver_model_permutation"])
    payload = {
        "schema": "chacha20-round20-w45-fine-band-recovery-a314-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FRESH_W45_TARGET_CNF_AND_EXACT_45_LITERAL_MAPPING_FROZEN",
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "target": row,
        "measurement_started_before_preflight": False,
        "candidate_or_rank_available": False,
        "preflight_sha256": canonical_sha256(row),
    }
    atomic_json(PREFLIGHT, payload)
    return payload


def load_preflight(
    expected_protocol_sha256: str, expected_preflight_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = load_protocol(expected_protocol_sha256)
    if file_sha256(PREFLIGHT) != expected_preflight_sha256:
        raise RuntimeError("A314 preflight hash differs")
    value = json.loads(PREFLIGHT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w45-fine-band-recovery-a314-preflight-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("public_challenge_sha256") != protocol["public_challenge_sha256"]
        or value.get("candidate_or_rank_available") is not False
        or len(value.get("target", {}).get("source_one_literals_bit0_upward", [])) != WIDTH
    ):
        raise RuntimeError("A314 preflight semantics differ")
    anchor(path_from_ref(value["target"]["CNF"]["path"]), value["target"]["CNF"]["sha256"])
    return protocol, value


def coarse_measurement(
    protocol: Mapping[str, Any], preflight_value: Mapping[str, Any]
) -> dict[str, Any]:
    a275, model, _a291, indices, helper = A308.A302.A300.A299.A297.A296._reader_stack()  # noqa: SLF001
    wrapper = load_module(A308.A302.A300.A299.A297.A251_WRAPPER, "a314_clause_wrapper")
    row = preflight_value["target"]
    started = time.perf_counter()
    raw_run = wrapper.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["CNF"]["path"]),
        mode="A314_W45_word0_high8_numeric_unlabeled",
        order=[f"{value:08b}" for value in range(COARSE_CELLS)],
        key_one_literals_bit0_through_bit19=row["synthetic_reader_mapping"],
        conflict_horizons=A308.A302.A300.A299.A297.HORIZONS,
        watchdog_seconds=A308.A302.A300.A299.A297.WATCHDOG_SECONDS,
        external_timeout_seconds=1800.0,
    )
    stable = {
        key: value for key, value in raw_run.items() if key not in {"command", "process_elapsed_seconds"}
    }
    measurement = {
        "schema": "chacha20-round20-w45-fine-band-recovery-a314-coarse-measurement-v1",
        "attempt_id": ATTEMPT_ID,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "unknown_key_bits": WIDTH,
        "order_name": "numeric",
        "partition_scope": "key_word0",
        "partition_coordinates_high_to_low": list(range(31, 23, -1)),
        "free_bits_per_cell": WIDTH - 8,
        "run": stable,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "target_label_available_to_measurement": False,
        "label_used_for_feature_construction_or_scoring": False,
        "complete_candidate_cover": len(raw_run["cells"]) == COARSE_CELLS,
    }
    matrix = a275._target_feature_matrix(measurement)  # noqa: SLF001
    contributions = a275.standardized_contributions(
        matrix,
        means=model.means,
        scales=model.scales,
        coefficients=model.coefficients,
    )
    scores = contributions[:, indices].sum(axis=1)
    order = a275._candidate_order(scores)  # noqa: SLF001
    if len(order) != COARSE_CELLS or set(order) != set(range(COARSE_CELLS)):
        raise RuntimeError("A314 coarse order is not an exact cover")
    raw = canonical_bytes(measurement)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    atomic_bytes(COARSE, compressed)
    return {
        "measurement": {
            "path": relative(COARSE),
            "raw_bytes": len(raw),
            "raw_sha256": sha256(raw),
            "compressed_bytes": len(compressed),
            "compressed_sha256": sha256(compressed),
        },
        "score_field": np.asarray(scores, dtype=np.float64).tolist(),
        "score_field_sha256": canonical_sha256(np.asarray(scores, dtype=np.float64).tolist()),
        "complete_coarse_order": order,
        "complete_coarse_order_uint8_sha256": sha256(bytes(order)),
        "selected_feature_indices": list(indices),
        "model_refits": 0,
        "target_labels_used": 0,
        "model_free_UNKNOWN_stages": len(stable["stages"]),
    }


def fine_lane_plan(
    *, preflight_value: Mapping[str, Any], coarse_readout: Mapping[str, Any]
) -> dict[str, Any]:
    fine_seed = A308.A302.A300.A299.A297.A296.fine_order(
        [int(value) for value in coarse_readout["complete_coarse_order"]]
    )
    if len(fine_seed) != CELLS or set(fine_seed) != set(range(CELLS)):
        raise RuntimeError("A314 coarse-plus-Gray fine seed is not an exact cover")
    source = preflight_value["target"]
    original_mapping = [int(value) for value in source["source_one_literals_bit0_upward"]]
    if len(original_mapping) != WIDTH or len({abs(value) for value in original_mapping}) != WIDTH:
        raise RuntimeError("A314 W45 source literal mapping differs")
    permutation = solver_model_permutation()
    permuted_mapping = [original_mapping[coordinate] for coordinate in permutation]
    arms: list[dict[str, Any]] = []
    active: list[int] = []
    for lane in range(LANES):
        front = fine_seed[lane::LANES]
        front_set = set(front)
        full = [*front, *[value for value in fine_seed if value not in front_set]]
        prefixes = [f"{value:012b}" for value in full]
        active.extend(front)
        arms.append(
            {
                "arm": f"a314_w45_fine12_lane{lane}",
                "lane": lane,
                "cadical_configuration": "default",
                "cell_order": prefixes,
                "active_prefixes": prefixes[:CELLS_PER_LANE],
                "active_prefixes_uint16be_sha256": sha256(
                    b"".join(value.to_bytes(2, "big") for value in front)
                ),
                "seconds_per_cell": SECONDS_PER_CELL,
                "max_cells": CELLS_PER_LANE,
                "cnf": source["CNF"],
                "model_one_literals_bit0_upward": permuted_mapping,
                "model_index_to_assignment_coordinate": permutation,
            }
        )
    if len(active) != CELLS or set(active) != set(range(CELLS)):
        raise RuntimeError("A314 active lane fronts are not an exact cover")
    return {
        "fine_seed_order": fine_seed,
        "fine_seed_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in fine_seed)
        ),
        "model_index_to_assignment_coordinate": permutation,
        "model_permutation_sha256": canonical_sha256(permutation),
        "arms": arms,
    }


def _trace_rows(directory: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.stdout")):
        for line in path.read_text(encoding="ascii").splitlines():
            if line.startswith("PARTITION_RESULT "):
                rows.append(json.loads(line.removeprefix("PARTITION_RESULT ")))
    return rows


def _order_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    direct = payload["direct_symbolic_winner"] is not None
    terminal = (
        "A314:direct_symbolic_W45_model_confirmed"
        if direct
        else "A314:frozen_model_free_W45_three_arm_order"
    )
    writer = CausalWriter(api_id="a314w45o")
    writer._rules = []
    writer.add_rule(
        name="W45_public_relation_to_complete_fine_field",
        description="The unchanged A295 selected-channel reader consumes a complete target-label-free W45 solver field over all 4096 word0-high12 prefixes.",
        pattern=["A314_public_W45_relation", "A295_selected_channel_reader"],
        conclusion="A314_W45_fine_readout",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="fine_readout_to_W45_execution_object",
        description="A direct model is independently confirmed, or the fine field is transformed by the precommitted W45 width-band and merged with raw fine and coarse-numeric orders under a factor-three bound.",
        pattern=["A314_W45_fine_readout", "A314_precommitted_W45_operator"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A314:public_fullround_W45_relation",
        mechanism="complete_4096_cell_selected_channel_solver_field",
        outcome="A314:W45_fine_readout",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["coverage"], sort_keys=True),
        evidence=json.dumps(payload["helper_build"], sort_keys=True),
        domain="AI-native ChaCha20-R20 W45 public-relation inference",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A314:W45_fine_readout",
        mechanism=(
            "direct_symbolic_dual_confirmation"
            if direct
            else "precommitted_width_band_plus_raw_fine_plus_coarse_numeric_baseline"
        ),
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(
            payload["confirmation"] if direct else payload["portfolio_guarantee"],
            sort_keys=True,
        ),
        evidence=payload["evidence_stage"],
        domain="W45 execution-object construction",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A314:public_fullround_W45_relation",
        mechanism="materialized_complete_fine_readout_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A314_W45_order_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A314 W45 fine-band execution object",
        entities=[
            "A314:public_fullround_W45_relation",
            "A314:W45_fine_readout",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "fresh_W45_replication_or_wider_residual_transfer"
            if direct
            else "A311_complete_grouped_execution_and_dual_confirmation"
        ),
        confidence=1.0,
        suggested_queries=[
            "Does the frozen W45 execution object recover the sole factual assignment before exhausting all 4096 complete prefix groups?"
        ],
    )
    temporary = ORDER_CAUSAL.with_name(f".{ORDER_CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, ORDER_CAUSAL)
    reader = CausalReader(str(ORDER_CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a314w45o"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A314 order Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(ORDER_CAUSAL),
        "sha256": file_sha256(ORDER_CAUSAL),
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


def measure(
    *, expected_protocol_sha256: str, expected_preflight_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (COARSE, ORDER, ORDER_CAUSAL, ORDER_REPORT)):
        raise FileExistsError("A314 measurement artifacts already exist")
    if (ARTIFACTS / "fine").exists():
        raise FileExistsError("A314 fine measurement artifacts already exist")
    protocol, preflight_value = load_preflight(
        expected_protocol_sha256, expected_preflight_sha256
    )
    coarse_readout = coarse_measurement(protocol, preflight_value)
    if coarse_readout["model_free_UNKNOWN_stages"] != 1024:
        raise RuntimeError("A314 requires exactly 1024 model-free coarse stages")
    plan = fine_lane_plan(preflight_value=preflight_value, coarse_readout=coarse_readout)
    helper_build = A312.A299.compile_w43_helper(
        output=W45_HELPER_BINARY,
        derived_source=W45_HELPER_DERIVED,
    )
    a293 = load_module(A312.A293_RUNNER, "a314_a293_fine_runner")
    original = (a293.WIDTH, a293.SUFFIX_BITS, a293.ARTIFACTS, a293.HELPER_BINARY)
    try:
        a293.WIDTH = WIDTH
        a293.SUFFIX_BITS = SUFFIX_BITS
        a293.ARTIFACTS = ARTIFACTS / "fine"
        a293.HELPER_BINARY = W45_HELPER_BINARY
        solver_rows, raw_winner = a293.run_partition(
            {"execution_plan": {"arms": plan["arms"]}}
        )
    finally:
        (a293.WIDTH, a293.SUFFIX_BITS, a293.ARTIFACTS, a293.HELPER_BINARY) = original

    traces = _trace_rows(ARTIFACTS / "fine")
    attempted = [str(row["prefix"]) for row in traces]
    if len(attempted) != len(set(attempted)):
        raise RuntimeError("A314 fine trace prefixes overlap")
    winner = None
    confirmation = None
    fine_readout = None
    band = None
    portfolio = None
    guarantee = None
    if raw_winner is not None:
        permuted_candidate = int(raw_winner["candidate_low24"])
        candidate = decode_permuted_candidate(permuted_candidate)
        prefix = int(raw_winner["prefix12"], 2)
        if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
            raise RuntimeError("A314 decoded symbolic model prefix differs")
        confirmation = confirm(protocol["public_challenge"], candidate)
        if confirmation.get("all_blocks_match") is not True:
            raise RuntimeError("A314 direct symbolic candidate failed dual confirmation")
        winner = {
            "arm": raw_winner["arm"],
            "candidate": candidate,
            "candidate_hex": f"{candidate:012x}",
            "permuted_candidate": permuted_candidate,
            "prefix12": raw_winner["prefix12"],
            "lane_cell_index": raw_winner["lane_cell_index"],
        }
    else:
        if (
            len(traces) != CELLS
            or set(attempted) != {f"{value:012b}" for value in range(CELLS)}
            or any(
                row.get("status") != "unknown" or row.get("model_bits_bit0_upward") != []
                for row in traces
            )
        ):
            raise RuntimeError("A314 requires a complete model-free W45 fine trace field")
        a295 = load_module(A312.A295_RUNNER, "a314_a295_reader")
        fine_readout = a295.frozen_order(traces)
        fine = [int(value) for value in fine_readout["complete_order"]]
        if len(fine) != CELLS or set(fine) != set(range(CELLS)):
            raise RuntimeError("A314 frozen fine order is not an exact cover")
        band = A313.band_order(fine=fine, center=CENTER)
        coarse_fine = [int(value) for value in plan["fine_seed_order"]]
        numeric = list(range(CELLS))
        baseline = A308.A302.A301.two_operator_portfolio(
            coarse=coarse_fine, numeric=numeric
        )
        portfolio = A313.three_arm_portfolio(
            band=band, fine=fine, baseline=baseline
        )
        guarantee = A313.portfolio_guarantee(
            portfolio=portfolio,
            band=band,
            fine=fine,
            baseline=baseline,
        )
        guarantee["statement"] = (
            "R_A314 <= 3 * min(R_width_band, R_fine, R_coarse_numeric_baseline)"
        )

    trace_anchors = [
        anchor(path)
        for path in sorted((ARTIFACTS / "fine").glob("*"))
        if path.is_file()
    ]
    direct = winner is not None
    components = None
    component_hashes = None
    if not direct:
        fine = [int(value) for value in fine_readout["complete_order"]]
        coarse_fine = [int(value) for value in plan["fine_seed_order"]]
        numeric = list(range(CELLS))
        baseline = A308.A302.A301.two_operator_portfolio(
            coarse=coarse_fine, numeric=numeric
        )
        components = {
            "width_conditioned_fine_rank_band": band,
            "fine_selected_channel": fine,
            "coarse_numeric_baseline": baseline,
            "coarse_high8_then_reflected_Gray4": coarse_fine,
            "numeric_word0_prefix12": numeric,
        }
        component_hashes = {
            name: sha256(b"".join(int(value).to_bytes(2, "big") for value in values))
            for name, values in components.items()
        }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w45-fine-band-recovery-a314-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FULLROUND_R20_W45_DIRECT_SYMBOLIC_RECOVERY_CONFIRMED"
            if direct
            else "FULLROUND_R20_W45_COMPLETE_MODEL_FREE_FINE_FIELD_AND_THREE_ARM_ORDER_FROZEN"
        ),
        "execution_branch": (
            "direct_symbolic_dual_confirmation_without_duplicate_grouped_execution"
            if direct
            else "complete_model_free_fine_field_to_three_arm_grouped_execution"
        ),
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "design_sha256": DESIGN_SHA256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "coarse_readout": coarse_readout,
        "helper_build": helper_build,
        "fine_lane_plan": {
            "fine_seed_order_uint16be_sha256": plan["fine_seed_order_uint16be_sha256"],
            "model_index_to_assignment_coordinate": plan[
                "model_index_to_assignment_coordinate"
            ],
            "model_permutation_sha256": plan["model_permutation_sha256"],
            "arms": plan["arms"],
        },
        "solver_arms": solver_rows,
        "attempted_prefix_cells": len(attempted),
        "direct_symbolic_winner": winner,
        "confirmation": confirmation,
        "fine_readout": fine_readout,
        "component_orders": components,
        "component_order_sha256": component_hashes,
        "portfolio_order": portfolio,
        "portfolio_order_uint16be_sha256": (
            None
            if portfolio is None
            else sha256(b"".join(value.to_bytes(2, "big") for value in portfolio))
        ),
        "portfolio_guarantee": guarantee,
        "trace_artifacts": trace_anchors,
        "coverage": {
            "coarse_prefix_cells": COARSE_CELLS,
            "fine_prefix_cells": CELLS,
            "attempted_fine_prefix_cells": len(attempted),
            "complete_model_free_fine_cover": not direct and len(attempted) == CELLS,
            "direct_symbolic_model": direct,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
        "information_boundary": {
            **load_design()["information_boundary"],
            "secret_or_assignment_read": False,
            "candidate_filter_outcome_read": False,
            "order_frozen_before_A311_production_candidate_discovery": True,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
        "anchors": {
            "protocol": anchor(PROTOCOL, expected_protocol_sha256),
            "preflight": anchor(PREFLIGHT, expected_preflight_sha256),
            "A311_qualification": anchor(
                A311.QUALIFICATION, protocol["A311_qualification_artifact_sha256"]
            ),
            "A295_result": anchor(A312.A295_RESULT, A312.A295_RESULT_SHA256),
            "A295_causal": anchor(A312.A295_CAUSAL, A312.A295_CAUSAL_SHA256),
            "A305_result": anchor(A312.A305_RESULT, A312.A305_RESULT_SHA256),
            "A305_causal": anchor(A312.A305_CAUSAL, A312.A305_CAUSAL_SHA256),
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "protocol_sha256": expected_protocol_sha256,
            "preflight_sha256": expected_preflight_sha256,
            "coarse_readout": coarse_readout,
            "helper_build": helper_build,
            "solver_arms": solver_rows,
            "attempted_prefix_cells": len(attempted),
            "direct_symbolic_winner": winner,
            "confirmation": confirmation,
            "fine_readout": fine_readout,
            "component_order_sha256": component_hashes,
            "portfolio_order_uint16be_sha256": payload[
                "portfolio_order_uint16be_sha256"
            ],
            "portfolio_guarantee": guarantee,
            "coverage": payload["coverage"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = _order_causal(payload)
    atomic_json(ORDER, payload)
    atomic_bytes(
        ORDER_REPORT,
        (
            "# A314 — W45 fine-band execution object\n\n"
            f"- Evidence: **{payload['evidence_stage']}**\n"
            f"- Coarse cells: **{COARSE_CELLS} / {COARSE_CELLS}**\n"
            f"- Attempted fine-prefix cells: **{len(attempted)} / {CELLS}**\n"
            f"- Direct symbolic model: **{'yes' if direct else 'no'}**\n"
            f"- Complete model-free fine order: **{'no' if direct else 'yes'}**\n"
            "- Reader refits: **0**\n"
            "- Target labels used: **0**\n"
            f"- Authentic AI-native Causal artifact: **{payload['causal']['sha256']}**\n"
        ).encode(),
    )
    return payload


def load_order(
    expected_protocol_sha256: str,
    expected_preflight_sha256: str,
    expected_order_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    protocol, preflight_value = load_preflight(
        expected_protocol_sha256, expected_preflight_sha256
    )
    if file_sha256(ORDER) != expected_order_sha256:
        raise RuntimeError("A314 order hash differs")
    value = json.loads(ORDER.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w45-fine-band-recovery-a314-order-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("preflight_sha256") != expected_preflight_sha256
        or value.get("public_challenge_sha256") != protocol["public_challenge_sha256"]
        or value.get("information_boundary", {}).get("target_labels_used") != 0
        or value.get("information_boundary", {}).get("candidate_filter_outcome_read")
        is not False
    ):
        raise RuntimeError("A314 order semantics differ")
    anchor(ORDER_CAUSAL, value["causal"]["sha256"])
    anchor(COARSE, value["coarse_readout"]["measurement"]["compressed_sha256"])
    if value["direct_symbolic_winner"] is not None:
        if value.get("confirmation", {}).get("all_blocks_match") is not True:
            raise RuntimeError("A314 direct branch is not confirmed")
    else:
        components = value.get("component_orders", {})
        if set(components) != {
            "width_conditioned_fine_rank_band",
            "fine_selected_channel",
            "coarse_numeric_baseline",
            "coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        } or value.get("portfolio_guarantee", {}).get("violations") != 0:
            raise RuntimeError("A314 model-free portfolio semantics differ")
        reconstructed = A313.three_arm_portfolio(
            band=components["width_conditioned_fine_rank_band"],
            fine=components["fine_selected_channel"],
            baseline=components["coarse_numeric_baseline"],
        )
        if reconstructed != value["portfolio_order"]:
            raise RuntimeError("A314 portfolio reconstruction differs")
    return protocol, preflight_value, value


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


def ordered_discovery(
    *,
    host_factory: Callable[[], Any],
    challenge: Mapping[str, Any],
    order: Sequence[int],
    host_refresh_groups: int = HOST_REFRESH_GROUPS,
    progress_callback: Callable[[Mapping[str, Any]], None] | None = None,
) -> dict[str, Any]:
    values = [int(value) for value in order]
    if len(values) != CELLS or set(values) != set(range(CELLS)):
        raise ValueError("A314 prefix order is not an exact 4096-cell cover")
    if host_refresh_groups <= 0:
        raise ValueError("A314 host refresh interval must be positive")
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    host: Any | None = None
    host_instances = 0
    factual: list[int] = []
    controls: list[int] = []
    gpu_seconds = 0.0
    started = time.perf_counter()
    try:
        for group_index, prefix in enumerate(values):
            if group_index % host_refresh_groups == 0:
                if host is not None:
                    host.close()
                host = host_factory()
                host_instances += 1
            observed = A311.filter_complete_prefix(
                host=host,
                challenge=challenge,
                prefix=prefix,
                target=target,
                control=control,
            )
            group_factual = [int(value) for value in observed["factual_candidates"]]
            group_controls = [int(value) for value in observed["control_candidates"]]
            factual.extend(group_factual)
            controls.extend(group_controls)
            gpu_seconds += float(observed["gpu_seconds"])
            if not group_factual:
                groups = group_index + 1
                if progress_callback is not None and (
                    groups == 1 or groups % 16 == 0 or groups == CELLS
                ):
                    progress_callback(
                        {
                            "status": "running",
                            "executed_prefix_groups": groups,
                            "complete_prefix_groups": CELLS,
                            "executed_assignments": groups * GROUP_SIZE,
                            "complete_domain_assignments": DOMAIN_SIZE,
                            "matched_control_candidates": len(controls),
                            "factual_filter_candidates": len(factual),
                            "gpu_seconds": gpu_seconds,
                            "last_completed_prefix12": prefix,
                        }
                    )
                continue
            if len(group_factual) != 1:
                raise RuntimeError("A314 complete W45 group produced multiple filters")
            candidate = group_factual[0]
            if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
                raise RuntimeError("A314 candidate prefix differs")
            groups = group_index + 1
            found = {
                "candidate": candidate,
                "candidate_hex": f"{candidate:012x}",
                "key_word0": candidate & MASK32,
                "key_word1_low13": candidate >> 32,
                "prefix12": prefix,
                "prefix12_hex": f"{prefix:03x}",
                "executed_prefix_groups": groups,
                "executed_group_dispatches": groups * 4,
                "executed_assignments": groups * GROUP_SIZE,
                "complete_domain_assignments": DOMAIN_SIZE,
                "complete_W45_group_execution_before_stop": True,
                "early_stop_inside_group": False,
                "strict_subset_of_complete_domain": groups < CELLS,
                "search_gain_bits": math.log2(CELLS / groups),
                "factual_filter_candidates": factual,
                "matched_control_candidates": len(controls),
                "control_filter_candidates": controls,
                "host_refresh_interval_prefix_groups": host_refresh_groups,
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
    raise RuntimeError("A314 exact frozen order exhausted without a factual filter")


def rank_analysis(*, prefix: int, order_value: Mapping[str, Any], challenge_sha: str) -> dict[str, Any]:
    components = order_value["component_orders"]
    orders = {
        "A314_three_arm_portfolio": order_value["portfolio_order"],
        "width_conditioned_fine_rank_band": components[
            "width_conditioned_fine_rank_band"
        ],
        "fine_selected_channel": components["fine_selected_channel"],
        "coarse_numeric_baseline": components["coarse_numeric_baseline"],
        "coarse_high8_then_reflected_Gray4": components[
            "coarse_high8_then_reflected_Gray4"
        ],
        "numeric_word0_prefix12": components["numeric_word0_prefix12"],
        "public_hash_control": A308.A302.A300.A299.public_hash_order(challenge_sha),
    }
    ranks = {
        name: [int(value) for value in values].index(prefix) + 1
        for name, values in orders.items()
    }
    best_three = min(
        ranks["width_conditioned_fine_rank_band"],
        ranks["fine_selected_channel"],
        ranks["coarse_numeric_baseline"],
    )
    rank = ranks["A314_three_arm_portfolio"]
    if rank > 3 * best_three:
        raise RuntimeError("A314 confirmed rank violates factor-three guarantee")
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "best_A314_arm_rank_one_based": best_three,
        "portfolio_regret_factor_vs_best_arm": rank / best_three,
        "portfolio_regret_bits_vs_best_arm": math.log2(rank / best_three),
        "portfolio_gain_bits_vs_complete_domain": math.log2(CELLS / rank),
        "assignment_upper_bounds": {
            name: value * GROUP_SIZE for name, value in ranks.items()
        },
        "rank_guarantee_holds": True,
        "component_ranks_computed_only_after_confirmation": True,
    }


def _result_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    direct = payload["execution_branch"] == "direct_symbolic_dual_confirmation"
    terminal = "A314:confirmed_fullround_W45_recovery"
    writer = CausalWriter(api_id="a314w45")
    writer._rules = []
    writer.add_rule(
        name="W45_execution_object_to_factual_model",
        description=(
            "The direct symbolic model is retained without duplicate enumeration."
            if direct
            else "The frozen three-arm order executes four complete 2^31 slabs per prefix before evaluating the factual and matched-control filters."
        ),
        pattern=["A314_frozen_W45_execution_object", "A314_exact_W45_constraints"],
        conclusion="A314_sole_factual_W45_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="factual_model_to_dual_fullround_confirmation",
        description="The recovered 45-bit assignment is confirmed across eight 20-round-plus-feed-forward blocks by independent byte and word implementations.",
        pattern=["A314_sole_factual_W45_model", "dual_eight_block_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A314:frozen_W45_execution_object",
        mechanism=(
            "direct_symbolic_constraint_solution"
            if direct
            else "four_complete_2^31_slabs_per_prefix_in_frozen_order"
        ),
        outcome="A314:sole_factual_W45_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload.get("rank_analysis"), sort_keys=True),
        domain="full-round ChaCha20 W45 residual-key recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A314:sole_factual_W45_model",
        mechanism="dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W45 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A314:frozen_W45_execution_object",
        mechanism="materialized_recovery_and_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A314_W45_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A314 confirmed full-round W45 recovery",
        entities=[
            "A314:frozen_W45_execution_object",
            "A314:sole_factual_W45_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_W45_replication_or_W46_plus_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the same target-label-free fine-band operator retain a strict-subset advantage on a fresh W45 target or a wider residual domain?"
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
        reader.api_id != "a314w45"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A314 result Causal reopen gate failed")
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
    *,
    expected_protocol_sha256: str,
    expected_preflight_sha256: str,
    expected_order_sha256: str,
    expected_a311_qualification_sha256: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A314 final artifacts already exist")
    protocol, _preflight, order_value = load_order(
        expected_protocol_sha256,
        expected_preflight_sha256,
        expected_order_sha256,
    )
    if protocol["A311_qualification_artifact_sha256"] != expected_a311_qualification_sha256:
        raise RuntimeError("A314 qualification hash differs from frozen protocol")
    qualification = load_a311_qualification(expected_a311_qualification_sha256)
    challenge = protocol["public_challenge"]
    direct = order_value["direct_symbolic_winner"] is not None
    if direct:
        candidate = int(order_value["direct_symbolic_winner"]["candidate"])
        confirmation = confirm(challenge, candidate)
        if confirmation["all_blocks_match"] is not True:
            raise RuntimeError("A314 direct branch reconfirmation failed")
        discovery = {
            "candidate": candidate,
            "candidate_hex": f"{candidate:012x}",
            "prefix12": (candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1),
            "symbolic_arm": order_value["direct_symbolic_winner"]["arm"],
            "lane_cell_index": order_value["direct_symbolic_winner"]["lane_cell_index"],
            "grouped_candidate_execution_skipped_as_predeclared": True,
            "duplicate_complete_domain_evaluation": False,
        }
        ranks = None
        strict_subset = True
        evidence_stage = "FULLROUND_R20_W45_DIRECT_SYMBOLIC_RECOVERY_DUAL_CONFIRMED"
        execution_branch = "direct_symbolic_dual_confirmation"
    else:
        a311_protocol = A311.load_protocol(A311_PROTOCOL_SHA256)
        executable_row = a311_protocol["anchors"]["grouped_executable"]
        executable = path_from_ref(executable_row["path"])
        anchor(executable, executable_row["sha256"])
        placeholder = np.asarray([0, 0], dtype=np.uint32)

        def host_factory() -> Any:
            return A311.A307.A304.GroupedMetalHost(
                executable,
                A311.initial_for_slab(challenge, 0),
                placeholder,
                placeholder,
            )

        def write_progress(row: Mapping[str, Any]) -> None:
            atomic_json(
                PROGRESS,
                {
                    "schema": "chacha20-round20-w45-fine-band-recovery-a314-progress-v1",
                    "attempt_id": ATTEMPT_ID,
                    "protocol_sha256": expected_protocol_sha256,
                    "order_sha256": expected_order_sha256,
                    "A311_qualification_artifact_sha256": expected_a311_qualification_sha256,
                    **dict(row),
                },
            )

        discovery = ordered_discovery(
            host_factory=host_factory,
            challenge=challenge,
            order=[int(value) for value in order_value["portfolio_order"]],
            progress_callback=write_progress,
        )
        if discovery["matched_control_candidates"] != 0:
            raise RuntimeError("A314 matched control produced a candidate")
        candidate = int(discovery["candidate"])
        confirmation = confirm(challenge, candidate)
        if confirmation["all_blocks_match"] is not True:
            raise RuntimeError("A314 dual independent confirmation failed")
        ranks = rank_analysis(
            prefix=int(discovery["prefix12"]),
            order_value=order_value,
            challenge_sha=protocol["public_challenge_sha256"],
        )
        rank = ranks["prefix_ranks_one_based"]["A314_three_arm_portfolio"]
        if rank != discovery["executed_prefix_groups"]:
            raise RuntimeError("A314 discovery rank differs from frozen order")
        strict_subset = rank < CELLS
        evidence_stage = (
            "FULLROUND_R20_W45_FINE_BAND_STRICT_SUBSET_RECOVERY_CONFIRMED"
            if strict_subset
            else "FULLROUND_R20_W45_FINE_BAND_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
        )
        execution_branch = "four_slab_grouped_portfolio_recovery"

    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w45-fine-band-recovery-a314-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "execution_branch": execution_branch,
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "order_sha256": expected_order_sha256,
        "A311_qualification_artifact_sha256": expected_a311_qualification_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W45_group_candidates": qualification["complete_group_gate"][
                "logical_candidates"
            ],
            "synthetic_filter_exact": qualification["synthetic_filter_exact"],
            "production_target_used": False,
        },
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "portfolio_guarantee": order_value.get("portfolio_guarantee"),
        "strict_subset_of_complete_domain": strict_subset,
        "information_boundary": order_value["information_boundary"],
        "anchors": {
            "protocol": anchor(PROTOCOL, expected_protocol_sha256),
            "preflight": anchor(PREFLIGHT, expected_preflight_sha256),
            "order": anchor(ORDER, expected_order_sha256),
            "order_causal": anchor(ORDER_CAUSAL, order_value["causal"]["sha256"]),
            "A311_qualification": anchor(
                A311.QUALIFICATION, expected_a311_qualification_sha256
            ),
        },
    }
    stable_discovery = {
        key: value for key, value in discovery.items() if not key.startswith("volatile_")
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "execution_branch": execution_branch,
            "discovery": stable_discovery,
            "A311_qualification_artifact_sha256": expected_a311_qualification_sha256,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
            "rank_analysis": ranks,
            "confirmation": confirmation,
            "qualification_gate": payload["qualification_gate"],
            "portfolio_guarantee": payload["portfolio_guarantee"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = _result_causal(payload)
    atomic_json(RESULT, payload)
    rank_text = (
        "direct symbolic model"
        if ranks is None
        else f"{ranks['prefix_ranks_one_based']['A314_three_arm_portfolio']} / {CELLS}"
    )
    assignment_text = (
        "symbolic constraint solution"
        if direct
        else f"{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}"
    )
    atomic_bytes(
        REPORT,
        (
            "# A314 — full-round ChaCha20 W45 fine-band recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Frozen execution rank: **{rank_text}**\n"
            f"- Candidate evaluations: **{assignment_text}**\n"
            f"- Recovered W45 assignment: **0x{candidate:012x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            + (
                "- Every executed prefix: **four complete 2^31 slabs before outcome evaluation**\n"
                "- Matched one-bit control: **zero candidates**\n"
                if not direct
                else "- Direct symbolic branch: **duplicate grouped enumeration skipped by frozen contract**\n"
            )
            + "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    progress = []
    fine_dir = ARTIFACTS / "fine"
    if fine_dir.exists():
        progress = [
            {
                "arm": path.stem,
                "completed_cells": sum(
                    line.startswith("PARTITION_RESULT ")
                    for line in path.read_text(encoding="ascii").splitlines()
                ),
            }
            for path in sorted(fine_dir.glob("*.stdout"))
        ]
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "A311_qualification_complete": A311.QUALIFICATION.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "preflight_complete": PREFLIGHT.exists(),
        "fine_progress": progress,
        "order_complete": ORDER.exists(),
        "result_complete": RESULT.exists(),
        "progress_checkpoint": (
            json.loads(PROGRESS.read_bytes()) if PROGRESS.exists() else None
        ),
        "predicted_W45_fine_rank_nearest_integer": CENTER,
        "candidate_group_size": GROUP_SIZE,
        "full_domain_size": DOMAIN_SIZE,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze", action="store_true")
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--measure", action="store_true")
    action.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-a311-qualification-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-preflight-sha256")
    parser.add_argument("--expected-order-sha256")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.freeze:
        if not args.expected_a311_qualification_sha256:
            parser.error("--freeze requires --expected-a311-qualification-sha256")
        payload = freeze(
            expected_a311_qualification_sha256=args.expected_a311_qualification_sha256
        )
    elif args.preflight:
        if not args.expected_protocol_sha256:
            parser.error("--preflight requires --expected-protocol-sha256")
        payload = preflight(expected_protocol_sha256=args.expected_protocol_sha256)
    elif args.measure:
        if not args.expected_protocol_sha256 or not args.expected_preflight_sha256:
            parser.error(
                "--measure requires --expected-protocol-sha256 and --expected-preflight-sha256"
            )
        payload = measure(
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_preflight_sha256=args.expected_preflight_sha256,
        )
    else:
        required = (
            args.expected_protocol_sha256,
            args.expected_preflight_sha256,
            args.expected_order_sha256,
            args.expected_a311_qualification_sha256,
        )
        if any(value is None for value in required):
            parser.error(
                "--recover requires protocol, preflight, order, and A311 qualification hashes"
            )
        payload = recover(
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_preflight_sha256=args.expected_preflight_sha256,
            expected_order_sha256=args.expected_order_sha256,
            expected_a311_qualification_sha256=args.expected_a311_qualification_sha256,
        )
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
