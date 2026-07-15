#!/usr/bin/env python3
"""A308: calibrated Causal coarse+numeric recovery on a fresh W44 target."""

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
import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"
ARTIFACTS = RESEARCH / "artifacts/a308_chacha20_r20_w44_coarse_numeric"
BUILD = RESEARCH / "build/chacha20_round20_w44_calibrated_coarse_numeric_a308"

DESIGN = CONFIGS / "chacha20_round20_w44_calibrated_coarse_numeric_a308_design_v1.json"
A302_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w43_calibrated_coarse_numeric_replication_a302.py"
)
A307_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_two_slab_grouped_engine_a307.py"
A308_TEST = ROOT / "tests/test_chacha20_round20_w44_calibrated_coarse_numeric_a308.py"
A308_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w44_calibrated_coarse_numeric_a308.sh"

PROTOCOL = CONFIGS / "chacha20_round20_w44_calibrated_coarse_numeric_a308_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_w44_calibrated_coarse_numeric_a308_preflight_v1.json"
COARSE = RESULTS / "chacha20_round20_w44_calibrated_coarse_numeric_a308_coarse_v1.json.zst"
ORDER = RESULTS / "chacha20_round20_w44_calibrated_coarse_numeric_a308_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w44_calibrated_coarse_numeric_a308_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_W44_CALIBRATED_COARSE_NUMERIC_A308_V1.md"
HELPER_DERIVED = BUILD / "cadical_ranked_variable_prefix_reverse_w44_derived.cpp"
HELPER_BINARY = BUILD / "cadical_ranked_variable_prefix_reverse_w44"

DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")
ATTEMPT_ID = "A308"
DESIGN_SHA256 = "2dc03f433ce59c49dbc5a99cd6af5f3fe0747bc5c46cb31aff091daf291063db"
A302_RUNNER_SHA256 = "335c6e002634185dd64999386723665f500953f29b7dc67573e2db654e9f91da"
A307_PROTOCOL_SHA256 = "6db581911ba38e1c02b8320e63c2e627f97800db2991266677cf972a3985935e"
A307_RUNNER_SHA256 = "717eaa14927e4313cb81ba57935773ae71b91e88e2aed982cd7ced73bcfe7669"
A307_EXECUTABLE_SHA256 = "d1c41a049db90997ada5eba880d1ba2d0787b1d74be499f0a254183f1b577acf"

WIDTH = 44
KNOWN_KEY_BITS = 256 - WIDTH
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
CELLS = 1 << PREFIX_BITS
COARSE_CELLS = 1 << 8
GROUP_SIZE = 1 << 32
DOMAIN_SIZE = 1 << WIDTH
BLOCK_COUNT = 8
HOST_REFRESH_GROUPS = 256
ZSTD_LEVEL = 10
MASK32 = 0xFFFFFFFF


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A308 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A302 = load_module(A302_RUNNER, "a308_a302_common")
A307 = load_module(A307_RUNNER, "a308_a307_common")
W43 = A302.A300.A299.W43
sha256 = A302.sha256
file_sha256 = A302.file_sha256
canonical_bytes = A302.canonical_bytes
canonical_sha256 = A302.canonical_sha256
atomic_bytes = A302.atomic_bytes
atomic_json = A302.atomic_json
relative = A302.relative
path_from_ref = A302.path_from_ref
anchor = A302.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A308 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    measurement = value.get("measurement_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w44-calibrated-coarse-numeric-a308-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_before_A307_W44_qualification_and_before_A308_runner_protocol_target_measurement_order_or_candidate_exists"
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("candidate_group_size") != GROUP_SIZE
        or execution.get("complete_residual_domain") != DOMAIN_SIZE
        or execution.get("rounds") != 20
        or execution.get("feedforward_included") is not True
        or measurement.get("coarse_cells") != COARSE_CELLS
        or measurement.get("expected_model_free_stages") != 1024
        or measurement.get("reader_refits") != 0
        or measurement.get("target_labels_used") != 0
        or boundary.get(
            "A308_assignment_target_measurement_order_model_candidate_filter_outcome_or_rank_available_at_design_freeze"
        )
        is not False
    ):
        raise RuntimeError("A308 design semantics differ")
    sources = value["source_anchors"]
    for key, source_path in sources.items():
        if not key.endswith("_path"):
            continue
        stem = key.removesuffix("_path")
        anchor(path_from_ref(source_path), sources[f"{stem}_sha256"])
    return value


def apply_assignment(known_zeroed_key_words: Sequence[int], assignment: int) -> list[int]:
    if len(known_zeroed_key_words) != 8:
        raise ValueError("A308 requires eight ChaCha20 key words")
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A308 assignment exceeds W44")
    key = [int(word) & MASK32 for word in known_zeroed_key_words]
    if key[0] != 0 or key[1] & 0xFFF:
        raise ValueError("A308 known key does not zero the W44 interval")
    key[0] = assignment & MASK32
    key[1] |= assignment >> 32
    return key


def challenge_from_assignment(*, label: str, assignment: int) -> dict[str, Any]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A308 assignment exceeds W44")
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = W43._words(derived)  # noqa: SLF001
    known = words[:8]
    known[0] = 0
    known[1] &= 0xFFFFF000
    counter = words[8]
    nonce = words[9:12]
    full_key = apply_assignment(known, assignment)
    targets = W43._reference_outputs(full_key, counter, nonce)  # noqa: SLF001
    hashes = [sha256(W43._word_bytes(block)) for block in targets]  # noqa: SLF001
    control = targets[0].copy()
    control[0] ^= 1
    return {
        "challenge_id": "chacha20-r20-w44-a308-fresh-v1",
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward": True,
        "known_material_derivation_label": label,
        "known_material_derivation_sha256": sha256(derived),
        "known_zeroed_key_words": known,
        "known_key_bits": KNOWN_KEY_BITS,
        "unknown_key_bits": WIDTH,
        "unknown_layout": "key_word0_all32_plus_key_word1_low12",
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
        challenge.get("challenge_id") != "chacha20-r20-w44-a308-fresh-v1"
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
        raise RuntimeError("A308 public challenge shape differs")
    label = str(challenge["known_material_derivation_label"])
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = W43._words(derived)  # noqa: SLF001
    expected_key = words[:8]
    expected_key[0] = 0
    expected_key[1] &= 0xFFFFF000
    targets = [[int(word) & MASK32 for word in block] for block in challenge["target_words"]]
    control = [int(word) & MASK32 for word in challenge["control_target_words"]]
    if (
        sha256(derived) != challenge["known_material_derivation_sha256"]
        or expected_key != challenge["known_zeroed_key_words"]
        or words[8] != challenge["counter_start"]
        or words[9:12] != challenge["nonce_words"]
        or expected_key[0] != 0
        or expected_key[1] & 0xFFF
        or [sha256(W43._word_bytes(block)) for block in targets]  # noqa: SLF001
        != challenge["target_block_sha256"]
        or control[0] != (targets[0][0] ^ 1)
        or control[1:] != targets[0][1:]
        or sha256(W43._word_bytes(control))  # noqa: SLF001
        != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("A308 public challenge identity differs")


def fresh_challenge() -> dict[str, Any]:
    label = f"A308|fresh|{secrets.token_hex(32)}"
    assignment = secrets.randbits(WIDTH)
    challenge = challenge_from_assignment(label=label, assignment=assignment)
    del assignment
    validate_challenge(challenge)
    return challenge


def reader_challenge(challenge: Mapping[str, Any], public_challenge_sha256: str) -> dict[str, Any]:
    validate_challenge(challenge)
    return {
        "challenge_id": "a308-reader-view-of-chacha20-r20-w44-fresh-v1",
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
        "known_key_mask_words": [0, 0xFFFFF000, *([0xFFFFFFFF] * 6)],
        "known_key_value_words": [int(value) for value in challenge["known_zeroed_key_words"]],
        "counter_start": int(challenge["counter_start"]),
        "nonce_words": [int(value) for value in challenge["nonce_words"]],
        "target_words": [[int(value) for value in block] for block in challenge["target_words"]],
        "target_block_sha256": list(challenge["target_block_sha256"]),
        "control_target_words": [int(value) for value in challenge["control_target_words"]],
        "control_target_block_sha256": challenge["control_target_block_sha256"],
        "source_public_challenge_sha256": public_challenge_sha256,
    }


def export_reader_cnf_w44(
    *, a223: Any, config: dict[str, Any], challenge: dict[str, Any]
) -> dict[str, Any]:
    return A302.A300.A299.A297.A296.export_reader_cnf(
        a223=a223,
        config=config,
        identifier="target",
        challenge=challenge,
        width=WIDTH,
    )


def execution_contract() -> dict[str, Any]:
    return load_design()["execution_contract"]


def freeze() -> dict[str, Any]:
    if (
        any(path.exists() for path in (PROTOCOL, PREFLIGHT, COARSE, ORDER, RESULT, CAUSAL, REPORT))
        or ARTIFACTS.exists()
    ):
        raise FileExistsError("A308 artifacts already exist")
    design = load_design()
    if not A308_TEST.exists() or not A308_REPRO.exists():
        raise FileNotFoundError("A308 test and reproducer must precede target generation")
    calibration = json.loads(A302.A301.CALIBRATION.read_bytes())
    aggregate = calibration["aggregate"]
    if aggregate.get("targets") != 14 or aggregate.get("strict_subset_targets") != 14:
        raise RuntimeError("A308 source calibration differs")
    a307_protocol = json.loads(A307.PROTOCOL.read_bytes())
    if (
        file_sha256(A307.PROTOCOL) != A307_PROTOCOL_SHA256
        or a307_protocol.get("production_W44_challenge_available") is not False
    ):
        raise RuntimeError("A308 requires the target-free A307 protocol")
    challenge = fresh_challenge()
    public_sha = canonical_sha256(challenge)
    adapted = reader_challenge(challenge, public_sha)
    reader_source = Path(
        inspect.getsourcefile(
            type(A302.A300._reader(A302.A300.A299.A297_CAUSAL))  # noqa: SLF001
        )
        or ""
    )
    payload = {
        "schema": "chacha20-round20-w44-calibrated-coarse-numeric-a308-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "fresh_W44_target_and_calibrated_coarse_numeric_contract_frozen_before_CNF_measurement_order_or_candidate_discovery",
        "design_sha256": DESIGN_SHA256,
        "execution_contract": design["execution_contract"],
        "execution_contract_sha256": canonical_sha256(design["execution_contract"]),
        "public_challenge": challenge,
        "public_challenge_sha256": public_sha,
        "reader_challenge": adapted,
        "reader_challenge_sha256": canonical_sha256(adapted),
        "calibration_aggregate": aggregate,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A308_TEST),
            "reproducer": anchor(A308_REPRO),
            "A302_runner": anchor(A302_RUNNER, A302_RUNNER_SHA256),
            "A301_calibration": anchor(A302.A301.CALIBRATION),
            "A297_result": anchor(A302.A300.A299.A297_RESULT),
            "A297_causal": anchor(A302.A300.A299.A297_CAUSAL),
            "A297_runner": anchor(A302.A300.A299.A297_RUNNER),
            "A223_source": anchor(A302.A300.A299.A297.A223_SOURCE),
            "A223_config": anchor(A302.A300.A299.A297.A223_CONFIG),
            "A251_wrapper": anchor(A302.A300.A299.A297.A251_WRAPPER),
            "A307_protocol": anchor(A307.PROTOCOL, A307_PROTOCOL_SHA256),
            "A307_runner": anchor(A307_RUNNER, A307_RUNNER_SHA256),
            "CausalReader": anchor(reader_source),
        },
        "information_boundary": {
            "assignment_absent_from_protocol": True,
            "target_key_label_available": False,
            "candidate_filter_outcome_available": False,
            "measurement_or_order_available": False,
            "A307_qualification_available_at_protocol_freeze": A307.QUALIFICATION.exists(),
            "reader_refits": 0,
            "target_labels_used": 0,
        },
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "execution_contract": payload["execution_contract"],
            "public_challenge_sha256": public_sha,
            "reader_challenge_sha256": payload["reader_challenge_sha256"],
            "information_boundary": payload["information_boundary"],
            "anchors": payload["anchors"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A308 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w44-calibrated-coarse-numeric-a308-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("execution_contract") != execution_contract()
        or canonical_sha256(value.get("public_challenge")) != value.get("public_challenge_sha256")
        or canonical_sha256(value.get("reader_challenge")) != value.get("reader_challenge_sha256")
        or value.get("information_boundary", {}).get("assignment_absent_from_protocol") is not True
    ):
        raise RuntimeError("A308 protocol semantics differ")
    validate_challenge(value["public_challenge"])
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    return value


def preflight(expected_protocol_sha256: str) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A308 preflight artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    a223 = load_module(A302.A300.A299.A297.A223_SOURCE, "a308_a223_preflight")
    config = json.loads(A302.A300.A299.A297.A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    original = A302.A300.A299.A297.A296.ARTIFACTS
    try:
        A302.A300.A299.A297.A296.ARTIFACTS = ARTIFACTS / "preflight"
        row = export_reader_cnf_w44(
            a223=a223,
            config=config,
            challenge=protocol["reader_challenge"],
        )
    finally:
        A302.A300.A299.A297.A296.ARTIFACTS = original
    mapping = [int(value) for value in row["source_one_literals_bit0_upward"]]
    if len(mapping) != WIDTH or len({abs(value) for value in mapping}) != WIDTH:
        raise RuntimeError("A308 W44 source literal mapping differs")
    coarse_view = [*mapping[:12], *mapping[24:32]]
    row["synthetic_reader_mapping"] = coarse_view
    row["synthetic_reader_mapping_sha256"] = canonical_sha256(coarse_view)
    row["coarse_partition_coordinates_high_to_low"] = list(range(31, 23, -1))
    row["diagnostic_model_view_coordinates"] = [*range(12), *range(24, 32)]
    payload = {
        "schema": "chacha20-round20-w44-calibrated-coarse-numeric-a308-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FRESH_W44_TARGET_CNF_AND_COARSE_MAPPING_FROZEN_BEFORE_ANY_A308_MEASUREMENT",
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
        raise RuntimeError("A308 preflight hash differs")
    value = json.loads(PREFLIGHT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w44-calibrated-coarse-numeric-a308-preflight-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("public_challenge_sha256") != protocol["public_challenge_sha256"]
        or value.get("candidate_or_rank_available") is not False
    ):
        raise RuntimeError("A308 preflight semantics differ")
    anchor(
        path_from_ref(value["target"]["CNF"]["path"]),
        value["target"]["CNF"]["sha256"],
    )
    return protocol, value


def coarse_measurement(
    protocol: Mapping[str, Any], preflight_value: Mapping[str, Any]
) -> dict[str, Any]:
    a275, model, _a291, indices, helper = (  # noqa: SLF001
        A302.A300.A299.A297.A296._reader_stack()
    )
    wrapper = load_module(A302.A300.A299.A297.A251_WRAPPER, "a308_clause_wrapper")
    row = preflight_value["target"]
    started = time.perf_counter()
    raw_run = wrapper.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["CNF"]["path"]),
        mode="A308_W44_word0_high8_numeric_unlabeled",
        order=[f"{value:08b}" for value in range(COARSE_CELLS)],
        key_one_literals_bit0_through_bit19=row["synthetic_reader_mapping"],
        conflict_horizons=A302.A300.A299.A297.HORIZONS,
        watchdog_seconds=A302.A300.A299.A297.WATCHDOG_SECONDS,
        external_timeout_seconds=1800.0,
    )
    stable = {
        key: value
        for key, value in raw_run.items()
        if key not in {"command", "process_elapsed_seconds"}
    }
    measurement = {
        "schema": "chacha20-round20-w44-calibrated-coarse-numeric-a308-measurement-v1",
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
        raise RuntimeError("A308 coarse order is not an exact cover")
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


def measure(*, expected_protocol_sha256: str, expected_preflight_sha256: str) -> dict[str, Any]:
    if COARSE.exists() or ORDER.exists():
        raise FileExistsError("A308 measurement artifacts already exist")
    protocol, preflight_value = load_preflight(expected_protocol_sha256, expected_preflight_sha256)
    coarse_readout = coarse_measurement(protocol, preflight_value)
    if coarse_readout["model_free_UNKNOWN_stages"] != 1024:
        raise RuntimeError("A308 requires exactly 1024 model-free stages")
    coarse = A302.A300.A299.A297.A296.fine_order(
        [int(value) for value in coarse_readout["complete_coarse_order"]]
    )
    numeric = list(range(CELLS))
    portfolio = A302.A301.two_operator_portfolio(coarse=coarse, numeric=numeric)
    guarantee = A302.A301.portfolio_guarantee(portfolio=portfolio, coarse=coarse, numeric=numeric)
    components = {
        "A297_coarse_high8_then_reflected_Gray4": coarse,
        "numeric_word0_prefix12": numeric,
    }
    payload = {
        "schema": "chacha20-round20-w44-calibrated-coarse-numeric-a308-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FRESH_W44_COMPLETE_MODEL_FREE_COARSE_NUMERIC_PORTFOLIO_ORDER_FROZEN",
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "coarse_readout": coarse_readout,
        "component_orders": components,
        "component_order_sha256": {
            name: sha256(b"".join(value.to_bytes(2, "big") for value in order))
            for name, order in components.items()
        },
        "portfolio_order": portfolio,
        "portfolio_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in portfolio)
        ),
        "portfolio_guarantee": guarantee,
        "measurement_efficiency": {
            "coarse_cells": COARSE_CELLS,
            "coarse_stages": 1024,
            "fine_cells": 0,
            "fine_stages": 0,
        },
        "information_boundary": {
            "target_key_label_available": False,
            "target_model_used_for_order": False,
            "candidate_filter_outcome_used_for_order": False,
            "reader_refits": 0,
            "target_labels_used": 0,
            "all_orders_frozen_before_Metal_candidate_discovery": True,
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "coarse_readout": coarse_readout,
            "component_order_sha256": payload["component_order_sha256"],
            "portfolio_order_uint16be_sha256": payload["portfolio_order_uint16be_sha256"],
            "portfolio_guarantee": guarantee,
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(ORDER, payload)
    return payload


def load_order(
    expected_protocol_sha256: str,
    expected_preflight_sha256: str,
    expected_order_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    protocol, preflight_value = load_preflight(expected_protocol_sha256, expected_preflight_sha256)
    if file_sha256(ORDER) != expected_order_sha256:
        raise RuntimeError("A308 order hash differs")
    value = json.loads(ORDER.read_bytes())
    components = value.get("component_orders", {})
    if (
        value.get("schema") != "chacha20-round20-w44-calibrated-coarse-numeric-a308-order-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("preflight_sha256") != expected_preflight_sha256
        or value.get("public_challenge_sha256") != protocol["public_challenge_sha256"]
        or set(components)
        != {
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        }
        or value.get("portfolio_guarantee", {}).get("violations") != 0
    ):
        raise RuntimeError("A308 order semantics differ")
    recomputed = A302.A301.two_operator_portfolio(
        coarse=components["A297_coarse_high8_then_reflected_Gray4"],
        numeric=components["numeric_word0_prefix12"],
    )
    if recomputed != value["portfolio_order"]:
        raise RuntimeError("A308 portfolio reconstruction differs")
    anchor(COARSE, value["coarse_readout"]["measurement"]["compressed_sha256"])
    return protocol, preflight_value, value


def load_a307_qualification(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(A307.QUALIFICATION) != expected_sha256:
        raise RuntimeError("A308 A307 qualification artifact hash differs")
    value = json.loads(A307.QUALIFICATION.read_bytes())
    group = value.get("complete_group_gate", {})
    if (
        value.get("schema") != "chacha20-round20-w44-two-slab-grouped-engine-a307-qualification-v1"
        or value.get("protocol_sha256") != A307_PROTOCOL_SHA256
        or value.get("evidence_stage") != "TARGET_FREE_COMPLETE_W44_GROUP_ENGINE_EXACTLY_QUALIFIED"
        or value.get("production_W44_challenge_used") is not False
        or value.get("production_W44_candidate_used") is not False
        or value.get("source_executable_sha256") != A307_EXECUTABLE_SHA256
        or group.get("logical_candidates") != GROUP_SIZE
        or group.get("slabs_executed") != [0, 1]
        or group.get("complete_W44_group_before_outcome_evaluation") is not True
        or len(group.get("factual_candidates", [])) != 1
        or group.get("control_candidates") != []
        or value.get("synthetic_filter_exact") is not True
    ):
        raise RuntimeError("A308 A307 qualification semantics differ")
    return value


def rank_analysis(
    *, prefix: int, order_value: Mapping[str, Any], challenge_sha: str
) -> dict[str, Any]:
    components = order_value["component_orders"]
    portfolio = [int(value) for value in order_value["portfolio_order"]]
    coarse = [int(value) for value in components["A297_coarse_high8_then_reflected_Gray4"]]
    numeric = [int(value) for value in components["numeric_word0_prefix12"]]
    ranks = {
        "A308_two_operator_portfolio": portfolio.index(prefix) + 1,
        "A297_coarse_high8_then_reflected_Gray4": coarse.index(prefix) + 1,
        "numeric_word0_prefix12": numeric.index(prefix) + 1,
        "public_hash_control": A302.A300.A299.public_hash_order(challenge_sha).index(prefix) + 1,
    }
    best = min(
        ranks["A297_coarse_high8_then_reflected_Gray4"],
        ranks["numeric_word0_prefix12"],
    )
    rank = ranks["A308_two_operator_portfolio"]
    if rank > 2 * best:
        raise RuntimeError("A308 portfolio rank violates the frozen guarantee")
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "best_component_rank_one_based": best,
        "portfolio_regret_factor_vs_best_component": rank / best,
        "portfolio_regret_bits_vs_best_component": math.log2(rank / best),
        "portfolio_gain_bits_vs_complete_domain": math.log2(CELLS / rank),
        "assignment_upper_bounds": {name: value * GROUP_SIZE for name, value in ranks.items()},
        "rank_guarantee_holds": True,
        "component_ranks_computed_only_after_confirmation": True,
    }


def ordered_discovery(
    *,
    host_factory: Callable[[], Any],
    challenge: Mapping[str, Any],
    order: Sequence[int],
    host_refresh_groups: int = HOST_REFRESH_GROUPS,
) -> dict[str, Any]:
    values = [int(value) for value in order]
    if len(values) != CELLS or set(values) != set(range(CELLS)):
        raise ValueError("A308 prefix order is not an exact 4096-cell cover")
    if host_refresh_groups <= 0:
        raise ValueError("A308 host refresh interval must be positive")
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
            observed = A307.filter_complete_prefix(
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
                continue
            if len(group_factual) != 1:
                raise RuntimeError("A308 complete W44 group produced multiple filters")
            candidate = group_factual[0]
            if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
                raise RuntimeError("A308 candidate prefix differs")
            groups = group_index + 1
            return {
                "candidate": candidate,
                "candidate_hex": f"{candidate:011x}",
                "key_word0": candidate & MASK32,
                "key_word1_low12": candidate >> 32,
                "prefix12": prefix,
                "prefix12_hex": f"{prefix:03x}",
                "executed_prefix_groups": groups,
                "executed_group_dispatches": groups * 2,
                "executed_assignments": groups * GROUP_SIZE,
                "complete_domain_assignments": DOMAIN_SIZE,
                "complete_W44_group_execution_before_stop": True,
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
    finally:
        if host is not None:
            host.close()
    raise RuntimeError("A308 exact frozen order exhausted without a factual filter")


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
        observed == expected for observed, expected in zip(byte_outputs, target_words, strict=True)
    ]
    word_matches = [
        observed == expected for observed, expected in zip(word_outputs, target_words, strict=True)
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
            sha256(W43._word_bytes(block))
            for block in byte_outputs  # noqa: SLF001
        ],
        "word_reference_sha256": [
            sha256(W43._word_bytes(block))
            for block in word_outputs  # noqa: SLF001
        ],
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A308:confirmed_calibrated_W44_recovery"
    writer = CausalWriter(api_id="a308w44")
    writer._rules = []
    writer.add_rule(
        name="coarse_numeric_order_to_W44_grouped_search",
        description="The target-blind 256-cell Causal coarse field and numeric control are merged before the A307 engine executes complete 2^32-member W44 prefix groups.",
        pattern=["A308_frozen_coarse_numeric_order", "A307_complete_W44_groups"],
        conclusion="A308_ordered_W44_search",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="W44_filter_to_dual_confirmation",
        description="The sole factual filter survives two independent ChaCha20 implementations across all eight complete output blocks while the matched control remains empty.",
        pattern=["A308_ordered_W44_search", "dual_eight_block_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A308:frozen_model_free_coarse_numeric_order",
        mechanism="A307:two_complete_2^31_slabs_per_prefix",
        outcome="A308:ordered_W44_search",
        confidence=1.0,
        source=payload["order_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=json.dumps(payload["qualification_gate"], sort_keys=True),
        domain="AI-native full-round ChaCha20 W44 search",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A308:ordered_W44_search",
        mechanism="complete_group_filter_plus_dual_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="confirmed full-round ChaCha20 W44 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A308:frozen_model_free_coarse_numeric_order",
        mechanism="materialized_order_execution_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A308_W44_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A308 calibrated W44 recovery",
        entities=[
            "A308:frozen_model_free_coarse_numeric_order",
            "A308:ordered_W44_search",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_W44_replication_or_W45_grouped_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the same zero-refit coarse operator retain strict-subset concentration on another W44 target or a wider residual domain?"
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
        reader.api_id != "a308w44"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A308 authentic Causal reopen gate failed")
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
    expected_preflight_sha256: str,
    expected_order_sha256: str,
    expected_a307_qualification_sha256: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A308 final artifacts already exist")
    protocol, _preflight, order_value = load_order(
        expected_protocol_sha256,
        expected_preflight_sha256,
        expected_order_sha256,
    )
    qualification = load_a307_qualification(expected_a307_qualification_sha256)
    challenge = protocol["public_challenge"]
    executable_row = json.loads(A307.PROTOCOL.read_bytes())["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, A307_EXECUTABLE_SHA256)
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A307.A304.GroupedMetalHost(
            executable,
            A307.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    discovery = ordered_discovery(
        host_factory=host_factory,
        challenge=challenge,
        order=[int(value) for value in order_value["portfolio_order"]],
    )
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A308 matched control produced a candidate")
    confirmation = confirm(challenge, int(discovery["candidate"]))
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A308 dual independent confirmation failed")
    ranks = rank_analysis(
        prefix=int(discovery["prefix12"]),
        order_value=order_value,
        challenge_sha=protocol["public_challenge_sha256"],
    )
    rank = ranks["prefix_ranks_one_based"]["A308_two_operator_portfolio"]
    if rank != discovery["executed_prefix_groups"]:
        raise RuntimeError("A308 discovery rank differs from frozen order")
    strict_subset = rank < CELLS
    evidence_stage = (
        "FULLROUND_R20_W44_CALIBRATED_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_W44_CALIBRATED_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w44-calibrated-coarse-numeric-a308-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "order_sha256": expected_order_sha256,
        "A307_protocol_sha256": A307_PROTOCOL_SHA256,
        "A307_qualification_artifact_sha256": expected_a307_qualification_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W44_group_candidates": qualification["complete_group_gate"][
                "logical_candidates"
            ],
            "synthetic_filter_exact": qualification["synthetic_filter_exact"],
            "production_target_used": False,
        },
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "strict_subset_of_complete_domain": strict_subset,
        "information_boundary": order_value["information_boundary"],
        "anchors": protocol["anchors"],
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "discovery": {
                key: value for key, value in discovery.items() if not key.startswith("volatile_")
            },
            "A307_qualification_artifact_sha256": expected_a307_qualification_sha256,
            "executable_sha256": A307_EXECUTABLE_SHA256,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": {
                key: value for key, value in discovery.items() if not key.startswith("volatile_")
            },
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
            "# A308 — calibrated Causal coarse+numeric ChaCha20-R20 W44 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Frozen portfolio prefix rank: **{rank} / 4,096**\n"
            f"- Search gain: **{ranks['portfolio_gain_bits_vs_complete_domain']:.6f} bits**\n"
            f"- Executed assignments: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W44 assignment: **0x{int(discovery['candidate']):011x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every executed prefix: **two complete 2^31 slabs, 2^32 candidates total**\n"
            "- Frozen operator: **256-cell Causal coarse field + numeric portfolio**\n"
            "- Matched one-bit control: **zero candidates**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "protocol_frozen": PROTOCOL.exists(),
        "preflight_complete": PREFLIGHT.exists(),
        "order_complete": ORDER.exists(),
        "result_complete": RESULT.exists(),
        "unknown_key_bits": WIDTH,
        "candidate_group_size": GROUP_SIZE,
        "complete_domain_size": DOMAIN_SIZE,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--measure", action="store_true")
    mode.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-preflight-sha256")
    parser.add_argument("--expected-order-sha256")
    parser.add_argument("--expected-a307-qualification-sha256")
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
    elif args.preflight:
        if not args.expected_protocol_sha256:
            parser.error("--preflight requires --expected-protocol-sha256")
        value = preflight(args.expected_protocol_sha256)
        output = {
            "preflight": relative(PREFLIGHT),
            "preflight_sha256": file_sha256(PREFLIGHT),
            "semantic_sha256": value["preflight_sha256"],
        }
    elif args.measure:
        if not args.expected_protocol_sha256 or not args.expected_preflight_sha256:
            parser.error("--measure requires protocol and preflight hashes")
        value = measure(
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_preflight_sha256=args.expected_preflight_sha256,
        )
        output = {
            "order": relative(ORDER),
            "order_sha256": file_sha256(ORDER),
            "measurement_sha256": value["measurement_sha256"],
        }
    else:
        required = (
            args.expected_protocol_sha256,
            args.expected_preflight_sha256,
            args.expected_order_sha256,
            args.expected_a307_qualification_sha256,
        )
        if not all(required):
            parser.error(
                "--recover requires protocol, preflight, order, and A307 qualification hashes"
            )
        value = recover(
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_preflight_sha256=args.expected_preflight_sha256,
            expected_order_sha256=args.expected_order_sha256,
            expected_a307_qualification_sha256=args.expected_a307_qualification_sha256,
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
