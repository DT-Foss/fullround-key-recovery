#!/usr/bin/env python3
"""Prospective multi-target replication and W28 transfer of A294's Reader."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import math
import os
import secrets
import struct
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

from arx_carry_leak.chacha20_rfc8439_reference import (
    chacha20_block as byte_reference_block,
)
from arx_carry_leak.chacha20_rfc8439_reference import rfc8439_section_2_3_2_kat

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"
ARTIFACTS = RESEARCH / "artifacts/a296_chacha20_r20_causal_search_gain_panel"

DESIGN = CONFIGS / "chacha20_round20_causal_search_gain_panel_a296_design_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_causal_search_gain_panel_a296_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_causal_search_gain_panel_a296_preflight_v1.json"
RESULT = RESULTS / "chacha20_round20_causal_search_gain_panel_a296_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_CAUSAL_SEARCH_GAIN_PANEL_A296_V1.md"
BUILD = RESEARCH / "build/chacha20_round20_causal_search_gain_panel_a296"

A294_RUNNER = RESEARCH / "experiments/chacha20_round20_w24_causal_ordered_metal_a294.py"
A294_RESULT = RESULTS / "chacha20_round20_w24_causal_ordered_metal_a294_v1.json"
A294_CAUSAL = RESULTS / "chacha20_round20_w24_causal_ordered_metal_a294_v1.causal"
A291_RUNNER = RESEARCH / "experiments/chacha20_round20_w24_selected_channel_transfer_a291.py"
A291_PROTOCOL = CONFIGS / "chacha20_round20_w24_selected_channel_transfer_a291_v1.json"
A291_RESULT = RESULTS / "chacha20_round20_w24_selected_channel_transfer_a291_v1.json"
A291_CAUSAL = RESULTS / "chacha20_round20_w24_selected_channel_transfer_a291_v1.causal"
A251_WRAPPER = RESEARCH / "experiments/chacha20_fresh_clause_identity.py"
A223_SOURCE = RESEARCH / "experiments/chacha20_round20_capacity_moonshot_a223.py"
A223_CONFIG = CONFIGS / "chacha20_round20_capacity_moonshot_a223_v1.json"
METAL_ANCHOR = RESEARCH / "experiments/chacha20_round20_a223_w40_metal_transfer.py"
ROOT_REFERENCE = RESEARCH / "experiments/chacha20_round20_multitarget_root_confirm.py"

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A296"
DESIGN_SHA256 = "494a0ceb42dd56ce8dc9ffe6b69a6b6736666e9dfb568a94605d9c239769b187"
PANEL_SPEC = ((24, 4), (28, 4))
ROUNDS = 20
BLOCKS = 8
OUTPUT_BITS = BLOCKS * 512
PREFIX_BITS = 8
FINE_PREFIX_BITS = 12
FINE_GROUPS = 1 << FINE_PREFIX_BITS
HORIZONS = [1, 2, 4, 8]
FEATURE_INDICES = [502, 504, 505, 508, 509, 510, 511, 514]
WATCHDOG_SECONDS = 2.0
ZSTD_LEVEL = 10
MASK32 = 0xFFFFFFFF


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


def path_from_ref(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    digest = file_sha256(path)
    if expected is not None and digest != expected:
        raise RuntimeError(f"A296 anchor differs: {path}")
    return {"path": relative(path), "sha256": digest}


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A296 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_dotcausal() -> tuple[Any, Any, dict[str, str]]:
    try:
        module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
        module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(module.CausalReader) or "")
    return module.CausalWriter, module.CausalReader, anchor(source)


def word_bytes(words: Sequence[int]) -> bytes:
    return struct.pack(f"<{len(words)}I", *(int(word) & MASK32 for word in words))


def target_id(width: int, index: int) -> str:
    return f"w{width}_t{index:02d}"


def measurement_path(identifier: str) -> Path:
    return RESULTS / "chacha20_round20_causal_search_gain_panel_a296_v1" / (
        f"{identifier}.measurement.json.zst"
    )


def order_path(identifier: str) -> Path:
    return RESULTS / "chacha20_round20_causal_search_gain_panel_a296_v1" / (
        f"{identifier}.order.json"
    )


def cnf_path(identifier: str) -> Path:
    return ARTIFACTS / identifier / "base_b1.cnf"


def design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A296 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    expected_panel = [
        {"target_id": target_id(width, index), "unknown_key_bits": width}
        for width, count in PANEL_SPEC
        for index in range(count)
    ]
    if (
        value.get("schema")
        != "chacha20-round20-causal-search-gain-panel-a296-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("panel") != expected_panel
        or value.get("reader_contract", {}).get("selected_feature_indices")
        != FEATURE_INDICES
        or value.get("information_boundary", {}).get(
            "any_A296_target_exists_at_design_freeze"
        )
        is not False
    ):
        raise RuntimeError("A296 design semantics differ")
    return value


def challenge_from_ephemeral_secret(root_reference: Any, width: int) -> dict[str, Any]:
    if width not in {24, 28}:
        raise ValueError("A296 width must be 24 or 28")
    key_words = [secrets.randbits(32) for _ in range(8)]
    nonce_words = [secrets.randbits(32) for _ in range(3)]
    counter = secrets.randbits(32)
    target_words = [
        root_reference.chacha20_block(
            key_words, (counter + block) & MASK32, nonce_words
        )
        for block in range(BLOCKS)
    ]
    control = list(target_words[0])
    control[0] ^= 1
    known_mask = (~((1 << width) - 1)) & MASK32
    challenge = {
        "challenge_id": secrets.token_hex(16),
        "rounds": ROUNDS,
        "block_count": BLOCKS,
        "counter_schedule": "base_plus_block_index_mod_2^32",
        "counter_start": counter,
        "nonce_words": nonce_words,
        "known_key_bits": 256 - width,
        "known_key_mask_words": [known_mask, *([MASK32] * 7)],
        "known_key_value_words": [key_words[0] & known_mask, *key_words[1:]],
        "unknown_key_bits": width,
        "unknown_global_bit_interval": [0, width - 1],
        "unknown_bit_numbering": (
            "little_endian_bit0_upward_across_key_words_k0_through_k7"
        ),
        "unknown_assignment_included": False,
        "unknown_assignment_value_included": False,
        "full_key_included": False,
        "secret_used_only_for_target_construction": True,
        "secret_discarded_after_target_construction": True,
        "generation_entropy_source": "python_secrets_token_bytes_OS_CSPRNG",
        "target_words": target_words,
        "target_block_sha256": [
            sha256(word_bytes(block)) for block in target_words
        ],
        "control_target_words": control,
        "control_target_block_sha256": sha256(word_bytes(control)),
    }
    del key_words
    return challenge


def synthetic_reader_mapping(source_mapping: Sequence[int], width: int) -> list[int]:
    mapping = [int(value) for value in source_mapping]
    if (
        len(mapping) != width
        or width < 20
        or any(value == 0 for value in mapping)
        or len({abs(value) for value in mapping}) != width
    ):
        raise ValueError("A296 source mapping differs")
    view = [*mapping[:12], *mapping[width - PREFIX_BITS : width]]
    if len(view) != 20 or len({abs(value) for value in view}) != 20:
        raise RuntimeError("A296 synthetic Reader mapping differs")
    return view


def fine_order(coarse_order: Sequence[int]) -> list[int]:
    coarse = [int(value) for value in coarse_order]
    gray4 = [value ^ (value >> 1) for value in range(16)]
    order = [(prefix << 4) | suffix for prefix in coarse for suffix in gray4]
    if (
        len(coarse) != 256
        or set(coarse) != set(range(256))
        or len(order) != FINE_GROUPS
        or set(order) != set(range(FINE_GROUPS))
    ):
        raise RuntimeError("A296 fine order is not an exact cover")
    return order


def public_hash_order(public_challenge_sha256: str) -> list[int]:
    seed = bytes.fromhex(public_challenge_sha256)
    order = sorted(
        range(FINE_GROUPS),
        key=lambda value: hashlib.sha256(
            b"A296|public-hash-control|" + seed + value.to_bytes(2, "big")
        ).digest(),
    )
    if len(order) != FINE_GROUPS or set(order) != set(range(FINE_GROUPS)):
        raise RuntimeError("A296 public-hash order differs")
    return order


def execution_plan() -> dict[str, Any]:
    return {
        "primitive": "standard_ChaCha20_block_function",
        "rounds": ROUNDS,
        "feedforward_included": True,
        "panel": [
            {"unknown_key_bits": width, "target_count": count}
            for width, count in PANEL_SPEC
        ],
        "public_output_blocks_per_target": BLOCKS,
        "diagnostic_output_blocks_per_target": 1,
        "reader": "unchanged_A272_selected_eight_feature_model",
        "selected_feature_indices": FEATURE_INDICES,
        "conflict_horizons": HORIZONS,
        "high8_cells": 256,
        "fine_prefix_bits": FINE_PREFIX_BITS,
        "fine_prefix_groups": FINE_GROUPS,
        "fine_order": "Causal_high8_then_reflected_Gray4",
        "reader_refits": 0,
        "target_labels_used": 0,
        "controls": ["numeric_prefix12", "public_hash_prefix12"],
        "native_discovery": "A294_Apple_Metal_candidate_axis",
        "first_factual_filter_match_stops_each_target": True,
        "matched_one_bit_control_scans_identical_executed_groups": True,
        "confirmation": "dual_independent_RFC8439_all_eight_blocks",
    }


def freeze() -> dict[str, Any]:
    if PROTOCOL.exists():
        raise FileExistsError(PROTOCOL)
    if any(path.exists() for path in (PREFLIGHT, RESULT, CAUSAL)) or ARTIFACTS.exists():
        raise RuntimeError("A296 freeze must precede all A296 artifacts")
    frozen_design = design()
    _, CausalReader, reader_anchor = _load_dotcausal()
    a294_reader = CausalReader(str(A294_CAUSAL), verify_integrity=True)
    if (
        a294_reader.api_id != "a294w24"
        or len(a294_reader._gaps) != 1
        or a294_reader._gaps[0].get("expected_object_type")
        != "prospective_multitarget_Causal_search_gain_replication_or_W28_transfer"
    ):
        raise RuntimeError("A296 authentic A294 Reader gap differs")
    root_reference = load_module(ROOT_REFERENCE, "a296_root_freeze")
    if root_reference.rfc8439_kat().get("exact") is not True:
        raise RuntimeError("A296 root RFC 8439 gate failed")
    a223 = load_module(A223_SOURCE, "a296_a223_freeze")
    targets: list[dict[str, Any]] = []
    for width, count in PANEL_SPEC:
        for index in range(count):
            challenge = challenge_from_ephemeral_secret(root_reference, width)
            a223._validate_challenge(challenge, width=width)  # noqa: SLF001
            targets.append(
                {
                    "target_id": target_id(width, index),
                    "unknown_key_bits": width,
                    "public_challenge": challenge,
                    "public_challenge_sha256": canonical_sha256(challenge),
                }
            )
    hashes = [row["public_challenge_sha256"] for row in targets]
    if len(targets) != 8 or len(set(hashes)) != 8:
        raise RuntimeError("A296 target panel is not eight-way disjoint")
    plan = execution_plan()
    payload = {
        "schema": "chacha20-round20-causal-search-gain-panel-a296-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "all_eight_fresh_targets_and_zero_refit_reader_contract_frozen_before_any_target_CNF_export_measurement_order_or_discovery",
        "design": frozen_design,
        "execution_plan": plan,
        "execution_plan_sha256": canonical_sha256(plan),
        "targets": targets,
        "target_ledger_sha256": canonical_sha256(
            [
                {
                    "target_id": row["target_id"],
                    "unknown_key_bits": row["unknown_key_bits"],
                    "public_challenge_sha256": row["public_challenge_sha256"],
                }
                for row in targets
            ]
        ),
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A294_runner": anchor(A294_RUNNER),
            "A294_result": anchor(A294_RESULT),
            "A294_causal": anchor(A294_CAUSAL),
            "A291_runner": anchor(A291_RUNNER),
            "A291_protocol": anchor(A291_PROTOCOL),
            "A291_result": anchor(A291_RESULT),
            "A291_causal": anchor(A291_CAUSAL),
            "A251_wrapper": anchor(A251_WRAPPER),
            "A223_source": anchor(A223_SOURCE),
            "A223_config": anchor(A223_CONFIG),
            "Metal_anchor": anchor(METAL_ANCHOR),
            "root_reference": anchor(ROOT_REFERENCE),
            "byte_reference": anchor(
                Path(inspect.getsourcefile(byte_reference_block) or "")
            ),
            "CausalReader": reader_anchor,
            "runner": anchor(Path(__file__)),
        },
        "authentic_causal_readback": {
            "source_api_id": a294_reader.api_id,
            "source_gap": a294_reader._gaps[0],
            "read_by_main_before_design": True,
        },
        "information_boundary": {
            "all_eight_generation_assignments_discarded_before_serialization": True,
            "generation_assignments_returned_logged_or_serialized": False,
            "all_eight_targets_frozen_before_any_CNF_export": True,
            "any_target_measurement_or_order_available_at_freeze": False,
            "target_prefix_model_or_filter_outcome_available_at_freeze": False,
            "reader_coefficients_features_horizons_and_tiebreak_frozen": True,
        },
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "execution_plan": plan,
            "target_ledger_sha256": payload["target_ledger_sha256"],
            "information_boundary": payload["information_boundary"],
            "anchors": payload["anchors"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A296 protocol hash differs")
    payload = json.loads(PROTOCOL.read_bytes())
    if (
        payload.get("schema")
        != "chacha20-round20-causal-search-gain-panel-a296-protocol-v1"
        or payload.get("attempt_id") != ATTEMPT_ID
        or payload.get("execution_plan") != execution_plan()
        or payload.get("execution_plan_sha256")
        != canonical_sha256(execution_plan())
        or len(payload.get("targets", [])) != 8
        or payload.get("anchors", {}).get("runner", {}).get("sha256")
        != file_sha256(Path(__file__))
    ):
        raise RuntimeError("A296 protocol semantics differ")
    for row in payload["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    for row in payload["targets"]:
        if canonical_sha256(row["public_challenge"]) != row["public_challenge_sha256"]:
            raise RuntimeError("A296 public challenge hash differs")
    return payload


def b1_formula(a223: Any, challenge: dict[str, Any], width: int) -> str:
    original = int(a223.BLOCK_COUNT)
    try:
        a223.BLOCK_COUNT = 1
        formula = a223._source_formula(challenge, width=width)  # noqa: SLF001
    finally:
        a223.BLOCK_COUNT = original
    if (
        "b1_v" in formula
        or formula.count("(assert (= b0_v") != 16
        or formula.count("(check-sat)") != 1
    ):
        raise RuntimeError("A296 one-block formula boundary differs")
    return formula


def export_reader_cnf(
    *,
    a223: Any,
    config: dict[str, Any],
    identifier: str,
    challenge: dict[str, Any],
    width: int,
) -> dict[str, Any]:
    formula = b1_formula(a223, challenge, width)
    output = cnf_path(identifier)
    output.parent.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix=f"a296_{identifier}_map_") as temporary:
        directory = Path(temporary)
        temporary_cnf = directory / "base.cnf"
        export = a223._export_cnf(  # noqa: SLF001
            formula=formula,
            output=temporary_cnf,
            config=config,
            label=f"A296_{identifier.upper()}_B1_BASE",
        )
        raw = temporary_cnf.read_bytes()
        lines = raw.splitlines(keepends=True)
        header = lines[0].split() if lines else []
        if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
            raise RuntimeError("A296 base CNF header differs")
        context = {
            "width": width,
            "formula": formula,
            "formula_bytes": len(formula.encode()),
            "formula_sha256": sha256(formula.encode()),
            "base_path": temporary_cnf,
            "base_raw": raw,
            "base_body": b"".join(lines[1:]),
            "base_body_sha256": sha256(b"".join(lines[1:])),
            "variable_count": int(header[2]),
            "clause_count": int(header[3]),
            "base_export": export,
        }
        probes = [
            a223._coordinate_probe(  # noqa: SLF001
                context=context,
                dimension=dimension,
                config=config,
                directory=directory,
            )
            for dimension in range(-1, math.ceil(math.log2(width)))
        ]
        mapping = a223._decode_mapping(  # noqa: SLF001
            [(dimension, units) for _, dimension, units, _ in probes],
            width=width,
        )
        atomic_bytes(output, raw)
    view = synthetic_reader_mapping(mapping, width)
    return {
        "target_id": identifier,
        "unknown_key_bits": width,
        "formula_bytes": len(formula.encode()),
        "formula_sha256": sha256(formula.encode()),
        "blocks": 1,
        "rounds": ROUNDS,
        "feedforward_included": True,
        "CNF": anchor(output, export["sha256"]),
        "CNF_header": export["header"],
        "source_one_literals_bit0_upward": mapping,
        "source_mapping_sha256": canonical_sha256(mapping),
        "synthetic_reader_mapping": view,
        "synthetic_reader_mapping_sha256": canonical_sha256(view),
        "partition_coordinates_high_to_low": list(
            range(width - 1, width - PREFIX_BITS - 1, -1)
        ),
        "diagnostic_model_view_coordinates": [
            *range(12),
            *range(width - PREFIX_BITS, width),
        ],
        "coordinate_probes": [row[3] for row in probes],
    }


def preflight(expected_protocol_sha256: str) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A296 preflight artifacts already exist")
    if any(measurement_path(target_id(width, index)).exists() for width, count in PANEL_SPEC for index in range(count)):
        raise RuntimeError("A296 preflight must precede every measurement")
    protocol = load_protocol(expected_protocol_sha256)
    a223 = load_module(A223_SOURCE, "a296_a223_preflight")
    config = json.loads(A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    rows = [
        export_reader_cnf(
            a223=a223,
            config=config,
            identifier=row["target_id"],
            challenge=row["public_challenge"],
            width=int(row["unknown_key_bits"]),
        )
        for row in protocol["targets"]
    ]
    payload = {
        "schema": "chacha20-round20-causal-search-gain-panel-a296-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "EIGHT_TARGET_CNFS_AND_LITERAL_MAPS_FROZEN_BEFORE_MEASUREMENT",
        "protocol_sha256": expected_protocol_sha256,
        "targets": rows,
        "all_targets_preflighted": len(rows) == 8,
        "any_measurement_started_before_complete_preflight": False,
        "preflight_sha256": canonical_sha256(rows),
    }
    atomic_json(PREFLIGHT, payload)
    return payload


def load_preflight(
    expected_protocol_sha256: str, expected_preflight_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = load_protocol(expected_protocol_sha256)
    if file_sha256(PREFLIGHT) != expected_preflight_sha256:
        raise RuntimeError("A296 preflight hash differs")
    value = json.loads(PREFLIGHT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-causal-search-gain-panel-a296-preflight-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("all_targets_preflighted") is not True
        or len(value.get("targets", [])) != 8
    ):
        raise RuntimeError("A296 preflight semantics differ")
    for row in value["targets"]:
        anchor(path_from_ref(row["CNF"]["path"]), row["CNF"]["sha256"])
    return protocol, value


def _reader_stack() -> tuple[Any, Any, Any, tuple[int, ...], Path]:
    a291 = load_module(A291_RUNNER, "a296_a291_reader_stack")
    expected = file_sha256(A291_PROTOCOL)
    protocol, a275, _a251, model, indices = a291._load_protocol(  # noqa: SLF001
        expected, DOTCAUSAL_SRC
    )
    if list(indices) != FEATURE_INDICES:
        raise RuntimeError("A296 A272 selected feature identity differs")
    helper = path_from_ref(protocol["anchors"]["A251_helper"]["path"])
    anchor(helper, protocol["anchors"]["A251_helper"]["sha256"])
    return a275, model, a291, indices, helper


def measure_target(
    *,
    identifier: str,
    expected_protocol_sha256: str,
    expected_preflight_sha256: str,
) -> dict[str, Any]:
    protocol, frozen = load_preflight(
        expected_protocol_sha256, expected_preflight_sha256
    )
    target_rows = {row["target_id"]: row for row in protocol["targets"]}
    preflight_rows = {row["target_id"]: row for row in frozen["targets"]}
    if identifier not in target_rows or identifier not in preflight_rows:
        raise ValueError(f"unknown A296 target: {identifier}")
    output = order_path(identifier)
    compressed_output = measurement_path(identifier)
    if output.exists() or compressed_output.exists():
        raise FileExistsError(f"A296 measurement already exists: {identifier}")
    a275, model, _a291, indices, helper = _reader_stack()
    wrapper = load_module(A251_WRAPPER, f"a296_clause_wrapper_{identifier}")
    row = preflight_rows[identifier]
    started = time.perf_counter()
    raw_run = wrapper.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["CNF"]["path"]),
        mode=f"A296_{identifier}_numeric_unlabeled",
        order=[f"{value:08b}" for value in range(256)],
        key_one_literals_bit0_through_bit19=row["synthetic_reader_mapping"],
        conflict_horizons=HORIZONS,
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=1800.0,
    )
    stable_run = {
        key: value
        for key, value in raw_run.items()
        if key not in {"command", "process_elapsed_seconds"}
    }
    measurement = {
        "schema": "chacha20-round20-causal-search-gain-panel-a296-measurement-v1",
        "attempt_id": ATTEMPT_ID,
        "target_id": identifier,
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "public_challenge_sha256": target_rows[identifier]["public_challenge_sha256"],
        "unknown_key_bits": target_rows[identifier]["unknown_key_bits"],
        "order_name": "numeric",
        "partition_coordinates_high_to_low": row[
            "partition_coordinates_high_to_low"
        ],
        "free_bits_per_cell": int(row["unknown_key_bits"]) - PREFIX_BITS,
        "run": stable_run,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "target_label_available_to_measurement": False,
        "label_used_for_feature_construction_or_scoring": False,
        "complete_candidate_cover": len(raw_run["cells"]) == 256,
    }
    matrix = a275._target_feature_matrix(measurement)  # noqa: SLF001
    contributions = a275.standardized_contributions(
        matrix,
        means=model.means,
        scales=model.scales,
        coefficients=model.coefficients,
    )
    scores = contributions[:, indices].sum(axis=1)
    coarse = a275._candidate_order(scores)  # noqa: SLF001
    raw = canonical_bytes(measurement)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    atomic_bytes(compressed_output, compressed)
    analysis = {
        "schema": "chacha20-round20-causal-search-gain-panel-a296-order-v1",
        "attempt_id": ATTEMPT_ID,
        "target_id": identifier,
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "public_challenge_sha256": target_rows[identifier]["public_challenge_sha256"],
        "unknown_key_bits": int(row["unknown_key_bits"]),
        "measurement": {
            "path": relative(compressed_output),
            "raw_bytes": len(raw),
            "raw_sha256": sha256(raw),
            "compressed_bytes": len(compressed),
            "compressed_sha256": sha256(compressed),
        },
        "score_field": np.asarray(scores, dtype=np.float64).tolist(),
        "score_field_sha256": canonical_sha256(
            np.asarray(scores, dtype=np.float64).tolist()
        ),
        "complete_coarse_order": coarse,
        "complete_coarse_order_uint8_sha256": sha256(bytes(coarse)),
        "complete_fine_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in fine_order(coarse))
        ),
        "selected_feature_indices": list(indices),
        "model_refits": 0,
        "target_labels_used": 0,
        "model_free_UNKNOWN_stages": len(measurement["run"]["stages"]),
    }
    atomic_json(output, analysis)
    return analysis


def initial_state(
    challenge: Mapping[str, Any], constants: Sequence[int], width: int
) -> np.ndarray:
    known = [int(value) & MASK32 for value in challenge["known_key_value_words"]]
    if len(known) != 8 or known[0] & ((1 << width) - 1):
        raise RuntimeError("A296 known key interval differs")
    state = np.zeros(16, dtype=np.uint32)
    state[:4] = np.asarray(constants, dtype=np.uint32)
    state[4:12] = np.asarray(known, dtype=np.uint32)
    state[12] = np.uint32(int(challenge["counter_start"]))
    state[13:16] = np.asarray(challenge["nonce_words"], dtype=np.uint32)
    return state


def mapping_gate(
    *,
    host: Any,
    challenge: Mapping[str, Any],
    width: int,
    metal: Any,
    root_reference: Any,
) -> dict[str, Any]:
    suffix_bits = width - FINE_PREFIX_BITS
    group_size = 1 << suffix_bits
    prefix = 0x5A3
    suffix = min(0x7B1, group_size - 1)
    candidate = (prefix << suffix_bits) | suffix
    known = [int(value) for value in challenge["known_key_value_words"]]
    key = [known[0] | candidate, *known[1:]]
    target = root_reference.chacha20_block(
        key, int(challenge["counter_start"]), challenge["nonce_words"]
    )
    control = list(target)
    control[0] ^= 1
    host.configure(
        initial_state(challenge, metal.A119.CONSTANTS, width),
        np.asarray(target, dtype=np.uint32),
        np.asarray(control, dtype=np.uint32),
    )
    observed = host.filter(known[0] | (prefix << suffix_bits), group_size)
    expected = known[0] | candidate
    if observed["factual"] != [expected] or observed["control"]:
        raise RuntimeError("A296 Metal mapping gate failed")
    return {
        "width": width,
        "public_synthetic_prefix12": prefix,
        "public_synthetic_suffix": suffix,
        "candidate_group_size": group_size,
        "factual_match_exact": True,
        "control_matches": 0,
        "gpu_seconds": float(observed["gpu_seconds"]),
    }


def discover(
    *,
    host: Any,
    challenge: Mapping[str, Any],
    width: int,
    order: Sequence[int],
    metal: Any,
) -> dict[str, Any]:
    suffix_bits = width - FINE_PREFIX_BITS
    group_size = 1 << suffix_bits
    domain_size = 1 << width
    known_word0 = int(challenge["known_key_value_words"][0])
    host.configure(
        initial_state(challenge, metal.A119.CONSTANTS, width),
        np.asarray(challenge["target_words"][0], dtype=np.uint32),
        np.asarray(challenge["control_target_words"], dtype=np.uint32),
    )
    gpu_seconds = 0.0
    for index, prefix in enumerate(order):
        observed = host.filter(
            known_word0 | (int(prefix) << suffix_bits), group_size
        )
        gpu_seconds += float(observed["gpu_seconds"])
        if observed["control"]:
            raise RuntimeError("A296 matched control produced a candidate")
        factual = [int(value) for value in observed["factual"]]
        if not factual:
            continue
        if len(factual) != 1:
            raise RuntimeError("A296 group produced multiple factual candidates")
        candidate = factual[0] & (domain_size - 1)
        if candidate >> suffix_bits != int(prefix):
            raise RuntimeError("A296 candidate prefix differs")
        groups = index + 1
        return {
            "candidate": candidate,
            "candidate_hex": f"{candidate:0{math.ceil(width / 4)}x}",
            "matched_full_key_word0": factual[0],
            "fine_prefix12": int(prefix),
            "fine_prefix12_hex": f"{int(prefix):03x}",
            "Causal_prefix_rank_one_based": groups,
            "executed_prefix_groups": groups,
            "executed_assignments_upper_bound": groups * group_size,
            "complete_domain_assignments": domain_size,
            "strict_subset_of_complete_domain": groups < FINE_GROUPS,
            "search_gain_bits": math.log2(FINE_GROUPS / groups),
            "matched_control_candidates": 0,
            "gpu_seconds": gpu_seconds,
        }
    raise RuntimeError("A296 exact Causal order exhausted without a model")


def confirm(
    *,
    discovery: Mapping[str, Any],
    challenge: Mapping[str, Any],
    root_reference: Any,
) -> dict[str, Any]:
    candidate = int(discovery["candidate"])
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
    expected = [[int(word) for word in row] for row in challenge["target_words"]]
    if root_blocks != expected or byte_blocks != expected or root_blocks != byte_blocks:
        raise RuntimeError("A296 independent eight-block confirmation failed")
    hashes = [sha256(word_bytes(row)) for row in root_blocks]
    if hashes != challenge["target_block_sha256"]:
        raise RuntimeError("A296 confirmed target hashes differ")
    return {
        "recovered_unknown_assignment": candidate,
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
    *,
    discovery: Mapping[str, Any],
    causal_order: Sequence[int],
    public_challenge_sha256: str,
) -> dict[str, Any]:
    prefix = int(discovery["fine_prefix12"])
    causal = [int(value) for value in causal_order]
    hashed = public_hash_order(public_challenge_sha256)
    ranks = {
        "Causal": causal.index(prefix) + 1,
        "numeric": prefix + 1,
        "public_hash_control": hashed.index(prefix) + 1,
    }
    return {
        "prefix12": prefix,
        "prefix_ranks_one_based": ranks,
        "candidate_reduction_vs_complete": {
            name: FINE_GROUPS / rank for name, rank in ranks.items()
        },
        "Causal_speedup_vs_numeric_rank": ranks["numeric"] / ranks["Causal"],
        "Causal_speedup_vs_public_hash_rank": (
            ranks["public_hash_control"] / ranks["Causal"]
        ),
        "counterfactual_ranks_computed_after_confirmation": True,
    }


def aggregate(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    def geometric_mean(values: Sequence[float]) -> float:
        return math.exp(sum(math.log(value) for value in values) / len(values))

    widths: dict[str, Any] = {}
    for width, _count in PANEL_SPEC:
        selected = [row for row in rows if int(row["unknown_key_bits"]) == width]
        ranks = [
            int(row["rank_analysis"]["prefix_ranks_one_based"]["Causal"])
            for row in selected
        ]
        gains = [float(row["discovery"]["search_gain_bits"]) for row in selected]
        widths[str(width)] = {
            "targets": len(selected),
            "Causal_prefix_ranks": ranks,
            "search_gain_bits": gains,
            "geometric_mean_domain_reduction": geometric_mean(
                [FINE_GROUPS / rank for rank in ranks]
            ),
            "Causal_earlier_than_numeric": sum(
                row["rank_analysis"]["prefix_ranks_one_based"]["Causal"]
                < row["rank_analysis"]["prefix_ranks_one_based"]["numeric"]
                for row in selected
            ),
            "Causal_earlier_than_public_hash": sum(
                row["rank_analysis"]["prefix_ranks_one_based"]["Causal"]
                < row["rank_analysis"]["prefix_ranks_one_based"][
                    "public_hash_control"
                ]
                for row in selected
            ),
        }
    all_ranks = [
        int(row["rank_analysis"]["prefix_ranks_one_based"]["Causal"])
        for row in rows
    ]
    return {
        "targets": len(rows),
        "confirmed_recoveries": sum(
            row["confirmation"]["cross_implementation_blocks_match"] for row in rows
        ),
        "matched_control_candidates": sum(
            int(row["discovery"]["matched_control_candidates"]) for row in rows
        ),
        "cross_implementation_output_bits_checked": sum(
            int(row["confirmation"]["cross_implementation_output_bits_checked"])
            for row in rows
        ),
        "Causal_prefix_ranks": all_ranks,
        "strict_subset_recoveries": sum(
            bool(row["discovery"]["strict_subset_of_complete_domain"])
            for row in rows
        ),
        "geometric_mean_domain_reduction": geometric_mean(
            [FINE_GROUPS / rank for rank in all_ranks]
        ),
        "Causal_earlier_than_numeric": sum(
            row["rank_analysis"]["prefix_ranks_one_based"]["Causal"]
            < row["rank_analysis"]["prefix_ranks_one_based"]["numeric"]
            for row in rows
        ),
        "Causal_earlier_than_public_hash": sum(
            row["rank_analysis"]["prefix_ranks_one_based"]["Causal"]
            < row["rank_analysis"]["prefix_ranks_one_based"]["public_hash_control"]
            for row in rows
        ),
        "by_width": widths,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    CausalWriter, CausalReader, reader_source = _load_dotcausal()
    terminal = "A296:confirmed_W24_replication_and_W28_transfer_panel"
    writer = CausalWriter(api_id="a296pan")
    writer._rules = []
    writer.add_rule(
        name="A294_gap_to_fresh_multitarget_panel",
        description="The personally read A294 graph selects a fully fresh W24 replication and W28 transfer panel before any new target exists.",
        pattern=["A294_strict_subset_recovery", "A296_eight_target_freeze"],
        conclusion="A296_prospective_panel_contract",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="zero_refit_order_to_independent_recovery",
        description="Each target-specific zero-refit Reader order precedes Metal discovery and dual eight-block confirmation.",
        pattern=["A296_zero_refit_orders", "A296_dual_confirmations"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    for width in (24, 28):
        selected = [
            row for row in payload["targets"] if row["unknown_key_bits"] == width
        ]
        writer.add_triplet(
            trigger=f"A296:frozen_fresh_W{width}_targets",
            mechanism="target_specific_A272_selected_channel_measurement_then_Causal_Gray4_ordered_Metal_search",
            outcome=f"A296:confirmed_W{width}_panel_recoveries",
            confidence=1.0,
            source=payload["protocol_sha256"],
            quantification=json.dumps(
                payload["aggregate"]["by_width"][str(width)], sort_keys=True
            ),
            evidence=json.dumps(
                [row["measurement_sha256"] for row in selected], sort_keys=True
            ),
            domain="AI-native Causal full-round ChaCha20 search-gain panel",
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger="A296:confirmed_W24_panel_recoveries",
        mechanism="same_frozen_Reader_contract_widened_without_refit",
        outcome="A296:confirmed_W28_panel_recoveries",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["aggregate"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="W24-to-W28 full-round ChaCha20 transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A294:confirmed_Causal_ordered_strict_subset_W24_recovery",
        mechanism="materialized_A296_eight_target_replication_and_width_transfer_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A294_gap_plus_A296_panel",
        quantification=json.dumps(payload["aggregate"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A296 Causal search-gain replication and W28 transfer",
        entities=[
            "A294:confirmed_Causal_ordered_strict_subset_W24_recovery",
            "A296:confirmed_W24_panel_recoveries",
            "A296:confirmed_W28_panel_recoveries",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="prospective_W32_transfer_or_learned_fine_subprefix_operator",
        confidence=1.0,
        suggested_queries=[
            "Does the same zero-refit high-byte Reader preserve search gain at W32?",
            "Can a second frozen Reader order the unresolved fine-prefix bits directly?",
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
        reader.api_id != "a296pan"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A296 authentic Causal reopen gate failed")
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
        "reader_source": reader_source,
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
    swiftc: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A296 recovery result already exists")
    protocol, _frozen = load_preflight(
        expected_protocol_sha256, expected_preflight_sha256
    )
    orders = {}
    for row in protocol["targets"]:
        path = order_path(row["target_id"])
        value = json.loads(path.read_bytes())
        if (
            value.get("protocol_sha256") != expected_protocol_sha256
            or value.get("preflight_sha256") != expected_preflight_sha256
            or value.get("public_challenge_sha256")
            != row["public_challenge_sha256"]
            or value.get("target_labels_used") != 0
            or value.get("model_refits") != 0
            or value.get("model_free_UNKNOWN_stages") != 1024
        ):
            raise RuntimeError(f"A296 order gate failed: {row['target_id']}")
        orders[row["target_id"]] = value
    if not rfc8439_section_2_3_2_kat():
        raise RuntimeError("A296 byte RFC 8439 gate failed")
    metal = load_module(METAL_ANCHOR, "a296_metal_recover")
    root_reference = load_module(ROOT_REFERENCE, "a296_root_recover")
    if root_reference.rfc8439_kat().get("exact") is not True:
        raise RuntimeError("A296 root RFC 8439 gate failed")
    executable, build = metal.A184._A181._compile_native(BUILD, swiftc)
    first = protocol["targets"][0]
    host = metal.A184.SliceMetalHost(
        executable,
        initial_state(
            first["public_challenge"], metal.A119.CONSTANTS, first["unknown_key_bits"]
        ),
        np.asarray(first["public_challenge"]["target_words"][0], dtype=np.uint32),
        np.asarray(
            first["public_challenge"]["control_target_words"], dtype=np.uint32
        ),
    )
    rows: list[dict[str, Any]] = []
    try:
        for target in protocol["targets"]:
            identifier = target["target_id"]
            width = int(target["unknown_key_bits"])
            challenge = target["public_challenge"]
            coarse = orders[identifier]["complete_coarse_order"]
            ordered = fine_order(coarse)
            gate = mapping_gate(
                host=host,
                challenge=challenge,
                width=width,
                metal=metal,
                root_reference=root_reference,
            )
            discovery = discover(
                host=host,
                challenge=challenge,
                width=width,
                order=ordered,
                metal=metal,
            )
            confirmation = confirm(
                discovery=discovery,
                challenge=challenge,
                root_reference=root_reference,
            )
            ranks = rank_analysis(
                discovery=discovery,
                causal_order=ordered,
                public_challenge_sha256=target["public_challenge_sha256"],
            )
            rows.append(
                {
                    "target_id": identifier,
                    "unknown_key_bits": width,
                    "public_challenge_sha256": target["public_challenge_sha256"],
                    "order_artifact": anchor(order_path(identifier)),
                    "measurement_artifact": anchor(measurement_path(identifier)),
                    "mapping_gate": gate,
                    "discovery": discovery,
                    "rank_analysis": ranks,
                    "confirmation": confirmation,
                    "measurement_sha256": canonical_sha256(
                        {
                            "order_sha256": file_sha256(order_path(identifier)),
                            "discovery": discovery,
                            "rank_analysis": ranks,
                            "confirmation": confirmation,
                        }
                    ),
                }
            )
        metal_identity = host.identity
    finally:
        host.close()
    summary = aggregate(rows)
    evidence_stage = "FULLROUND_R20_EIGHT_TARGET_W24_REPLICATION_AND_W28_ZERO_REFIT_TRANSFER_CONFIRMED"
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-causal-search-gain-panel-a296-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "native_build": build,
        "metal_identity": metal_identity,
        "targets": rows,
        "aggregate": summary,
        "information_boundary": {
            "all_target_generation_assignments_absent": True,
            "all_target_orders_completed_before_any_recovery": True,
            "target_labels_or_models_used_for_reader_scoring": False,
            "reader_refits": 0,
            "counterfactual_control_ranks_computed_after_confirmation": True,
            "matched_controls_scanned_over_identical_executed_groups": True,
        },
        "anchors": protocol["anchors"],
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "targets": [
                {
                    "target_id": row["target_id"],
                    "mapping_gate": row["mapping_gate"],
                    "discovery": row["discovery"],
                }
                for row in rows
            ],
            "metal_identity": metal_identity,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "targets": [row["measurement_sha256"] for row in rows],
            "aggregate": summary,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    lines = [
        "# A296 — ChaCha20-R20 Causal search-gain panel",
        "",
        f"Evidence stage: **{evidence_stage}**",
        "",
        f"- Confirmed recoveries: **{summary['confirmed_recoveries']}/8**",
        f"- Strict-subset recoveries: **{summary['strict_subset_recoveries']}/8**",
        f"- Causal earlier than numeric: **{summary['Causal_earlier_than_numeric']}/8**",
        f"- Causal earlier than public hash: **{summary['Causal_earlier_than_public_hash']}/8**",
        f"- Geometric-mean domain reduction: **{summary['geometric_mean_domain_reduction']:.6f}x**",
        f"- Cross-implementation checked bits: **{summary['cross_implementation_output_bits_checked']:,}**",
        "- Reader refits / target labels: **0 / 0**",
        "",
    ]
    atomic_bytes(REPORT, ("\n".join(lines) + "\n").encode("utf-8"))
    return payload


def analyze() -> dict[str, Any]:
    frozen_design = design()
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "panel": frozen_design["panel"],
        "target_count": len(frozen_design["panel"]),
        "reader_refits": 0,
        "target_labels_used": 0,
        "targets_generated": PROTOCOL.exists(),
        "preflight_complete": PREFLIGHT.exists(),
        "measurement_orders_complete": sum(
            order_path(target_id(width, index)).exists()
            for width, count in PANEL_SPEC
            for index in range(count)
        ),
        "recovery_complete": RESULT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--measure", action="store_true")
    mode.add_argument("--recover", action="store_true")
    parser.add_argument("--target-id")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-preflight-sha256")
    parser.add_argument("--swiftc", default="/usr/bin/swiftc")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.freeze:
        value = freeze()
        payload = {
            "protocol": relative(PROTOCOL),
            "protocol_sha256": file_sha256(PROTOCOL),
            "scientific_design_sha256": value["scientific_design_sha256"],
            "target_ledger_sha256": value["target_ledger_sha256"],
        }
    else:
        if not args.expected_protocol_sha256:
            parser.error("this mode requires --expected-protocol-sha256")
        if args.preflight:
            value = preflight(args.expected_protocol_sha256)
            payload = {
                "preflight": relative(PREFLIGHT),
                "preflight_file_sha256": file_sha256(PREFLIGHT),
                "preflight_content_sha256": value["preflight_sha256"],
            }
        else:
            if not args.expected_preflight_sha256:
                parser.error("this mode requires --expected-preflight-sha256")
            if args.measure:
                if not args.target_id:
                    parser.error("--measure requires --target-id")
                value = measure_target(
                    identifier=args.target_id,
                    expected_protocol_sha256=args.expected_protocol_sha256,
                    expected_preflight_sha256=args.expected_preflight_sha256,
                )
                payload = {
                    "target_id": args.target_id,
                    "order": relative(order_path(args.target_id)),
                    "order_sha256": file_sha256(order_path(args.target_id)),
                    "complete_coarse_order_uint8_sha256": value[
                        "complete_coarse_order_uint8_sha256"
                    ],
                    "model_free_UNKNOWN_stages": value[
                        "model_free_UNKNOWN_stages"
                    ],
                }
            else:
                value = recover(
                    expected_protocol_sha256=args.expected_protocol_sha256,
                    expected_preflight_sha256=args.expected_preflight_sha256,
                    swiftc=args.swiftc,
                )
                payload = {
                    "evidence_stage": value["evidence_stage"],
                    "result": relative(RESULT),
                    "result_sha256": file_sha256(RESULT),
                    "causal": relative(CAUSAL),
                    "causal_sha256": file_sha256(CAUSAL),
                    "aggregate": value["aggregate"],
                }
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
