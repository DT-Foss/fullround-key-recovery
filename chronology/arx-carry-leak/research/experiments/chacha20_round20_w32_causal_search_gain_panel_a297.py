#!/usr/bin/env python3
"""Prospective four-target W32 transfer of A296's zero-refit Reader."""

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
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"
ARTIFACTS = RESEARCH / "artifacts/a297_chacha20_r20_w32_causal_search_gain_panel"

DESIGN = CONFIGS / "chacha20_round20_w32_causal_search_gain_panel_a297_design_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w32_causal_search_gain_panel_a297_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_w32_causal_search_gain_panel_a297_preflight_v1.json"
RESULT = RESULTS / "chacha20_round20_w32_causal_search_gain_panel_a297_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_W32_CAUSAL_SEARCH_GAIN_PANEL_A297_V1.md"
BUILD = RESEARCH / "build/chacha20_round20_w32_causal_search_gain_panel_a297"

A296_RUNNER = RESEARCH / "experiments/chacha20_round20_causal_search_gain_panel_a296.py"
A296_RESULT = RESULTS / "chacha20_round20_causal_search_gain_panel_a296_v1.json"
A296_CAUSAL = RESULTS / "chacha20_round20_causal_search_gain_panel_a296_v1.causal"
A251_WRAPPER = RESEARCH / "experiments/chacha20_fresh_clause_identity.py"
A223_SOURCE = RESEARCH / "experiments/chacha20_round20_capacity_moonshot_a223.py"
A223_CONFIG = CONFIGS / "chacha20_round20_capacity_moonshot_a223_v1.json"
ROOT_REFERENCE = RESEARCH / "experiments/chacha20_round20_multitarget_root_confirm.py"
METAL_ANCHOR = RESEARCH / "experiments/chacha20_round20_a223_w40_metal_transfer.py"

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A297"
DESIGN_SHA256 = "64037393209a6c791f13202d37715baa61f45fbd718146e7e03f3218b9609edc"
WIDTH = 32
TARGETS = 4
ROUNDS = 20
BLOCKS = 8
PREFIX_BITS = 8
FINE_PREFIX_BITS = 12
FINE_GROUPS = 1 << FINE_PREFIX_BITS
SUFFIX_BITS = WIDTH - FINE_PREFIX_BITS
GROUP_SIZE = 1 << SUFFIX_BITS
DOMAIN_SIZE = 1 << WIDTH
HORIZONS = [1, 2, 4, 8]
FEATURE_INDICES = [502, 504, 505, 508, 509, 510, 511, 514]
WATCHDOG_SECONDS = 2.0
ZSTD_LEVEL = 10
MASK32 = 0xFFFFFFFF


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A297 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A296 = load_module(A296_RUNNER, "a297_a296_common")
sha256 = A296.sha256
file_sha256 = A296.file_sha256
canonical_bytes = A296.canonical_bytes
canonical_sha256 = A296.canonical_sha256
atomic_bytes = A296.atomic_bytes
atomic_json = A296.atomic_json
relative = A296.relative
path_from_ref = A296.path_from_ref
anchor = A296.anchor


def target_id(index: int) -> str:
    return f"w32_t{index:02d}"


def measurement_path(identifier: str) -> Path:
    return RESULTS / "chacha20_round20_w32_causal_search_gain_panel_a297_v1" / (
        f"{identifier}.measurement.json.zst"
    )


def order_path(identifier: str) -> Path:
    return RESULTS / "chacha20_round20_w32_causal_search_gain_panel_a297_v1" / (
        f"{identifier}.order.json"
    )


def cnf_path(identifier: str) -> Path:
    return ARTIFACTS / identifier / "base_b1.cnf"


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A297 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w32-causal-search-gain-panel-a297-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("panel")
        != [
            {"target_id": target_id(index), "unknown_key_bits": WIDTH}
            for index in range(TARGETS)
        ]
        or value.get("reader_contract", {}).get("selected_feature_indices")
        != FEATURE_INDICES
        or value.get("information_boundary", {}).get(
            "any_A297_target_exists_at_design_freeze"
        )
        is not False
    ):
        raise RuntimeError("A297 design semantics differ")
    return value


def challenge_from_ephemeral_secret(root_reference: Any) -> dict[str, Any]:
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
    challenge = {
        "challenge_id": secrets.token_hex(16),
        "rounds": ROUNDS,
        "block_count": BLOCKS,
        "counter_schedule": "base_plus_block_index_mod_2^32",
        "counter_start": counter,
        "nonce_words": nonce_words,
        "known_key_bits": 256 - WIDTH,
        "known_key_mask_words": [0, *([MASK32] * 7)],
        "known_key_value_words": [0, *key_words[1:]],
        "unknown_key_bits": WIDTH,
        "unknown_global_bit_interval": [0, WIDTH - 1],
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
            sha256(A296.word_bytes(block)) for block in target_words
        ],
        "control_target_words": control,
        "control_target_block_sha256": sha256(A296.word_bytes(control)),
    }
    del key_words
    return challenge


def public_hash_order(public_challenge_sha256: str) -> list[int]:
    seed = bytes.fromhex(public_challenge_sha256)
    order = sorted(
        range(FINE_GROUPS),
        key=lambda value: hashlib.sha256(
            b"A297|public-hash-control|" + seed + value.to_bytes(2, "big")
        ).digest(),
    )
    if len(order) != FINE_GROUPS or set(order) != set(range(FINE_GROUPS)):
        raise RuntimeError("A297 public-hash order differs")
    return order


def execution_plan() -> dict[str, Any]:
    return {
        "primitive": "standard_ChaCha20_block_function",
        "rounds": ROUNDS,
        "feedforward_included": True,
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "target_count": TARGETS,
        "public_output_blocks_per_target": BLOCKS,
        "diagnostic_output_blocks_per_target": 1,
        "reader": "unchanged_A272_selected_eight_feature_model",
        "selected_feature_indices": FEATURE_INDICES,
        "conflict_horizons": HORIZONS,
        "partition_coordinates_high_to_low": list(range(31, 23, -1)),
        "high8_cells": 256,
        "fine_prefix_bits": FINE_PREFIX_BITS,
        "fine_prefix_groups": FINE_GROUPS,
        "suffix_bits_per_group": SUFFIX_BITS,
        "candidate_group_size": GROUP_SIZE,
        "complete_residual_domain": DOMAIN_SIZE,
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
        raise RuntimeError("A297 freeze must precede all A297 artifacts")
    frozen_design = load_design()
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(A296_CAUSAL), verify_integrity=True)
    if (
        file_sha256(A296_RESULT)
        != frozen_design["source_gap"]["A296_result_sha256"]
        or file_sha256(A296_CAUSAL)
        != frozen_design["source_gap"]["A296_Causal_sha256"]
        or reader.api_id != "a296pan"
        or len(reader._gaps) != 1
        or reader._gaps[0].get("expected_object_type")
        != "prospective_W32_transfer_or_learned_fine_subprefix_operator"
    ):
        raise RuntimeError("A297 authentic A296 source gap differs")
    root_reference = load_module(ROOT_REFERENCE, "a297_root_freeze")
    a223 = load_module(A223_SOURCE, "a297_a223_freeze")
    targets = []
    for index in range(TARGETS):
        challenge = challenge_from_ephemeral_secret(root_reference)
        a223._validate_challenge(challenge, width=WIDTH)  # noqa: SLF001
        targets.append(
            {
                "target_id": target_id(index),
                "unknown_key_bits": WIDTH,
                "public_challenge": challenge,
                "public_challenge_sha256": canonical_sha256(challenge),
            }
        )
    if len({row["public_challenge_sha256"] for row in targets}) != TARGETS:
        raise RuntimeError("A297 public targets are not disjoint")
    plan = execution_plan()
    reader_source = Path(inspect.getsourcefile(CausalReader) or "")
    payload = {
        "schema": "chacha20-round20-w32-causal-search-gain-panel-a297-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "all_four_fresh_W32_targets_and_zero_refit_reader_contract_frozen_before_any_target_CNF_export_measurement_order_or_discovery",
        "design": frozen_design,
        "execution_plan": plan,
        "execution_plan_sha256": canonical_sha256(plan),
        "targets": targets,
        "target_ledger_sha256": canonical_sha256(
            [
                {
                    "target_id": row["target_id"],
                    "public_challenge_sha256": row["public_challenge_sha256"],
                }
                for row in targets
            ]
        ),
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A296_runner": anchor(A296_RUNNER),
            "A296_result": anchor(A296_RESULT),
            "A296_causal": anchor(A296_CAUSAL),
            "A251_wrapper": anchor(A251_WRAPPER),
            "A223_source": anchor(A223_SOURCE),
            "A223_config": anchor(A223_CONFIG),
            "Metal_anchor": anchor(METAL_ANCHOR),
            "root_reference": anchor(ROOT_REFERENCE),
            "CausalReader": anchor(reader_source),
            "runner": anchor(Path(__file__)),
        },
        "authentic_causal_readback": {
            "source_api_id": reader.api_id,
            "source_gap": reader._gaps[0],
            "read_by_main_before_design": True,
        },
        "information_boundary": {
            "all_four_generation_assignments_discarded_before_serialization": True,
            "generation_assignments_returned_logged_or_serialized": False,
            "all_four_targets_frozen_before_any_CNF_export": True,
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
        raise RuntimeError("A297 protocol hash differs")
    payload = json.loads(PROTOCOL.read_bytes())
    if (
        payload.get("schema")
        != "chacha20-round20-w32-causal-search-gain-panel-a297-protocol-v1"
        or payload.get("execution_plan") != execution_plan()
        or payload.get("execution_plan_sha256")
        != canonical_sha256(execution_plan())
        or len(payload.get("targets", [])) != TARGETS
        or payload.get("anchors", {}).get("runner", {}).get("sha256")
        != file_sha256(Path(__file__))
    ):
        raise RuntimeError("A297 protocol semantics differ")
    for row in payload["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    for row in payload["targets"]:
        if canonical_sha256(row["public_challenge"]) != row["public_challenge_sha256"]:
            raise RuntimeError("A297 public challenge hash differs")
    return payload


def export_reader_cnf(
    *,
    a223: Any,
    config: dict[str, Any],
    identifier: str,
    challenge: dict[str, Any],
) -> dict[str, Any]:
    formula = A296.b1_formula(a223, challenge, WIDTH)
    output = cnf_path(identifier)
    output.parent.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix=f"a297_{identifier}_map_") as temporary:
        directory = Path(temporary)
        temporary_cnf = directory / "base.cnf"
        export = a223._export_cnf(  # noqa: SLF001
            formula=formula,
            output=temporary_cnf,
            config=config,
            label=f"A297_{identifier.upper()}_B1_BASE",
        )
        raw = temporary_cnf.read_bytes()
        lines = raw.splitlines(keepends=True)
        header = lines[0].split() if lines else []
        if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
            raise RuntimeError("A297 base CNF header differs")
        context = {
            "width": WIDTH,
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
            for dimension in range(-1, math.ceil(math.log2(WIDTH)))
        ]
        mapping = a223._decode_mapping(  # noqa: SLF001
            [(dimension, units) for _, dimension, units, _ in probes],
            width=WIDTH,
        )
        atomic_bytes(output, raw)
    view = A296.synthetic_reader_mapping(mapping, WIDTH)
    return {
        "target_id": identifier,
        "unknown_key_bits": WIDTH,
        "formula_bytes": len(formula.encode()),
        "formula_sha256": sha256(formula.encode()),
        "CNF": anchor(output, export["sha256"]),
        "CNF_header": export["header"],
        "source_one_literals_bit0_upward": mapping,
        "source_mapping_sha256": canonical_sha256(mapping),
        "synthetic_reader_mapping": view,
        "synthetic_reader_mapping_sha256": canonical_sha256(view),
        "partition_coordinates_high_to_low": list(range(31, 23, -1)),
        "diagnostic_model_view_coordinates": [*range(12), *range(24, 32)],
        "coordinate_probes": [row[3] for row in probes],
    }


def preflight(expected_protocol_sha256: str) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A297 preflight artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    a223 = load_module(A223_SOURCE, "a297_a223_preflight")
    config = json.loads(A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    rows = [
        export_reader_cnf(
            a223=a223,
            config=config,
            identifier=row["target_id"],
            challenge=row["public_challenge"],
        )
        for row in protocol["targets"]
    ]
    payload = {
        "schema": "chacha20-round20-w32-causal-search-gain-panel-a297-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FOUR_W32_TARGET_CNFS_AND_LITERAL_MAPS_FROZEN_BEFORE_MEASUREMENT",
        "protocol_sha256": expected_protocol_sha256,
        "targets": rows,
        "all_targets_preflighted": len(rows) == TARGETS,
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
        raise RuntimeError("A297 preflight hash differs")
    value = json.loads(PREFLIGHT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w32-causal-search-gain-panel-a297-preflight-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("all_targets_preflighted") is not True
        or len(value.get("targets", [])) != TARGETS
    ):
        raise RuntimeError("A297 preflight semantics differ")
    for row in value["targets"]:
        anchor(path_from_ref(row["CNF"]["path"]), row["CNF"]["sha256"])
    return protocol, value


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
    if identifier not in target_rows:
        raise ValueError(f"unknown A297 target: {identifier}")
    if order_path(identifier).exists() or measurement_path(identifier).exists():
        raise FileExistsError(f"A297 measurement already exists: {identifier}")
    a275, model, _a291, indices, helper = A296._reader_stack()  # noqa: SLF001
    wrapper = load_module(A251_WRAPPER, f"a297_clause_wrapper_{identifier}")
    row = preflight_rows[identifier]
    started = time.perf_counter()
    raw_run = wrapper.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["CNF"]["path"]),
        mode=f"A297_{identifier}_numeric_unlabeled",
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
        "schema": "chacha20-round20-w32-causal-search-gain-panel-a297-measurement-v1",
        "attempt_id": ATTEMPT_ID,
        "target_id": identifier,
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "public_challenge_sha256": target_rows[identifier]["public_challenge_sha256"],
        "unknown_key_bits": WIDTH,
        "order_name": "numeric",
        "partition_coordinates_high_to_low": row[
            "partition_coordinates_high_to_low"
        ],
        "free_bits_per_cell": WIDTH - PREFIX_BITS,
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
    atomic_bytes(measurement_path(identifier), compressed)
    analysis = {
        "schema": "chacha20-round20-w32-causal-search-gain-panel-a297-order-v1",
        "attempt_id": ATTEMPT_ID,
        "target_id": identifier,
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "public_challenge_sha256": target_rows[identifier]["public_challenge_sha256"],
        "unknown_key_bits": WIDTH,
        "measurement": {
            "path": relative(measurement_path(identifier)),
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
            b"".join(
                value.to_bytes(2, "big") for value in A296.fine_order(coarse)
            )
        ),
        "selected_feature_indices": list(indices),
        "model_refits": 0,
        "target_labels_used": 0,
        "model_free_UNKNOWN_stages": len(measurement["run"]["stages"]),
    }
    atomic_json(order_path(identifier), analysis)
    return analysis


def rank_analysis(
    discovery: Mapping[str, Any], causal_order: Sequence[int], challenge_sha: str
) -> dict[str, Any]:
    prefix = int(discovery["fine_prefix12"])
    causal = [int(value) for value in causal_order]
    hashed = public_hash_order(challenge_sha)
    ranks = {
        "Causal": causal.index(prefix) + 1,
        "numeric": prefix + 1,
        "public_hash_control": hashed.index(prefix) + 1,
    }
    return {
        "prefix12": prefix,
        "prefix_ranks_one_based": ranks,
        "Causal_speedup_vs_numeric_rank": ranks["numeric"] / ranks["Causal"],
        "Causal_speedup_vs_public_hash_rank": (
            ranks["public_hash_control"] / ranks["Causal"]
        ),
        "counterfactual_ranks_computed_after_confirmation": True,
    }


def aggregate(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    ranks = [
        int(row["rank_analysis"]["prefix_ranks_one_based"]["Causal"])
        for row in rows
    ]
    numeric_ratios = [
        row["rank_analysis"]["Causal_speedup_vs_numeric_rank"] for row in rows
    ]
    hash_ratios = [
        row["rank_analysis"]["Causal_speedup_vs_public_hash_rank"] for row in rows
    ]
    gm = lambda values: math.exp(  # noqa: E731
        sum(math.log(float(value)) for value in values) / len(values)
    )
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
        "Causal_prefix_ranks": ranks,
        "strict_subset_recoveries": sum(
            bool(row["discovery"]["strict_subset_of_complete_domain"])
            for row in rows
        ),
        "geometric_mean_domain_reduction": gm(
            [FINE_GROUPS / rank for rank in ranks]
        ),
        "Causal_earlier_than_numeric": sum(float(value) > 1 for value in numeric_ratios),
        "Causal_earlier_than_public_hash": sum(float(value) > 1 for value in hash_ratios),
        "geometric_mean_Causal_speedup_vs_numeric": gm(numeric_ratios),
        "geometric_mean_Causal_speedup_vs_public_hash": gm(hash_ratios),
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A297:confirmed_four_target_W32_zero_refit_transfer"
    writer = CausalWriter(api_id="a297w32")
    writer._rules = []
    writer.add_rule(
        name="A296_gap_to_fresh_W32_panel",
        description="The personally read A296 gap selects four full-word W32 targets before any target generation or measurement.",
        pattern=["A296_W24_W28_panel", "A297_four_target_freeze"],
        conclusion="A297_prospective_W32_contract",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="zero_refit_W32_order_to_independent_recovery",
        description="Each W32 target-specific order precedes candidate discovery and dual eight-block confirmation.",
        pattern=["A297_zero_refit_orders", "A297_dual_confirmations"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A296:confirmed_W24_replication_and_W28_transfer_panel",
        mechanism="same_A272_A291_reader_contract_on_four_fresh_W32_targets",
        outcome="A297:target_blind_W32_orders",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification="four targets; 4096 model-free stages; zero refits; zero labels",
        evidence=payload["preflight_sha256"],
        domain="AI-native full-word ChaCha20 Reader transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A297:target_blind_W32_orders",
        mechanism="Causal_Gray4_ordered_Metal_search_then_dual_RFC_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["aggregate"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W32 search",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A296:confirmed_W24_replication_and_W28_transfer_panel",
        mechanism="materialized_W24_W28_to_W32_transfer_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A296_gap_plus_A297_panel",
        quantification=json.dumps(payload["aggregate"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A297 full-word W32 zero-refit transfer",
        entities=[
            "A296:confirmed_W24_replication_and_W28_transfer_panel",
            "A297:target_blind_W32_orders",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fine_subprefix_reader_or_prospective_W36_transfer",
        confidence=1.0,
        suggested_queries=[
            "Can the A295 fine-channel operator improve W32 order?",
            "Does the same contract widen beyond one complete 32-bit key word?",
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
        reader.api_id != "a297w32"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A297 authentic Causal reopen gate failed")
    source = Path(inspect.getsourcefile(CausalReader) or "")
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
        "reader_source": anchor(source),
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
        raise FileExistsError("A297 result already exists")
    protocol, _ = load_preflight(
        expected_protocol_sha256, expected_preflight_sha256
    )
    orders = {}
    for target in protocol["targets"]:
        value = json.loads(order_path(target["target_id"]).read_bytes())
        if (
            value.get("protocol_sha256") != expected_protocol_sha256
            or value.get("preflight_sha256") != expected_preflight_sha256
            or value.get("public_challenge_sha256")
            != target["public_challenge_sha256"]
            or value.get("model_free_UNKNOWN_stages") != 1024
            or value.get("model_refits") != 0
            or value.get("target_labels_used") != 0
        ):
            raise RuntimeError(f"A297 order gate failed: {target['target_id']}")
        orders[target["target_id"]] = value
    metal = load_module(METAL_ANCHOR, "a297_metal_recover")
    root_reference = load_module(ROOT_REFERENCE, "a297_root_recover")
    executable, build = metal.A184._A181._compile_native(BUILD, swiftc)
    first = protocol["targets"][0]["public_challenge"]
    host = metal.A184.SliceMetalHost(
        executable,
        A296.initial_state(first, metal.A119.CONSTANTS, WIDTH),
        np.asarray(first["target_words"][0], dtype=np.uint32),
        np.asarray(first["control_target_words"], dtype=np.uint32),
    )
    rows = []
    try:
        for target in protocol["targets"]:
            identifier = target["target_id"]
            challenge = target["public_challenge"]
            ordered = A296.fine_order(orders[identifier]["complete_coarse_order"])
            mapping = A296.mapping_gate(
                host=host,
                challenge=challenge,
                width=WIDTH,
                metal=metal,
                root_reference=root_reference,
            )
            discovery = A296.discover(
                host=host,
                challenge=challenge,
                width=WIDTH,
                order=ordered,
                metal=metal,
            )
            confirmation = A296.confirm(
                discovery=discovery,
                challenge=challenge,
                root_reference=root_reference,
            )
            ranks = rank_analysis(
                discovery, ordered, target["public_challenge_sha256"]
            )
            rows.append(
                {
                    "target_id": identifier,
                    "unknown_key_bits": WIDTH,
                    "public_challenge_sha256": target["public_challenge_sha256"],
                    "order_artifact": anchor(order_path(identifier)),
                    "measurement_artifact": anchor(measurement_path(identifier)),
                    "mapping_gate": mapping,
                    "discovery": discovery,
                    "rank_analysis": ranks,
                    "confirmation": confirmation,
                }
            )
        metal_identity = host.identity
    finally:
        host.close()
    summary = aggregate(rows)
    evidence_stage = "FULLROUND_R20_FOUR_TARGET_W32_ZERO_REFIT_CAUSAL_TRANSFER_CONFIRMED"
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w32-causal-search-gain-panel-a297-result-v1",
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
        [
            {"target_id": row["target_id"], "discovery": row["discovery"]}
            for row in rows
        ]
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "targets": rows,
            "aggregate": summary,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    lines = [
        "# A297 — ChaCha20-R20 W32 Causal search-gain panel",
        "",
        f"Evidence stage: **{evidence_stage}**",
        "",
        f"- Confirmed recoveries: **{summary['confirmed_recoveries']}/4**",
        f"- Strict-subset recoveries: **{summary['strict_subset_recoveries']}/4**",
        f"- Geometric-mean domain reduction: **{summary['geometric_mean_domain_reduction']:.6f}x**",
        f"- Causal versus numeric geometric rank ratio: **{summary['geometric_mean_Causal_speedup_vs_numeric']:.6f}x**",
        f"- Causal versus public-hash geometric rank ratio: **{summary['geometric_mean_Causal_speedup_vs_public_hash']:.6f}x**",
        "- Reader refits / target labels: **0 / 0**",
        "",
    ]
    atomic_bytes(REPORT, ("\n".join(lines) + "\n").encode("utf-8"))
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "target_count": TARGETS,
        "unknown_key_bits": WIDTH,
        "targets_generated": PROTOCOL.exists(),
        "preflight_complete": PREFLIGHT.exists(),
        "measurement_orders_complete": sum(
            order_path(target_id(index)).exists() for index in range(TARGETS)
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
