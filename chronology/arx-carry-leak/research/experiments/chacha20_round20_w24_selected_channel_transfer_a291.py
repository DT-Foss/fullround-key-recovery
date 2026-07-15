#!/usr/bin/env python3
"""Freeze and execute A272's unchanged selected-channel Reader at ChaCha20 W24.

A291 is deliberately split into two phases.  ``--freeze`` exports a one-block
W24 CNF, derives its exact key-literal map, and freezes the unchanged A272
eight-feature Reader before any A291 trajectory is measured.  ``--run`` then
measures all 256 high-byte cells at four shallow conflict horizons and creates
a complete target-blind order.  No candidate label or solver outcome is used
to construct the order.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import math
import os
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
ARTIFACTS = RESEARCH / "artifacts/a291_chacha20_r20_w24_selected_channel"
REPORTS = RESEARCH / "reports"

A223_SOURCE = RESEARCH / "experiments/chacha20_round20_capacity_moonshot_a223.py"
A223_CONFIG = CONFIGS / "chacha20_round20_capacity_moonshot_a223_v1.json"
A251_WRAPPER = RESEARCH / "experiments/chacha20_fresh_clause_identity.py"
A251_NATIVE = RESEARCH / "native/cadical_fresh_clause_identity.cpp"
A251_BASE_NATIVE = RESEARCH / "native/cadical_fresh_multihorizon.cpp"
A275_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_selected_channel_target_replication_measure.py"
)
A275_PROTOCOL = CONFIGS / "chacha20_round20_selected_channel_target_replication_v1.json"
A286_RESULT = RESULTS / "chacha20_round20_multitarget_panel_root_confirmation_a286_v1.json"
A286_CAUSAL = RESULTS / "chacha20_round20_multitarget_panel_root_confirmation_a286_v1.causal"
A287_SOURCE = RESEARCH / "experiments/chacha20_round20_w24_global_portfolio_a287.py"
A287_PROTOCOL = CONFIGS / "chacha20_round20_w24_global_portfolio_a287_v1.json"
A287_PREFLIGHT = RESULTS / "chacha20_round20_w24_global_portfolio_a287_preflight_v1.json"
A287_RESULT = RESULTS / "chacha20_round20_w24_global_portfolio_a287_v1.json"
A289_RESULT = RESULTS / "chacha20_round20_w24_cross_solver_portfolio_a289_v1.json"
A290_RESULT = RESULTS / "chacha20_round20_w24_reverse_global_transfer_a290_v1.json"

PROTOCOL = CONFIGS / "chacha20_round20_w24_selected_channel_transfer_a291_v1.json"
RESULT = RESULTS / "chacha20_round20_w24_selected_channel_transfer_a291_v1.json"
MEASUREMENT = (
    RESULTS
    / "chacha20_round20_w24_selected_channel_transfer_a291_v1"
    / "target.numeric.measurement.json.zst"
)
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_W24_SELECTED_CHANNEL_TRANSFER_A291_V1.md"
BASE_CNF = ARTIFACTS / "a291_chacha20_r20_w24_b1_base.cnf"
HELPER_BASE = RESEARCH / "native/build/cadical_fresh_clause_identity_a291"

DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A291"
WIDTH = 24
PREFIX_BITS = 8
FREE_BITS = WIDTH - PREFIX_BITS
HORIZONS = [1, 2, 4, 8]
FEATURE_INDICES = [502, 504, 505, 508, 509, 510, 511, 514]
WATCHDOG_SECONDS = 2.0
EXPORT_TIMEOUT_SECONDS = 60
ZSTD_LEVEL = 10

FORBIDDEN_KEYS = {
    "known_low20",
    "low20",
    "low20_hex",
    "recovered_unknown_low20",
    "recovered_unknown_low20_hex",
    "secret",
    "secret_assignment",
    "target_prefix8",
    "true_prefix",
    "unknown_assignment",
    "unknown_assignment_value",
}


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
        raise RuntimeError(f"A291 anchor differs: {path}")
    return {"path": relative(path), "sha256": digest}


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load A291 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def assert_secret_free(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in FORBIDDEN_KEYS:
                raise RuntimeError(f"A291 forbidden field: {key}")
            assert_secret_free(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            assert_secret_free(child)


def numeric_order() -> list[str]:
    return [f"{value:08b}" for value in range(256)]


def synthetic_reader_mapping(source_mapping: Sequence[int]) -> list[int]:
    """Embed the W24 high-byte partition in the legacy twenty-literal reader ABI.

    Positions 12..19 become genuine W24 coordinates 16..23, so the unchanged
    helper fixes the correct high byte.  Coordinates 12..15 are intentionally
    omitted only from the diagnostic model-view vector; they remain free in the
    CNF together with coordinates 0..15.
    """

    mapping = [int(value) for value in source_mapping]
    if (
        len(mapping) != WIDTH
        or any(value == 0 for value in mapping)
        or len({abs(value) for value in mapping}) != WIDTH
    ):
        raise ValueError("A291 source mapping must contain 24 distinct literals")
    view = [*mapping[:12], *mapping[16:24]]
    if len(view) != 20 or len({abs(value) for value in view}) != 20:
        raise RuntimeError("A291 synthetic Reader mapping differs")
    return view


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, str]]:
    try:
        module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(module.CausalReader) or "")
    return (
        module.CausalWriter,
        module.CausalReader,
        {
            "path": str(source),
            "sha256": file_sha256(source),
        },
    )


def _source_gate(dotcausal_src: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    a286 = json.loads(A286_RESULT.read_bytes())
    a287 = json.loads(A287_PROTOCOL.read_bytes())
    preflight = json.loads(A287_PREFLIGHT.read_bytes())
    if (
        a286.get("attempt_id") != "A286"
        or a286.get("evidence_stage")
        != "FULLROUND_R20_FOUR_OF_FOUR_CROSS_MATERIAL_RECOVERIES_INDEPENDENTLY_CONFIRMED"
        or a287.get("attempt_id") != "A287"
        or a287.get("schema") != "chacha20-round20-w24-global-portfolio-a287-protocol-v1"
        or preflight.get("attempt_id") != "A287"
        or preflight.get("evidence_stage") != "W24_TWO_ARM_GLOBAL_PORTFOLIO_PREFLIGHT_FROZEN"
        or preflight.get("protocol", {}).get("sha256") != file_sha256(A287_PROTOCOL)
        or preflight.get("public_challenge_sha256") != a287.get("public_challenge_sha256")
        or len(preflight.get("source_one_literals_bit0_upward", [])) != WIDTH
    ):
        raise RuntimeError("A291 A286/A287 source gate failed")
    assert_secret_free(a287)
    _, CausalReader, _ = _load_dotcausal(dotcausal_src)
    reader = CausalReader(str(A286_CAUSAL), verify_integrity=True)
    if (
        reader.api_id != "a286pan"
        or len(reader._gaps) != 1
        or reader._gaps[0].get("expected_object_type")
        != "prospectively_frozen_W24_cross_material_transfer"
    ):
        raise RuntimeError("A291 A286 authentic Causal gap differs")
    return a286, {"protocol": a287, "preflight": preflight}


def _b1_formula(a223: Any, challenge: dict[str, Any]) -> str:
    """Use A223's exact split-18 compiler with only its first public block."""

    original = int(a223.BLOCK_COUNT)
    try:
        a223.BLOCK_COUNT = 1
        formula = a223._source_formula(challenge, width=WIDTH)  # noqa: SLF001
    finally:
        a223.BLOCK_COUNT = original
    if (
        "b1_v" in formula
        or formula.count("(assert (= b0_v") != 16
        or formula.count("(check-sat)") != 1
    ):
        raise RuntimeError("A291 one-block formula boundary differs")
    return formula


def _export_reader_cnf(
    *, a223: Any, config: dict[str, Any], challenge: dict[str, Any]
) -> dict[str, Any]:
    formula = _b1_formula(a223, challenge)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a291_w24_b1_map_") as temporary:
        directory = Path(temporary)
        base_temporary = directory / "a291_w24_b1_base.cnf"
        export = a223._export_cnf(  # noqa: SLF001
            formula=formula,
            output=base_temporary,
            config=config,
            label="A291_W24_B1_BASE",
        )
        raw = base_temporary.read_bytes()
        lines = raw.splitlines(keepends=True)
        header = lines[0].split() if lines else []
        if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
            raise RuntimeError("A291 base CNF header differs")
        context = {
            "width": WIDTH,
            "formula": formula,
            "formula_bytes": len(formula.encode()),
            "formula_sha256": sha256(formula.encode()),
            "base_path": base_temporary,
            "base_raw": raw,
            "base_body": b"".join(lines[1:]),
            "base_body_sha256": sha256(b"".join(lines[1:])),
            "variable_count": int(header[2]),
            "clause_count": int(header[3]),
            "base_export": export,
        }
        probe_rows = [
            a223._coordinate_probe(  # noqa: SLF001
                context=context,
                dimension=dimension,
                config=config,
                directory=directory,
            )
            for dimension in range(-1, math.ceil(math.log2(WIDTH)))
        ]
        mapping = a223._decode_mapping(  # noqa: SLF001
            [(dimension, units) for _, dimension, units, _ in probe_rows],
            width=WIDTH,
        )
        atomic_bytes(BASE_CNF, raw)
    if file_sha256(BASE_CNF) != export["sha256"]:
        raise RuntimeError("A291 persisted base CNF hash differs")
    return {
        "formula_bytes": len(formula.encode()),
        "formula_sha256": sha256(formula.encode()),
        "blocks": 1,
        "rounds": 20,
        "feedforward_included": True,
        "split_round": 18,
        "CNF": anchor(BASE_CNF),
        "CNF_header": export["header"],
        "CNF_export": export,
        "source_one_literals_bit0_upward": mapping,
        "source_mapping_sha256": canonical_sha256(mapping),
        "synthetic_reader_mapping": synthetic_reader_mapping(mapping),
        "synthetic_reader_mapping_sha256": canonical_sha256(synthetic_reader_mapping(mapping)),
        "omitted_from_diagnostic_model_view_but_free_in_CNF": [12, 13, 14, 15],
        "partition_coordinates_high_to_low": list(range(23, 15, -1)),
        "coordinate_probes": [row[3] for row in probe_rows],
    }


def execution_plan(cnf: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "primitive": "standard_ChaCha20_block_function",
        "rounds": 20,
        "feedforward_included": True,
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "diagnostic_target_blocks": 1,
        "recovery_target_blocks_available": 8,
        "partition_prefix_coordinates_high_to_low": list(range(23, 15, -1)),
        "prefix_cells": 256,
        "free_bits_per_cell": FREE_BITS,
        "complete_disjoint_assignment_domain": 1 << WIDTH,
        "candidate_order": "numeric_0_through_255",
        "fresh_solver_instance_per_cell": True,
        "conflict_horizons": HORIZONS,
        "watchdog_seconds_per_stage": WATCHDOG_SECONDS,
        "all_1024_stages_must_remain_UNKNOWN_and_model_free": True,
        "reader": "unchanged_A272_eight_feature_selected_channel_reader",
        "selected_feature_indices": FEATURE_INDICES,
        "model_refits": 0,
        "target_labels_used": 0,
        "score": "sum_of_frozen_standardized_additive_contributions",
        "order_tiebreak": "descending_score_then_ascending_prefix",
        "CNF_sha256": cnf["CNF"]["sha256"],
        "source_mapping_sha256": cnf["source_mapping_sha256"],
        "synthetic_reader_mapping_sha256": cnf["synthetic_reader_mapping_sha256"],
    }


def freeze(*, dotcausal_src: Path) -> dict[str, Any]:
    if PROTOCOL.exists():
        raise FileExistsError(PROTOCOL)
    if any(path.exists() for path in (A287_RESULT, A289_RESULT, A290_RESULT, RESULT)):
        raise RuntimeError("A291 must freeze before every global W24 outcome")
    a286, source = _source_gate(dotcausal_src)
    a223 = load_module(A223_SOURCE, "a291_a223_freeze")
    config = json.loads(A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    cnf = _export_reader_cnf(
        a223=a223,
        config=config,
        challenge=source["protocol"]["public_challenge"],
    )
    wrapper = load_module(A251_WRAPPER, "a291_clause_wrapper_freeze")
    build = wrapper.compile_helper(output_base=HELPER_BASE)
    helper = Path(build["binary_path"])
    a275_protocol = json.loads(A275_PROTOCOL.read_bytes())
    a272_anchors = {
        stem: anchor(
            path_from_ref(a275_protocol["anchors"][f"{stem}_path"]),
            a275_protocol["anchors"][f"{stem}_sha256"],
        )
        for stem in ("A272_protocol", "A272_result", "A272_causal")
    }
    if (
        a275_protocol.get("readout", {}).get("feature_indices") != FEATURE_INDICES
        or a275_protocol.get("readout", {}).get("model_refit_or_coefficient_update_permitted")
        is not False
    ):
        raise RuntimeError("A291 A272 selected Reader identity differs")
    plan = execution_plan(cnf)
    payload = {
        "schema": "chacha20-round20-w24-selected-channel-transfer-a291-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "unchanged_A272_reader_and_complete_W24_measurement_frozen_before_any_A291_measurement_or_global_W24_outcome",
        "research_question": "Does A272's unchanged target-blind selected channel preserve prefix-order information after widening the same full-round relation from W20 to W24?",
        "public_challenge_sha256": source["protocol"]["public_challenge_sha256"],
        "execution_plan": plan,
        "execution_plan_sha256": canonical_sha256(plan),
        "reader_CNF": cnf,
        "anchors": {
            "runner": anchor(Path(__file__)),
            "A286_result": anchor(A286_RESULT),
            "A286_causal": anchor(A286_CAUSAL),
            "A287_source": anchor(A287_SOURCE),
            "A287_protocol": anchor(A287_PROTOCOL),
            "A287_preflight": anchor(A287_PREFLIGHT),
            "A223_source": anchor(A223_SOURCE),
            "A223_config": anchor(A223_CONFIG),
            "A251_wrapper": anchor(A251_WRAPPER),
            "A251_native": anchor(A251_NATIVE),
            "A251_base_native": anchor(A251_BASE_NATIVE),
            "A251_helper": anchor(helper, build["binary_sha256"]),
            "A275_runner": anchor(A275_RUNNER),
            "A275_protocol": anchor(A275_PROTOCOL),
            **a272_anchors,
        },
        "authentic_causal_readback": {
            "source_api_id": a286["causal"]["api_id"],
            "source_gap": a286["causal"]["personal_semantic_readback"]["next_gap"],
            "read_by_main_before_freeze": True,
        },
        "information_boundary": {
            "A272_reader_frozen_before_A287_target_generation": True,
            "A286_W24_gap_read_before_A291_design": True,
            "A287_public_target_exists_but_secret_assignment_is_absent": True,
            "A287_A289_A290_outcomes_available_at_freeze": False,
            "A291_trajectory_measurement_started_before_freeze": False,
            "target_prefix_or_model_available_to_reader": False,
            "all_cells_horizons_features_and_tiebreak_frozen": True,
            "UNKNOWN_will_not_be_treated_as_UNSAT": True,
        },
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "execution_plan": plan,
            "reader_CNF": cnf,
            "anchors": payload["anchors"],
            "information_boundary": payload["information_boundary"],
        }
    )
    assert_secret_free(payload)
    atomic_json(PROTOCOL, payload)
    return payload


def _load_protocol(
    expected_sha256: str, dotcausal_src: Path
) -> tuple[dict[str, Any], Any, Any, Any, tuple[int, ...]]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A291 protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    if (
        protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("schema")
        != "chacha20-round20-w24-selected-channel-transfer-a291-protocol-v1"
        or protocol.get("execution_plan") != execution_plan(protocol["reader_CNF"])
        or protocol.get("execution_plan_sha256") != canonical_sha256(protocol["execution_plan"])
        or protocol.get("reader_CNF", {}).get("CNF", {}).get("sha256") != file_sha256(BASE_CNF)
    ):
        raise RuntimeError("A291 frozen protocol semantic gate failed")
    for name, row in protocol["anchors"].items():
        if not isinstance(row, Mapping) or set(row) != {"path", "sha256"}:
            raise RuntimeError(f"A291 anchor shape differs: {name}")
        if file_sha256(path_from_ref(str(row["path"]))) != row["sha256"]:
            raise RuntimeError(f"A291 anchored dependency differs: {name}")
    _, CausalReader, _ = _load_dotcausal(dotcausal_src)
    source_reader = CausalReader(str(A286_CAUSAL), verify_integrity=True)
    if source_reader._gaps[0] != protocol["authentic_causal_readback"]["source_gap"]:
        raise RuntimeError("A291 source Causal gap changed")
    a275 = load_module(A275_RUNNER, "a291_a275_run")
    (
        _,
        _,
        _,
        a268,
        a251_protocol,
        a242,
        model,
        indices,
    ) = a275._load_protocol(  # noqa: SLF001
        A275_PROTOCOL,
        protocol["anchors"]["A275_protocol"]["sha256"],
    )
    if tuple(FEATURE_INDICES) != indices:
        raise RuntimeError("A291 loaded A272 feature indices differ")
    _, _, a251, _, _ = a268._load_protocol()  # noqa: SLF001
    return protocol, a275, a251, model, indices


def _write_measurement(path: Path, measurement: Mapping[str, Any]) -> dict[str, Any]:
    raw = canonical_bytes(measurement)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    atomic_bytes(path, compressed)
    return {
        "path": relative(path),
        "raw_bytes": len(raw),
        "raw_sha256": sha256(raw),
        "compressed_bytes": len(compressed),
        "compressed_sha256": sha256(compressed),
        "resumed": False,
    }


def _read_measurement(
    path: Path, *, expected_protocol_sha256: str, a275: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    compressed = path.read_bytes()
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    value = json.loads(raw)
    if (
        value.get("schema") != "chacha20-round20-w24-selected-channel-transfer-a291-measurement-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("complete_candidate_cover") is not True
        or canonical_bytes(value) != raw
    ):
        raise RuntimeError("A291 measurement shard gate failed")
    a275._target_feature_matrix(value)  # noqa: SLF001
    return value, {
        "path": relative(path),
        "raw_bytes": len(raw),
        "raw_sha256": sha256(raw),
        "compressed_bytes": len(compressed),
        "compressed_sha256": sha256(compressed),
        "resumed": True,
    }


def _build_causal(path: Path, payload: Mapping[str, Any], dotcausal_src: Path) -> dict[str, Any]:
    CausalWriter, CausalReader, source = _load_dotcausal(dotcausal_src)
    writer = CausalWriter(api_id="a291w24")
    writer._rules = []
    writer.add_rule(
        name="panel_gap_selects_zero_refit_wider_reader",
        description="A286's authentic W24 gap selects a direct, zero-refit transfer of A272's eight-feature Reader onto the independently frozen A287 target.",
        pattern=["A286_retained_four_target_panel", "A272_frozen_eight_feature_reader"],
        conclusion="A291_W24_zero_refit_reader_contract",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_model_free_cover_precedes_order",
        description="All 256 W24 high-byte cells and all 1024 shallow stages complete without a model before the frozen additive score creates a total order.",
        pattern=["A291_complete_W24_model_free_cover", "A291_W24_zero_refit_reader_contract"],
        conclusion="A291_hash_frozen_W24_prefix_order",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A286:retained_four_target_panel",
        mechanism="apply_unchanged_A272_eight_feature_reader_to_W24_high_byte_cells",
        outcome="A291:W24_zero_refit_reader_contract",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification="256 cells; 16 free bits per cell; one R20 output block; zero refits",
        evidence=payload["public_challenge_sha256"],
        domain="prospective full-round ChaCha20 W20-to-W24 Reader transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A291:W24_zero_refit_reader_contract",
        mechanism="complete_1024_model_free_stages_then_frozen_additive_score",
        outcome="A291:hash_frozen_W24_prefix_order",
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification="256/256 cells; 1024/1024 UNKNOWN stages; zero labels",
        evidence=json.dumps(payload["headline"], sort_keys=True),
        domain="target-blind W24 prefix ranking",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A286:retained_four_target_panel",
        mechanism="materialized_panel_gap_reader_cover_order_chain",
        outcome="A291:hash_frozen_W24_prefix_order",
        confidence=1.0,
        source="materialized:A286_gap_plus_A291_complete_cover",
        quantification="AI-native wider-transfer chain",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A291 zero-refit W24 selected-channel transfer",
        entities=[
            "A286:retained_four_target_panel",
            "A291:W24_zero_refit_reader_contract",
            "A291:hash_frozen_W24_prefix_order",
        ],
    )
    writer.add_gap(
        subject="A291:hash_frozen_W24_prefix_order",
        predicate="next_required_object",
        expected_object_type="ranked_W24_partition_recovery_with_16_free_bits_per_cell",
        confidence=1.0,
        suggested_queries=[
            "Does the frozen A291 order return a confirmed model before the complete 256-cell domain?",
            "How does its discovery rank compare with numeric, Gray, and the six global W24 operators?",
        ],
    )
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a291w24"
        or len(explicit) != 2
        or len(rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A291 authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(path),
        "sha256": file_sha256(path),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": source,
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def run(*, expected_protocol_sha256: str, dotcausal_src: Path) -> dict[str, Any]:
    protocol, a275, a251, model, indices = _load_protocol(expected_protocol_sha256, dotcausal_src)
    if RESULT.exists():
        raise FileExistsError(RESULT)
    mapping = protocol["reader_CNF"]["synthetic_reader_mapping"]
    if MEASUREMENT.exists():
        measurement, ledger = _read_measurement(
            MEASUREMENT,
            expected_protocol_sha256=expected_protocol_sha256,
            a275=a275,
        )
    else:
        wrapper = load_module(A251_WRAPPER, "a291_clause_wrapper_run")
        helper = path_from_ref(protocol["anchors"]["A251_helper"]["path"])
        started = time.perf_counter()
        raw_run = wrapper.run_fresh_clause_identity(
            helper=helper,
            cnf=BASE_CNF,
            mode="A291_W24_B1_numeric_unlabeled",
            order=numeric_order(),
            key_one_literals_bit0_through_bit19=mapping,
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
            "schema": "chacha20-round20-w24-selected-channel-transfer-a291-measurement-v1",
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": expected_protocol_sha256,
            "public_challenge_sha256": protocol["public_challenge_sha256"],
            "order_name": "numeric",
            "partition_coordinates_high_to_low": list(range(23, 15, -1)),
            "free_bits_per_cell": FREE_BITS,
            "run": stable_run,
            "volatile_process_elapsed_seconds": time.perf_counter() - started,
            "target_label_available_to_measurement": False,
            "label_used_for_feature_construction_or_scoring": False,
            "complete_candidate_cover": len(raw_run["cells"]) == 256,
        }
        assert_secret_free(measurement)
        a275._target_feature_matrix(measurement)  # noqa: SLF001
        ledger = _write_measurement(MEASUREMENT, measurement)
    matrix = a275._target_feature_matrix(measurement)  # noqa: SLF001
    contributions = a275.standardized_contributions(
        matrix,
        means=model.means,
        scales=model.scales,
        coefficients=model.coefficients,
    )
    scores = contributions[:, indices].sum(axis=1)
    order = a275._candidate_order(scores)  # noqa: SLF001
    analysis = {
        "score_field": np.asarray(scores, dtype=np.float64).tolist(),
        "score_field_sha256": canonical_sha256(np.asarray(scores, dtype=np.float64).tolist()),
        "complete_cell_order": order,
        "complete_cell_order_uint8_sha256": sha256(bytes(order)),
        "top64_cell_order": order[:64],
        "top64_cell_order_uint8_sha256": sha256(bytes(order[:64])),
        "top128_cell_order": order[:128],
        "top128_cell_order_uint8_sha256": sha256(bytes(order[:128])),
        "selected_feature_indices": list(indices),
        "model_refits": 0,
        "target_labels_used": 0,
        "order_tiebreak": "descending_score_then_ascending_prefix",
    }
    headline = {
        "complete_candidate_cells": len(order),
        "model_free_UNKNOWN_stages": len(measurement["run"]["stages"]),
        "free_bits_per_cell": FREE_BITS,
        "complete_domain_bits": WIDTH,
        "complete_order_uint8_sha256": analysis["complete_cell_order_uint8_sha256"],
        "target_label_available": False,
        "reader_refits": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w24-selected-channel-transfer-a291-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_R20_W24_ZERO_REFIT_SELECTED_CHANNEL_ORDER_FROZEN",
        "protocol_sha256": expected_protocol_sha256,
        "runner_sha256": file_sha256(Path(__file__)),
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "measurement": ledger,
        "analysis": analysis,
        "analysis_sha256": canonical_sha256(analysis),
        "headline": headline,
        "information_boundary": protocol["information_boundary"],
    }
    assert_secret_free(payload)
    payload["causal"] = _build_causal(CAUSAL, payload, dotcausal_src)
    atomic_json(RESULT, payload)
    report = "\n".join(
        [
            "# A291 — zero-refit ChaCha20-R20 W24 selected-channel transfer",
            "",
            f"Evidence stage: **{payload['evidence_stage']}**",
            "",
            f"- Complete cells: **{headline['complete_candidate_cells']}/256**",
            f"- Model-free shallow stages: **{headline['model_free_UNKNOWN_stages']}/1024**",
            f"- Free bits per cell: **{headline['free_bits_per_cell']}**",
            "- A272 model refits / target labels: **0 / 0**",
            f"- Complete order SHA-256: `{headline['complete_order_uint8_sha256']}`",
            f"- Authentic Causal next gap: **{payload['causal']['personal_semantic_readback']['next_gap']['expected_object_type']}**",
            "",
        ]
    )
    atomic_bytes(REPORT, report.encode("utf-8"))
    return payload


def analyze(dotcausal_src: Path) -> dict[str, Any]:
    a286, source = _source_gate(dotcausal_src)
    return {
        "attempt_id": ATTEMPT_ID,
        "A286_evidence_stage": a286["evidence_stage"],
        "public_challenge_sha256": source["protocol"]["public_challenge_sha256"],
        "unknown_key_bits": WIDTH,
        "candidate_cells": 256,
        "free_bits_per_cell": FREE_BITS,
        "selected_feature_count": len(FEATURE_INDICES),
        "A291_measurement_started": False,
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--freeze", action="store_true")
    action.add_argument("--run", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    if args.freeze:
        payload = freeze(dotcausal_src=args.dotcausal_src)
        output = {
            "protocol": relative(PROTOCOL),
            "protocol_sha256": file_sha256(PROTOCOL),
            "scientific_design_sha256": payload["scientific_design_sha256"],
            "reader_CNF_sha256": payload["reader_CNF"]["CNF"]["sha256"],
        }
    elif args.run:
        if not args.expected_protocol_sha256:
            parser.error("--run requires --expected-protocol-sha256")
        payload = run(
            expected_protocol_sha256=args.expected_protocol_sha256,
            dotcausal_src=args.dotcausal_src,
        )
        output = {
            "evidence_stage": payload["evidence_stage"],
            "result": relative(RESULT),
            "result_sha256": file_sha256(RESULT),
            "causal": relative(CAUSAL),
            "causal_sha256": file_sha256(CAUSAL),
            **payload["headline"],
        }
    else:
        output = analyze(args.dotcausal_src)
    print(json.dumps(output, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
