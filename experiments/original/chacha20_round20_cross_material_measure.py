#!/usr/bin/env python3
"""Execute A280's frozen cross-public-material target measurement and order."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
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
ATTEMPT_ID = "A280"
RESULT_SCHEMA = "chacha20-round20-cross-material-order-result-v1"
MEASUREMENT_SCHEMA = "chacha20-round20-cross-material-measurement-v1"
DEFAULT_MASTER = (
    ROOT / "research/configs/chacha20_round20_cross_material_composite_master_v1.json"
)
DEFAULT_TARGET = ROOT / "research/configs/chacha20_round20_cross_material_target_v1.json"
DEFAULT_SYMBOLIC = (
    ROOT / "research/configs/chacha20_round20_cross_material_symbolic_template_v1.json"
)
DEFAULT_RESULT = ROOT / "research/results/v1/chacha20_round20_cross_material_order_v1.json"
DEFAULT_MEASUREMENT = (
    ROOT
    / "research/results/v1/chacha20_round20_cross_material_order_v1"
    / "target.numeric.measurement.json.zst"
)
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = (
    ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_CROSS_MATERIAL_ORDER_V1.md"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
MASTER_SHA256 = "256504ef394fbc4d5e1da2881f3de0c8a32af5908f454e58cf9711da733551b6"
TARGET_SHA256 = "a2685c03c3fb486c25362e5e7ae99a001ae14b36a7d96595b0f66628c52b0b16"
SYMBOLIC_SHA256 = "5443d4ef635d1b31001a99295be34fa0e4878f0496c570b58fed59efb60e1f75"
ZSTD_LEVEL = 10
FORBIDDEN_SERIALIZED_KEYS = {
    "known_low20",
    "low20",
    "low20_hex",
    "recovered_unknown_low20",
    "recovered_unknown_low20_hex",
    "salt",
    "salt_hex",
    "secret_low20",
    "target_prefix8",
    "true_prefix",
    "unknown_assignment",
    "unknown_key_word0_low_value",
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_bytes(
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


def _path(value: str) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else ROOT / candidate


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A280 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _assert_secret_free(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in FORBIDDEN_SERIALIZED_KEYS:
                raise RuntimeError(f"A280 secret-bearing field is forbidden: {key}")
            _assert_secret_free(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _assert_secret_free(child)


def _verify_anchor_set(anchors: Mapping[str, Any], *, context: str) -> None:
    for name, anchor in anchors.items():
        if not isinstance(anchor, Mapping) or set(anchor) != {"path", "sha256"}:
            raise RuntimeError(f"{context} anchor shape differs: {name}")
        if _file_sha256(_path(str(anchor["path"]))) != anchor["sha256"]:
            raise RuntimeError(f"{context} anchored dependency hash differs: {name}")


def _load_inputs(
    *,
    master_path: Path,
    expected_master_sha256: str,
    target_path: Path,
    expected_target_sha256: str,
    symbolic_path: Path,
    expected_symbolic_sha256: str,
) -> dict[str, Any]:
    if _file_sha256(master_path) != expected_master_sha256:
        raise RuntimeError("A280 frozen master hash differs")
    if _file_sha256(target_path) != expected_target_sha256:
        raise RuntimeError("A280 frozen target hash differs")
    if _file_sha256(symbolic_path) != expected_symbolic_sha256:
        raise RuntimeError("A280 frozen symbolic protocol hash differs")
    master = json.loads(master_path.read_bytes())
    target = json.loads(target_path.read_bytes())
    symbolic = json.loads(symbolic_path.read_bytes())
    schedule = master.get("frozen_schedule", {})
    measurement = schedule.get("measurement", {})
    boundary = target.get("information_boundary", {})
    if (
        master.get("schema")
        != "chacha20-round20-cross-material-composite-master-v1"
        or master.get("attempt_id") != "A278"
        or master.get("protocol_state")
        != "frozen_before_cross_material_target_generation_measurement_order_or_solve"
        or measurement.get("candidate_order") != "numeric_0_through_255"
        or measurement.get("complete_256_candidate_cover_before_scoring") is not True
        or measurement.get("conflict_horizons") != [1, 2, 4, 8]
        or measurement.get("watchdog_seconds_per_stage") != 2.0
        or measurement.get("all_stages_must_remain_model_free_UNKNOWN") is not True
        or measurement.get("feature_indices") != [502, 504, 505, 508, 509, 510, 511, 514]
        or target.get("schema") != "chacha20-round20-cross-material-target-v1"
        or target.get("attempt_id") != "A279"
        or target.get("protocol_state")
        != "frozen_after_A278_master_and_label_discard_before_any_target_measurement_or_solve"
        or target.get("master_protocol", {}).get("sha256") != expected_master_sha256
        or target.get("master_protocol", {}).get("scientific_design_sha256")
        != master.get("scientific_design_sha256")
        or boundary.get("master_schedule_frozen_before_target_generation") is not True
        or boundary.get("target_generation_label_available") is not False
        or boundary.get("target_measurement_started") is not False
        or boundary.get("target_solver_execution_started") is not False
        or boundary.get("target_candidate_order_known") is not False
        or symbolic.get("schema")
        != "chacha20-round20-cross-material-symbolic-template-v1"
        or symbolic.get("attempt_id") != "A280T"
        or symbolic.get("protocol_state")
        != "frozen_from_A278_public_material_without_reading_A279_target"
        or symbolic.get("master_protocol", {}).get("sha256") != expected_master_sha256
        or symbolic.get("target_independence", {}).get("A279_protocol_opened") is not False
        or symbolic.get("target_independence", {}).get("A279_target_words_read") is not False
        or symbolic.get("target_independence", {}).get(
            "symbolic_formula_depends_only_on_A278_public_material"
        )
        is not True
    ):
        raise RuntimeError("A280 frozen semantic gate failed")
    _verify_anchor_set(master["anchors"], context="A280 master")
    _verify_anchor_set(symbolic["anchors"], context="A280 symbolic")
    if (
        target["public_template"] != master["cross_material_public_template"]
        or target["public_template_sha256"]
        != master["cross_material_public_template_sha256"]
        or target["public_template_sha256"] != symbolic["public_template_sha256"]
        or _canonical_sha256(target["public_template"])
        != target["public_template_sha256"]
        or _canonical_sha256(target["public_challenge"])
        != target["public_challenge_sha256"]
        or target["target_block_sha256"]
        != target["public_challenge"]["target_block_sha256"]
        or target["generation"]["generation_label_returned_or_serialized"] is not False
    ):
        raise RuntimeError("A280 cross-material target identity differs")
    _assert_secret_free(target)

    a275_anchor = master["anchors"]["A275_runner"]
    a275 = _import_path(_path(a275_anchor["path"]), "a280_a275")
    a275_protocol_anchor = master["anchors"]["A275_protocol"]
    (
        _,
        _,
        _,
        a268,
        a251_protocol,
        a242,
        model,
        indices,
    ) = a275._load_protocol(
        _path(a275_protocol_anchor["path"]),
        a275_protocol_anchor["sha256"],
    )
    if tuple(measurement["feature_indices"]) != indices:
        raise RuntimeError("A280 frozen A272 reader indices differ")

    a276_anchor = master["anchors"]["A276_runner"]
    a276 = _import_path(_path(a276_anchor["path"]), "a280_a276")
    a276_protocol_anchor = master["anchors"]["A276_protocol"]
    _, _, _, public, template, _, _ = a276._load_protocol(
        _path(a276_protocol_anchor["path"]),
        a276_protocol_anchor["sha256"],
    )
    public.P1._validate_challenge(target["public_challenge"])
    if _canonical_sha256(public.validate_public_template(target["public_template"])) != target[
        "public_template_sha256"
    ]:
        raise RuntimeError("A280 public-core validation differs")
    return {
        "master": master,
        "target": target,
        "symbolic": symbolic,
        "a275": a275,
        "a268": a268,
        "a251_protocol": a251_protocol,
        "a242": a242,
        "model": model,
        "indices": indices,
        "public": public,
        "template": template,
    }


def analyze(
    *,
    master_path: Path,
    expected_master_sha256: str,
    target_path: Path,
    expected_target_sha256: str,
    symbolic_path: Path,
    expected_symbolic_sha256: str,
) -> dict[str, Any]:
    loaded = _load_inputs(
        master_path=master_path,
        expected_master_sha256=expected_master_sha256,
        target_path=target_path,
        expected_target_sha256=expected_target_sha256,
        symbolic_path=symbolic_path,
        expected_symbolic_sha256=expected_symbolic_sha256,
    )
    schedule = loaded["master"]["frozen_schedule"]["measurement"]
    return {
        "attempt_id": ATTEMPT_ID,
        "master_protocol_sha256": expected_master_sha256,
        "target_protocol_sha256": expected_target_sha256,
        "symbolic_protocol_sha256": expected_symbolic_sha256,
        "public_challenge_sha256": loaded["target"]["public_challenge_sha256"],
        "candidate_measurements": 256,
        "shallow_stages": 256 * len(schedule["conflict_horizons"]),
        "selected_feature_count": len(loaded["indices"]),
        "target_label_available": False,
        "solver_measurement_started": False,
    }


def _write_measurement(path: Path, measurement: Mapping[str, Any]) -> dict[str, Any]:
    raw = _canonical_bytes(measurement)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    _atomic_bytes(path, compressed)
    return {
        "path": str(path.relative_to(ROOT)),
        "raw_bytes": len(raw),
        "raw_sha256": _sha256(raw),
        "compressed_bytes": len(compressed),
        "compressed_sha256": _sha256(compressed),
    }


def _read_measurement(
    path: Path,
    *,
    expected_master_sha256: str,
    expected_target_sha256: str,
    expected_symbolic_sha256: str,
    expected_public_challenge_sha256: str,
    a275: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    compressed = path.read_bytes()
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    value = json.loads(raw)
    if (
        value.get("schema") != MEASUREMENT_SCHEMA
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("master_protocol_sha256") != expected_master_sha256
        or value.get("target_protocol_sha256") != expected_target_sha256
        or value.get("symbolic_protocol_sha256") != expected_symbolic_sha256
        or value.get("public_challenge_sha256") != expected_public_challenge_sha256
        or value.get("complete_candidate_cover") is not True
        or value.get("target_label_available_to_measurement") is not False
        or _canonical_bytes(value) != raw
    ):
        raise RuntimeError("A280 measurement shard gate failed")
    _assert_secret_free(value)
    a275._target_feature_matrix(value)
    return value, {
        "path": str(path.relative_to(ROOT)),
        "raw_bytes": len(raw),
        "raw_sha256": _sha256(raw),
        "compressed_bytes": len(compressed),
        "compressed_sha256": _sha256(compressed),
        "resumed": True,
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        io_module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        io_module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(io_module.CausalReader) or "")
    return io_module.CausalWriter, io_module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": _file_sha256(source),
    }


def _build_causal(
    path: Path, payload: Mapping[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = _load_dotcausal(dotcausal_src)
    writer = CausalWriter(api_id="a280")
    writer._rules = []
    writer.add_rule(
        name="master_schedule_precedes_cross_material_target",
        description="A278 freezes the complete measurement and composite recovery schedule before A279 generates a label-free target under independently derived public key, counter, and nonce material.",
        pattern=["A278_frozen_complete_schedule", "A279_distinct_cross_material_target"],
        conclusion="A280_cross_material_prospective_contract",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_model_free_measurement_precedes_order",
        description="All 256 numeric prefix cells and all 1024 shallow stages remain model-free UNKNOWN before the unchanged eight-feature reader creates the total order.",
        pattern=["A280_complete_model_free_target_cover", "A272_frozen_eight_feature_reader"],
        conclusion="A280_hash_frozen_cross_material_order",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A278:frozen_complete_cross_material_schedule",
        mechanism="generate_distinct_label_free_target_only_after_schedule_freeze",
        outcome="A279:cross_material_target_contract",
        confidence=1.0,
        source=payload["target_protocol_sha256"],
        quantification="new key upper bits, seven key words, counter, nonce, and eight R20 outputs",
        evidence=payload["public_challenge_sha256"],
        domain="prospective full-round ChaCha20 public-material transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A279:cross_material_target_contract",
        mechanism="measure_all_256_numeric_cells_then_apply_unchanged_A272_reader",
        outcome="A280:hash_frozen_cross_material_candidate_order",
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification="256/256 cells; 1024/1024 model-free UNKNOWN stages; zero labels; zero refits",
        evidence=json.dumps(payload["headline"], sort_keys=True),
        domain="cross-material label-free full-round target ranking",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A278:frozen_complete_cross_material_schedule",
        mechanism="materialized_schedule_target_measurement_order_chain",
        outcome="A280:hash_frozen_cross_material_candidate_order",
        confidence=1.0,
        source="materialized:A278_plus_A279_plus_A280_complete_cover",
        quantification="prospective three-stage closure materialized in-file",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A280 cross-public-material target order",
        entities=[
            "A278:frozen_complete_cross_material_schedule",
            "A279:cross_material_target_contract",
            "A280:hash_frozen_cross_material_candidate_order",
        ],
    )
    writer.add_gap(
        subject="A280:hash_frozen_cross_material_candidate_order",
        predicate="next_required_object",
        expected_object_type="execute_frozen_top128_then_exact_residual_schedule_on_cross_material_target",
        confidence=1.0,
        suggested_queries=[
            "Execute the first 128 ranked cells at 30 seconds each and stop only on SAT.",
            "If and only if all 128 are exact UNSAT, materialize their clauses and execute the frozen residual global-discovery-fallback schedule.",
        ],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a280"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"]
        != "A280:hash_frozen_cross_material_candidate_order"
    ):
        raise RuntimeError("A280 authentic Causal Reader reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "file_sha256": _file_sha256(path),
        "file_bytes": path.stat().st_size,
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "integrity_verified_by_authoritative_reader": True,
        "reader_source": source,
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _report(payload: Mapping[str, Any]) -> str:
    headline = payload["headline"]
    causal = payload["causal"]
    return "\n".join(
        [
            "# A280 — ChaCha20-R20 cross-public-material target order",
            "",
            "A278 froze the complete reader and composite recovery schedule before A279 generated a target under independently derived public key, counter, and nonce material. A280 then measured every prefix cell without a terminal model and applied A272's unchanged reader exactly once.",
            "",
            "## Frozen cross-material order",
            "",
            f"- Complete cells: **{headline['complete_candidate_cells']}/256**",
            f"- Model-free UNKNOWN stages: **{headline['model_free_unknown_stages']}/1024**",
            f"- Top-128 logical assignment domain: **2^{headline['top128_assignment_bits']}**",
            f"- Complete order SHA-256: `{headline['complete_order_uint8_sha256']}`",
            f"- Target label available: **{headline['target_label_available']}**",
            "",
            "## Authentic AI-native Causal readback",
            "",
            f"- Reader integrity: **{causal['integrity_verified_by_authoritative_reader']}**",
            f"- Explicit / materialized: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
            f"- Next gap: **{causal['personal_semantic_readback']['next_gap']['expected_object_type']}**",
            "",
        ]
    )


def execute(
    *,
    master_path: Path,
    expected_master_sha256: str,
    target_path: Path,
    expected_target_sha256: str,
    symbolic_path: Path,
    expected_symbolic_sha256: str,
    output: Path,
    measurement_output: Path,
    causal_output: Path,
    report_output: Path,
    dotcausal_src: Path,
) -> dict[str, Any]:
    loaded = _load_inputs(
        master_path=master_path,
        expected_master_sha256=expected_master_sha256,
        target_path=target_path,
        expected_target_sha256=expected_target_sha256,
        symbolic_path=symbolic_path,
        expected_symbolic_sha256=expected_symbolic_sha256,
    )
    master = loaded["master"]
    target_protocol = loaded["target"]
    challenge = target_protocol["public_challenge"]
    a275 = loaded["a275"]
    if measurement_output.exists():
        measurement, ledger = _read_measurement(
            measurement_output,
            expected_master_sha256=expected_master_sha256,
            expected_target_sha256=expected_target_sha256,
            expected_symbolic_sha256=expected_symbolic_sha256,
            expected_public_challenge_sha256=target_protocol["public_challenge_sha256"],
            a275=a275,
        )
    else:
        _, _, a251, _, _ = loaded["a268"]._load_protocol()
        with tempfile.TemporaryDirectory(prefix="a280_cross_material_measurement_") as temporary:
            directory = Path(temporary)
            support_directory = directory / "support"
            support_directory.mkdir()
            prepared = a251._prepare(
                loaded["a251_protocol"], loaded["a242"], support_directory
            )
            symbolic_directory = directory / "symbolic"
            symbolic_directory.mkdir()
            base_raw, key_mapping, output_mapping, template_manifest = loaded[
                "template"
            ].compile_template(
                r20=loaded["public"],
                public_challenge=challenge,
                protocol=loaded["symbolic"],
                directory=symbolic_directory,
            )
            raw_cnf, _, instantiation = loaded["template"].instantiate_output(
                base_raw,
                output_mapping,
                challenge["target_words"][0],
            )
            cnf = directory / "a280_cross_material_unlabeled_target.cnf"
            _atomic_bytes(cnf, raw_cnf)
            if _file_sha256(cnf) != instantiation["sha256"]:
                raise RuntimeError("A280 target CNF readback differs")
            schedule = master["frozen_schedule"]["measurement"]
            started = time.perf_counter()
            run = prepared["clause_wrapper"].run_fresh_clause_identity(
                helper=prepared["clause_helper"],
                cnf=cnf,
                mode="A280_cross_material_numeric_unlabeled",
                order=prepared["fresh"].numeric_order(),
                key_one_literals_bit0_through_bit19=key_mapping,
                conflict_horizons=schedule["conflict_horizons"],
                watchdog_seconds=float(schedule["watchdog_seconds_per_stage"]),
                external_timeout_seconds=900.0,
            )
            measurement = {
                "schema": MEASUREMENT_SCHEMA,
                "attempt_id": ATTEMPT_ID,
                "master_protocol_sha256": expected_master_sha256,
                "target_protocol_sha256": expected_target_sha256,
                "symbolic_protocol_sha256": expected_symbolic_sha256,
                "public_challenge_sha256": target_protocol["public_challenge_sha256"],
                "public_target_block_sha256": target_protocol["target_block_sha256"],
                "order_name": "numeric",
                "symbolic_template_manifest": template_manifest,
                "cnf_instantiation": instantiation,
                "run": a251._stable_run(run),
                "volatile_process_elapsed_seconds": time.perf_counter() - started,
                "target_label_available_to_measurement": False,
                "label_used_for_feature_construction_or_scoring": False,
                "complete_candidate_cover": len(run["cells"]) == 256,
            }
            _assert_secret_free(measurement)
            a275._target_feature_matrix(measurement)
            ledger = {**_write_measurement(measurement_output, measurement), "resumed": False}
    matrix = a275._target_feature_matrix(measurement)
    contributions = a275.standardized_contributions(
        matrix,
        means=loaded["model"].means,
        scales=loaded["model"].scales,
        coefficients=loaded["model"].coefficients,
    )
    scores = contributions[:, loaded["indices"]].sum(axis=1)
    order = a275._candidate_order(scores)
    top128 = order[:128]
    analysis = {
        "score_field": np.asarray(scores, dtype=np.float64).tolist(),
        "score_field_sha256": _canonical_sha256(
            np.asarray(scores, dtype=np.float64).tolist()
        ),
        "complete_cell_order": order,
        "complete_cell_order_uint8_sha256": _sha256(bytes(order)),
        "top128_cell_order": top128,
        "top128_cell_order_uint8_sha256": _sha256(bytes(top128)),
        "order_tiebreak": "descending_score_then_ascending_candidate",
        "selected_feature_indices": list(loaded["indices"]),
        "model_refits": 0,
        "target_labels_used": 0,
    }
    headline = {
        "complete_candidate_cells": len(order),
        "model_free_unknown_stages": len(measurement["run"]["stages"]),
        "complete_order_uint8_sha256": analysis["complete_cell_order_uint8_sha256"],
        "top128_order_uint8_sha256": analysis["top128_cell_order_uint8_sha256"],
        "top128_assignment_bits": 19,
        "target_label_available": False,
        "public_material_transfer": True,
    }
    payload: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_R20_CROSS_MATERIAL_TARGET_BLIND_ORDER_FROZEN",
        "master_protocol_sha256": expected_master_sha256,
        "target_protocol_sha256": expected_target_sha256,
        "symbolic_protocol_sha256": expected_symbolic_sha256,
        "runner_sha256": _file_sha256(Path(__file__)),
        "public_challenge_sha256": target_protocol["public_challenge_sha256"],
        "measurement": {
            **ledger,
            "complete_candidate_cover": measurement["complete_candidate_cover"],
            "accepted_learned_clauses": measurement["run"]["summary"][
                "learned_clause_accepted_total"
            ],
            "rejected_over_64_literal_clauses": measurement["run"]["summary"][
                "learned_clause_rejected_large_total"
            ],
        },
        "analysis": analysis,
        "analysis_sha256": _canonical_sha256(analysis),
        "headline": headline,
        "information_boundary": {
            "master_frozen_before_target_generation": True,
            "target_label_available": False,
            "all_256_cells_complete_before_scoring": True,
            "all_1024_stages_model_free_UNKNOWN": True,
            "reader_refits": 0,
            "recovery_started_before_order_freeze": False,
        },
    }
    _assert_secret_free(payload)
    payload["causal"] = _build_causal(causal_output, payload, dotcausal_src)
    _atomic_json(output, payload)
    _atomic_bytes(report_output, _report(payload).encode("utf-8"))
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--master", type=Path, default=DEFAULT_MASTER)
    parser.add_argument("--expected-master-sha256", default=MASTER_SHA256)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--expected-target-sha256", default=TARGET_SHA256)
    parser.add_argument("--symbolic", type=Path, default=DEFAULT_SYMBOLIC)
    parser.add_argument("--expected-symbolic-sha256", default=SYMBOLIC_SHA256)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT)
    parser.add_argument("--measurement-output", type=Path, default=DEFAULT_MEASUREMENT)
    parser.add_argument("--causal-output", type=Path, default=DEFAULT_CAUSAL)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    if not args.run:
        print(
            json.dumps(
                analyze(
                    master_path=args.master,
                    expected_master_sha256=args.expected_master_sha256,
                    target_path=args.target,
                    expected_target_sha256=args.expected_target_sha256,
                    symbolic_path=args.symbolic,
                    expected_symbolic_sha256=args.expected_symbolic_sha256,
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return
    payload = execute(
        master_path=args.master,
        expected_master_sha256=args.expected_master_sha256,
        target_path=args.target,
        expected_target_sha256=args.expected_target_sha256,
        symbolic_path=args.symbolic,
        expected_symbolic_sha256=args.expected_symbolic_sha256,
        output=args.output,
        measurement_output=args.measurement_output,
        causal_output=args.causal_output,
        report_output=args.report_output,
        dotcausal_src=args.dotcausal_src,
    )
    print(
        json.dumps(
            {
                "evidence_stage": payload["evidence_stage"],
                **payload["headline"],
                "result": str(args.output),
                "result_sha256": _file_sha256(args.output),
                "causal": str(args.causal_output),
                "causal_sha256": _file_sha256(args.causal_output),
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
