#!/usr/bin/env python3
"""Execute A281's frozen cross-material top-half plus residual R20 recovery."""

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
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
ATTEMPT_ID = "A281"
DEFAULT_PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_cross_material_composite_recovery_v1.json"
)
DEFAULT_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_cross_material_composite_recovery_v1.json"
)
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = (
    ROOT
    / "research/reports/CAUSAL_CHACHA20_ROUND20_CROSS_MATERIAL_COMPOSITE_RECOVERY_V1.md"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


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
        raise RuntimeError(f"cannot import A281 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _verify_anchors(anchors: Mapping[str, Any]) -> None:
    for name, anchor in anchors.items():
        if not isinstance(anchor, Mapping) or set(anchor) != {"path", "sha256"}:
            raise RuntimeError(f"A281 anchor shape differs: {name}")
        if _file_sha256(_path(str(anchor["path"]))) != anchor["sha256"]:
            raise RuntimeError(f"A281 anchored dependency differs: {name}")


def _load_protocol(
    protocol_path: Path, expected_protocol_sha256: str
) -> dict[str, Any]:
    if _file_sha256(protocol_path) != expected_protocol_sha256:
        raise RuntimeError("A281 frozen protocol hash differs")
    protocol = json.loads(protocol_path.read_bytes())
    schedule = protocol.get("solver_schedule", {})
    measurement = schedule.get("measurement", {})
    top = schedule.get("top_half", {})
    residual = schedule.get("residual", {})
    order = protocol.get("frozen_order", {})
    complete = order.get("complete_cell_order", [])
    top128 = order.get("top128_cell_order", [])
    bottom128 = order.get("residual_cell_order", [])
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-cross-material-composite-recovery-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A280_complete_unlabeled_order_before_any_A281_recovery"
        or measurement.get("feature_indices") != [502, 504, 505, 508, 509, 510, 511, 514]
        or top.get("prefix_cells") != 128
        or top.get("seconds_per_cell") != 30.0
        or top.get("stop_condition") != "first_SAT_only"
        or residual.get("global_seconds") != 300.0
        or residual.get("discovery_seconds_per_cell") != 10.0
        or residual.get("fallback_seconds_per_discovery_UNKNOWN_cell") != 30.0
        or residual.get("entry_condition")
        != "no_top_half_SAT_and_all_128_top_half_cells_exact_UNSAT"
        or len(complete) != 256
        or set(complete) != set(range(256))
        or top128 != complete[:128]
        or bottom128 != complete[128:]
        or len(set(top128)) != 128
        or len(set(bottom128)) != 128
        or set(top128) & set(bottom128)
        or _sha256(bytes(complete)) != order.get("complete_cell_order_uint8_sha256")
        or _sha256(bytes(top128)) != order.get("top128_cell_order_uint8_sha256")
        or _sha256(bytes(bottom128)) != order.get("residual_cell_order_uint8_sha256")
        or order.get("order_change_permitted") is not False
        or protocol.get("target", {}).get("generation_label_available") is not False
        or protocol.get("target", {}).get("correct_prefix_or_rank_known") is not False
        or boundary.get("A278_schedule_frozen_before_A279_target") is not True
        or boundary.get("A280_complete_order_frozen_before_A281_recovery") is not True
        or boundary.get("residual_phase_permitted_only_after_all_top128_cells_exact_UNSAT")
        is not True
        or boundary.get("any_A281_solver_execution_started") is not False
    ):
        raise RuntimeError("A281 frozen protocol semantic gate failed")
    _verify_anchors(protocol["anchors"])
    anchors = protocol["anchors"]
    target_protocol = json.loads(_path(anchors["A279_target"]["path"]).read_bytes())
    order_result = json.loads(_path(anchors["A280_result"]["path"]).read_bytes())
    symbolic = json.loads(_path(anchors["A280_symbolic"]["path"]).read_bytes())
    if (
        target_protocol.get("public_challenge_sha256")
        != protocol["target"]["public_challenge_sha256"]
        or target_protocol.get("information_boundary", {}).get(
            "target_generation_label_available"
        )
        is not False
        or order_result.get("analysis", {}).get("complete_cell_order") != complete
        or order_result.get("headline", {}).get("model_free_unknown_stages") != 1024
        or symbolic.get("target_independence", {}).get("A279_target_words_read") is not False
    ):
        raise RuntimeError("A281 target, order, or symbolic identity differs")

    a276 = _import_path(_path(anchors["A276_runner"]["path"]), "a281_a276")
    (
        a276_protocol,
        _,
        _,
        public,
        template,
        ranked,
        _,
    ) = a276._load_protocol(
        _path(anchors["A276_protocol"]["path"]),
        anchors["A276_protocol"]["sha256"],
    )
    a277 = _import_path(_path(anchors["A277_runner"]["path"]), "a281_a277")
    two_pass = _import_path(_path(anchors["residual_wrapper"]["path"]), "a281_two_pass")
    challenge = target_protocol["public_challenge"]
    public.P1._validate_challenge(challenge)
    return {
        "protocol": protocol,
        "target_protocol": target_protocol,
        "order_result": order_result,
        "symbolic": symbolic,
        "a276": a276,
        "a276_protocol": a276_protocol,
        "a277": a277,
        "public": public,
        "template": template,
        "ranked": ranked,
        "two_pass": two_pass,
    }


def analyze(protocol_path: Path, expected_protocol_sha256: str) -> dict[str, Any]:
    loaded = _load_protocol(protocol_path, expected_protocol_sha256)
    protocol = loaded["protocol"]
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["target"]["public_challenge_sha256"],
        "top128_cells": len(protocol["frozen_order"]["top128_cell_order"]),
        "residual_cells": len(protocol["frozen_order"]["residual_cell_order"]),
        "target_label_available": False,
        "correct_prefix_or_rank_known": False,
        "solver_execution_started": False,
    }


def _confirm_model(
    *,
    loaded: Mapping[str, Any],
    sat_row: Mapping[str, Any],
    allowed_prefixes: set[int],
    discovery_stage: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    anchors = loaded["protocol"]["anchors"]
    for name in ("independent_reference", "public_core"):
        if _file_sha256(_path(anchors[name]["path"])) != anchors[name]["sha256"]:
            raise RuntimeError(f"A281 {name} changed before confirmation")
    low20 = loaded["a276"]._decode_model(sat_row["model_bits_bit0_through_bit19"])
    prefix = low20 >> 12
    if prefix not in allowed_prefixes:
        raise RuntimeError("A281 SAT model lies outside the active prefix domain")
    prefix8 = sat_row.get("prefix8")
    if prefix8 is not None and prefix8 != f"{prefix:08b}":
        raise RuntimeError("A281 SAT model prefix differs from its solver assumption")
    confirmation = loaded["a276"]._confirm(
        loaded["public"], loaded["target_protocol"]["public_challenge"], low20
    )
    if (
        any(
            _file_sha256(_path(anchors[name]["path"])) != anchors[name]["sha256"]
            for name in ("independent_reference", "public_core")
        )
        or confirmation["claim_gate_source_sha256"]
        != anchors["independent_reference"]["sha256"]
        or confirmation["all_blocks_match"] is not True
        or confirmation["all_cross_implementation_blocks_match"] is not True
        or confirmation["claim_gate_rfc8439_section_2_3_2_kat"] is not True
        or confirmation["control_first_block_match"] is not False
        or confirmation["output_bits_checked"] != 4096
    ):
        raise RuntimeError("A281 SAT model failed dual-independent confirmation")
    return confirmation, {
        "recovered_prefix8": prefix,
        "discovery_stage": discovery_stage,
        "computed_only_after_confirmed_model": True,
    }


def _top_summary(execution: Mapping[str, Any]) -> dict[str, Any]:
    counts = Counter(str(row["status"]) for row in execution["rows"])
    attempted = len(execution["rows"])
    return {
        "attempted_cells": attempted,
        "logical_assignments_inside_attempted_cells": attempted * 2**12,
        "sat": counts["sat"],
        "unsat": counts["unsat"],
        "unknown": counts["unknown"],
        "sat_found": execution["sat_found"],
        "all_attempted_cells_exact_UNSAT": attempted == 128 and counts["unsat"] == 128,
        "retained_state_continuity_verified": execution[
            "retained_state_continuity_verified"
        ],
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(module.CausalReader) or "")
    return module.CausalWriter, module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": _file_sha256(source),
    }


def _build_causal(
    path: Path, payload: Mapping[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = _load_dotcausal(dotcausal_src)
    confirmed = payload["confirmation"] is not None
    terminal = (
        "A281:confirmed_cross_material_R20_recovery"
        if confirmed
        else "A281:cross_material_composite_budget_boundary"
    )
    residual_entered = payload["residual_execution"] is not None
    middle = (
        "A281:exact_residual_formula_and_three_phase_execution"
        if residual_entered
        else "A281:top128_retained_execution"
    )
    writer = CausalWriter(api_id="a281")
    writer._rules = []
    writer.add_rule(
        name="frozen_cross_material_order_precedes_composite_recovery",
        description="A280 completes and hashes the label-free cross-material order before A281 begins its retained top-half solve.",
        pattern=["A280_hash_frozen_cross_material_order", "A281_top128_execution_contract"],
        conclusion="A281_cross_material_solver_evidence",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="residual_requires_exact_top_half_boundary_and_confirmation_requires_model",
        description="The residual solver is reachable only after 128 exact top-half UNSAT results; any accepted model requires dual 4096-bit confirmation and a rejecting flipped control.",
        pattern=["A281_cross_material_solver_evidence", "A281_dual_confirmation_contract"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A280:hash_frozen_cross_material_candidate_order",
        mechanism="execute_first_128_cells_in_one_retained_CaDiCaL_state",
        outcome="A281:top128_retained_execution",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification=json.dumps(payload["top_execution_summary"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="full-round ChaCha20-R20 cross-material recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A281:top128_retained_execution",
        mechanism=(
            "materialize_exact_UNSAT_prefix_clauses_then_run_global_discovery_fallback"
            if residual_entered
            else "stop_on_model_or_non_exact_top_half_boundary"
        ),
        outcome=middle,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["residual_execution_summary"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="frozen composite solver schedule",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=middle,
        mechanism=(
            "dual_independent_all_eight_block_confirmation"
            if confirmed
            else "complete_frozen_available_budget_without_confirmed_model"
        ),
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=(
            "4096 output bits plus flipped control"
            if confirmed
            else "exactly the prospectively frozen schedule"
        ),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="independently confirmed recovery or measured solver boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A280:hash_frozen_cross_material_candidate_order",
        mechanism="materialized_order_solver_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A280_order_plus_A281_execution",
        quantification="AI-native end-to-end prospective closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A281 cross-material composite recovery",
        entities=[
            "A280:hash_frozen_cross_material_candidate_order",
            "A281:top128_retained_execution",
            middle,
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "multi_target_cross_material_replication_or_wider_unknown_domain"
            if confirmed
            else "reader_or_budget_intervention_at_observed_composite_boundary"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze the same end-to-end schedule across multiple independently derived public targets.",
                "Transfer the confirmed cross-material mechanism to a wider unknown-key domain.",
            ]
            if confirmed
            else [
                "Which exact phase produced the strongest retained-state transition?",
                "Can a prospectively frozen intervention move the measured composite boundary?",
            ]
        ),
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
        or reader.api_id != "a281"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A281 authentic Causal Reader reopen gate failed")
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
    top = payload["top_execution_summary"]
    residual = payload["residual_execution_summary"]
    confirmation = payload["confirmation"]
    rows = [
        "# A281 — ChaCha20-R20 cross-material composite recovery",
        "",
        f"Evidence stage: **{payload['evidence_stage']}**",
        "",
        f"- Top-half cells attempted: **{top['attempted_cells']}/128**",
        f"- Top-half exact UNSAT / UNKNOWN / SAT: **{top['unsat']} / {top['unknown']} / {top['sat']}**",
        f"- Residual schedule entered: **{residual['entered']}**",
        f"- Model-discovery stage: **{residual['model_discovery_stage']}**",
    ]
    if confirmation is not None:
        rows.extend(
            [
                f"- Recovered low20: **`0x{confirmation['recovered_unknown_low20_hex']}`**",
                f"- Independent output bits confirmed: **{confirmation['output_bits_checked']}**",
                f"- Flipped control matched: **{confirmation['control_first_block_match']}**",
            ]
        )
    rows.extend(
        [
            "",
            "## Authentic AI-native Causal readback",
            "",
            f"- Next gap: **{payload['causal']['personal_semantic_readback']['next_gap']['expected_object_type']}**",
            "",
        ]
    )
    return "\n".join(rows)


def execute(
    *,
    protocol_path: Path,
    expected_protocol_sha256: str,
    output: Path,
    causal_output: Path,
    report_output: Path,
    dotcausal_src: Path,
) -> dict[str, Any]:
    loaded = _load_protocol(protocol_path, expected_protocol_sha256)
    protocol = loaded["protocol"]
    anchors = protocol["anchors"]
    ranked_build = loaded["ranked"].compile_helper(
        output=_path(anchors["ranked_binary"]["path"])
    )
    if (
        ranked_build["source_sha256"] != anchors["ranked_native"]["sha256"]
        or ranked_build["binary_sha256"] != anchors["ranked_binary"]["sha256"]
    ):
        raise RuntimeError("A281 ranked helper rebuild differs from freeze")
    residual_build = loaded["two_pass"].compile_helper()
    if residual_build["source_sha256"] != anchors["residual_native"]["sha256"]:
        raise RuntimeError("A281 residual helper rebuild differs from freeze")

    challenge = loaded["target_protocol"]["public_challenge"]
    with tempfile.TemporaryDirectory(prefix="a281_cross_material_composite_") as temporary:
        directory = Path(temporary)
        base_raw, key_mapping, output_mapping, template_manifest = loaded[
            "template"
        ].compile_template(
            r20=loaded["public"],
            public_challenge=challenge,
            protocol=loaded["symbolic"],
            directory=directory,
        )
        target_raw, _, target_instantiation = loaded["template"].instantiate_output(
            base_raw,
            output_mapping,
            challenge["target_words"][0],
        )
        target_cnf = directory / "a281_cross_material_target.cnf"
        _atomic_bytes(target_cnf, target_raw)
        if _file_sha256(target_cnf) != target_instantiation["sha256"]:
            raise RuntimeError("A281 target CNF readback differs")

        complete_values = protocol["frozen_order"]["complete_cell_order"]
        top_values = protocol["frozen_order"]["top128_cell_order"]
        a276_solver = loaded["a276_protocol"]["solver_protocol"]
        top_execution = loaded["ranked"].run_ranked(
            helper=_path(anchors["ranked_binary"]["path"]),
            cnf=target_cnf,
            mode="A281_cross_material_frozen_top128",
            order=[f"{int(value):08b}" for value in complete_values],
            key_one_literals_bit0_through_bit19=key_mapping,
            seconds=float(protocol["solver_schedule"]["top_half"]["seconds_per_cell"]),
            max_cells=128,
            external_timeout_seconds=float(a276_solver["external_timeout_seconds"]),
        )
        top_summary = _top_summary(top_execution)
        top_scientific = loaded["a276"]._scientific_execution(top_execution)
        confirmation = None
        post_model = None
        residual_execution = None
        residual_scientific = None
        blocking_manifest = None
        discovery_stage = "none"
        if top_execution["sat_found"]:
            discovery_stage = "top128"
            confirmation, post_model = _confirm_model(
                loaded=loaded,
                sat_row=top_execution["sat_row"],
                allowed_prefixes=set(top_values),
                discovery_stage=discovery_stage,
            )
        elif top_summary["all_attempted_cells_exact_UNSAT"]:
            blocked_raw, blocking_manifest = loaded["a277"].append_blocking_clauses(
                target_raw,
                blocked_prefixes=top_values,
                key_one_literals_bit0_through_bit19=key_mapping,
            )
            if (
                blocking_manifest["blocked_prefixes_uint8_sha256"]
                != protocol["frozen_order"]["top128_cell_order_uint8_sha256"]
                or blocking_manifest["added_clause_count"] != 128
            ):
                raise RuntimeError("A281 exact blocking-clause reconstruction differs")
            residual_cnf = directory / "a281_cross_material_residual.cnf"
            _atomic_bytes(residual_cnf, blocked_raw)
            residual_values = protocol["frozen_order"]["residual_cell_order"]
            residual_schedule = protocol["solver_schedule"]["residual"]
            a277_protocol = json.loads(_path(anchors["A277_protocol"]["path"]).read_bytes())
            residual_execution = loaded["two_pass"].run_two_pass(
                helper=loaded["two_pass"].BINARY,
                cnf=residual_cnf,
                mode="A281_cross_material_exact_residual",
                order=[f"{int(value):08b}" for value in residual_values],
                key_one_literals_bit0_through_bit19=key_mapping,
                global_seconds=float(residual_schedule["global_seconds"]),
                discovery_seconds=float(residual_schedule["discovery_seconds_per_cell"]),
                fallback_seconds=float(
                    residual_schedule["fallback_seconds_per_discovery_UNKNOWN_cell"]
                ),
                external_timeout_seconds=float(
                    a277_protocol["solver_protocol"]["external_timeout_seconds"]
                ),
            )
            if residual_execution["global_row"]["status"] == "unsat":
                raise RuntimeError("A281 residual formula contradicts the exact top-half boundary")
            residual_scientific = loaded["a277"]._scientific_execution(
                residual_execution
            )
            if residual_execution["sat_row"] is not None:
                discovery_stage = str(residual_execution["sat_row"]["phase"])
                confirmation, post_model = _confirm_model(
                    loaded=loaded,
                    sat_row=residual_execution["sat_row"],
                    allowed_prefixes=set(residual_values),
                    discovery_stage=discovery_stage,
                )

    residual_summary = {
        "entered": residual_execution is not None,
        "model_discovery_stage": discovery_stage,
        "sat_found": bool(residual_execution and residual_execution["sat_found"]),
        "global_status": (
            None
            if residual_execution is None
            else residual_execution["global_row"]["status"]
        ),
        "new_exact_unsat_prefixes": (
            0
            if residual_execution is None
            else len(residual_execution["exact_unsat_prefixes"])
        ),
        "complete_remaining_half_enumeration_used": False,
    }
    if confirmation is not None:
        stage = (
            "FULLROUND_R20_CROSS_MATERIAL_TARGET_BLIND_"
            f"{discovery_stage.upper()}_RECOVERY_CONFIRMED"
        )
    else:
        stage = "FULLROUND_R20_CROSS_MATERIAL_TARGET_BLIND_COMPOSITE_BUDGET_BOUNDARY"
    scientific_execution = {
        "top128": top_scientific,
        "residual": residual_scientific,
    }
    measurement_sha256 = _canonical_sha256(scientific_execution)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-cross-material-composite-recovery-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": stage,
        "protocol_sha256": expected_protocol_sha256,
        "runner_sha256": _file_sha256(Path(__file__)),
        "public_challenge_sha256": protocol["target"]["public_challenge_sha256"],
        "A280_result_sha256": anchors["A280_result"]["sha256"],
        "A280_complete_order_sha256": protocol["frozen_order"][
            "complete_cell_order_uint8_sha256"
        ],
        "native_helper_builds": {
            "ranked": ranked_build,
            "residual": residual_build,
        },
        "symbolic_template_manifest": template_manifest,
        "target_instantiation": target_instantiation,
        "top_execution": top_execution,
        "top_execution_summary": top_summary,
        "residual_execution": residual_execution,
        "residual_execution_summary": residual_summary,
        "blocking_clause_manifest": blocking_manifest,
        "scientific_execution": scientific_execution,
        "measurement_sha256": measurement_sha256,
        "confirmation": confirmation,
        "post_model_controls": post_model,
        "information_boundary": {
            "target_label_available": False,
            "correct_prefix_or_rank_known_before_execution": False,
            "order_frozen_before_execution": True,
            "residual_entered_only_after_128_exact_UNSAT": (
                residual_execution is None
                or top_summary["all_attempted_cells_exact_UNSAT"]
            ),
            "confirmation_only_after_solver_model": confirmation is not None,
            "complete_full_domain_enumeration_used": False,
        },
    }
    payload["causal"] = _build_causal(causal_output, payload, dotcausal_src)
    _atomic_json(output, payload)
    _atomic_bytes(report_output, _report(payload).encode("utf-8"))
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    parser.add_argument("--expected-protocol-sha256", required=True)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT)
    parser.add_argument("--causal-output", type=Path, default=DEFAULT_CAUSAL)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    if not args.run:
        print(
            json.dumps(
                analyze(args.protocol, args.expected_protocol_sha256),
                indent=2,
                sort_keys=True,
            )
        )
        return
    payload = execute(
        protocol_path=args.protocol,
        expected_protocol_sha256=args.expected_protocol_sha256,
        output=args.output,
        causal_output=args.causal_output,
        report_output=args.report_output,
        dotcausal_src=args.dotcausal_src,
    )
    print(
        json.dumps(
            {
                "evidence_stage": payload["evidence_stage"],
                "top_execution_summary": payload["top_execution_summary"],
                "residual_execution_summary": payload["residual_execution_summary"],
                "confirmation": payload["confirmation"],
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
