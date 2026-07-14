#!/usr/bin/env python3
"""Freeze and execute A285's four independent cross-material recoveries."""

from __future__ import annotations

import argparse
import copy
import json
import os
import statistics
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from chacha20_round20_multitarget_common import (
    DEFAULT_DOTCAUSAL_SRC,
    ROOT,
    anchor,
    assert_label_free,
    atomic_bytes,
    atomic_json,
    canonical_sha256,
    file_sha256,
    import_path,
    load_dotcausal,
    path_from_ref,
    path_ref,
    sha256,
    verify_anchors,
)

ATTEMPT_ID = "A285"
DEFAULT_MASTER = (
    ROOT / "research/configs/chacha20_round20_multitarget_panel_master_v1.json"
)
DEFAULT_TARGETS = (
    ROOT / "research/configs/chacha20_round20_multitarget_targets_v1.json"
)
DEFAULT_ORDERS = (
    ROOT / "research/results/v1/chacha20_round20_multitarget_orders_v1.json"
)
DEFAULT_PROTOCOL_LEDGER = (
    ROOT
    / "research/configs/chacha20_round20_multitarget_recovery_protocols_v1.json"
)
DEFAULT_RESULT = (
    ROOT
    / "research/results/v1/chacha20_round20_multitarget_recovery_panel_v1.json"
)
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = (
    ROOT
    / "research/reports/CAUSAL_CHACHA20_ROUND20_MULTITARGET_RECOVERY_PANEL_V1.md"
)
BASE_PROTOCOL = (
    ROOT
    / "research/configs/chacha20_round20_cross_material_composite_recovery_v1.json"
)
BASE_PROTOCOL_SHA256 = "8c82ff74661a74c453bd744d847d0d9c14bec869a956d8b9961d49f9df82bde7"


def _protocol_path(index: int) -> Path:
    return (
        ROOT
        / f"research/configs/chacha20_round20_multitarget_t{index:02d}_recovery_v1.json"
    )


def _result_paths(index: int) -> dict[str, Path]:
    stem = f"chacha20_round20_multitarget_t{index:02d}_composite_recovery_v1"
    result = ROOT / f"research/results/v1/{stem}.json"
    canonical = result.with_name(result.stem.removesuffix("_v1") + "_canonical_v1.json")
    return {
        "result": result,
        "causal": result.with_suffix(".causal"),
        "report": ROOT / f"research/reports/{stem.upper()}.md",
        "canonical": canonical,
        "canonical_causal": canonical.with_suffix(".causal"),
        "canonical_report": ROOT
        / f"research/reports/{canonical.stem.upper()}.md",
    }


def _load_triplet(
    *,
    master_path: Path,
    expected_master_sha256: str,
    targets_path: Path,
    expected_targets_sha256: str,
    orders_path: Path,
    expected_orders_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    fixed = {
        master_path: expected_master_sha256,
        targets_path: expected_targets_sha256,
        orders_path: expected_orders_sha256,
        BASE_PROTOCOL: BASE_PROTOCOL_SHA256,
    }
    for path, digest in fixed.items():
        if file_sha256(path) != digest:
            raise RuntimeError(f"A285 frozen input differs: {path.name}")
    panel = json.loads(master_path.read_bytes())
    targets = json.loads(targets_path.read_bytes())
    orders = json.loads(orders_path.read_bytes())
    if (
        panel.get("schema") != "chacha20-round20-multitarget-panel-master-v1"
        or panel.get("attempt_id") != "A282"
        or panel.get("frozen_execution_schedule", {}).get("recovery_parallel_workers")
        != 2
        or targets.get("schema")
        != "chacha20-round20-multitarget-target-ledger-v1"
        or targets.get("attempt_id") != "A283"
        or orders.get("schema") != "chacha20-round20-multitarget-order-ledger-v1"
        or orders.get("attempt_id") != "A284"
        or orders.get("evidence_stage")
        != "FOUR_CROSS_MATERIAL_TARGET_BLIND_ORDERS_FROZEN"
        or orders.get("target_count") != 4
        or orders.get("headline", {}).get("all_orders_frozen_before_any_recovery")
        is not True
        or orders.get("information_boundary", {}).get("any_recovery_started")
        is not False
    ):
        raise RuntimeError("A285 A282-A284 semantic gate failed")
    verify_anchors(panel["source_anchors"], context="A285 panel sources")
    if (
        [row["target_id"] for row in panel["panel_rows"]]
        != [row["target_id"] for row in targets["targets"]]
        or [row["target_id"] for row in targets["targets"]]
        != [row["target_id"] for row in orders["orders"]]
    ):
        raise RuntimeError("A285 panel row identities differ")
    return panel, targets, orders


def _build_protocol(
    *,
    index: int,
    panel: dict[str, Any],
    target_row: dict[str, Any],
    order_row: dict[str, Any],
    master_path: Path,
    expected_master_sha256: str,
    targets_path: Path,
    expected_targets_sha256: str,
    orders_path: Path,
    expected_orders_sha256: str,
    dotcausal_src: Path,
) -> dict[str, Any]:
    target_id = str(target_row["target_id"])
    panel_row = panel["panel_rows"][index - 1]
    target_path = path_from_ref(target_row["target_protocol"]["path"])
    order_path = path_from_ref(order_row["result"]["path"])
    order_causal = path_from_ref(order_row["causal"]["path"])
    measurement = path_from_ref(order_row["measurement"]["path"])
    symbolic_path = path_from_ref(panel_row["symbolic_protocol"]["path"])
    submaster_path = path_from_ref(panel_row["master_protocol"]["path"])
    target = json.loads(target_path.read_bytes())
    order_result = json.loads(order_path.read_bytes())
    complete = order_result.get("analysis", {}).get("complete_cell_order", [])
    top128 = complete[:128]
    residual = complete[128:]
    if (
        file_sha256(target_path) != target_row["target_protocol"]["sha256"]
        or file_sha256(order_path) != order_row["result"]["sha256"]
        or file_sha256(order_causal) != order_row["causal"]["sha256"]
        or file_sha256(measurement) != order_row["measurement"]["sha256"]
        or file_sha256(symbolic_path) != panel_row["symbolic_protocol"]["sha256"]
        or file_sha256(submaster_path) != panel_row["master_protocol"]["sha256"]
        or target.get("public_challenge_sha256")
        != target_row["public_challenge_sha256"]
        or target.get("information_boundary", {}).get(
            "target_generation_label_available"
        )
        is not False
        or order_result.get("evidence_stage")
        != "FULLROUND_R20_CROSS_MATERIAL_TARGET_BLIND_ORDER_FROZEN"
        or order_result.get("headline", {}).get("model_free_unknown_stages") != 1024
        or len(complete) != 256
        or set(complete) != set(range(256))
        or order_result.get("analysis", {}).get("target_labels_used") != 0
    ):
        raise RuntimeError(f"A285 {target_id} frozen row gate failed")
    assert_label_free(target)
    assert_label_free(order_result)

    _, CausalReader, reader_source = load_dotcausal(dotcausal_src)
    order_reader = CausalReader(str(order_causal), verify_integrity=True)
    gaps = list(order_reader._gaps)
    if (
        order_reader.version != 1
        or order_reader.api_id != "a280"
        or len(gaps) != 1
        or gaps[0].get("expected_object_type")
        != "execute_frozen_top128_then_exact_residual_schedule_on_cross_material_target"
    ):
        raise RuntimeError(f"A285 {target_id} A284 Causal gap differs")

    base = json.loads(BASE_PROTOCOL.read_bytes())
    anchors = copy.deepcopy(base["anchors"])
    anchors.update(
        {
            "A278_master": anchor(
                submaster_path, panel_row["master_protocol"]["sha256"]
            ),
            "A279_target": anchor(
                target_path, target_row["target_protocol"]["sha256"]
            ),
            "A280_symbolic": anchor(
                symbolic_path, panel_row["symbolic_protocol"]["sha256"]
            ),
            "A280_result": anchor(order_path, order_row["result"]["sha256"]),
            "A280_causal": anchor(order_causal, order_row["causal"]["sha256"]),
            "A280_measurement": anchor(
                measurement, order_row["measurement"]["sha256"]
            ),
            "A280_runner": panel["source_anchors"]["A280_order_runner"],
            "preflight": anchor(Path(__file__)),
            "runner": panel["source_anchors"]["A281_recovery_runner"],
            "residual_wrapper": panel["source_anchors"][
                "parallel_residual_adapter"
            ],
            "A282_panel_master": anchor(master_path, expected_master_sha256),
            "A283_target_ledger": anchor(targets_path, expected_targets_sha256),
            "A284_order_ledger": anchor(orders_path, expected_orders_sha256),
        }
    )
    ranked = import_path(
        path_from_ref(anchors["ranked_wrapper"]["path"]),
        f"a285_ranked_compile_{target_id}",
    )
    ranked_binary = (
        ROOT / f"research/native/build/cadical_ranked_until_sat_a285_{target_id}"
    )
    ranked_build = ranked.compile_helper(output=ranked_binary)
    if ranked_build["source_sha256"] != anchors["ranked_native"]["sha256"]:
        raise RuntimeError(f"A285 {target_id} ranked source differs")
    anchors["ranked_binary"] = anchor(
        ranked_binary, ranked_build["binary_sha256"]
    )
    verify_anchors(anchors, context=f"A285 {target_id} recovery")

    schedule = json.loads(
        json.dumps(panel["frozen_execution_schedule"]["per_target_solver_schedule"])
    )
    protocol: dict[str, Any] = {
        "schema": "chacha20-round20-cross-material-composite-recovery-protocol-v1",
        "attempt_id": "A281",
        "protocol_state": (
            "frozen_after_A280_complete_unlabeled_order_before_any_A281_recovery"
        ),
        "panel_context": {
            "panel_attempt_id": ATTEMPT_ID,
            "target_id": target_id,
            "panel_index": index,
            "all_four_orders_frozen_before_this_protocol": True,
            "all_four_recovery_protocols_required_before_any_solver": True,
        },
        "anchors": anchors,
        "target": {
            "public_challenge_sha256": target["public_challenge_sha256"],
            "generation_label_available": False,
            "correct_prefix_or_rank_known": False,
            "unknown_assignment_bits": 20,
            "full_residual_domain_assignments": 2**20,
        },
        "frozen_order": {
            "complete_cell_order": complete,
            "complete_cell_order_uint8_sha256": sha256(bytes(complete)),
            "top128_cell_order": top128,
            "top128_cell_order_uint8_sha256": sha256(bytes(top128)),
            "residual_cell_order": residual,
            "residual_cell_order_uint8_sha256": sha256(bytes(residual)),
            "order_change_permitted": False,
        },
        "solver_schedule": schedule,
        "authentic_causal_readback": {
            "reader_source": reader_source,
            "A280_gap": gaps[0],
            "read_by_root_before_freeze": True,
        },
        "information_boundary": {
            "A278_schedule_frozen_before_A279_target": True,
            "A280_complete_order_frozen_before_A281_recovery": True,
            "all_four_A284_orders_frozen_before_any_A285_recovery": True,
            "target_generation_label_available": False,
            "correct_prefix_or_rank_known": False,
            "confirmation_permitted_only_after_solver_model": True,
            "residual_phase_permitted_only_after_all_top128_cells_exact_UNSAT": True,
            "UNKNOWN_top_half_cell_is_not_elimination": True,
            "UNKNOWN_residual_cell_is_not_elimination": True,
            "any_A281_solver_execution_started": False,
        },
    }
    protocol["scientific_design_sha256"] = canonical_sha256(
        {
            "target": protocol["target"],
            "frozen_order": protocol["frozen_order"],
            "solver_schedule": protocol["solver_schedule"],
            "information_boundary": protocol["information_boundary"],
        }
    )
    assert_label_free(protocol)
    return protocol


def freeze_protocols(
    *,
    master_path: Path,
    expected_master_sha256: str,
    targets_path: Path,
    expected_targets_sha256: str,
    orders_path: Path,
    expected_orders_sha256: str,
    output: Path,
    dotcausal_src: Path,
) -> dict[str, Any]:
    panel, targets, orders = _load_triplet(
        master_path=master_path,
        expected_master_sha256=expected_master_sha256,
        targets_path=targets_path,
        expected_targets_sha256=expected_targets_sha256,
        orders_path=orders_path,
        expected_orders_sha256=expected_orders_sha256,
    )
    result_artifacts = [
        path
        for index in range(1, 5)
        for path in _result_paths(index).values()
        if path.exists()
    ]
    if result_artifacts:
        raise RuntimeError(
            f"A285 result exists before all recovery protocols: {result_artifacts[0]}"
        )
    protocol_paths = [_protocol_path(index) for index in range(1, 5)]
    existing = [path for path in [output, *protocol_paths] if path.exists()]
    if existing:
        raise FileExistsError(f"A285 recovery protocol already exists: {existing[0]}")
    protocols: list[tuple[Path, dict[str, Any]]] = []
    for index, (target_row, order_row) in enumerate(
        zip(targets["targets"], orders["orders"], strict=True), start=1
    ):
        protocol = _build_protocol(
            index=index,
            panel=panel,
            target_row=target_row,
            order_row=order_row,
            master_path=master_path,
            expected_master_sha256=expected_master_sha256,
            targets_path=targets_path,
            expected_targets_sha256=expected_targets_sha256,
            orders_path=orders_path,
            expected_orders_sha256=expected_orders_sha256,
            dotcausal_src=dotcausal_src,
        )
        protocols.append((_protocol_path(index), protocol))
    for path, protocol in protocols:
        atomic_json(path, protocol)
    rows = [
        {
            "target_id": protocol["panel_context"]["target_id"],
            "panel_index": protocol["panel_context"]["panel_index"],
            "public_challenge_sha256": protocol["target"][
                "public_challenge_sha256"
            ],
            "protocol": anchor(path),
            "scientific_design_sha256": protocol["scientific_design_sha256"],
            "complete_order_uint8_sha256": protocol["frozen_order"][
                "complete_cell_order_uint8_sha256"
            ],
            "top128_order_uint8_sha256": protocol["frozen_order"][
                "top128_cell_order_uint8_sha256"
            ],
            "ranked_binary": protocol["anchors"]["ranked_binary"],
        }
        for path, protocol in protocols
    ]
    ledger: dict[str, Any] = {
        "schema": "chacha20-round20-multitarget-recovery-protocol-ledger-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "all_four_recovery_protocols_frozen_before_any_solver_execution",
        "panel_master": anchor(master_path, expected_master_sha256),
        "target_ledger": anchor(targets_path, expected_targets_sha256),
        "order_ledger": anchor(orders_path, expected_orders_sha256),
        "preflight": anchor(Path(__file__)),
        "protocol_count": len(rows),
        "protocols": rows,
        "execution_schedule": {
            "parallel_workers": 2,
            "cross_target_adaptation_permitted": False,
            "all_protocols_frozen_before_first_solver": True,
            "per_target_residual_binary_isolated": True,
        },
        "information_boundary": {
            "all_four_targets_frozen_before_any_measurement": True,
            "all_four_orders_frozen_before_any_recovery_protocol": True,
            "all_four_recovery_protocols_frozen_before_any_solver": True,
            "any_target_label_available": False,
            "any_solver_execution_started": False,
        },
    }
    ledger["scientific_design_sha256"] = canonical_sha256(
        {
            "protocols": rows,
            "execution_schedule": ledger["execution_schedule"],
            "information_boundary": ledger["information_boundary"],
        }
    )
    assert_label_free(ledger)
    atomic_json(output, ledger)
    return ledger


def _rank_from_result(
    result: dict[str, Any], protocol: dict[str, Any]
) -> tuple[int | None, str | None]:
    top_row = result.get("top_execution", {}).get("sat_row")
    if isinstance(top_row, dict) and isinstance(top_row.get("prefix8"), str):
        return int(top_row["cell_index"]) + 1, top_row["prefix8"]
    residual_row = (result.get("residual_execution") or {}).get("sat_row")
    if isinstance(residual_row, dict) and isinstance(residual_row.get("prefix8"), str):
        prefix = int(residual_row["prefix8"], 2)
        return protocol["frozen_order"]["complete_cell_order"].index(prefix) + 1, residual_row[
            "prefix8"
        ]
    return None, None


def _canonicalize_one(
    *,
    index: int,
    result_path: Path,
    causal_path: Path,
    protocol_path: Path,
    outputs: dict[str, Path],
    dotcausal_src: Path,
) -> dict[str, Any]:
    result_sha256 = file_sha256(result_path)
    causal_sha256 = file_sha256(causal_path)
    result = json.loads(result_path.read_bytes())
    protocol = json.loads(protocol_path.read_bytes())
    target_id = f"t{index:02d}"
    confirmation = result.get("confirmation")
    confirmed = confirmation is not None
    rank, prefix8 = _rank_from_result(result, protocol)
    _, CausalReader, _ = load_dotcausal(dotcausal_src)
    original = CausalReader(str(causal_path), verify_integrity=True)
    if original.version != 1 or original.api_id != "a281":
        raise RuntimeError(f"A285 {target_id} original Causal identity differs")

    CausalWriter, CausalReader, reader_source = load_dotcausal(dotcausal_src)
    order_node = f"A284:{target_id}_hash_frozen_cross_material_order"
    solver_node = f"A285:{target_id}_frozen_composite_solver_execution"
    evidence_node = (
        f"A285:{target_id}_dual_4096_bit_confirmation"
        if confirmed
        else f"A285:{target_id}_measured_composite_budget_boundary"
    )
    terminal = (
        f"A285:{target_id}_confirmed_cross_material_R20_recovery"
        if confirmed
        else f"A285:{target_id}_retained_cross_material_boundary"
    )
    writer = CausalWriter(api_id=f"a285{target_id}")
    writer._rules = []
    writer.add_rule(
        name=f"{target_id}_frozen_order_precedes_solver",
        description="The complete target-blind order and all panel protocols are hash-frozen before this retained-state solver starts.",
        pattern=[order_node, solver_node],
        conclusion=evidence_node,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name=f"{target_id}_model_requires_dual_confirmation",
        description="A solver model becomes recovery evidence only after two standard implementations match all eight blocks and the flipped control rejects.",
        pattern=[solver_node, evidence_node],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger=order_node,
        mechanism="execute_exactly_the_hash_frozen_top128_then_conditional_residual_schedule",
        outcome=solver_node,
        confidence=1.0,
        source=result["protocol_sha256"],
        quantification=json.dumps(
            {
                "top": result["top_execution_summary"],
                "residual": result["residual_execution_summary"],
                "order_rank": rank,
            },
            sort_keys=True,
        ),
        evidence=result["evidence_stage"],
        domain="full-round ChaCha20-R20 prospective multi-target recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=solver_node,
        mechanism=(
            "decode_model_then_recompute_eight_standard_R20_blocks_twice"
            if confirmed
            else "complete_the_frozen_available_budget_without_model_disclosure"
        ),
        outcome=evidence_node,
        confidence=1.0,
        source=result_sha256,
        quantification=(
            f"rank={rank}; prefix8={prefix8}; output_bits=4096; flipped_control=false"
            if confirmed
            else json.dumps(result["residual_execution_summary"], sort_keys=True)
        ),
        evidence=json.dumps(confirmation, sort_keys=True),
        domain="independent confirmation or exact measured solver boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=evidence_node,
        mechanism="bind_prospective_panel_freeze_solver_evidence_and_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=result_sha256,
        quantification=(
            "strict subset of declared residual domain; no complete-domain enumeration"
            if confirmed
            else "exactly the prospectively frozen schedule"
        ),
        evidence=result["evidence_stage"],
        domain="canonical AI-native recovery evidence",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=order_node,
        mechanism="materialized_order_solver_evidence_terminal_chain",
        outcome=terminal,
        confidence=1.0,
        source=f"materialized:A284_order_plus_A285_{target_id}_execution",
        quantification="canonical three-edge AI-native closure",
        evidence=result["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name=f"A285 {target_id} canonical cross-material result",
        entities=[order_node, solver_node, evidence_node, terminal],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "complete_remaining_panel_targets_then_widen_unknown_domain"
            if confirmed
            else "reader_or_budget_intervention_at_measured_panel_boundary"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Complete the independently frozen panel and measure its rank distribution.",
                "Transfer the panel mechanism to a wider unknown-key domain.",
            ]
            if confirmed
            else [
                "Which frozen reader feature best predicts this material-specific boundary?",
                "Can a prospectively selected diverse operator move this exact boundary?",
            ]
        ),
    )
    outputs["canonical_causal"].parent.mkdir(parents=True, exist_ok=True)
    temporary = outputs["canonical_causal"].with_name(
        f".{outputs['canonical_causal'].name}.tmp"
    )
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, outputs["canonical_causal"])
    reader = CausalReader(str(outputs["canonical_causal"]), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != f"a285{target_id}"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or any(row.get("trigger") == row.get("outcome") for row in explicit)
        or len(reader._clusters[0]["entity_indices"])
        != len(set(reader._clusters[0]["entity_indices"]))
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError(f"A285 {target_id} canonical Causal gate failed")
    payload = {
        "schema": "chacha20-round20-multitarget-canonical-causal-v1",
        "attempt_id": ATTEMPT_ID,
        "target_id": target_id,
        "evidence_stage": result["evidence_stage"],
        "source_result": anchor(result_path, result_sha256),
        "source_causal": {
            **anchor(causal_path, causal_sha256),
            "retained_as_immutable_original": True,
        },
        "solver_or_measurement_reexecuted": False,
        "scientific_result_changed": False,
        "confirmed": confirmed,
        "order_rank": rank,
        "prefix8": prefix8,
        "causal": {
            "format": "authentic_dotcausal_v1_AI_native",
            "path": path_ref(outputs["canonical_causal"]),
            "sha256": file_sha256(outputs["canonical_causal"]),
            "bytes": outputs["canonical_causal"].stat().st_size,
            "api_id": reader.api_id,
            "explicit_triplets": len(explicit),
            "materialized_inferred_triplets": len(inferred),
            "embedded_rules": len(reader._rules),
            "clusters": len(reader._clusters),
            "gaps": len(reader._gaps),
            "integrity_verified_by_authoritative_reader": True,
            "reader_source": reader_source,
            "writer_stats": stats,
            "personal_semantic_readback": {
                "terminal_chain": all_rows[-1],
                "next_gap": reader._gaps[0],
            },
        },
    }
    atomic_json(outputs["canonical"], payload)
    atomic_bytes(
        outputs["canonical_report"],
        "\n".join(
            [
                f"# A285 {target_id} — canonical AI-native recovery graph",
                "",
                f"- Evidence: **{result['evidence_stage']}**",
                f"- Confirmed: **{confirmed}**",
                f"- Frozen-order rank: **{rank}**",
                f"- Canonical Causal SHA-256: `{payload['causal']['sha256']}`",
                "- Solver re-executed during canonicalization: **False**",
                "",
            ]
        ).encode("utf-8"),
    )
    return payload


def _execute_one(
    *, index: int, protocol_row: dict[str, Any], panel: dict[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    target_id = str(protocol_row["target_id"])
    protocol_path = path_from_ref(protocol_row["protocol"]["path"])
    outputs = _result_paths(index)
    runner = path_from_ref(panel["source_anchors"]["A281_recovery_runner"]["path"])
    if not outputs["result"].exists():
        command = [
            sys.executable,
            str(runner),
            "--protocol",
            str(protocol_path),
            "--expected-protocol-sha256",
            protocol_row["protocol"]["sha256"],
            "--run",
            "--output",
            str(outputs["result"]),
            "--causal-output",
            str(outputs["causal"]),
            "--report-output",
            str(outputs["report"]),
            "--dotcausal-src",
            str(dotcausal_src),
        ]
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=14400,
            env={
                **os.environ,
                "PYTHONHASHSEED": "0",
                "F8_CAUSAL_RESIDUAL_BINARY_SUFFIX": f"a285_{target_id}",
            },
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"A285 {target_id} recovery failed: "
                f"stdout={completed.stdout[-2000:]!r} stderr={completed.stderr[-2000:]!r}"
            )
        process = {
            "returncode": completed.returncode,
            "stdout_sha256": sha256(completed.stdout.encode()),
            "stderr_sha256": sha256(completed.stderr.encode()),
            "resumed_existing_result": False,
        }
    else:
        process = {
            "returncode": 0,
            "stdout_sha256": None,
            "stderr_sha256": None,
            "resumed_existing_result": True,
        }
    for name in ("result", "causal", "report"):
        if not outputs[name].is_file():
            raise RuntimeError(f"A285 {target_id} missing {name} artifact")
    result = json.loads(outputs["result"].read_bytes())
    confirmation = result.get("confirmation")
    if (
        result.get("schema")
        != "chacha20-round20-cross-material-composite-recovery-result-v1"
        or result.get("attempt_id") != "A281"
        or result.get("protocol_sha256") != protocol_row["protocol"]["sha256"]
        or result.get("public_challenge_sha256")
        != protocol_row["public_challenge_sha256"]
        or result.get("runner_sha256")
        != panel["source_anchors"]["A281_recovery_runner"]["sha256"]
        or result.get("information_boundary", {}).get(
            "complete_full_domain_enumeration_used"
        )
        is not False
        or (
            confirmation is not None
            and (
                confirmation.get("all_blocks_match") is not True
                or confirmation.get("all_cross_implementation_blocks_match") is not True
                or confirmation.get("output_bits_checked") != 4096
                or confirmation.get("control_first_block_match") is not False
            )
        )
    ):
        raise RuntimeError(f"A285 {target_id} recovery result gate failed")
    canonical = _canonicalize_one(
        index=index,
        result_path=outputs["result"],
        causal_path=outputs["causal"],
        protocol_path=protocol_path,
        outputs=outputs,
        dotcausal_src=dotcausal_src,
    )
    protocol = json.loads(protocol_path.read_bytes())
    rank, prefix8 = _rank_from_result(result, protocol)
    return {
        "target_id": target_id,
        "panel_index": index,
        "evidence_stage": result["evidence_stage"],
        "confirmed": confirmation is not None,
        "discovery_stage": result["residual_execution_summary"][
            "model_discovery_stage"
        ],
        "order_rank": rank,
        "prefix8": prefix8,
        "prefix_cells_visited": rank,
        "prefix_domain_upper_bound_assignments": (
            None if rank is None else rank * 4096
        ),
        "prefix_domain_upper_bound_fraction": (
            None if rank is None else rank / 256.0
        ),
        "recovered_unknown_low20_hex": (
            None
            if confirmation is None
            else confirmation["recovered_unknown_low20_hex"]
        ),
        "output_bits_confirmed": (
            0 if confirmation is None else confirmation["output_bits_checked"]
        ),
        "complete_full_domain_enumeration_used": False,
        "protocol": protocol_row["protocol"],
        "result": anchor(outputs["result"]),
        "original_causal": anchor(outputs["causal"]),
        "canonical_result": anchor(outputs["canonical"]),
        "canonical_causal": anchor(outputs["canonical_causal"]),
        "report": anchor(outputs["report"]),
        "canonical_report": anchor(outputs["canonical_report"]),
        "canonical_next_gap": canonical["causal"]["personal_semantic_readback"][
            "next_gap"
        ],
        "process": process,
    }


def _build_batch_causal(
    *, path: Path, payload: dict[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, reader_source = load_dotcausal(dotcausal_src)
    confirmed = payload["headline"]["confirmed_recoveries"]
    outcome = "A285:four_target_panel_result"
    writer = CausalWriter(api_id="a285panel")
    writer._rules = []
    writer.add_rule(
        name="single_target_gap_selects_prospective_panel",
        description="A281C's next gap selects a multi-target cross-material replication whose complete phase order is frozen before target generation.",
        pattern=["A281C_confirmed_rank37_recovery", "A282_panel_freeze"],
        conclusion="A284_four_hash_frozen_orders",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="four_orders_precede_four_recovery_protocols",
        description="All four complete orders and all four recovery protocols precede the first A285 solver execution.",
        pattern=["A284_four_hash_frozen_orders", "A285_four_frozen_recovery_protocols"],
        conclusion=outcome,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A281C:confirmed_rank37_cross_material_recovery",
        mechanism="freeze_four_fresh_public_materials_and_408_exact_literal_mapping_probes",
        outcome="A282:four_target_panel_freeze",
        confidence=1.0,
        source=payload["panel_master"]["sha256"],
        quantification="4 public materials; 4 symbolic templates; 408 exact mapping probes",
        evidence="A282 before-target master freeze",
        domain="prospective full-round ChaCha20-R20 replication",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A282:four_target_panel_freeze",
        mechanism="generate_four_label_discarded_targets_then_complete_all_4096_shallow_stages",
        outcome="A284:four_hash_frozen_orders",
        confidence=1.0,
        source=payload["order_ledger"]["sha256"],
        quantification="4 targets; 1024 cells; 4096 model-free UNKNOWN shallow stages",
        evidence="zero labels and zero reader refits",
        domain="target-blind candidate ordering",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A284:four_hash_frozen_orders",
        mechanism="execute_four_precommitted_retained_top128_plus_conditional_residual_schedules",
        outcome=outcome,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["headline"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="multi-target full-round residual-key recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A281C:confirmed_rank37_cross_material_recovery",
        mechanism="materialized_single_target_gap_to_complete_panel_result",
        outcome=outcome,
        confidence=1.0,
        source="materialized:A281C_gap_plus_A282_A285_panel",
        quantification=f"confirmed_recoveries={confirmed}/4",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A282-A285 prospective ChaCha20-R20 multi-target panel",
        entities=[
            "A281C:confirmed_rank37_cross_material_recovery",
            "A282:four_target_panel_freeze",
            "A284:four_hash_frozen_orders",
            outcome,
        ],
    )
    writer.add_gap(
        subject=outcome,
        predicate="next_required_object",
        expected_object_type="wider_unknown_domain_or_diverse_reader_selected_from_panel_distribution",
        confidence=1.0,
        suggested_queries=[
            "Freeze a W24 transfer using the panel's material-specific rank distribution.",
            "Select a second trajectory-diverse reader before another disjoint target panel.",
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
        or reader.api_id != "a285panel"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or any(row.get("trigger") == row.get("outcome") for row in explicit)
        or len(reader._clusters[0]["entity_indices"])
        != len(set(reader._clusters[0]["entity_indices"]))
        or all_rows[-1]["outcome"] != outcome
    ):
        raise RuntimeError("A285 panel Causal Reader gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": path_ref(path),
        "sha256": file_sha256(path),
        "bytes": path.stat().st_size,
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "integrity_verified_by_authoritative_reader": True,
        "reader_source": reader_source,
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def execute_panel(
    *,
    master_path: Path,
    expected_master_sha256: str,
    orders_path: Path,
    expected_orders_sha256: str,
    protocol_ledger_path: Path,
    expected_protocol_ledger_sha256: str,
    output: Path,
    causal_output: Path,
    report_output: Path,
    dotcausal_src: Path,
) -> dict[str, Any]:
    if file_sha256(master_path) != expected_master_sha256:
        raise RuntimeError("A285 execution panel-master hash differs")
    if file_sha256(orders_path) != expected_orders_sha256:
        raise RuntimeError("A285 execution order-ledger hash differs")
    if file_sha256(protocol_ledger_path) != expected_protocol_ledger_sha256:
        raise RuntimeError("A285 recovery-protocol-ledger hash differs")
    panel = json.loads(master_path.read_bytes())
    order_ledger = json.loads(orders_path.read_bytes())
    ledger = json.loads(protocol_ledger_path.read_bytes())
    if (
        ledger.get("schema")
        != "chacha20-round20-multitarget-recovery-protocol-ledger-v1"
        or ledger.get("attempt_id") != ATTEMPT_ID
        or ledger.get("protocol_state")
        != "all_four_recovery_protocols_frozen_before_any_solver_execution"
        or ledger.get("protocol_count") != 4
        or len(ledger.get("protocols", [])) != 4
        or ledger.get("information_boundary", {}).get("any_solver_execution_started")
        is not False
        or ledger.get("execution_schedule", {}).get("parallel_workers") != 2
        or order_ledger.get("headline", {}).get(
            "all_orders_frozen_before_any_recovery"
        )
        is not True
    ):
        raise RuntimeError("A285 execution-ledger semantic gate failed")
    verify_anchors(
        {
            "panel_master": ledger["panel_master"],
            "target_ledger": ledger["target_ledger"],
            "order_ledger": ledger["order_ledger"],
            "preflight": ledger["preflight"],
        },
        context="A285 execution ledger",
    )
    verify_anchors(
        {row["target_id"]: row["protocol"] for row in ledger["protocols"]},
        context="A285 recovery protocols",
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                _execute_one,
                index=int(row["panel_index"]),
                protocol_row=row,
                panel=panel,
                dotcausal_src=dotcausal_src,
            )
            for row in ledger["protocols"]
        ]
        rows = [future.result() for future in futures]
    rows.sort(key=lambda row: row["panel_index"])
    confirmed_rows = [row for row in rows if row["confirmed"]]
    ranks = [int(row["order_rank"]) for row in confirmed_rows if row["order_rank"]]
    headline = {
        "panel_targets": len(rows),
        "confirmed_recoveries": len(confirmed_rows),
        "measured_budget_boundaries": len(rows) - len(confirmed_rows),
        "strict_subset_recoveries": sum(
            1
            for row in confirmed_rows
            if row["complete_full_domain_enumeration_used"] is False
        ),
        "confirmed_order_ranks": ranks,
        "minimum_confirmed_order_rank": min(ranks) if ranks else None,
        "median_confirmed_order_rank": statistics.median(ranks) if ranks else None,
        "maximum_confirmed_order_rank": max(ranks) if ranks else None,
        "all_confirmations_check_4096_output_bits": bool(confirmed_rows)
        and all(row["output_bits_confirmed"] == 4096 for row in confirmed_rows),
        "any_complete_full_domain_enumeration_used": False,
        "target_labels_used": 0,
        "reader_refits": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-multitarget-recovery-panel-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            f"FULLROUND_R20_MULTITARGET_PANEL_{len(confirmed_rows)}_OF_4_"
            "RECOVERIES_CONFIRMED"
        ),
        "panel_master": anchor(master_path, expected_master_sha256),
        "order_ledger": anchor(orders_path, expected_orders_sha256),
        "recovery_protocol_ledger": anchor(
            protocol_ledger_path, expected_protocol_ledger_sha256
        ),
        "runner": anchor(Path(__file__)),
        "target_results": rows,
        "headline": headline,
        "information_boundary": {
            "all_four_targets_frozen_before_any_measurement": True,
            "all_four_orders_frozen_before_any_recovery_protocol": True,
            "all_four_recovery_protocols_frozen_before_any_solver": True,
            "cross_target_adaptation_permitted": False,
            "target_labels_available_before_or_during_execution": False,
            "confirmation_only_after_solver_model": True,
            "complete_full_domain_enumeration_used": False,
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "target_results": [
                {
                    key: row[key]
                    for key in (
                        "target_id",
                        "evidence_stage",
                        "confirmed",
                        "discovery_stage",
                        "order_rank",
                        "prefix8",
                        "prefix_domain_upper_bound_assignments",
                        "output_bits_confirmed",
                        "result",
                        "canonical_causal",
                    )
                }
                for row in rows
            ],
            "headline": headline,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = _build_batch_causal(
        path=causal_output, payload=payload, dotcausal_src=dotcausal_src
    )
    atomic_json(output, payload)
    report = [
        "# A285 — Prospective four-target ChaCha20-R20 recovery panel",
        "",
        f"Evidence stage: **{payload['evidence_stage']}**",
        "",
        f"- Confirmed recoveries: **{headline['confirmed_recoveries']}/4**",
        f"- Frozen-order ranks: **{ranks}**",
        f"- Strict-subset recoveries: **{headline['strict_subset_recoveries']}**",
        "- Target labels used: **0**",
        "- Reader refits: **0**",
        "- Complete residual-domain enumeration used: **False**",
        "",
    ]
    report.extend(
        (
            f"- {row['target_id']}: {row['evidence_stage']}; "
            f"rank={row['order_rank']}; confirmed={row['confirmed']}"
        )
        for row in rows
    )
    report.extend(
        [
            "",
            "## Authentic AI-native Causal readback",
            "",
            f"- Panel next gap: **{payload['causal']['personal_semantic_readback']['next_gap']['expected_object_type']}**",
            "",
        ]
    )
    atomic_bytes(report_output, "\n".join(report).encode("utf-8"))
    return payload


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze", action="store_true")
    action.add_argument("--run", action="store_true")
    parser.add_argument("--master", type=Path, default=DEFAULT_MASTER)
    parser.add_argument("--expected-master-sha256", required=True)
    parser.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    parser.add_argument("--expected-targets-sha256")
    parser.add_argument("--orders", type=Path, default=DEFAULT_ORDERS)
    parser.add_argument("--expected-orders-sha256", required=True)
    parser.add_argument("--protocol-ledger", type=Path, default=DEFAULT_PROTOCOL_LEDGER)
    parser.add_argument("--expected-protocol-ledger-sha256")
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT)
    parser.add_argument("--causal-output", type=Path, default=DEFAULT_CAUSAL)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    if args.freeze:
        if not args.expected_targets_sha256:
            parser.error("--freeze requires --expected-targets-sha256")
        ledger = freeze_protocols(
            master_path=args.master,
            expected_master_sha256=args.expected_master_sha256,
            targets_path=args.targets,
            expected_targets_sha256=args.expected_targets_sha256,
            orders_path=args.orders,
            expected_orders_sha256=args.expected_orders_sha256,
            output=args.protocol_ledger,
            dotcausal_src=args.dotcausal_src,
        )
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "protocol_ledger": path_ref(args.protocol_ledger),
                    "protocol_ledger_sha256": file_sha256(args.protocol_ledger),
                    "scientific_design_sha256": ledger[
                        "scientific_design_sha256"
                    ],
                    "protocol_count": ledger["protocol_count"],
                    "solver_execution_started": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    if not args.expected_protocol_ledger_sha256:
        parser.error("--run requires --expected-protocol-ledger-sha256")
    if args.output.exists():
        raise FileExistsError(f"A285 panel result already exists: {args.output}")
    payload = execute_panel(
        master_path=args.master,
        expected_master_sha256=args.expected_master_sha256,
        orders_path=args.orders,
        expected_orders_sha256=args.expected_orders_sha256,
        protocol_ledger_path=args.protocol_ledger,
        expected_protocol_ledger_sha256=args.expected_protocol_ledger_sha256,
        output=args.output,
        causal_output=args.causal_output,
        report_output=args.report_output,
        dotcausal_src=args.dotcausal_src,
    )
    print(
        json.dumps(
            {
                "attempt_id": ATTEMPT_ID,
                "evidence_stage": payload["evidence_stage"],
                "result": path_ref(args.output),
                "result_sha256": file_sha256(args.output),
                "causal": path_ref(args.causal_output),
                "causal_sha256": file_sha256(args.causal_output),
                "headline": payload["headline"],
                "next_gap": payload["causal"]["personal_semantic_readback"][
                    "next_gap"
                ]["expected_object_type"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
