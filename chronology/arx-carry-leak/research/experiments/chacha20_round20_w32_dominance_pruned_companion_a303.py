#!/usr/bin/env python3
"""A303: calibrated two-operator companion recovery for the sealed A298 target."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"

DESIGN = CONFIGS / "chacha20_round20_w32_dominance_pruned_companion_a303_design_v1.json"
A301_RUNNER = RESEARCH / "experiments/chacha20_round20_w43_dominance_pruned_portfolio_a301.py"
A298_RUNNER = RESEARCH / "experiments/chacha20_round20_w32_fine_selected_channel_transfer_a298.py"
A303_TEST = ROOT / "tests/test_chacha20_round20_w32_dominance_pruned_companion_a303.py"

PROTOCOL = CONFIGS / "chacha20_round20_w32_dominance_pruned_companion_a303_v1.json"
ORDER = RESULTS / "chacha20_round20_w32_dominance_pruned_companion_a303_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w32_dominance_pruned_companion_a303_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_W32_DOMINANCE_PRUNED_COMPANION_A303_V1.md"
BUILD = RESEARCH / "build/chacha20_round20_w32_dominance_pruned_companion_a303"

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A303"
DESIGN_SHA256 = "1880b22f0787e0b0ffec5826fe50e8ead2218d5590174a317c1c596127dc9ccf"
WIDTH = 32
PREFIX_BITS = 12
CELLS = 1 << PREFIX_BITS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A303 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A301 = load_module(A301_RUNNER, "a303_a301_common")
A298 = load_module(A298_RUNNER, "a303_a298_common")
sha256 = A301.sha256
file_sha256 = A301.file_sha256
canonical_sha256 = A301.canonical_sha256
atomic_bytes = A301.atomic_bytes
atomic_json = A301.atomic_json
relative = A301.relative
path_from_ref = A301.path_from_ref
anchor = A301.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A303 prospective design hash differs")
    value = json.loads(DESIGN.read_bytes())
    operator = value.get("operator_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w32-dominance-pruned-companion-a303-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A301_calibration_and_before_A298_order_candidate_assignment_or_result_exists"
        or operator.get("candidate_execution_orders")
        != [
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        ]
        or operator.get("audit_only_order")
        != "A295_fine_selected_channel_as_measured_by_A298"
        or boundary.get(
            "A298_order_model_candidate_assignment_filter_outcome_or_result_available_at_freeze"
        )
        is not False
    ):
        raise RuntimeError("A303 prospective design semantics differ")
    return value


def execution_contract() -> dict[str, Any]:
    return {
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward_included": True,
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "public_output_blocks": 8,
        "prefix_cells": CELLS,
        "candidate_group_size": GROUP_SIZE,
        "complete_residual_domain": DOMAIN_SIZE,
        "candidate_execution_orders": [
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        ],
        "audit_only_order": "A295_fine_selected_channel_as_measured_by_A298",
        "merge": "rank_round_robin_then_first_occurrence_deduplication",
        "rank_guarantee": "R_A303 <= 2 * min(R_coarse, R_numeric)",
        "reader_refits": 0,
        "target_labels_used": 0,
        "recovery": "portfolio_ordered_word0_prefix12_groups_then_dual_eight_block_confirmation",
    }


def freeze() -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, ORDER, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A303 artifacts already exist")
    design = load_design()
    sources = design["source_anchors"]
    for path_key, sha_key in (
        ("A301_design_path", "A301_design_sha256"),
        ("A301_calibration_path", "A301_calibration_sha256"),
        ("A301_protocol_path", "A301_protocol_sha256"),
        ("A301_runner_path", "A301_runner_sha256"),
        ("A298_design_path", "A298_design_sha256"),
        ("A298_protocol_path", "A298_protocol_sha256"),
        ("A298_preflight_path", "A298_preflight_sha256"),
        ("A298_runner_path", "A298_runner_sha256"),
        ("A298_test_path", "A298_test_sha256"),
    ):
        anchor(path_from_ref(sources[path_key]), sources[sha_key])
    A301.load_protocol(sources["A301_protocol_sha256"])
    a298_protocol, _ = A298.load_preflight(
        sources["A298_protocol_sha256"], sources["A298_preflight_sha256"]
    )
    if A298.ORDER.exists() or A298.RESULT.exists():
        raise RuntimeError("A303 must freeze before A298 order or result exists")
    if not A303_TEST.exists():
        raise FileNotFoundError("A303 tests must exist before protocol freeze")
    calibration = json.loads(A301.CALIBRATION.read_bytes())
    aggregate = calibration["aggregate"]
    if (
        aggregate.get("targets") != 14
        or aggregate.get("strict_subset_targets") != 14
        or aggregate.get("fine_operator_dominated_calibrations") != 2
    ):
        raise RuntimeError("A303 calibration frontier differs")
    plan = execution_contract()
    payload = {
        "schema": "chacha20-round20-w32-dominance-pruned-companion-a303-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A303_two_operator_allocation_frozen_before_A298_order_or_candidate_discovery",
        "design": design,
        "execution_contract": plan,
        "execution_contract_sha256": canonical_sha256(plan),
        "public_challenge_sha256": a298_protocol["public_challenge_sha256"],
        "calibration_aggregate": aggregate,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A303_TEST),
            "A301_design": anchor(A301.DESIGN, sources["A301_design_sha256"]),
            "A301_calibration": anchor(
                A301.CALIBRATION, sources["A301_calibration_sha256"]
            ),
            "A301_protocol": anchor(
                A301.PROTOCOL, sources["A301_protocol_sha256"]
            ),
            "A301_runner": anchor(A301_RUNNER, sources["A301_runner_sha256"]),
            "A298_design": anchor(A298.DESIGN, sources["A298_design_sha256"]),
            "A298_protocol": anchor(
                A298.PROTOCOL, sources["A298_protocol_sha256"]
            ),
            "A298_preflight": anchor(
                A298.PREFLIGHT, sources["A298_preflight_sha256"]
            ),
            "A298_runner": anchor(A298_RUNNER, sources["A298_runner_sha256"]),
        },
        "information_boundary": {
            "sealed_A298_public_challenge_exists": True,
            "partial_unlabeled_A298_measurement_exists": True,
            "A298_order_model_candidate_assignment_filter_outcome_or_result_available_at_freeze": False,
            "calibration_labels_are_disjoint_completed_targets": True,
            "operator_allocation_merge_and_precedence_frozen": True,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "execution_contract": plan,
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "calibration_sha256": sources["A301_calibration_sha256"],
            "information_boundary": payload["information_boundary"],
            "anchors": payload["anchors"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A303 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w32-dominance-pruned-companion-a303-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("execution_contract") != execution_contract()
        or value.get("anchors", {}).get("runner", {}).get("sha256")
        != file_sha256(Path(__file__))
        or value.get("anchors", {}).get("test", {}).get("sha256")
        != file_sha256(A303_TEST)
        or value.get("information_boundary", {}).get(
            "A298_order_model_candidate_assignment_filter_outcome_or_result_available_at_freeze"
        )
        is not False
    ):
        raise RuntimeError("A303 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    A298.load_preflight(
        value["anchors"]["A298_protocol"]["sha256"],
        value["anchors"]["A298_preflight"]["sha256"],
    )
    return value


def derive_order(
    *, expected_protocol_sha256: str, expected_a298_order_sha256: str
) -> dict[str, Any]:
    if ORDER.exists():
        raise FileExistsError("A303 order already exists")
    protocol = load_protocol(expected_protocol_sha256)
    _, _, a298_order = A298.load_order(
        protocol["anchors"]["A298_protocol"]["sha256"],
        protocol["anchors"]["A298_preflight"]["sha256"],
        expected_a298_order_sha256,
    )
    coarse = A298.A297.A296.fine_order(
        [int(value) for value in a298_order["coarse_readout"]["complete_coarse_order"]]
    )
    numeric = list(range(CELLS))
    portfolio = A301.two_operator_portfolio(coarse=coarse, numeric=numeric)
    guarantee = A301.portfolio_guarantee(
        portfolio=portfolio, coarse=coarse, numeric=numeric
    )
    fine = (
        [int(value) for value in a298_order["fine_readout"]["complete_order"]]
        if a298_order.get("fine_readout") is not None
        else []
    )
    payload = {
        "schema": "chacha20-round20-w32-dominance-pruned-companion-a303-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "SEALED_W32_TARGET_BLIND_TWO_OPERATOR_ORDER_FROZEN",
        "protocol_sha256": expected_protocol_sha256,
        "A298_order": anchor(A298.ORDER, expected_a298_order_sha256),
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "candidate_execution_orders": {
            "A297_coarse_high8_then_reflected_Gray4": coarse,
            "numeric_word0_prefix12": numeric,
        },
        "audit_only_fine_order": {
            "available": bool(fine),
            "order_uint16be_sha256": (
                sha256(b"".join(value.to_bytes(2, "big") for value in fine))
                if fine
                else None
            ),
            "direct_symbolic_winner": a298_order["direct_symbolic_winner"],
        },
        "portfolio_order": portfolio,
        "portfolio_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in portfolio)
        ),
        "portfolio_guarantee": guarantee,
        "information_boundary": {
            "A298_target_key_label_available": False,
            "A298_target_model_used_for_portfolio_order": False,
            "candidate_filter_outcome_used_for_order": False,
            "A298_result_available": False,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "A298_order_sha256": expected_a298_order_sha256,
            "candidate_execution_orders": payload["candidate_execution_orders"],
            "audit_only_fine_order": payload["audit_only_fine_order"],
            "portfolio_order_uint16be_sha256": payload[
                "portfolio_order_uint16be_sha256"
            ],
            "portfolio_guarantee": guarantee,
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(ORDER, payload)
    return payload


def load_order(
    expected_protocol_sha256: str, expected_order_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = load_protocol(expected_protocol_sha256)
    if file_sha256(ORDER) != expected_order_sha256:
        raise RuntimeError("A303 order hash differs")
    value = json.loads(ORDER.read_bytes())
    components = value.get("candidate_execution_orders", {})
    if (
        value.get("schema")
        != "chacha20-round20-w32-dominance-pruned-companion-a303-order-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("public_challenge_sha256")
        != protocol["public_challenge_sha256"]
        or set(components)
        != {
            "A297_coarse_high8_then_reflected_Gray4",
            "numeric_word0_prefix12",
        }
        or value.get("portfolio_guarantee", {}).get("violations") != 0
        or value.get("information_boundary", {}).get("A298_result_available")
        is not False
    ):
        raise RuntimeError("A303 order semantics differ")
    recomputed = A301.two_operator_portfolio(
        coarse=components["A297_coarse_high8_then_reflected_Gray4"],
        numeric=components["numeric_word0_prefix12"],
    )
    if recomputed != value["portfolio_order"]:
        raise RuntimeError("A303 portfolio order reconstruction differs")
    anchor(A298.ORDER, value["A298_order"]["sha256"])
    return protocol, value


def rank_analysis(
    *, discovery: Mapping[str, Any], order_value: Mapping[str, Any], challenge_sha: str
) -> dict[str, Any]:
    prefix = int(discovery["fine_prefix12"])
    components = order_value["candidate_execution_orders"]
    portfolio = [int(value) for value in order_value["portfolio_order"]]
    coarse = [
        int(value)
        for value in components["A297_coarse_high8_then_reflected_Gray4"]
    ]
    numeric = [int(value) for value in components["numeric_word0_prefix12"]]
    a298_order = json.loads(A298.ORDER.read_bytes())
    fine = (
        [int(value) for value in a298_order["fine_readout"]["complete_order"]]
        if a298_order.get("fine_readout") is not None
        else [prefix]
    )
    ranks = {
        "A303_two_operator_portfolio": portfolio.index(prefix) + 1,
        "A297_coarse_high8_then_reflected_Gray4": coarse.index(prefix) + 1,
        "numeric_word0_prefix12": numeric.index(prefix) + 1,
        "A298_fine_selected_channel_audit_only": fine.index(prefix) + 1,
        "public_hash_control": A298.public_hash_order(challenge_sha).index(prefix) + 1,
    }
    best = min(
        ranks["A297_coarse_high8_then_reflected_Gray4"],
        ranks["numeric_word0_prefix12"],
    )
    portfolio_rank = ranks["A303_two_operator_portfolio"]
    if portfolio_rank > 2 * best:
        raise RuntimeError("A303 target rank violates the frozen portfolio guarantee")
    return {
        "prefix12": prefix,
        "prefix_ranks_one_based": ranks,
        "best_allocated_component_rank_one_based": best,
        "portfolio_gain_bits_vs_complete_domain": math.log2(CELLS / portfolio_rank),
        "portfolio_regret_factor_vs_best_allocated": portfolio_rank / best,
        "portfolio_speedup_vs_A298_fine_rank": ranks[
            "A298_fine_selected_channel_audit_only"
        ]
        / portfolio_rank,
        "portfolio_speedup_vs_public_hash_rank": ranks["public_hash_control"]
        / portfolio_rank,
        "assignment_upper_bounds": {
            name: rank * GROUP_SIZE for name, rank in ranks.items()
        },
        "rank_guarantee_holds": True,
        "counterfactual_ranks_computed_only_after_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A303:confirmed_two_operator_W32_recovery"
    writer = CausalWriter(api_id="a303w32")
    writer._rules = []
    writer.add_rule(
        name="calibrated_two_operator_rank_bound",
        description="The frozen coarse/numeric round-robin visits both rank-r prefixes by portfolio position at most 2r.",
        pattern=["A301_calibration", "A303_two_operator_round_robin"],
        conclusion="A303_bounded_regret_prefix_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="bounded_regret_order_to_confirmed_recovery",
        description="Each frozen prefix expands over every 2^20 residual assignment before dual confirmation.",
        pattern=["A303_bounded_regret_prefix_order", "dual_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A303:sealed_A298_W32_relation",
        mechanism="A301_calibrated_coarse_numeric_portfolio",
        outcome="A303:frozen_factor_two_prefix_order",
        confidence=1.0,
        source=payload["order_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=json.dumps(payload["portfolio_guarantee"], sort_keys=True),
        domain="AI-native calibrated ChaCha20-R20 W32 readout",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A303:frozen_factor_two_prefix_order",
        mechanism="complete_2^20_candidate_groups_plus_dual_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="confirmed full-round ChaCha20 W32 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A303:sealed_A298_W32_relation",
        mechanism="materialized_calibration_order_recovery_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A303_companion_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A303 calibrated W32 companion recovery",
        entities=[
            "A303:sealed_A298_W32_relation",
            "A303:frozen_factor_two_prefix_order",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_low_overhead_W43_replication",
        confidence=1.0,
        suggested_queries=["Does A302 retain the same allocation on its fresh W43 target?"],
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
        reader.api_id != "a303w32"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A303 authentic Causal reopen gate failed")
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
    *, expected_protocol_sha256: str, expected_order_sha256: str, swiftc: str
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A303 final artifacts already exist")
    protocol, order_value = load_order(
        expected_protocol_sha256, expected_order_sha256
    )
    a298_protocol = A298.load_protocol(
        protocol["anchors"]["A298_protocol"]["sha256"]
    )
    challenge = a298_protocol["public_challenge"]
    metal = load_module(A298.A297.METAL_ANCHOR, "a303_metal_recover")
    root_reference = load_module(A298.A297.ROOT_REFERENCE, "a303_root_recover")
    executable, build = metal.A184._A181._compile_native(BUILD, swiftc)
    host = metal.A184.SliceMetalHost(
        executable,
        A298.A297.A296.initial_state(challenge, metal.A119.CONSTANTS, WIDTH),
        np.asarray(challenge["target_words"][0], dtype=np.uint32),
        np.asarray(challenge["control_target_words"], dtype=np.uint32),
    )
    try:
        mapping = A298.A297.A296.mapping_gate(
            host=host,
            challenge=challenge,
            width=WIDTH,
            metal=metal,
            root_reference=root_reference,
        )
        discovery = A298.A297.A296.discover(
            host=host,
            challenge=challenge,
            width=WIDTH,
            order=[int(value) for value in order_value["portfolio_order"]],
            metal=metal,
        )
        identity = host.identity
    finally:
        host.close()
    confirmation = A298.A297.A296.confirm(
        discovery=discovery,
        challenge=challenge,
        root_reference=root_reference,
    )
    ranks = rank_analysis(
        discovery=discovery,
        order_value=order_value,
        challenge_sha=protocol["public_challenge_sha256"],
    )
    portfolio_rank = ranks["prefix_ranks_one_based"][
        "A303_two_operator_portfolio"
    ]
    strict_subset = portfolio_rank < CELLS
    evidence_stage = (
        "FULLROUND_R20_W32_CALIBRATED_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_W32_CALIBRATED_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w32-dominance-pruned-companion-a303-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "order_sha256": expected_order_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "calibration_aggregate": protocol["calibration_aggregate"],
        "native_build": build,
        "metal_identity": identity,
        "mapping_gate": mapping,
        "portfolio_guarantee": order_value["portfolio_guarantee"],
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "strict_subset_of_complete_domain": strict_subset,
        "information_boundary": order_value["information_boundary"],
        "anchors": protocol["anchors"],
    }
    payload["execution_sha256"] = canonical_sha256(
        {"mapping_gate": mapping, "discovery": discovery, "metal_identity": identity}
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
    atomic_bytes(
        REPORT,
        (
            "# A303 — calibrated ChaCha20-R20 W32 companion recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Portfolio prefix rank: **{portfolio_rank} / 4,096**\n"
            f"- Search gain: **{ranks['portfolio_gain_bits_vs_complete_domain']:.6f} bits**\n"
            f"- Recovered full key word: **0x{int(discovery['candidate']):08x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Frozen guarantee: **R <= 2 min(R_coarse, R_numeric)**\n"
        ).encode()
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "protocol_frozen": PROTOCOL.exists(),
        "A298_order_complete": A298.ORDER.exists(),
        "A303_order_complete": ORDER.exists(),
        "result_complete": RESULT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--derive-order", action="store_true")
    mode.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-a298-order-sha256")
    parser.add_argument("--expected-order-sha256")
    parser.add_argument("--swiftc", default="/usr/bin/swiftc")
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
    else:
        if not args.expected_protocol_sha256:
            parser.error("this mode requires --expected-protocol-sha256")
        if args.derive_order:
            if not args.expected_a298_order_sha256:
                parser.error("--derive-order requires --expected-a298-order-sha256")
            value = derive_order(
                expected_protocol_sha256=args.expected_protocol_sha256,
                expected_a298_order_sha256=args.expected_a298_order_sha256,
            )
            output = {
                "order": relative(ORDER),
                "order_sha256": file_sha256(ORDER),
                "evidence_stage": value["evidence_stage"],
                "portfolio_guarantee": value["portfolio_guarantee"],
            }
        else:
            if not args.expected_order_sha256:
                parser.error("--recover requires --expected-order-sha256")
            value = recover(
                expected_protocol_sha256=args.expected_protocol_sha256,
                expected_order_sha256=args.expected_order_sha256,
                swiftc=args.swiftc,
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
