#!/usr/bin/env python3
"""A318: precommit A317's multiview atlas on the unseen A314 W45 target."""

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

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w45_multiview_operator_atlas_a318_design_v1.json"
COMMITMENT = CONFIGS / "chacha20_round20_w45_multiview_operator_atlas_a318_commitment_v1.json"
ORDER = RESULTS / "chacha20_round20_w45_multiview_operator_atlas_a318_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w45_multiview_operator_atlas_a318_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w45_multiview_operator_atlas_a318_v1.causal"
REPORT = RESULTS / "chacha20_round20_w45_multiview_operator_atlas_a318_v1.md"

A314_RUNNER = RESEARCH / "experiments/chacha20_round20_w45_fine_band_recovery_a314.py"
A317_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_multiview_operator_atlas_a317.py"
A318_TEST = ROOT / "tests/test_chacha20_round20_w45_multiview_operator_atlas_a318.py"
A318_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w45_multiview_operator_atlas_a318.sh"

ATTEMPT_ID = "A318"
DESIGN_SHA256 = "75807a37fb87991fabb78ecfc7ab32068a452c27eeb5d04f3fe34a86de36324f"
A314_PROTOCOL_SHA256 = "17877a15624f7ab6fec1333c57260fa447d71d1112b9df5aa8219f8403968574"
A314_PREFLIGHT_SHA256 = "cfb5bacd6e6e17479260d8a2cacd2f9808afc632d82e31f80e8dc6ed2d4159a4"
A317_COMMITMENT_SHA256 = "e7b4be79a4a0902d631cfef6073818c7afdc89108b18b7b2b1e22e568d773240"
A317_ORDER_SHA256 = "3c3779cb26ace4e4361399969a89461eb69e443e8b4630f953cb0a8892f672a2"
CELLS = 1 << 12


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A318 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A314 = load_module(A314_RUNNER, "a318_a314_common")
A317 = load_module(A317_RUNNER, "a318_a317_common")
file_sha256 = A314.file_sha256
canonical_sha256 = A314.canonical_sha256
sha256 = A314.sha256
atomic_json = A314.atomic_json
atomic_bytes = A314.atomic_bytes
relative = A314.relative
path_from_ref = A314.path_from_ref
anchor = A314.anchor
DOTCAUSAL_SRC = A314.DOTCAUSAL_SRC


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A318 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    branch = design.get("conditional_branch_contract", {})
    operator = design.get("operator_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-w45-multiview-operator-atlas-a318-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A314_measurement_is_running_before_any_A314_order_model_candidate_or_prefix_rank_exists"
        or branch.get("branch_selected_only_by_A314_public_measurement_outcome") is not True
        or branch.get("branch_logic_frozen_before_A314_order_exists") is not True
        or operator.get("confirmed_prototypes") != [list(row) for row in A317.PROTOTYPES]
        or tuple(operator.get("frozen_distance_views", [])) != A317.METRICS
        or operator.get("primary_view") != "nearest_prototype_L1"
        or operator.get("selection_or_refit_after_A314_reveal") is not False
        or operator.get("candidate_execution_by_A318") is not False
        or boundary.get("A314_order_available_at_design_freeze") is not False
        or boundary.get("A314_result_available_at_design_freeze") is not False
        or boundary.get("A314_candidate_available_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A314") != 0
    ):
        raise RuntimeError("A318 frozen design semantics differ")
    for key, expected in design["source_anchors"].items():
        if key.endswith("_path"):
            sha_key = key.removesuffix("_path") + "_sha256"
            anchor(path_from_ref(expected), design["source_anchors"][sha_key])
    A317.load_frozen(A317_COMMITMENT_SHA256)
    return design


def derive_model_free_atlas(order_value: Mapping[str, Any]) -> dict[str, Any]:
    components = order_value.get("component_orders")
    if not isinstance(components, Mapping):
        raise ValueError("A318 requires the A314 model-free component orders")
    source = {
        "fine": A317._exact_order(components["fine_selected_channel"], "A314 fine"),  # noqa: SLF001
        "coarse": A317._exact_order(  # noqa: SLF001
            components["coarse_high8_then_reflected_Gray4"], "A314 coarse"
        ),
        "numeric": A317._exact_order(  # noqa: SLF001
            components["numeric_word0_prefix12"], "A314 numeric"
        ),
        "A314_portfolio": A317._exact_order(  # noqa: SLF001
            order_value["portfolio_order"], "A314 portfolio"
        ),
    }
    atlas = {
        metric: A317.atlas_order(
            fine=source["fine"],
            coarse=source["coarse"],
            numeric=source["numeric"],
            metric=metric,
        )
        for metric in A317.METRICS
    }
    all_orders = {**atlas, **source}
    hashes = {
        name: sha256(b"".join(value.to_bytes(2, "big") for value in values))
        for name, values in all_orders.items()
    }
    return {
        "source": source,
        "atlas": atlas,
        "hashes": hashes,
        "diversity": A317.diversity_audit(all_orders),
    }


def authentic_order_readback(order_value: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(A314.ORDER_CAUSAL), verify_integrity=True)
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
        or order_value.get("causal", {}).get("sha256") != file_sha256(A314.ORDER_CAUSAL)
    ):
        raise RuntimeError("A318 authentic A314 order Causal readback differs")
    return {
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "terminal_chain": all_rows[-1],
        "next_gap": reader._gaps[0],
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
    }


def load_a314_order(expected_a314_order_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    _protocol, _preflight, order_value = A314.load_order(
        A314_PROTOCOL_SHA256,
        A314_PREFLIGHT_SHA256,
        expected_a314_order_sha256,
    )
    return order_value, authentic_order_readback(order_value)


def materialize(*, expected_a314_order_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (ORDER, COMMITMENT, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A318 artifacts already exist")
    if A314.RESULT.exists() or A314.CAUSAL.exists():
        raise RuntimeError("A318 must freeze before any A314 result exists")
    design = load_design()
    order_value, readback = load_a314_order(expected_a314_order_sha256)
    direct = order_value.get("direct_symbolic_winner") is not None
    derived = None if direct else derive_model_free_atlas(order_value)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w45-multiview-operator-atlas-a318-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "A318_DIRECT_A314_SYMBOLIC_BRANCH_RETAINED_WITHOUT_RANK_COUNTERFACTUAL"
            if direct
            else "A318_TARGET_BLIND_MULTIVIEW_OPERATOR_ATLAS_FROZEN_BEFORE_A314_RECOVERY"
        ),
        "execution_branch": (
            "A314_direct_symbolic_model_no_rank_counterfactual_required"
            if direct
            else "A314_complete_model_free_field_to_multiview_W45_atlas"
        ),
        "design_sha256": DESIGN_SHA256,
        "A314_order_sha256": expected_a314_order_sha256,
        "public_challenge_sha256": order_value["public_challenge_sha256"],
        "prototype_coordinates_one_based": [list(row) for row in A317.PROTOTYPES],
        "authentic_A314_order_causal_readback": readback,
        "direct_symbolic_winner": order_value.get("direct_symbolic_winner"),
        "direct_symbolic_confirmation": order_value.get("confirmation"),
        "coordinate_source_orders": None if direct else derived["source"],
        "atlas_orders": None if direct else derived["atlas"],
        "order_uint16be_sha256": None if direct else derived["hashes"],
        "operator_diversity_audit": None if direct else derived["diversity"],
        "primary_view": "nearest_prototype_L1",
        "information_boundary": {
            **design["information_boundary"],
            "A314_outcome_used_only_to_select_predeclared_conditional_branch": True,
            "A314_result_available_at_materialization": False,
            "A314_candidate_or_prefix_rank_available_at_materialization": False,
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "A314_order_sha256": expected_a314_order_sha256,
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "execution_branch": payload["execution_branch"],
            "order_uint16be_sha256": payload["order_uint16be_sha256"],
            "operator_diversity_audit": payload["operator_diversity_audit"],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(ORDER, payload)
    order_sha = file_sha256(ORDER)
    commitment = {
        "schema": "chacha20-round20-w45-multiview-operator-atlas-a318-commitment-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_after_target_blind_A314_measurement_before_A314_recovery",
        "design_sha256": DESIGN_SHA256,
        "order_sha256": order_sha,
        "A314_order_sha256": expected_a314_order_sha256,
        "public_challenge_sha256": payload["public_challenge_sha256"],
        "execution_branch": payload["execution_branch"],
        "order_uint16be_sha256": payload["order_uint16be_sha256"],
        "primary_view": payload["primary_view"],
        "A314_result_available_at_commitment": False,
        "candidate_or_rank_available_at_commitment": False,
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "order": {"path": relative(ORDER), "sha256": order_sha},
            "A314_protocol": {"path": relative(A314.PROTOCOL), "sha256": A314_PROTOCOL_SHA256},
            "A314_preflight": {"path": relative(A314.PREFLIGHT), "sha256": A314_PREFLIGHT_SHA256},
            "A314_order": {"path": relative(A314.ORDER), "sha256": expected_a314_order_sha256},
            "A314_order_causal": {
                "path": relative(A314.ORDER_CAUSAL),
                "sha256": order_value["causal"]["sha256"],
            },
            "A317_commitment": {
                "path": relative(A317.COMMITMENT),
                "sha256": A317_COMMITMENT_SHA256,
            },
            "A317_order": {"path": relative(A317.ORDER), "sha256": A317_ORDER_SHA256},
            "runner": {"path": relative(Path(__file__)), "sha256": file_sha256(Path(__file__))},
            "test": {"path": relative(A318_TEST), "sha256": file_sha256(A318_TEST)},
            "reproducer": {"path": relative(A318_REPRO), "sha256": file_sha256(A318_REPRO)},
        },
    }
    atomic_json(COMMITMENT, commitment)
    return {
        "order": relative(ORDER),
        "order_sha256": order_sha,
        "commitment": relative(COMMITMENT),
        "commitment_sha256": file_sha256(COMMITMENT),
        "execution_branch": payload["execution_branch"],
        "order_uint16be_sha256": payload["order_uint16be_sha256"],
        "operator_diversity_audit": payload["operator_diversity_audit"],
    }


def load_frozen(expected_commitment_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(COMMITMENT) != expected_commitment_sha256:
        raise RuntimeError("A318 commitment hash differs")
    commitment = json.loads(COMMITMENT.read_bytes())
    if (
        commitment.get("schema")
        != "chacha20-round20-w45-multiview-operator-atlas-a318-commitment-v1"
        or commitment.get("commitment_state")
        != "frozen_after_target_blind_A314_measurement_before_A314_recovery"
        or commitment.get("candidate_or_rank_available_at_commitment") is not False
    ):
        raise RuntimeError("A318 commitment semantics differ")
    for row in commitment["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    order = json.loads(ORDER.read_bytes())
    a314_order, _readback = load_a314_order(commitment["A314_order_sha256"])
    direct = a314_order.get("direct_symbolic_winner") is not None
    if direct != (order["atlas_orders"] is None):
        raise RuntimeError("A318 conditional branch differs")
    if not direct:
        derived = derive_model_free_atlas(a314_order)
        if (
            order["atlas_orders"] != derived["atlas"]
            or order["coordinate_source_orders"] != derived["source"]
            or order["order_uint16be_sha256"] != derived["hashes"]
        ):
            raise RuntimeError("A318 exact atlas reconstruction differs")
    return commitment, order


def rank_analysis(prefix: int, order: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(order.get("atlas_orders"), Mapping):
        raise ValueError("A318 direct branch has no rank counterfactual")
    orders = {
        **order["atlas_orders"],
        "A314_three_arm_portfolio": order["coordinate_source_orders"]["A314_portfolio"],
        "fine": order["coordinate_source_orders"]["fine"],
        "coarse": order["coordinate_source_orders"]["coarse"],
        "numeric": order["coordinate_source_orders"]["numeric"],
    }
    ranks = {
        name: A317._exact_order(values, name).index(prefix) + 1  # noqa: SLF001
        for name, values in orders.items()
    }
    atlas_ranks = {name: ranks[name] for name in A317.METRICS}
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "best_atlas_view": min(atlas_ranks, key=atlas_ranks.get),
        "best_atlas_rank_one_based": min(atlas_ranks.values()),
        "primary_L1_gain_bits_vs_complete_prefix_domain": math.log2(
            CELLS / ranks["nearest_prototype_L1"]
        ),
        "counterfactual_only_no_duplicate_candidate_execution": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    direct = payload["rank_analysis"] is None
    terminal = "A318:prospective_multiview_W45_atlas_evaluated"
    writer = CausalWriter(api_id="a318w45")
    writer._rules = []
    writer.add_rule(
        name="A317_multiview_atlas_to_unseen_W45_conditional_branch",
        description="The exact prototypes, metrics and branch logic are frozen while A314 is still measuring its target-blind W45 field.",
        pattern=["A317_frozen_multiview_atlas", "A314_future_public_measurement"],
        conclusion="A318_frozen_W45_multiview_object",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="A318_object_to_post_confirmation_evaluation",
        description="A direct symbolic model is retained without duplicate work, or the independently confirmed A314 prefix is located in all unchanged atlas views.",
        pattern=["A318_frozen_W45_multiview_object", "A314_confirmed_W45_model"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A317:confirmed_multiview_prototypes_and_metrics",
        mechanism="pre_reveal_conditional_transfer_to_A314_W45_coordinates",
        outcome="A318:frozen_W45_multiview_object",
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(payload["order_commitment"], sort_keys=True),
        evidence=json.dumps(payload.get("operator_diversity_audit"), sort_keys=True),
        domain="AI-native multiview ChaCha20-R20 W45 search operator",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A318:frozen_W45_multiview_object",
        mechanism=(
            "direct_symbolic_branch_retained_without_duplicate_execution"
            if direct
            else "post_confirmation_rank_only_evaluation_without_duplicate_search"
        ),
        outcome=terminal,
        confidence=1.0,
        source=payload["A314_result_sha256"],
        quantification=json.dumps(
            payload["direct_symbolic_retention"] if direct else payload["rank_analysis"],
            sort_keys=True,
        ),
        evidence=payload["evidence_stage"],
        domain="prospective multiview width transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A317:confirmed_multiview_prototypes_and_metrics",
        mechanism="materialized_conditional_multiview_evaluation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A318_multiview_atlas_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A318 prospective multiview W45 atlas",
        entities=[
            "A317:confirmed_multiview_prototypes_and_metrics",
            "A318:frozen_W45_multiview_object",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="selected_geometry_replication_or_online_prototype_update",
        confidence=1.0,
        suggested_queries=[
            "Does one multiview geometry transfer across both unseen W44 and W45 targets strongly enough for direct execution next?"
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
        reader.api_id != "a318w45"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A318 authentic Causal reopen gate failed")
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


def evaluate(*, expected_commitment_sha256: str, expected_a314_result_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A318 evaluation artifacts already exist")
    commitment, order = load_frozen(expected_commitment_sha256)
    if file_sha256(A314.RESULT) != expected_a314_result_sha256:
        raise RuntimeError("A318 A314 result hash differs")
    a314 = json.loads(A314.RESULT.read_bytes())
    if (
        a314.get("confirmation", {}).get("all_blocks_match") is not True
        or a314.get("public_challenge_sha256") != order["public_challenge_sha256"]
    ):
        raise RuntimeError("A318 requires the independently confirmed A314 target")
    direct = order["atlas_orders"] is None
    ranks = None if direct else rank_analysis(int(a314["discovery"]["prefix12"]), order)
    direct_retention = (
        {
            "A314_direct_symbolic_model_retained": True,
            "duplicate_grouped_candidate_execution": False,
            "candidate": int(a314["discovery"]["candidate"]),
            "confirmation_all_blocks_match": True,
        }
        if direct
        else None
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w45-multiview-operator-atlas-a318-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "PRE_REVEAL_CONDITIONAL_DIRECT_SYMBOLIC_BRANCH_RETAINED"
            if direct
            else "PRE_REVEAL_COMMITTED_MULTIVIEW_W45_ATLAS_EVALUATED"
        ),
        "design_sha256": DESIGN_SHA256,
        "commitment_sha256": expected_commitment_sha256,
        "order_sha256": commitment["order_sha256"],
        "A314_result_sha256": expected_a314_result_sha256,
        "public_challenge_sha256": order["public_challenge_sha256"],
        "order_commitment": commitment,
        "rank_analysis": ranks,
        "direct_symbolic_retention": direct_retention,
        "operator_diversity_audit": order["operator_diversity_audit"],
        "candidate_execution": {
            "performed_by_A318": False,
            "duplicate_candidate_execution": False,
            "confirmed_model_source": "A314_dual_independent_confirmation",
        },
        "information_boundary": order["information_boundary"],
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "commitment": {"path": relative(COMMITMENT), "sha256": expected_commitment_sha256},
            "order": {"path": relative(ORDER), "sha256": commitment["order_sha256"]},
            "A314_result": {"path": relative(A314.RESULT), "sha256": expected_a314_result_sha256},
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "order_commitment": commitment,
            "rank_analysis": ranks,
            "direct_symbolic_retention": direct_retention,
            "operator_diversity_audit": payload["operator_diversity_audit"],
            "candidate_execution": payload["candidate_execution"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    if direct:
        body = (
            "- Frozen direct-symbolic branch: **retained**\n"
            "- Duplicate grouped candidate execution: **none**\n"
        )
    else:
        rank_rows = ranks["prefix_ranks_one_based"]
        body = (
            f"- L1 prototype rank: **{rank_rows['nearest_prototype_L1']} / 4,096**\n"
            f"- Linf prototype rank: **{rank_rows['nearest_prototype_Linf']} / 4,096**\n"
            f"- squared-L2 prototype rank: **{rank_rows['nearest_prototype_squared_L2']} / 4,096**\n"
            f"- A314 executed-order rank: **{rank_rows['A314_three_arm_portfolio']} / 4,096**\n"
        )
    atomic_bytes(
        REPORT,
        (
            "# A318 — Fine-Coarse-Numeric W45 operator atlas\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            + body
            + "- Conditional logic frozen before A314 measurement completed: **yes**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "A314_order_complete": A314.ORDER.exists(),
        "order_materialized": ORDER.exists(),
        "commitment_frozen": COMMITMENT.exists(),
        "A314_result_complete": A314.RESULT.exists(),
        "evaluation_complete": RESULT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--materialize", action="store_true")
    action.add_argument("--evaluate", action="store_true")
    parser.add_argument("--expected-a314-order-sha256")
    parser.add_argument("--expected-commitment-sha256")
    parser.add_argument("--expected-a314-result-sha256")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.materialize:
        if not args.expected_a314_order_sha256:
            parser.error("--materialize requires --expected-a314-order-sha256")
        payload = materialize(expected_a314_order_sha256=args.expected_a314_order_sha256)
    else:
        if not args.expected_commitment_sha256 or not args.expected_a314_result_sha256:
            parser.error(
                "--evaluate requires --expected-commitment-sha256 and --expected-a314-result-sha256"
            )
        payload = evaluate(
            expected_commitment_sha256=args.expected_commitment_sha256,
            expected_a314_result_sha256=args.expected_a314_result_sha256,
        )
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
