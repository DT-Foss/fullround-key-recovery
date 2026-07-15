#!/usr/bin/env python3
"""A317: freeze a Fine-Coarse-Numeric prototype atlas before A313 reveal."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w44_multiview_operator_atlas_a317_design_v1.json"
COMMITMENT = CONFIGS / "chacha20_round20_w44_multiview_operator_atlas_a317_commitment_v1.json"
ORDER = RESULTS / "chacha20_round20_w44_multiview_operator_atlas_a317_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w44_multiview_operator_atlas_a317_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w44_multiview_operator_atlas_a317_v1.causal"
REPORT = RESULTS / "chacha20_round20_w44_multiview_operator_atlas_a317_v1.md"

A295_RESULT = RESULTS / "chacha20_round20_w24_fine_selected_channel_a295_v1.json"
A303_RESULT = RESULTS / "chacha20_round20_w32_dominance_pruned_companion_a303_v1.json"
A305_RESULT = RESULTS / "chacha20_round20_w43_a299_grouped_replay_a305_v1.json"
A309_RESULT = RESULTS / "chacha20_round20_w43_width_conditioned_band_portfolio_a309_v1.json"
A308_ORDER = RESULTS / "chacha20_round20_w44_calibrated_coarse_numeric_a308_order_v1.json"
A313_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_width_conditioned_fine_portfolio_a313.py"
A317_TEST = ROOT / "tests/test_chacha20_round20_w44_multiview_operator_atlas_a317.py"
A317_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w44_multiview_operator_atlas_a317.sh"

ATTEMPT_ID = "A317"
DESIGN_SHA256 = "4f17da4f0f300a3fbae60c229e018f4d19b36334c652c2edf6e0238caf65f4f1"
A295_RESULT_SHA256 = "93a591d75ab882345091c813f4ace877dc85ae37d748ed8f70c91e7323effc03"
A303_RESULT_SHA256 = "bc1878203ed1dc8dffab86e8cd1a85bd01fb12e09a1de6a86b29fd9d1ceae3fe"
A305_RESULT_SHA256 = "adbc8b879f09e03896699188d8141ac0164296eaf2ad688b6fb1036f2b1ac40e"
A309_RESULT_SHA256 = "73edd2514cb644330c481d9fe01293e3a0242aad5157ba7a598ac776fbfb8abd"
A308_ORDER_SHA256 = "d69b594a5c7a8ce17d7e5e8d5736006f76a3757a532aa6e4e84f2ca5d6ab2f0b"
A313_PROTOCOL_SHA256 = "dd5d59c52b8d5247d4a51b5a078f640577a2b8e3506fd2c7a46a8ca2a34c2f3c"
A313_ORDER_SHA256 = "2772df2531cc150d04002816661fb755c272f1afd5d699d5b802a2ff96eb42e3"
PROTOTYPES = [
    (2605, 202, 1006),
    (2366, 3113, 3197),
    (2114, 427, 3952),
    (3829, 1789, 3227),
]
METRICS = ("nearest_prototype_L1", "nearest_prototype_Linf", "nearest_prototype_squared_L2")
CELLS = 1 << 12


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A317 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A313 = load_module(A313_RUNNER, "a317_a313_common")
file_sha256 = A313.file_sha256
canonical_sha256 = A313.canonical_sha256
sha256 = A313.sha256
atomic_json = A313.atomic_json
atomic_bytes = A313.atomic_bytes
relative = A313.relative
path_from_ref = A313.path_from_ref
anchor = A313.anchor
DOTCAUSAL_SRC = A313.DOTCAUSAL_SRC


def _exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A317 {label} is not an exact 4,096-cell cover")
    return order


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A317 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    operator = design.get("operator_contract", {})
    boundary = design.get("information_boundary", {})
    rows = operator.get("confirmed_prototypes", [])
    observed = [tuple(int(value) for value in row["coordinates_one_based"]) for row in rows]
    if (
        design.get("schema")
        != "chacha20-round20-w44-multiview-operator-atlas-a317-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A313_recovery_is_running_before_any_A313_result_candidate_or_prefix_rank_exists"
        or observed != PROTOTYPES
        or tuple(operator.get("frozen_distance_views", [])) != METRICS
        or operator.get("primary_view") != "nearest_prototype_L1"
        or operator.get("selection_or_refit_after_A313_reveal") is not False
        or operator.get("candidate_execution_by_A317") is not False
        or boundary.get("A313_result_available_at_design_freeze") is not False
        or boundary.get("A313_candidate_available_at_design_freeze") is not False
        or boundary.get("A313_prefix_rank_available_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A313") != 0
    ):
        raise RuntimeError("A317 frozen design semantics differ")
    for key, expected in design["source_anchors"].items():
        if key.endswith("_path"):
            sha_key = key.removesuffix("_path") + "_sha256"
            anchor(path_from_ref(expected), design["source_anchors"][sha_key])
    _verify_prototypes()
    return design


def _verify_prototypes() -> None:
    sources = [
        (
            A295_RESULT,
            A295_RESULT_SHA256,
            ("A295_fine_selected_channel", "A294_coarse_Causal_Gray4", "numeric"),
        ),
        (
            A303_RESULT,
            A303_RESULT_SHA256,
            (
                "A298_fine_selected_channel_audit_only",
                "A297_coarse_high8_then_reflected_Gray4",
                "numeric_word0_prefix12",
            ),
        ),
        (
            A305_RESULT,
            A305_RESULT_SHA256,
            ("A299_fine_selected_channel", "A297_coarse_seed", "numeric"),
        ),
        (
            A309_RESULT,
            A309_RESULT_SHA256,
            (
                "A295_fine_selected_channel",
                "A297_coarse_high8_then_reflected_Gray4",
                "numeric_word0_prefix12",
            ),
        ),
    ]
    rows: list[tuple[int, int, int]] = []
    challenges: set[str] = set()
    for path, expected_sha, keys in sources:
        if file_sha256(path) != expected_sha:
            raise RuntimeError(f"A317 source hash differs: {path}")
        value = json.loads(path.read_bytes())
        confirmation = value.get("confirmation", {})
        confirmed = confirmation.get("all_blocks_match") is True or (
            confirmation.get("cross_implementation_blocks_match") is True
            and confirmation.get("independent_byte_reference_all_eight_blocks_match")
            is True
            and confirmation.get("root_operation_reference_all_eight_blocks_match")
            is True
        )
        if not confirmed:
            raise RuntimeError("A317 prototype source lacks independent confirmation")
        challenge = str(value["public_challenge_sha256"])
        if challenge in challenges:
            raise RuntimeError("A317 prototype challenges are not disjoint")
        challenges.add(challenge)
        rank_root = value["rank_analysis"]
        if path == A309_RESULT:
            rank_root = rank_root["A300_rank_analysis"]
        ranks = rank_root["prefix_ranks_one_based"]
        rows.append(tuple(int(ranks[key]) for key in keys))
    if rows != PROTOTYPES:
        raise RuntimeError(f"A317 confirmed prototype rows differ: {rows}")


def coordinate_source_orders() -> dict[str, list[int]]:
    if file_sha256(A313.ORDER) != A313_ORDER_SHA256:
        raise RuntimeError("A317 A313 order hash differs")
    if file_sha256(A313.PROTOCOL) != A313_PROTOCOL_SHA256:
        raise RuntimeError("A317 A313 protocol hash differs")
    if file_sha256(A308_ORDER) != A308_ORDER_SHA256:
        raise RuntimeError("A317 A308 order hash differs")
    a313 = json.loads(A313.ORDER.read_bytes())
    a308 = json.loads(A308_ORDER.read_bytes())
    if (
        a313.get("public_challenge_sha256")
        != json.loads(A313.PROTOCOL.read_bytes())["public_challenge_sha256"]
        or a313.get("information_boundary", {}).get(
            "A308_candidate_or_prefix_rank_available_at_materialization"
        )
        is not False
    ):
        raise RuntimeError("A317 target-blind source semantics differ")
    return {
        "fine": _exact_order(
            a313["component_orders"]["A312_fine_selected_channel"], "fine"
        ),
        "coarse": _exact_order(
            a308["component_orders"]["A297_coarse_high8_then_reflected_Gray4"],
            "coarse",
        ),
        "numeric": _exact_order(
            a308["component_orders"]["numeric_word0_prefix12"], "numeric"
        ),
        "A313_portfolio": _exact_order(a313["portfolio_order"], "A313 portfolio"),
    }


def _distance(point: tuple[int, int, int], prototype: tuple[int, int, int], metric: str) -> int:
    differences = [abs(left - right) for left, right in zip(point, prototype, strict=True)]
    if metric == "nearest_prototype_L1":
        return sum(differences)
    if metric == "nearest_prototype_Linf":
        return max(differences)
    if metric == "nearest_prototype_squared_L2":
        return sum(value * value for value in differences)
    raise ValueError(f"A317 unknown metric {metric}")


def atlas_order(
    *, fine: Sequence[int], coarse: Sequence[int], numeric: Sequence[int], metric: str
) -> list[int]:
    source = {
        "fine": _exact_order(fine, "fine source"),
        "coarse": _exact_order(coarse, "coarse source"),
        "numeric": _exact_order(numeric, "numeric source"),
    }
    ranks = {
        name: {cell: rank for rank, cell in enumerate(order, 1)}
        for name, order in source.items()
    }

    def key(cell: int) -> tuple[int, int, int, int, int, int]:
        point = (ranks["fine"][cell], ranks["coarse"][cell], ranks["numeric"][cell])
        distances = [_distance(point, prototype, metric) for prototype in PROTOTYPES]
        minimum = min(distances)
        return (
            minimum,
            distances.index(minimum),
            point[0],
            point[1],
            point[2],
            cell,
        )

    return _exact_order(sorted(range(CELLS), key=key), metric)


def _rank_vector(order: Sequence[int]) -> list[float]:
    result = [0.0] * CELLS
    for rank, cell in enumerate(_exact_order(order, "rank vector"), 1):
        result[cell] = float(rank)
    return result


def _correlation(left: Sequence[int], right: Sequence[int]) -> float:
    x = _rank_vector(left)
    y = _rank_vector(right)
    mean = (CELLS + 1) / 2.0
    numerator = sum((a - mean) * (b - mean) for a, b in zip(x, y, strict=True))
    denominator = math.sqrt(
        sum((a - mean) ** 2 for a in x) * sum((b - mean) ** 2 for b in y)
    )
    return numerator / denominator


def diversity_audit(orders: Mapping[str, Sequence[int]]) -> dict[str, Any]:
    names = list(orders)
    correlations: dict[str, float] = {}
    overlaps: dict[str, dict[str, int]] = {}
    for left_index, left_name in enumerate(names):
        for right_name in names[left_index + 1 :]:
            key = f"{left_name}__vs__{right_name}"
            correlations[key] = _correlation(orders[left_name], orders[right_name])
            overlaps[key] = {
                f"top_{limit}": len(
                    set(list(orders[left_name])[:limit])
                    & set(list(orders[right_name])[:limit])
                )
                for limit in (16, 64, 256, 1024)
            }
    return {
        "spearman_rank_correlations": correlations,
        "top_k_overlaps": overlaps,
        "operator_pairs": len(correlations),
        "target_labels_used": 0,
    }


def reconstruct() -> dict[str, Any]:
    design = load_design()
    source = coordinate_source_orders()
    atlas = {
        metric: atlas_order(
            fine=source["fine"],
            coarse=source["coarse"],
            numeric=source["numeric"],
            metric=metric,
        )
        for metric in METRICS
    }
    all_orders = {**atlas, **source}
    hashes = {
        name: sha256(b"".join(value.to_bytes(2, "big") for value in order))
        for name, order in all_orders.items()
    }
    return {
        "design": design,
        "public_challenge_sha256": json.loads(A313.ORDER.read_bytes())[
            "public_challenge_sha256"
        ],
        "source": source,
        "atlas": atlas,
        "hashes": hashes,
        "diversity": diversity_audit(all_orders),
    }


def materialize() -> dict[str, Any]:
    if any(path.exists() for path in (ORDER, COMMITMENT, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A317 artifacts already exist")
    if A313.RESULT.exists() or A313.CAUSAL.exists():
        raise RuntimeError("A317 must freeze before any A313 result exists")
    value = reconstruct()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w44-multiview-operator-atlas-a317-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "A317_TARGET_BLIND_MULTIVIEW_OPERATOR_ATLAS_FROZEN_BEFORE_A313_REVEAL",
        "design_sha256": DESIGN_SHA256,
        "public_challenge_sha256": value["public_challenge_sha256"],
        "prototype_coordinates_one_based": [list(row) for row in PROTOTYPES],
        "coordinate_source_orders": value["source"],
        "atlas_orders": value["atlas"],
        "order_uint16be_sha256": value["hashes"],
        "operator_diversity_audit": value["diversity"],
        "primary_view": "nearest_prototype_L1",
        "information_boundary": {
            **value["design"]["information_boundary"],
            "A313_result_available_at_materialization": False,
            "A313_candidate_or_prefix_rank_available_at_materialization": False,
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "prototype_coordinates_one_based": payload["prototype_coordinates_one_based"],
            "order_uint16be_sha256": payload["order_uint16be_sha256"],
            "operator_diversity_audit": payload["operator_diversity_audit"],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(ORDER, payload)
    order_sha = file_sha256(ORDER)
    commitment = {
        "schema": "chacha20-round20-w44-multiview-operator-atlas-a317-commitment-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A313_result_candidate_or_rank_exists",
        "design_sha256": DESIGN_SHA256,
        "order_sha256": order_sha,
        "public_challenge_sha256": payload["public_challenge_sha256"],
        "prototype_coordinates_one_based": payload["prototype_coordinates_one_based"],
        "order_uint16be_sha256": payload["order_uint16be_sha256"],
        "primary_view": payload["primary_view"],
        "A313_result_available_at_commitment": False,
        "candidate_or_rank_available_at_commitment": False,
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "order": {"path": relative(ORDER), "sha256": order_sha},
            "A313_protocol": {"path": relative(A313.PROTOCOL), "sha256": A313_PROTOCOL_SHA256},
            "A313_order": {"path": relative(A313.ORDER), "sha256": A313_ORDER_SHA256},
            "A308_order": {"path": relative(A308_ORDER), "sha256": A308_ORDER_SHA256},
            "runner": {"path": relative(Path(__file__)), "sha256": file_sha256(Path(__file__))},
            "test": {"path": relative(A317_TEST), "sha256": file_sha256(A317_TEST)},
            "reproducer": {"path": relative(A317_REPRO), "sha256": file_sha256(A317_REPRO)},
        },
    }
    atomic_json(COMMITMENT, commitment)
    return {
        "order": relative(ORDER),
        "order_sha256": order_sha,
        "commitment": relative(COMMITMENT),
        "commitment_sha256": file_sha256(COMMITMENT),
        "order_uint16be_sha256": payload["order_uint16be_sha256"],
        "operator_diversity_audit": payload["operator_diversity_audit"],
    }


def load_frozen(expected_commitment_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(COMMITMENT) != expected_commitment_sha256:
        raise RuntimeError("A317 commitment hash differs")
    commitment = json.loads(COMMITMENT.read_bytes())
    if (
        commitment.get("schema")
        != "chacha20-round20-w44-multiview-operator-atlas-a317-commitment-v1"
        or commitment.get("commitment_state")
        != "frozen_before_A313_result_candidate_or_rank_exists"
        or commitment.get("candidate_or_rank_available_at_commitment") is not False
    ):
        raise RuntimeError("A317 commitment semantics differ")
    for row in commitment["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    order = json.loads(ORDER.read_bytes())
    reconstructed = reconstruct()
    if (
        order.get("atlas_orders") != reconstructed["atlas"]
        or order.get("coordinate_source_orders") != reconstructed["source"]
        or order.get("order_uint16be_sha256") != reconstructed["hashes"]
    ):
        raise RuntimeError("A317 exact atlas reconstruction differs")
    return commitment, order


def rank_analysis(prefix: int, order: Mapping[str, Any]) -> dict[str, Any]:
    orders = {
        **order["atlas_orders"],
        "A313_three_arm_portfolio": order["coordinate_source_orders"]["A313_portfolio"],
        "fine": order["coordinate_source_orders"]["fine"],
        "coarse": order["coordinate_source_orders"]["coarse"],
        "numeric": order["coordinate_source_orders"]["numeric"],
    }
    ranks = {
        name: _exact_order(values, name).index(prefix) + 1
        for name, values in orders.items()
    }
    atlas_ranks = {name: ranks[name] for name in METRICS}
    best_atlas = min(atlas_ranks.values())
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "best_atlas_view": min(atlas_ranks, key=atlas_ranks.get),
        "best_atlas_rank_one_based": best_atlas,
        "primary_L1_gain_bits_vs_complete_prefix_domain": math.log2(
            CELLS / ranks["nearest_prototype_L1"]
        ),
        "counterfactual_only_no_duplicate_candidate_execution": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A317:prospective_multiview_W44_atlas_evaluated"
    writer = CausalWriter(api_id="a317w44")
    writer._rules = []
    writer.add_rule(
        name="confirmed_operator_coordinates_to_multiview_atlas",
        description="Four independently confirmed targets define typed Fine-Coarse-Numeric rank prototypes; the future target receives coordinates but no label.",
        pattern=["four_confirmed_operator_coordinate_prototypes", "A313_target_blind_operator_orders"],
        conclusion="A317_frozen_multiview_atlas",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_multiview_atlas_to_counterfactual_rank",
        description="After A313 independently confirms the target, its prefix is located in all three unchanged distance views without candidate re-execution.",
        pattern=["A317_frozen_multiview_atlas", "A313_confirmed_prefix"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A295_A303_A305_A309:confirmed_operator_coordinate_prototypes",
        mechanism="target_blind_Fine_Coarse_Numeric_nearest_prototype_atlas",
        outcome="A317:frozen_multiview_W44_order_panel",
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(payload["order_commitment"], sort_keys=True),
        evidence=json.dumps(payload["operator_diversity_audit"], sort_keys=True),
        domain="AI-native multiview ChaCha20-R20 search operator",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A317:frozen_multiview_W44_order_panel",
        mechanism="post_confirmation_rank_only_evaluation_without_duplicate_search",
        outcome=terminal,
        confidence=1.0,
        source=payload["A313_result_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="prospective multiview operator transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A295_A303_A305_A309:confirmed_operator_coordinate_prototypes",
        mechanism="materialized_multiview_commitment_evaluation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A317_multiview_atlas_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A317 prospective multiview W44 atlas",
        entities=[
            "A295_A303_A305_A309:confirmed_operator_coordinate_prototypes",
            "A317:frozen_multiview_W44_order_panel",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="selected_geometry_replication_or_online_prototype_update",
        confidence=1.0,
        suggested_queries=[
            "Which frozen multiview geometry best concentrates the unseen W44 prefix, and does appending it improve the next width?"
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
        reader.api_id != "a317w44"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A317 authentic Causal reopen gate failed")
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


def evaluate(*, expected_commitment_sha256: str, expected_a313_result_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A317 evaluation artifacts already exist")
    commitment, order = load_frozen(expected_commitment_sha256)
    if file_sha256(A313.RESULT) != expected_a313_result_sha256:
        raise RuntimeError("A317 A313 result hash differs")
    a313 = json.loads(A313.RESULT.read_bytes())
    if (
        a313.get("confirmation", {}).get("all_blocks_match") is not True
        or a313.get("public_challenge_sha256") != order["public_challenge_sha256"]
        or a313.get("discovery", {}).get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A317 requires the independently confirmed A313 target")
    ranks = rank_analysis(int(a313["discovery"]["prefix12"]), order)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w44-multiview-operator-atlas-a317-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_REVEAL_COMMITTED_MULTIVIEW_W44_ATLAS_EVALUATED",
        "design_sha256": DESIGN_SHA256,
        "commitment_sha256": expected_commitment_sha256,
        "order_sha256": commitment["order_sha256"],
        "A313_result_sha256": expected_a313_result_sha256,
        "public_challenge_sha256": order["public_challenge_sha256"],
        "order_commitment": commitment,
        "rank_analysis": ranks,
        "operator_diversity_audit": order["operator_diversity_audit"],
        "candidate_execution": {
            "performed_by_A317": False,
            "duplicate_candidate_execution": False,
            "confirmed_prefix_source": "A313_dual_independent_confirmation",
        },
        "information_boundary": order["information_boundary"],
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "commitment": {"path": relative(COMMITMENT), "sha256": expected_commitment_sha256},
            "order": {"path": relative(ORDER), "sha256": commitment["order_sha256"]},
            "A313_result": {"path": relative(A313.RESULT), "sha256": expected_a313_result_sha256},
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "order_commitment": commitment,
            "rank_analysis": ranks,
            "operator_diversity_audit": payload["operator_diversity_audit"],
            "candidate_execution": payload["candidate_execution"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    rank_rows = ranks["prefix_ranks_one_based"]
    atomic_bytes(
        REPORT,
        (
            "# A317 — Fine-Coarse-Numeric W44 operator atlas\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- L1 prototype rank: **{rank_rows['nearest_prototype_L1']} / 4,096**\n"
            f"- Linf prototype rank: **{rank_rows['nearest_prototype_Linf']} / 4,096**\n"
            f"- squared-L2 prototype rank: **{rank_rows['nearest_prototype_squared_L2']} / 4,096**\n"
            f"- A313 executed-order rank: **{rank_rows['A313_three_arm_portfolio']} / 4,096**\n"
            "- Exact multiview orders frozen before A313 reveal: **yes**\n"
            "- Duplicate candidate execution: **none**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "order_materialized": ORDER.exists(),
        "commitment_frozen": COMMITMENT.exists(),
        "A313_result_complete": A313.RESULT.exists(),
        "evaluation_complete": RESULT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--materialize", action="store_true")
    action.add_argument("--evaluate", action="store_true")
    parser.add_argument("--expected-commitment-sha256")
    parser.add_argument("--expected-a313-result-sha256")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.materialize:
        payload = materialize()
    else:
        if not args.expected_commitment_sha256 or not args.expected_a313_result_sha256:
            parser.error(
                "--evaluate requires --expected-commitment-sha256 and --expected-a313-result-sha256"
            )
        payload = evaluate(
            expected_commitment_sha256=args.expected_commitment_sha256,
            expected_a313_result_sha256=args.expected_a313_result_sha256,
        )
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
