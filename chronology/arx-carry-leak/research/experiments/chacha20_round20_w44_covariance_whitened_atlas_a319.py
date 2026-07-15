#!/usr/bin/env python3
"""A319: freeze exact covariance-whitened rank geometry before A313 reveal."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import itertools
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from fractions import Fraction
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w44_covariance_whitened_atlas_a319_design_v1.json"
COMMITMENT = CONFIGS / "chacha20_round20_w44_covariance_whitened_atlas_a319_commitment_v1.json"
ORDER = RESULTS / "chacha20_round20_w44_covariance_whitened_atlas_a319_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w44_covariance_whitened_atlas_a319_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w44_covariance_whitened_atlas_a319_v1.causal"
REPORT = RESULTS / "chacha20_round20_w44_covariance_whitened_atlas_a319_v1.md"

A317_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_multiview_operator_atlas_a317.py"
A317_ORDER = RESULTS / "chacha20_round20_w44_multiview_operator_atlas_a317_order_v1.json"
A317_COMMITMENT = CONFIGS / "chacha20_round20_w44_multiview_operator_atlas_a317_commitment_v1.json"
A319_TEST = ROOT / "tests/test_chacha20_round20_w44_covariance_whitened_atlas_a319.py"
A319_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w44_covariance_whitened_atlas_a319.sh"

ATTEMPT_ID = "A319"
DESIGN_SHA256 = "5e5a4d3497104ad64a185b4f2d41572aa76f7f35dfb1c4a4fdf6dc3d5790ecb3"
A317_ORDER_SHA256 = "3c3779cb26ace4e4361399969a89461eb69e443e8b4630f953cb0a8892f672a2"
A317_COMMITMENT_SHA256 = "e7b4be79a4a0902d631cfef6073818c7afdc89108b18b7b2b1e22e568d773240"
A313_PROTOCOL_SHA256 = "dd5d59c52b8d5247d4a51b5a078f640577a2b8e3506fd2c7a46a8ca2a34c2f3c"
A313_ORDER_SHA256 = "2772df2531cc150d04002816661fb755c272f1afd5d699d5b802a2ff96eb42e3"
METRICS = (
    "nearest_exact_shrinkage_mahalanobis",
    "nearest_exact_diagonal_variance_L2",
    "nearest_exact_pairwise_median_scaled_L1",
)
CELLS = 1 << 12


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A319 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A317 = load_module(A317_RUNNER, "a319_a317_common")
A313 = A317.A313
file_sha256 = A317.file_sha256
canonical_sha256 = A317.canonical_sha256
sha256 = A317.sha256
atomic_json = A317.atomic_json
atomic_bytes = A317.atomic_bytes
relative = A317.relative
path_from_ref = A317.path_from_ref
anchor = A317.anchor
DOTCAUSAL_SRC = A317.DOTCAUSAL_SRC
PROTOTYPES = tuple(tuple(value for value in row) for row in A317.PROTOTYPES)


def _fraction(value: Fraction) -> str:
    return f"{value.numerator}/{value.denominator}"


def _fraction_matrix(values: Sequence[Sequence[Fraction]]) -> list[list[str]]:
    return [[_fraction(value) for value in row] for row in values]


def _exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A319 {label} is not an exact 4,096-cell cover")
    return order


def _inverse(matrix: Sequence[Sequence[Fraction]]) -> list[list[Fraction]]:
    size = len(matrix)
    augmented = [
        [Fraction(value) for value in row]
        + [Fraction(int(column == index)) for column in range(size)]
        for index, row in enumerate(matrix)
    ]
    for column in range(size):
        pivot = next(
            (row for row in range(column, size) if augmented[row][column] != 0),
            None,
        )
        if pivot is None:
            raise RuntimeError("A319 covariance matrix is singular")
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        divisor = augmented[column][column]
        augmented[column] = [value / divisor for value in augmented[column]]
        for row in range(size):
            if row == column:
                continue
            factor = augmented[row][column]
            augmented[row] = [
                left - factor * right
                for left, right in zip(augmented[row], augmented[column], strict=True)
            ]
    return [row[size:] for row in augmented]


def exact_geometry() -> dict[str, Any]:
    dimensions = len(PROTOTYPES[0])
    count = len(PROTOTYPES)
    means = [
        sum(Fraction(row[column]) for row in PROTOTYPES) / count
        for column in range(dimensions)
    ]
    covariance = [
        [
            sum(
                (Fraction(row[left]) - means[left])
                * (Fraction(row[right]) - means[right])
                for row in PROTOTYPES
            )
            / (count - 1)
            for right in range(dimensions)
        ]
        for left in range(dimensions)
    ]
    trace = sum(covariance[index][index] for index in range(dimensions))
    ridge = trace / 48
    shrunk = [
        [
            (
                covariance[left][right]
                if left == right
                else covariance[left][right] / 2
            )
            + (ridge if left == right else 0)
            for right in range(dimensions)
        ]
        for left in range(dimensions)
    ]
    inverse = _inverse(shrunk)
    diagonal = [covariance[index][index] + ridge for index in range(dimensions)]
    robust_scales: list[Fraction] = []
    for column in range(dimensions):
        distances = sorted(
            abs(PROTOTYPES[left][column] - PROTOTYPES[right][column])
            for left, right in itertools.combinations(range(count), 2)
        )
        scale = Fraction(distances[2] + distances[3], 2)
        if scale <= 0:
            raise RuntimeError("A319 robust coordinate scale is not positive")
        robust_scales.append(scale)
    leading_minor_two = shrunk[0][0] * shrunk[1][1] - shrunk[0][1] * shrunk[1][0]
    determinant = (
        shrunk[0][0]
        * (shrunk[1][1] * shrunk[2][2] - shrunk[1][2] * shrunk[2][1])
        - shrunk[0][1]
        * (shrunk[1][0] * shrunk[2][2] - shrunk[1][2] * shrunk[2][0])
        + shrunk[0][2]
        * (shrunk[1][0] * shrunk[2][1] - shrunk[1][1] * shrunk[2][0])
    )
    if shrunk[0][0] <= 0 or leading_minor_two <= 0 or determinant <= 0:
        raise RuntimeError("A319 regularized covariance is not positive definite")
    return {
        "means": means,
        "sample_covariance": covariance,
        "ridge": ridge,
        "shrunk_covariance": shrunk,
        "inverse_shrunk_covariance": inverse,
        "diagonal_variances_with_ridge": diagonal,
        "pairwise_median_scales": robust_scales,
        "positive_definite_certificate": [
            shrunk[0][0],
            leading_minor_two,
            determinant,
        ],
    }


def geometry_json(geometry: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "prototype_mean": [_fraction(value) for value in geometry["means"]],
        "sample_covariance": _fraction_matrix(geometry["sample_covariance"]),
        "fixed_shrinkage_weight": "1/2",
        "fixed_identity_ridge": _fraction(geometry["ridge"]),
        "shrunk_covariance": _fraction_matrix(geometry["shrunk_covariance"]),
        "inverse_shrunk_covariance": _fraction_matrix(
            geometry["inverse_shrunk_covariance"]
        ),
        "diagonal_variances_with_ridge": [
            _fraction(value) for value in geometry["diagonal_variances_with_ridge"]
        ],
        "pairwise_median_scales": [
            _fraction(value) for value in geometry["pairwise_median_scales"]
        ],
        "positive_definite_leading_principal_minors": [
            _fraction(value) for value in geometry["positive_definite_certificate"]
        ],
        "arithmetic": "exact_rational",
    }


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A319 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    operator = design.get("operator_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-w44-covariance-whitened-atlas-a319-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A313_recovery_is_running_before_any_A313_result_candidate_or_prefix_rank_exists"
        or tuple(operator.get("frozen_views", [])) != METRICS
        or operator.get("primary_view") != METRICS[0]
        or operator.get("selection_or_refit_after_A313_reveal") is not False
        or operator.get("candidate_execution_by_A319") is not False
        or boundary.get("A313_result_available_at_design_freeze") is not False
        or boundary.get("A313_candidate_available_at_design_freeze") is not False
        or boundary.get("A313_prefix_rank_available_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A313") != 0
    ):
        raise RuntimeError("A319 frozen design semantics differ")
    anchors = design["source_anchors"]
    for key, value in anchors.items():
        if key.endswith("_path"):
            anchor(path_from_ref(value), anchors[key.removesuffix("_path") + "_sha256"])
    A317._verify_prototypes()  # noqa: SLF001
    return design


def _quadratic(delta: Sequence[Fraction], matrix: Sequence[Sequence[Fraction]]) -> Fraction:
    return sum(
        delta[left] * matrix[left][right] * delta[right]
        for left in range(3)
        for right in range(3)
    )


def _distance(
    point: tuple[int, int, int],
    prototype: tuple[int, int, int],
    metric: str,
    geometry: Mapping[str, Any],
) -> Fraction:
    delta = [Fraction(left - right) for left, right in zip(point, prototype, strict=True)]
    if metric == METRICS[0]:
        return _quadratic(delta, geometry["inverse_shrunk_covariance"])
    if metric == METRICS[1]:
        return sum(
            value * value / variance
            for value, variance in zip(
                delta, geometry["diagonal_variances_with_ridge"], strict=True
            )
        )
    if metric == METRICS[2]:
        return sum(
            abs(value) / scale
            for value, scale in zip(
                delta, geometry["pairwise_median_scales"], strict=True
            )
        )
    raise ValueError(f"A319 unknown metric {metric}")


def whitened_order(
    *,
    fine: Sequence[int],
    coarse: Sequence[int],
    numeric: Sequence[int],
    metric: str,
    geometry: Mapping[str, Any] | None = None,
) -> list[int]:
    exact_geometry_value = exact_geometry() if geometry is None else geometry
    source = {
        "fine": _exact_order(fine, "fine source"),
        "coarse": _exact_order(coarse, "coarse source"),
        "numeric": _exact_order(numeric, "numeric source"),
    }
    ranks = {
        name: {cell: rank for rank, cell in enumerate(order, 1)}
        for name, order in source.items()
    }

    def key(cell: int) -> tuple[Fraction, int, int, int, int, int]:
        point = (ranks["fine"][cell], ranks["coarse"][cell], ranks["numeric"][cell])
        distances = [
            _distance(point, prototype, metric, exact_geometry_value)
            for prototype in PROTOTYPES
        ]
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


def reconstruct() -> dict[str, Any]:
    design = load_design()
    if file_sha256(A317_ORDER) != A317_ORDER_SHA256:
        raise RuntimeError("A319 A317 order hash differs")
    if file_sha256(A317_COMMITMENT) != A317_COMMITMENT_SHA256:
        raise RuntimeError("A319 A317 commitment hash differs")
    a317 = json.loads(A317_ORDER.read_bytes())
    source = A317.coordinate_source_orders()
    geometry = exact_geometry()
    orders = {
        metric: whitened_order(
            fine=source["fine"],
            coarse=source["coarse"],
            numeric=source["numeric"],
            metric=metric,
            geometry=geometry,
        )
        for metric in METRICS
    }
    comparison = {
        **orders,
        **a317["atlas_orders"],
        **source,
    }
    hashes = {
        name: sha256(b"".join(value.to_bytes(2, "big") for value in order))
        for name, order in comparison.items()
    }
    return {
        "design": design,
        "public_challenge_sha256": a317["public_challenge_sha256"],
        "source": source,
        "orders": orders,
        "geometry": geometry_json(geometry),
        "hashes": hashes,
        "diversity": A317.diversity_audit(comparison),
    }


def materialize() -> dict[str, Any]:
    if any(path.exists() for path in (ORDER, COMMITMENT, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A319 artifacts already exist")
    if A313.RESULT.exists() or A313.CAUSAL.exists():
        raise RuntimeError("A319 must freeze before any A313 result exists")
    value = reconstruct()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w44-covariance-whitened-atlas-a319-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "A319_EXACT_COVARIANCE_WHITENED_ATLAS_FROZEN_BEFORE_A313_REVEAL",
        "design_sha256": DESIGN_SHA256,
        "public_challenge_sha256": value["public_challenge_sha256"],
        "prototype_coordinates_one_based": [list(row) for row in PROTOTYPES],
        "exact_geometry": value["geometry"],
        "whitened_orders": value["orders"],
        "order_uint16be_sha256": value["hashes"],
        "operator_diversity_audit": value["diversity"],
        "primary_view": METRICS[0],
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
            "exact_geometry": payload["exact_geometry"],
            "order_uint16be_sha256": payload["order_uint16be_sha256"],
            "operator_diversity_audit": payload["operator_diversity_audit"],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(ORDER, payload)
    order_sha = file_sha256(ORDER)
    commitment = {
        "schema": "chacha20-round20-w44-covariance-whitened-atlas-a319-commitment-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A313_result_candidate_or_rank_exists",
        "design_sha256": DESIGN_SHA256,
        "order_sha256": order_sha,
        "public_challenge_sha256": payload["public_challenge_sha256"],
        "prototype_coordinates_one_based": payload["prototype_coordinates_one_based"],
        "exact_geometry": payload["exact_geometry"],
        "order_uint16be_sha256": payload["order_uint16be_sha256"],
        "primary_view": payload["primary_view"],
        "A313_result_available_at_commitment": False,
        "candidate_or_rank_available_at_commitment": False,
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "order": {"path": relative(ORDER), "sha256": order_sha},
            "A317_order": {"path": relative(A317_ORDER), "sha256": A317_ORDER_SHA256},
            "A317_commitment": {
                "path": relative(A317_COMMITMENT),
                "sha256": A317_COMMITMENT_SHA256,
            },
            "A313_protocol": {
                "path": relative(A313.PROTOCOL),
                "sha256": A313_PROTOCOL_SHA256,
            },
            "A313_order": {"path": relative(A313.ORDER), "sha256": A313_ORDER_SHA256},
            "runner": {"path": relative(Path(__file__)), "sha256": file_sha256(Path(__file__))},
            "test": {"path": relative(A319_TEST), "sha256": file_sha256(A319_TEST)},
            "reproducer": {"path": relative(A319_REPRO), "sha256": file_sha256(A319_REPRO)},
        },
    }
    atomic_json(COMMITMENT, commitment)
    return {
        "order": relative(ORDER),
        "order_sha256": order_sha,
        "commitment": relative(COMMITMENT),
        "commitment_sha256": file_sha256(COMMITMENT),
        "order_uint16be_sha256": {
            name: payload["order_uint16be_sha256"][name] for name in METRICS
        },
        "primary_view_correlations": {
            key: value
            for key, value in payload["operator_diversity_audit"][
                "spearman_rank_correlations"
            ].items()
            if key.startswith(METRICS[0] + "__vs__")
        },
    }


def load_frozen(expected_commitment_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(COMMITMENT) != expected_commitment_sha256:
        raise RuntimeError("A319 commitment hash differs")
    commitment = json.loads(COMMITMENT.read_bytes())
    if (
        commitment.get("schema")
        != "chacha20-round20-w44-covariance-whitened-atlas-a319-commitment-v1"
        or commitment.get("commitment_state")
        != "frozen_before_A313_result_candidate_or_rank_exists"
        or commitment.get("candidate_or_rank_available_at_commitment") is not False
    ):
        raise RuntimeError("A319 commitment semantics differ")
    for row in commitment["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    order = json.loads(ORDER.read_bytes())
    reconstructed = reconstruct()
    if (
        order.get("whitened_orders") != reconstructed["orders"]
        or order.get("exact_geometry") != reconstructed["geometry"]
        or order.get("order_uint16be_sha256") != reconstructed["hashes"]
    ):
        raise RuntimeError("A319 exact reconstruction differs")
    return commitment, order


def rank_analysis(prefix: int, order: Mapping[str, Any]) -> dict[str, Any]:
    source = A317.coordinate_source_orders()
    a317 = json.loads(A317_ORDER.read_bytes())
    orders = {
        **order["whitened_orders"],
        **a317["atlas_orders"],
        "A313_three_arm_portfolio": source["A313_portfolio"],
        "fine": source["fine"],
        "coarse": source["coarse"],
        "numeric": source["numeric"],
    }
    ranks = {
        name: _exact_order(values, name).index(prefix) + 1
        for name, values in orders.items()
    }
    whitened = {name: ranks[name] for name in METRICS}
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "best_whitened_view": min(whitened, key=whitened.get),
        "best_whitened_rank_one_based": min(whitened.values()),
        "primary_gain_bits_vs_complete_prefix_domain": math.log2(
            CELLS / ranks[METRICS[0]]
        ),
        "counterfactual_only_no_duplicate_candidate_execution": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A319:prospective_covariance_whitened_W44_atlas_evaluated"
    writer = CausalWriter(api_id="a319w44")
    writer._rules = []
    writer.add_rule(
        name="confirmed_rank_covariance_to_exact_whitened_atlas",
        description="The four confirmed rank triplets fix an exact regularized covariance and three target-blind normalized distance operators.",
        pattern=["four_confirmed_operator_coordinate_prototypes", "A313_target_blind_operator_orders"],
        conclusion="A319_exact_whitened_atlas",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_whitened_atlas_to_counterfactual_rank",
        description="Independent A313 confirmation locates the target in every pre-reveal exact-rational view without candidate re-execution.",
        pattern=["A319_exact_whitened_atlas", "A313_confirmed_prefix"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A295_A303_A305_A309:confirmed_operator_coordinate_covariance",
        mechanism="exact_shrinkage_whitening_and_robust_coordinate_scaling",
        outcome="A319:frozen_covariance_whitened_W44_order_panel",
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(payload["exact_geometry"], sort_keys=True),
        evidence=json.dumps(payload["operator_diversity_audit"], sort_keys=True),
        domain="AI-native normalized ChaCha20-R20 search geometry",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A319:frozen_covariance_whitened_W44_order_panel",
        mechanism="post_confirmation_rank_only_evaluation_without_duplicate_search",
        outcome=terminal,
        confidence=1.0,
        source=payload["A313_result_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="prospective normalized multiview transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A295_A303_A305_A309:confirmed_operator_coordinate_covariance",
        mechanism="materialized_exact_whitening_commitment_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A319_covariance_whitened_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A319 prospective covariance-whitened W44 atlas",
        entities=[
            "A295_A303_A305_A309:confirmed_operator_coordinate_covariance",
            "A319:frozen_covariance_whitened_W44_order_panel",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="unchanged_whitened_geometry_replication_or_online_update",
        confidence=1.0,
        suggested_queries=[
            "Does the exact covariance-normalized geometry concentrate both unseen W44 and W45 targets under the unchanged parameterization?"
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
        reader.api_id != "a319w44"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A319 authentic Causal reopen gate failed")
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
        raise FileExistsError("A319 evaluation artifacts already exist")
    commitment, order = load_frozen(expected_commitment_sha256)
    if file_sha256(A313.RESULT) != expected_a313_result_sha256:
        raise RuntimeError("A319 A313 result hash differs")
    a313 = json.loads(A313.RESULT.read_bytes())
    if (
        a313.get("confirmation", {}).get("all_blocks_match") is not True
        or a313.get("public_challenge_sha256") != order["public_challenge_sha256"]
        or a313.get("discovery", {}).get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A319 requires the independently confirmed A313 target")
    ranks = rank_analysis(int(a313["discovery"]["prefix12"]), order)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w44-covariance-whitened-atlas-a319-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_REVEAL_COMMITTED_EXACT_COVARIANCE_WHITENED_W44_ATLAS_EVALUATED",
        "design_sha256": DESIGN_SHA256,
        "commitment_sha256": expected_commitment_sha256,
        "order_sha256": commitment["order_sha256"],
        "A313_result_sha256": expected_a313_result_sha256,
        "public_challenge_sha256": order["public_challenge_sha256"],
        "exact_geometry": order["exact_geometry"],
        "rank_analysis": ranks,
        "operator_diversity_audit": order["operator_diversity_audit"],
        "candidate_execution": {
            "performed_by_A319": False,
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
            "exact_geometry": payload["exact_geometry"],
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
            "# A319 — exact covariance-whitened W44 operator atlas\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Shrinkage-Mahalanobis rank: **{rank_rows[METRICS[0]]} / 4,096**\n"
            f"- Diagonal-variance L2 rank: **{rank_rows[METRICS[1]]} / 4,096**\n"
            f"- Pairwise-median scaled L1 rank: **{rank_rows[METRICS[2]]} / 4,096**\n"
            f"- A313 executed-order rank: **{rank_rows['A313_three_arm_portfolio']} / 4,096**\n"
            "- Exact-rational geometry frozen before A313 reveal: **yes**\n"
            "- Duplicate candidate execution: **none**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    reconstructed = reconstruct()
    response: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "A313_result_exists": A313.RESULT.exists(),
        "order_exists": ORDER.exists(),
        "commitment_exists": COMMITMENT.exists(),
        "result_exists": RESULT.exists(),
        "exact_geometry": reconstructed["geometry"],
    }
    if ORDER.exists():
        response["order_sha256"] = file_sha256(ORDER)
    if COMMITMENT.exists():
        response["commitment_sha256"] = file_sha256(COMMITMENT)
    if RESULT.exists():
        response["result_sha256"] = file_sha256(RESULT)
        response["rank_analysis"] = json.loads(RESULT.read_bytes())["rank_analysis"]
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--materialize", action="store_true")
    mode.add_argument("--evaluate", action="store_true")
    mode.add_argument("--analyze", action="store_true")
    parser.add_argument("--expected-commitment-sha256")
    parser.add_argument("--expected-a313-result-sha256")
    args = parser.parse_args()
    if args.materialize:
        payload = materialize()
    elif args.evaluate:
        if not args.expected_commitment_sha256 or not args.expected_a313_result_sha256:
            parser.error("--evaluate requires both expected SHA-256 arguments")
        payload = evaluate(
            expected_commitment_sha256=args.expected_commitment_sha256,
            expected_a313_result_sha256=args.expected_a313_result_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
