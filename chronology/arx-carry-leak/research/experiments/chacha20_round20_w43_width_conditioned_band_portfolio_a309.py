#!/usr/bin/env python3
"""A309: prospective width-conditioned band reader for sealed ChaCha20 W43."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from fractions import Fraction
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"

DESIGN = (
    CONFIGS
    / "chacha20_round20_w43_width_conditioned_band_portfolio_a309_design_v1.json"
)
A300_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w43_three_operator_portfolio_a300.py"
)
A304_RUNNER = RESEARCH / "experiments/chacha20_round20_w43_grouped_engine_a304.py"
A309_TEST = (
    ROOT / "tests/test_chacha20_round20_w43_width_conditioned_band_portfolio_a309.py"
)
A309_REPRO = (
    ROOT / "scripts/reproduce_chacha20_round20_w43_width_conditioned_band_portfolio_a309.sh"
)

PROTOCOL = (
    CONFIGS / "chacha20_round20_w43_width_conditioned_band_portfolio_a309_v1.json"
)
ORDER = (
    RESULTS
    / "chacha20_round20_w43_width_conditioned_band_portfolio_a309_order_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w43_width_conditioned_band_portfolio_a309_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = (
    REPORTS / "CHACHA20_ROUND20_W43_WIDTH_CONDITIONED_BAND_PORTFOLIO_A309_V1.md"
)

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A309"
DESIGN_SHA256 = "5dde7d22eac9b01a706d46366e13653db61826ca29710c6d9b545d5ea2443552"
A300_PROTOCOL_SHA256 = "d132e818e598458f0ac2aa53d8032c7c4dc5f2ffed5d863410b76c10c5b43307"
A300_PREFLIGHT_SHA256 = "5479756d446f2a2349e780844a8a8373dde328b7bb448ce85271bf116b46db2d"
A300_ORDER_SHA256 = "76af63fd14613520bda54316e242c16e4530af22ddb2ec9e5a7a6e6df5afefd1"
A304_PROTOCOL_SHA256 = "2b2ea9febb74397437e0c3a772463d9ed46093461d6cc848aa6c77d2c38e7168"
A304_QUALIFICATION_SHA256 = (
    "a9a92f4f8ecceede5dee44a429352ee4bc55e581531145fb5bb8a9606bc96c9c"
)
WIDTH = 43
CELLS = 1 << 12
GROUP_SIZE = 1 << 31
DOMAIN_SIZE = 1 << WIDTH


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A309 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A300 = load_module(A300_RUNNER, "a309_a300_common")
A304 = load_module(A304_RUNNER, "a309_a304_common")
W43 = A300.A299.W43
sha256 = A300.sha256
file_sha256 = A300.file_sha256
canonical_sha256 = A300.canonical_sha256
atomic_bytes = A300.atomic_bytes
atomic_json = A300.atomic_json
relative = A300.relative
path_from_ref = A300.path_from_ref
anchor = A300.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A309 prospective design hash differs")
    value = json.loads(DESIGN.read_bytes())
    operator = value.get("operator_contract", {})
    boundary = value.get("information_boundary", {})
    fit = operator.get("fit", {})
    if (
        value.get("schema")
        != "chacha20-round20-w43-width-conditioned-band-portfolio-a309-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or fit.get("predicted_W43_fine_rank_nearest_integer") != 2105
        or operator.get("merge")
        != "rank_synchronous_round_robin_first_occurrence_band_then_A300_baseline"
        or operator.get("training_fit_is_not_recomputed_after_A300_reveal")
        is not True
        or boundary.get("A300_candidate_available_at_freeze") is not False
        or boundary.get("A300_prefix_rank_available_at_freeze") is not False
        or boundary.get("A300_target_assignment_available_at_freeze") is not False
        or boundary.get("A302_result_available_at_freeze") is not False
        or boundary.get("disjoint_confirmed_training_labels_used") != 3
        or boundary.get("target_labels_used_from_A300") != 0
    ):
        raise RuntimeError("A309 prospective design semantics differ")
    sources = value["source_anchors"]
    for path_key, sha_key in (
        ("A295_causal_path", "A295_causal_sha256"),
        ("A295_result_path", "A295_result_sha256"),
        ("A303_causal_path", "A303_causal_sha256"),
        ("A303_result_path", "A303_result_sha256"),
        ("A305_causal_path", "A305_causal_sha256"),
        ("A305_result_path", "A305_result_sha256"),
        ("A300_protocol_path", "A300_protocol_sha256"),
        ("A300_preflight_path", "A300_preflight_sha256"),
        ("A300_order_path", "A300_order_sha256"),
        ("A300_runner_path", "A300_runner_sha256"),
        ("A304_qualification_path", "A304_qualification_sha256"),
        ("A304_runner_path", "A304_runner_sha256"),
        ("CausalReader_path", "CausalReader_sha256"),
    ):
        anchor(path_from_ref(sources[path_key]), sources[sha_key])
    return value


def exact_linear_fit(rows: Sequence[Mapping[str, int]]) -> dict[str, Any]:
    if len(rows) != 3:
        raise ValueError("A309 requires exactly three disjoint training rows")
    widths = [Fraction(int(row["unknown_key_bits"])) for row in rows]
    ranks = [Fraction(int(row["confirmed_fine_rank_one_based"])) for row in rows]
    x_mean = sum(widths) / len(widths)
    y_mean = sum(ranks) / len(ranks)
    denominator = sum((value - x_mean) ** 2 for value in widths)
    if denominator == 0:
        raise ValueError("A309 width calibration is singular")
    slope = sum(
        (width - x_mean) * (rank - y_mean)
        for width, rank in zip(widths, ranks, strict=True)
    ) / denominator
    intercept = y_mean - slope * x_mean
    predicted = slope * WIDTH + intercept
    center = round(predicted)
    residuals = [rank - (slope * width + intercept) for width, rank in zip(widths, ranks, strict=True)]

    leave_one_out: list[dict[str, Any]] = []
    for held_out in range(len(rows)):
        retained = [index for index in range(len(rows)) if index != held_out]
        x0, x1 = (widths[index] for index in retained)
        y0, y1 = (ranks[index] for index in retained)
        local_slope = (y1 - y0) / (x1 - x0)
        local_intercept = y0 - local_slope * x0
        local_prediction = local_slope * widths[held_out] + local_intercept
        error = ranks[held_out] - local_prediction
        leave_one_out.append(
            {
                "attempt_id": rows[held_out]["attempt_id"],
                "predicted_rank": float(local_prediction),
                "signed_error": float(error),
                "absolute_error": float(abs(error)),
            }
        )
    return {
        "slope": {
            "numerator": slope.numerator,
            "denominator": slope.denominator,
            "decimal": float(slope),
        },
        "intercept": {
            "numerator": intercept.numerator,
            "denominator": intercept.denominator,
            "decimal": float(intercept),
        },
        "predicted_W43_rank": {
            "numerator": predicted.numerator,
            "denominator": predicted.denominator,
            "decimal": float(predicted),
            "nearest_integer": center,
        },
        "training_residuals": [float(value) for value in residuals],
        "maximum_absolute_training_residual": max(float(abs(value)) for value in residuals),
        "leave_one_out": leave_one_out,
        "maximum_absolute_leave_one_out_error": max(
            row["absolute_error"] for row in leave_one_out
        ),
    }


def band_order(*, fine: Sequence[int], center: int) -> list[int]:
    values = [int(value) for value in fine]
    if len(values) != CELLS or set(values) != set(range(CELLS)):
        raise ValueError("A309 fine order is not an exact 4096-cell cover")
    if not 1 <= center <= CELLS:
        raise ValueError("A309 predicted fine rank lies outside the cell field")
    ranks = {cell: rank for rank, cell in enumerate(values, 1)}
    result = sorted(
        range(CELLS),
        key=lambda cell: (abs(ranks[cell] - center), ranks[cell]),
    )
    if len(result) != CELLS or set(result) != set(range(CELLS)):
        raise RuntimeError("A309 band order is not an exact cell cover")
    return result


def two_arm_portfolio(*, band: Sequence[int], baseline: Sequence[int]) -> list[int]:
    orders = [[int(value) for value in band], [int(value) for value in baseline]]
    if any(len(order) != CELLS or set(order) != set(range(CELLS)) for order in orders):
        raise ValueError("A309 component order is not an exact cell cover")
    result: list[int] = []
    seen: set[int] = set()
    for rank in range(CELLS):
        for order in orders:
            value = order[rank]
            if value not in seen:
                seen.add(value)
                result.append(value)
    if len(result) != CELLS or set(result) != set(range(CELLS)):
        raise RuntimeError("A309 portfolio order is not an exact cell cover")
    return result


def portfolio_guarantee(
    *, portfolio: Sequence[int], band: Sequence[int], baseline: Sequence[int]
) -> dict[str, Any]:
    ranks = {
        "portfolio": {int(value): rank for rank, value in enumerate(portfolio, 1)},
        "band": {int(value): rank for rank, value in enumerate(band, 1)},
        "baseline": {int(value): rank for rank, value in enumerate(baseline, 1)},
    }
    worst_factor = 0.0
    worst_cell = 0
    for cell in range(CELLS):
        best = min(ranks["band"][cell], ranks["baseline"][cell])
        observed = ranks["portfolio"][cell]
        if observed > 2 * best:
            raise RuntimeError("A309 factor-two portfolio guarantee failed")
        factor = observed / best
        if factor > worst_factor:
            worst_factor = factor
            worst_cell = cell
    return {
        "statement": "R_A309 <= 2 * min(R_width_band, R_A300_baseline)",
        "checked_prefix_cells": CELLS,
        "violations": 0,
        "maximum_observed_regret_factor": worst_factor,
        "maximum_observed_regret_bits": math.log2(worst_factor),
        "maximum_observed_regret_cell": worst_cell,
        "frozen_worst_case_bound_factor": 2,
        "frozen_worst_case_bound_bits": 1.0,
        "transitive_bound_vs_best_A300_component_factor": 6,
        "transitive_bound_vs_best_A300_component_bits": math.log2(6),
    }


def causal_readback(design: Mapping[str, Any]) -> list[dict[str, Any]]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    sources = design["source_anchors"]
    rows = []
    for attempt, expected_api in (
        ("A295", "a295w24"),
        ("A303", "a303w32"),
        ("A305", "a305w43"),
    ):
        path = path_from_ref(sources[f"{attempt}_causal_path"])
        reader = CausalReader(str(path), verify_integrity=True)
        explicit = reader.get_all_triplets(include_inferred=False)
        all_rows = reader.get_all_triplets(include_inferred=True)
        materialized = [row for row in reader._triplets if row.get("is_inferred", False)]
        if (
            reader.api_id != expected_api
            or len(explicit) != 2
            or len(all_rows) != 3
            or len(materialized) != 1
            or len(reader._rules) != 2
            or len(reader._clusters) != 1
            or len(reader._gaps) != 1
        ):
            raise RuntimeError(f"A309 authentic {attempt} Causal readback differs")
        rows.append(
            {
                "attempt_id": attempt,
                "api_id": reader.api_id,
                "explicit_triplets": len(explicit),
                "materialized_inferred_triplets": len(materialized),
                "embedded_rules": len(reader._rules),
                "clusters": len(reader._clusters),
                "gaps": len(reader._gaps),
                "next_gap": reader._gaps[0],
                "terminal_chain": all_rows[-1],
            }
        )
    return rows


def training_rows(design: Mapping[str, Any]) -> list[dict[str, Any]]:
    sources = design["source_anchors"]
    a295 = json.loads(path_from_ref(sources["A295_result_path"]).read_bytes())
    a303 = json.loads(path_from_ref(sources["A303_result_path"]).read_bytes())
    a305 = json.loads(path_from_ref(sources["A305_result_path"]).read_bytes())
    observed = [
        {
            "attempt_id": "A295",
            "unknown_key_bits": 24,
            "confirmed_fine_rank_one_based": int(
                a295["rank_analysis"]["prefix_ranks_one_based"][
                    "A295_fine_selected_channel"
                ]
            ),
            "public_challenge_sha256": a295["public_challenge_sha256"],
        },
        {
            "attempt_id": "A303",
            "unknown_key_bits": 32,
            "confirmed_fine_rank_one_based": int(
                a303["rank_analysis"]["prefix_ranks_one_based"][
                    "A298_fine_selected_channel_audit_only"
                ]
            ),
            "public_challenge_sha256": a303["public_challenge_sha256"],
        },
        {
            "attempt_id": "A305",
            "unknown_key_bits": 43,
            "confirmed_fine_rank_one_based": int(
                a305["rank_analysis"]["prefix_ranks_one_based"][
                    "A299_fine_selected_channel"
                ]
            ),
            "public_challenge_sha256": a305["public_challenge_sha256"],
        },
    ]
    expected = design["operator_contract"]["fit"]["training_rows"]
    stripped = [
        {
            "attempt_id": row["attempt_id"],
            "unknown_key_bits": row["unknown_key_bits"],
            "confirmed_fine_rank_one_based": row[
                "confirmed_fine_rank_one_based"
            ],
        }
        for row in observed
    ]
    if stripped != expected:
        raise RuntimeError("A309 confirmed training rows differ from frozen design")
    return observed


def freeze() -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, ORDER, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A309 artifacts already exist")
    design = load_design()
    if A300.RESULT.exists() or A300.CAUSAL.exists():
        raise RuntimeError("A300 result existed before A309 order freeze")
    a300_protocol, _preflight, a300_order = A300.load_order(
        A300_PROTOCOL_SHA256,
        A300_PREFLIGHT_SHA256,
        A300_ORDER_SHA256,
    )
    rows = training_rows(design)
    if a300_protocol["public_challenge_sha256"] in {
        row["public_challenge_sha256"] for row in rows
    }:
        raise RuntimeError("A309 training and target challenges are not disjoint")
    fit = exact_linear_fit(rows)
    frozen_fit = design["operator_contract"]["fit"]
    if (
        fit["slope"]["numerator"] != frozen_fit["slope_numerator"]
        or fit["slope"]["denominator"] != frozen_fit["slope_denominator"]
        or fit["intercept"]["numerator"] != frozen_fit["intercept_numerator"]
        or fit["intercept"]["denominator"] != frozen_fit["intercept_denominator"]
        or fit["predicted_W43_rank"]["nearest_integer"]
        != frozen_fit["predicted_W43_fine_rank_nearest_integer"]
    ):
        raise RuntimeError("A309 exact width calibration differs from frozen design")
    fine = [
        int(value)
        for value in a300_order["component_orders"]["A295_fine_selected_channel"]
    ]
    baseline = [int(value) for value in a300_order["portfolio_order"]]
    band = band_order(
        fine=fine,
        center=fit["predicted_W43_rank"]["nearest_integer"],
    )
    portfolio = two_arm_portfolio(band=band, baseline=baseline)
    guarantee = portfolio_guarantee(
        portfolio=portfolio,
        band=band,
        baseline=baseline,
    )
    readback = causal_readback(design)
    order_payload = {
        "schema": "chacha20-round20-w43-width-conditioned-band-portfolio-a309-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FRESH_A300_W43_WIDTH_CONDITIONED_BAND_PORTFOLIO_ORDER_FROZEN",
        "A300_protocol_sha256": A300_PROTOCOL_SHA256,
        "A300_preflight_sha256": A300_PREFLIGHT_SHA256,
        "A300_order_sha256": A300_ORDER_SHA256,
        "public_challenge_sha256": a300_protocol["public_challenge_sha256"],
        "training_rows": rows,
        "exact_width_fit": fit,
        "personal_authentic_causal_readback": readback,
        "component_orders": {
            "width_conditioned_fine_rank_band": band,
            "A300_three_operator_baseline": baseline,
        },
        "component_order_sha256": {
            "width_conditioned_fine_rank_band": sha256(
                b"".join(value.to_bytes(2, "big") for value in band)
            ),
            "A300_three_operator_baseline": sha256(
                b"".join(value.to_bytes(2, "big") for value in baseline)
            ),
        },
        "portfolio_order": portfolio,
        "portfolio_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in portfolio)
        ),
        "portfolio_guarantee": guarantee,
        "information_boundary": design["information_boundary"],
    }
    order_payload["measurement_sha256"] = canonical_sha256(
        {
            "training_rows": rows,
            "exact_width_fit": fit,
            "personal_authentic_causal_readback": readback,
            "component_order_sha256": order_payload["component_order_sha256"],
            "portfolio_order_uint16be_sha256": order_payload[
                "portfolio_order_uint16be_sha256"
            ],
            "portfolio_guarantee": guarantee,
            "information_boundary": order_payload["information_boundary"],
        }
    )
    atomic_json(ORDER, order_payload)
    order_sha = file_sha256(ORDER)
    protocol = {
        "schema": "chacha20-round20-w43-width-conditioned-band-portfolio-a309-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_A300_candidate_execution_or_reveal",
        "design_sha256": DESIGN_SHA256,
        "public_challenge_sha256": a300_protocol["public_challenge_sha256"],
        "order_sha256": order_sha,
        "portfolio_order_uint16be_sha256": order_payload[
            "portfolio_order_uint16be_sha256"
        ],
        "predicted_W43_fine_rank_nearest_integer": fit["predicted_W43_rank"]
        ["nearest_integer"],
        "execution_contract": {
            "primitive": "RFC8439_ChaCha20_block_function",
            "full_rounds": 20,
            "feedforward_included": True,
            "unknown_key_bits": WIDTH,
            "candidate_group_size": GROUP_SIZE,
            "complete_prefix_group_before_success_evaluation": True,
            "early_stop_inside_prefix_group": False,
            "control_target_in_same_kernel": True,
            "grouped_engine": "A304",
            "frozen_execution_order": "A309_width_band_plus_A300_baseline",
        },
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "order": {"path": relative(ORDER), "sha256": order_sha},
            "A300_protocol": {
                "path": relative(A300.PROTOCOL),
                "sha256": A300_PROTOCOL_SHA256,
            },
            "A300_preflight": {
                "path": relative(A300.PREFLIGHT),
                "sha256": A300_PREFLIGHT_SHA256,
            },
            "A300_order": {
                "path": relative(A300.ORDER),
                "sha256": A300_ORDER_SHA256,
            },
            "A304_qualification": {
                "path": relative(A304.QUALIFICATION),
                "sha256": A304_QUALIFICATION_SHA256,
            },
            "A309_runner": {
                "path": relative(Path(__file__)),
                "sha256": file_sha256(Path(__file__)),
            },
            "A309_test": {
                "path": relative(A309_TEST),
                "sha256": file_sha256(A309_TEST),
            },
            "A309_reproducer": {
                "path": relative(A309_REPRO),
                "sha256": file_sha256(A309_REPRO),
            },
        },
        "candidate_execution_started": False,
        "candidate_assignment_supplied_to_runner": False,
    }
    atomic_json(PROTOCOL, protocol)
    return protocol


def load_protocol(
    expected_protocol_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A309 protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    if (
        protocol.get("schema")
        != "chacha20-round20-w43-width-conditioned-band-portfolio-a309-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_before_A300_candidate_execution_or_reveal"
        or protocol.get("candidate_execution_started") is not False
        or protocol.get("candidate_assignment_supplied_to_runner") is not False
        or protocol.get("predicted_W43_fine_rank_nearest_integer") != 2105
    ):
        raise RuntimeError("A309 protocol semantics differ")
    for row in protocol["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    order = json.loads(ORDER.read_bytes())
    if (
        order.get("schema")
        != "chacha20-round20-w43-width-conditioned-band-portfolio-a309-order-v1"
        or order.get("public_challenge_sha256")
        != protocol["public_challenge_sha256"]
        or order.get("portfolio_order_uint16be_sha256")
        != protocol["portfolio_order_uint16be_sha256"]
        or len(order.get("portfolio_order", [])) != CELLS
        or set(order.get("portfolio_order", [])) != set(range(CELLS))
        or order.get("portfolio_guarantee", {}).get("violations") != 0
    ):
        raise RuntimeError("A309 order semantics differ")
    components = order["component_orders"]
    reconstructed = two_arm_portfolio(
        band=components["width_conditioned_fine_rank_band"],
        baseline=components["A300_three_operator_baseline"],
    )
    if reconstructed != order["portfolio_order"]:
        raise RuntimeError("A309 portfolio reconstruction differs")
    a300_protocol, _preflight, a300_order = A300.load_order(
        A300_PROTOCOL_SHA256,
        A300_PREFLIGHT_SHA256,
        A300_ORDER_SHA256,
    )
    if (
        a300_protocol["public_challenge_sha256"]
        != protocol["public_challenge_sha256"]
        or components["A300_three_operator_baseline"]
        != a300_order["portfolio_order"]
    ):
        raise RuntimeError("A309 A300 baseline anchor differs")
    return protocol, order, a300_protocol


def rank_analysis(
    *, prefix: int, order: Mapping[str, Any], a300_order: Mapping[str, Any], challenge_sha: str
) -> dict[str, Any]:
    components = order["component_orders"]
    a309 = [int(value) for value in order["portfolio_order"]]
    band = [int(value) for value in components["width_conditioned_fine_rank_band"]]
    baseline = [int(value) for value in components["A300_three_operator_baseline"]]
    a300_ranks = A300.rank_analysis(
        prefix=prefix,
        order_value=a300_order,
        challenge_sha=challenge_sha,
    )
    ranks = {
        "A309_width_band_plus_baseline": a309.index(prefix) + 1,
        "width_conditioned_fine_rank_band": band.index(prefix) + 1,
        "A300_three_operator_baseline": baseline.index(prefix) + 1,
        **a300_ranks["prefix_ranks_one_based"],
    }
    portfolio_rank = ranks["A309_width_band_plus_baseline"]
    best_arm = min(
        ranks["width_conditioned_fine_rank_band"],
        ranks["A300_three_operator_baseline"],
    )
    if portfolio_rank > 2 * best_arm:
        raise RuntimeError("A309 observed rank violates factor-two guarantee")
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "A300_rank_analysis": a300_ranks,
        "best_A309_arm_rank_one_based": best_arm,
        "portfolio_regret_factor_vs_best_A309_arm": portfolio_rank / best_arm,
        "portfolio_gain_bits_vs_complete_domain": math.log2(CELLS / portfolio_rank),
        "speedup_vs_A300_baseline": (
            ranks["A300_three_operator_baseline"] / portfolio_rank
        ),
        "gain_bits_vs_A300_baseline": math.log2(
            ranks["A300_three_operator_baseline"] / portfolio_rank
        ),
        "counterfactual_ranks_computed_only_after_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A309:confirmed_width_conditioned_band_W43_recovery"
    writer = CausalWriter(api_id="a309w43")
    writer._rules = []
    writer.add_rule(
        name="confirmed_width_rank_sequence_to_target_blind_band",
        description="Three disjoint confirmed fine ranks define one exact width-conditioned center before the sealed A300 target is revealed.",
        pattern=["three_disjoint_confirmed_width_rank_pairs", "exact_linear_fit"],
        conclusion="A309_width_conditioned_band_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="band_baseline_portfolio_to_confirmed_recovery",
        description="The band order and unchanged A300 baseline are merged with a factor-two bound and scanned as complete 2^31-member groups before dual confirmation.",
        pattern=["A309_width_conditioned_band_order", "A300_bounded_baseline"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A295_A303_A305:confirmed_disjoint_fine_rank_sequence",
        mechanism="exact_width_conditioning_plus_target_blind_rank_band",
        outcome="A309:frozen_band_plus_A300_baseline_order",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=json.dumps(payload["portfolio_guarantee"], sort_keys=True),
        domain="AI-native learned ChaCha20-R20 W43 search operator",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A309:frozen_band_plus_A300_baseline_order",
        mechanism="complete_grouped_Metal_search_plus_dual_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="confirmed full-round ChaCha20 W43 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A295_A303_A305:confirmed_disjoint_fine_rank_sequence",
        mechanism="materialized_width_fit_band_search_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A309_width_conditioned_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A309 width-conditioned band W43 recovery",
        entities=[
            "A295_A303_A305:confirmed_disjoint_fine_rank_sequence",
            "A309:frozen_band_plus_A300_baseline_order",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_width_conditioned_band_replication_or_W44_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the frozen width-conditioned band retain concentration on another fresh W43 target or W44?"
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
        reader.api_id != "a309w43"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A309 authentic Causal reopen gate failed")
    reader_source = Path(inspect.getsourcefile(CausalReader) or "")
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
        "reader_source": anchor(reader_source),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def recover(*, expected_protocol_sha256: str, swiftc: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A309 final artifacts already exist")
    if A300.RESULT.exists() or A300.CAUSAL.exists():
        raise RuntimeError("A300 result existed before A309 candidate execution")
    protocol, order, a300_protocol = load_protocol(expected_protocol_sha256)
    _a300_protocol, _preflight, a300_order = A300.load_order(
        A300_PROTOCOL_SHA256,
        A300_PREFLIGHT_SHA256,
        A300_ORDER_SHA256,
    )
    _a304_protocol, _a302_order, qualification = A304.load_qualification(
        A304_PROTOCOL_SHA256,
        A304_QUALIFICATION_SHA256,
    )
    challenge = a300_protocol["public_challenge"]
    executable, build = A304.compile_native(swiftc)
    if (
        build["source_sha256"] != qualification["grouped_build"]["source_sha256"]
        or build["executable_sha256"]
        != qualification["grouped_build"]["executable_sha256"]
    ):
        raise RuntimeError("A309 grouped build differs from A304 qualification")
    base = W43._initial(  # noqa: SLF001
        challenge["known_zeroed_key_words"],
        int(challenge["counter_start"]),
        challenge["nonce_words"],
        0,
    )
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    host = A304.GroupedMetalHost(executable, base, target, control)
    try:
        discovery = A304.ordered_discovery(
            host=host,
            challenge=challenge,
            order=[int(value) for value in order["portfolio_order"]],
        )
        identity = host.identity
    finally:
        host.close()
    discovery["source_operator_attempt"] = ATTEMPT_ID
    discovery["grouped_execution_engine"] = "A304"
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A309 matched control produced a candidate")
    confirmation = W43._confirm(  # noqa: SLF001
        {"challenge": challenge}, int(discovery["candidate"])
    )
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A309 dual independent confirmation failed")
    prefix = int(discovery["fine_prefix12"])
    ranks = rank_analysis(
        prefix=prefix,
        order=order,
        a300_order=a300_order,
        challenge_sha=protocol["public_challenge_sha256"],
    )
    portfolio_rank = ranks["prefix_ranks_one_based"][
        "A309_width_band_plus_baseline"
    ]
    if portfolio_rank != discovery["executed_prefix_groups"]:
        raise RuntimeError("A309 discovery rank differs from frozen portfolio")
    strict_subset = portfolio_rank < CELLS
    evidence_stage = (
        "FULLROUND_R20_W43_WIDTH_CONDITIONED_BAND_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_W43_WIDTH_CONDITIONED_BAND_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w43-width-conditioned-band-portfolio-a309-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "order_sha256": file_sha256(ORDER),
        "A300_protocol_sha256": A300_PROTOCOL_SHA256,
        "A300_preflight_sha256": A300_PREFLIGHT_SHA256,
        "A300_order_sha256": A300_ORDER_SHA256,
        "A304_protocol_sha256": A304_PROTOCOL_SHA256,
        "A304_qualification_artifact_sha256": A304_QUALIFICATION_SHA256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "exact_width_fit": order["exact_width_fit"],
        "training_rows": order["training_rows"],
        "personal_source_causal_readback": order[
            "personal_authentic_causal_readback"
        ],
        "grouped_build": build,
        "metal_identity": identity,
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "full_block_bits_checked": qualification[
                "total_full_block_bits_checked"
            ],
            "synthetic_filter_exact": qualification["synthetic_filter_gate"][
                "exact"
            ],
            "production_target_used": False,
        },
        "discovery": discovery,
        "rank_analysis": ranks,
        "portfolio_guarantee": order["portfolio_guarantee"],
        "confirmation": confirmation,
        "strict_subset_of_complete_domain": strict_subset,
        "information_boundary": protocol["information_boundary"],
        "anchors": protocol["anchors"],
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "discovery": {
                key: value
                for key, value in discovery.items()
                if not key.startswith("volatile_")
            },
            "metal_identity": identity,
            "grouped_build": build,
            "A304_qualification_artifact_sha256": A304_QUALIFICATION_SHA256,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "exact_width_fit": payload["exact_width_fit"],
            "training_rows": payload["training_rows"],
            "discovery": {
                key: value
                for key, value in discovery.items()
                if not key.startswith("volatile_")
            },
            "rank_analysis": ranks,
            "portfolio_guarantee": payload["portfolio_guarantee"],
            "confirmation": confirmation,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A309 — width-conditioned band recovery on sealed A300 W43\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- A309 portfolio rank: **{portfolio_rank} / 4,096**\n"
            f"- Width-band rank: **{ranks['prefix_ranks_one_based']['width_conditioned_fine_rank_band']} / 4,096**\n"
            f"- A300 baseline rank: **{ranks['prefix_ranks_one_based']['A300_three_operator_baseline']} / 4,096**\n"
            f"- Gain versus A300 baseline: **{ranks['gain_bits_vs_A300_baseline']:.6f} bits**\n"
            f"- Executed assignments: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W43 assignment: **0x{int(discovery['candidate']):011x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Matched one-bit control: **zero candidates**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode()
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "protocol_frozen": PROTOCOL.exists(),
        "order_frozen": ORDER.exists(),
        "result_complete": RESULT.exists(),
        "predicted_W43_fine_rank_nearest_integer": 2105,
        "source_target": "A300",
        "grouped_engine": "A304",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--swiftc", default="/usr/bin/swiftc")
    args = parser.parse_args()
    if args.analyze:
        output = analyze()
    elif args.freeze:
        value = freeze()
        output = {
            "protocol": relative(PROTOCOL),
            "protocol_sha256": file_sha256(PROTOCOL),
            "order": relative(ORDER),
            "order_sha256": value["order_sha256"],
            "public_challenge_sha256": value["public_challenge_sha256"],
        }
    else:
        if not args.expected_protocol_sha256:
            parser.error("--recover requires --expected-protocol-sha256")
        value = recover(
            expected_protocol_sha256=args.expected_protocol_sha256,
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
