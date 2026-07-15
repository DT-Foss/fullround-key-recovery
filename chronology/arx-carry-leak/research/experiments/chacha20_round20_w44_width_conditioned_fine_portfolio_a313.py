#!/usr/bin/env python3
"""A313: compile and execute the pre-reveal W44 fine-band portfolio."""

from __future__ import annotations

import argparse
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

DESIGN = CONFIGS / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_design_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.json"
ORDER = RESULTS / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.causal"
REPORT = RESULTS / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.md"

A295_RESULT = RESULTS / "chacha20_round20_w24_fine_selected_channel_a295_v1.json"
A303_RESULT = RESULTS / "chacha20_round20_w32_dominance_pruned_companion_a303_v1.json"
A305_RESULT = RESULTS / "chacha20_round20_w43_a299_grouped_replay_a305_v1.json"
A308_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_calibrated_coarse_numeric_a308.py"
A309_DESIGN = CONFIGS / "chacha20_round20_w43_width_conditioned_band_portfolio_a309_design_v1.json"
A312_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_fine_selected_channel_transfer_a312.py"
A313_TEST = ROOT / "tests/test_chacha20_round20_w44_width_conditioned_fine_portfolio_a313.py"
A313_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w44_width_conditioned_fine_portfolio_a313.sh"

ATTEMPT_ID = "A313"
DESIGN_SHA256 = "7c3f2b78933cc64f9bdc7322aa185eef4997c4bab86f5d47576bd0a2687daf8e"
A295_RESULT_SHA256 = "93a591d75ab882345091c813f4ace877dc85ae37d748ed8f70c91e7323effc03"
A303_RESULT_SHA256 = "bc1878203ed1dc8dffab86e8cd1a85bd01fb12e09a1de6a86b29fd9d1ceae3fe"
A305_RESULT_SHA256 = "adbc8b879f09e03896699188d8141ac0164296eaf2ad688b6fb1036f2b1ac40e"
A308_PROTOCOL_SHA256 = "06fcdf7e79f07408292ced64eb19c7c973ba202061d47f8c9499bd23fe679dbd"
A308_PREFLIGHT_SHA256 = "7afda29f1cf4f12d4ab09348d2393a80c30b7689d2e6623fffb9351f966cd5fd"
A308_ORDER_SHA256 = "d69b594a5c7a8ce17d7e5e8d5736006f76a3757a532aa6e4e84f2ca5d6ab2f0b"
A309_DESIGN_SHA256 = "5dde7d22eac9b01a706d46366e13653db61826ca29710c6d9b545d5ea2443552"
A312_DESIGN_SHA256 = "40da3c04819ecba94300d5306edd8fcfe21b65174623ceb725ae9c4d9edff272"
A312_PROTOCOL_SHA256 = "a8fb67f813b09776168e6447b1f4eee44795b413b4a6cc12688a30f5b932f014"
A307_QUALIFICATION_SHA256 = "b6b8f0193229d034a16f88ae37b1da11eed6568499dbb579f81eb47b84f9293a"

WIDTH = 44
CELLS = 1 << 12
CENTER = 2079
GROUP_SIZE = 1 << 32
DOMAIN_SIZE = 1 << WIDTH


def load_module(path: Path, name: str) -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A313 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A308 = load_module(A308_RUNNER, "a313_a308_common")
A312 = load_module(A312_RUNNER, "a313_a312_common")
file_sha256 = A308.file_sha256
canonical_sha256 = A308.canonical_sha256
atomic_json = A308.atomic_json
atomic_bytes = A308.atomic_bytes
relative = A308.relative
path_from_ref = A308.path_from_ref
anchor = A308.anchor
sha256 = A308.sha256
DOTCAUSAL_SRC = A312.DOTCAUSAL_SRC


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A313 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    operator = value.get("operator_contract", {})
    fit = operator.get("fit", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w44-width-conditioned-fine-portfolio-a313-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_while_A309_and_A312_are_running_before_any_A312_search_object_A308_candidate_or_W44_prefix_rank_exists"
        or fit.get("predicted_W44_fine_rank_nearest_integer") != CENTER
        or fit.get("predicted_W44_fine_rank_numerator") != 1135327
        or fit.get("predicted_W44_fine_rank_denominator") != 546
        or operator.get("training_fit_is_not_recomputed_after_A309_A312_or_A308_reveal")
        is not True
        or boundary.get("A308_result_available_at_design_freeze") is not False
        or boundary.get("A312_measurement_complete_at_design_freeze") is not False
        or boundary.get("A312_fine_order_available_at_design_freeze") is not False
        or boundary.get("A312_direct_symbolic_outcome_available_at_design_freeze")
        is not False
    ):
        raise RuntimeError("A313 design semantics differ")
    sources = value["source_anchors"]
    for path_key, sha_key in (
        ("A295_result_path", "A295_result_sha256"),
        ("A303_result_path", "A303_result_sha256"),
        ("A305_result_path", "A305_result_sha256"),
        ("A308_protocol_path", "A308_protocol_sha256"),
        ("A308_order_path", "A308_order_sha256"),
        ("A309_design_path", "A309_design_sha256"),
        ("A312_design_path", "A312_design_sha256"),
        ("A312_protocol_path", "A312_protocol_sha256"),
    ):
        anchor(path_from_ref(sources[path_key]), sources[sha_key])
    return value


def confirmed_training_rows(design: Mapping[str, Any]) -> list[dict[str, Any]]:
    sources = (
        ("A295", 24, A295_RESULT, A295_RESULT_SHA256, "A295_fine_selected_channel"),
        ("A303", 32, A303_RESULT, A303_RESULT_SHA256, "A298_fine_selected_channel_audit_only"),
        ("A305", 43, A305_RESULT, A305_RESULT_SHA256, "A299_fine_selected_channel"),
    )
    rows: list[dict[str, Any]] = []
    challenge_hashes: set[str] = set()
    for attempt, width, path, expected_sha, rank_key in sources:
        if file_sha256(path) != expected_sha:
            raise RuntimeError(f"A313 {attempt} result hash differs")
        payload = json.loads(path.read_bytes())
        confirmation = payload.get("confirmation", {})
        rank = int(payload["rank_analysis"]["prefix_ranks_one_based"][rank_key])
        challenge_sha = str(payload["public_challenge_sha256"])
        confirmed = confirmation.get("all_blocks_match") is True or (
            confirmation.get("cross_implementation_blocks_match") is True
            and confirmation.get("independent_byte_reference_all_eight_blocks_match")
            is True
            and confirmation.get("root_operation_reference_all_eight_blocks_match")
            is True
        )
        if not confirmed or challenge_sha in challenge_hashes:
            raise RuntimeError("A313 training confirmation or challenge disjointness differs")
        challenge_hashes.add(challenge_sha)
        rows.append(
            {
                "attempt_id": attempt,
                "unknown_key_bits": width,
                "confirmed_fine_rank_one_based": rank,
                "public_challenge_sha256": challenge_sha,
            }
        )
    frozen = design["operator_contract"]["fit"]["training_rows"]
    stripped = [
        {
            "attempt_id": row["attempt_id"],
            "unknown_key_bits": row["unknown_key_bits"],
            "confirmed_fine_rank_one_based": row["confirmed_fine_rank_one_based"],
        }
        for row in rows
    ]
    if stripped != frozen:
        raise RuntimeError("A313 training rows differ from frozen design")
    return rows


def exact_fit(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    xs = [Fraction(int(row["unknown_key_bits"])) for row in rows]
    ys = [Fraction(int(row["confirmed_fine_rank_one_based"])) for row in rows]
    x_bar = sum(xs) / len(xs)
    y_bar = sum(ys) / len(ys)
    slope = sum((x - x_bar) * (y - y_bar) for x, y in zip(xs, ys, strict=True)) / sum(
        (x - x_bar) ** 2 for x in xs
    )
    intercept = y_bar - slope * x_bar
    predicted = intercept + slope * WIDTH
    nearest = math.floor(predicted + Fraction(1, 2))
    if (
        slope != Fraction(-4671, 182)
        or intercept != Fraction(1751899, 546)
        or predicted != Fraction(1135327, 546)
        or nearest != CENTER
    ):
        raise RuntimeError("A313 exact W44 fit differs")
    return {
        "slope": {"numerator": slope.numerator, "denominator": slope.denominator},
        "intercept": {
            "numerator": intercept.numerator,
            "denominator": intercept.denominator,
        },
        "predicted_W44_rank": {
            "numerator": predicted.numerator,
            "denominator": predicted.denominator,
            "decimal": float(predicted),
            "nearest_integer": nearest,
        },
    }


def band_order(*, fine: Sequence[int], center: int = CENTER) -> list[int]:
    values = [int(value) for value in fine]
    if len(values) != CELLS or set(values) != set(range(CELLS)):
        raise ValueError("A313 fine order is not an exact cover")
    ranks = {cell: rank for rank, cell in enumerate(values, 1)}
    return sorted(values, key=lambda cell: (abs(ranks[cell] - center), ranks[cell]))


def three_arm_portfolio(*, band: Sequence[int], fine: Sequence[int], baseline: Sequence[int]) -> list[int]:
    arms = [[int(value) for value in arm] for arm in (band, fine, baseline)]
    if any(len(arm) != CELLS or set(arm) != set(range(CELLS)) for arm in arms):
        raise ValueError("A313 portfolio arm is not an exact cover")
    output: list[int] = []
    seen: set[int] = set()
    for rank in range(CELLS):
        for arm in arms:
            cell = arm[rank]
            if cell not in seen:
                seen.add(cell)
                output.append(cell)
    if len(output) != CELLS or set(output) != set(range(CELLS)):
        raise RuntimeError("A313 portfolio is not an exact cover")
    return output


def portfolio_guarantee(
    *, portfolio: Sequence[int], band: Sequence[int], fine: Sequence[int], baseline: Sequence[int]
) -> dict[str, Any]:
    ranks = {
        "portfolio": {int(value): rank for rank, value in enumerate(portfolio, 1)},
        "band": {int(value): rank for rank, value in enumerate(band, 1)},
        "fine": {int(value): rank for rank, value in enumerate(fine, 1)},
        "baseline": {int(value): rank for rank, value in enumerate(baseline, 1)},
    }
    violations = 0
    maximum = 0.0
    maximum_cell = -1
    for cell in range(CELLS):
        best = min(ranks["band"][cell], ranks["fine"][cell], ranks["baseline"][cell])
        observed = ranks["portfolio"][cell]
        ratio = observed / best
        if ratio > maximum:
            maximum = ratio
            maximum_cell = cell
        if observed > 3 * best:
            violations += 1
    if violations or maximum > 3.0:
        raise RuntimeError("A313 factor-three portfolio guarantee failed")
    return {
        "checked_prefix_cells": CELLS,
        "violations": violations,
        "maximum_observed_regret_factor": maximum,
        "maximum_observed_regret_bits": math.log2(maximum),
        "maximum_observed_regret_cell": maximum_cell,
        "frozen_worst_case_bound_factor": 3,
        "frozen_worst_case_bound_bits": math.log2(3),
        "statement": "R_A313 <= 3 * min(R_band, R_A312_fine, R_A308_baseline)",
    }


def authentic_a312_readback() -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(A312.CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a312w44"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A313 authentic A312 Causal readback differs")
    return {
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "next_gap": reader._gaps[0],
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
    }


def materialize(*, expected_a312_order_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (ORDER, PROTOCOL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A313 artifacts already exist")
    if A308.RESULT.exists() or A308.CAUSAL.exists():
        raise RuntimeError("A308 result exists before A313 materialization")
    design = load_design()
    rows = confirmed_training_rows(design)
    fit = exact_fit(rows)
    if file_sha256(A312.ORDER) != expected_a312_order_sha256:
        raise RuntimeError("A313 A312 order hash differs")
    a312 = json.loads(A312.ORDER.read_bytes())
    if (
        a312.get("schema")
        != "chacha20-round20-w44-fine-selected-channel-transfer-a312-order-v1"
        or a312.get("protocol_sha256") != A312_PROTOCOL_SHA256
        or a312.get("public_challenge_sha256") != A312.PUBLIC_CHALLENGE_SHA256
        or a312.get("information_boundary", {}).get("A308_result_read") is not False
    ):
        raise RuntimeError("A313 A312 search object semantics differ")
    readback = authentic_a312_readback()
    if a312.get("confirmation") is not None:
        if (
            a312.get("direct_symbolic_winner") is None
            or a312["confirmation"].get("all_blocks_match") is not True
        ):
            raise RuntimeError("A313 direct A312 branch is not confirmed")
        payload = {
            "schema": "chacha20-round20-w44-width-conditioned-fine-portfolio-a313-order-v1",
            "attempt_id": ATTEMPT_ID,
            "execution_branch": "A312_direct_symbolic_recovery_retained_without_duplicate_grouped_execution",
            "design_sha256": DESIGN_SHA256,
            "A312_order_sha256": expected_a312_order_sha256,
            "direct_symbolic_winner": a312["direct_symbolic_winner"],
            "confirmation": a312["confirmation"],
            "authentic_A312_causal_readback": readback,
            "A308_result_available_at_materialization": False,
            "anchors": {
                "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
                "A312_order": {
                    "path": relative(A312.ORDER),
                    "sha256": expected_a312_order_sha256,
                },
                "A312_causal": {
                    "path": relative(A312.CAUSAL),
                    "sha256": file_sha256(A312.CAUSAL),
                },
            },
        }
        atomic_json(ORDER, payload)
        return payload

    fine_readout = a312.get("fine_readout")
    if not isinstance(fine_readout, dict):
        raise RuntimeError("A313 A312 branch has neither direct model nor fine order")
    fine = [int(value) for value in fine_readout["complete_order"]]
    _a308_protocol, _preflight, a308_order = A308.load_order(
        A308_PROTOCOL_SHA256,
        A308_PREFLIGHT_SHA256,
        A308_ORDER_SHA256,
    )
    baseline = [int(value) for value in a308_order["portfolio_order"]]
    band = band_order(fine=fine)
    portfolio = three_arm_portfolio(band=band, fine=fine, baseline=baseline)
    guarantee = portfolio_guarantee(
        portfolio=portfolio,
        band=band,
        fine=fine,
        baseline=baseline,
    )
    order_payload = {
        "schema": "chacha20-round20-w44-width-conditioned-fine-portfolio-a313-order-v1",
        "attempt_id": ATTEMPT_ID,
        "execution_branch": "A312_complete_model_free_fine_order_to_A313_three_arm_portfolio",
        "evidence_stage": "FRESH_A308_W44_WIDTH_CONDITIONED_FINE_PORTFOLIO_ORDER_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "A312_order_sha256": expected_a312_order_sha256,
        "public_challenge_sha256": A312.PUBLIC_CHALLENGE_SHA256,
        "training_rows": rows,
        "exact_width_fit": fit,
        "authentic_A312_causal_readback": readback,
        "component_orders": {
            "width_conditioned_A312_fine_rank_band": band,
            "A312_fine_selected_channel": fine,
            "A308_two_operator_baseline": baseline,
        },
        "component_order_sha256": {
            "width_conditioned_A312_fine_rank_band": sha256(
                b"".join(value.to_bytes(2, "big") for value in band)
            ),
            "A312_fine_selected_channel": sha256(
                b"".join(value.to_bytes(2, "big") for value in fine)
            ),
            "A308_two_operator_baseline": sha256(
                b"".join(value.to_bytes(2, "big") for value in baseline)
            ),
        },
        "portfolio_order": portfolio,
        "portfolio_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in portfolio)
        ),
        "portfolio_guarantee": guarantee,
        "information_boundary": {
            **design["information_boundary"],
            "A312_outcome_used_only_to_select_predeclared_conditional_branch": True,
            "A308_result_available_at_materialization": False,
            "A308_candidate_or_prefix_rank_available_at_materialization": False,
        },
    }
    order_payload["measurement_sha256"] = canonical_sha256(
        {
            "A312_order_sha256": expected_a312_order_sha256,
            "training_rows": rows,
            "exact_width_fit": fit,
            "authentic_A312_causal_readback": readback,
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
        "schema": "chacha20-round20-w44-width-conditioned-fine-portfolio-a313-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_before_A308_grouped_candidate_execution_or_reveal",
        "design_sha256": DESIGN_SHA256,
        "A312_order_sha256": expected_a312_order_sha256,
        "public_challenge_sha256": A312.PUBLIC_CHALLENGE_SHA256,
        "order_sha256": order_sha,
        "portfolio_order_uint16be_sha256": order_payload[
            "portfolio_order_uint16be_sha256"
        ],
        "execution_contract": {
            "primitive": "RFC8439_ChaCha20_block_function",
            "full_rounds": 20,
            "feedforward_included": True,
            "unknown_key_bits": WIDTH,
            "candidate_group_size": GROUP_SIZE,
            "complete_prefix_group_before_success_evaluation": True,
            "early_stop_inside_prefix_group": False,
            "matched_control_target": True,
            "grouped_engine": "A307_two_slab_W44",
            "frozen_execution_order": "A313_band_plus_fine_plus_A308_baseline",
        },
        "information_boundary": order_payload["information_boundary"],
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "order": {"path": relative(ORDER), "sha256": order_sha},
            "A312_order": {
                "path": relative(A312.ORDER),
                "sha256": expected_a312_order_sha256,
            },
            "A312_causal": {
                "path": relative(A312.CAUSAL),
                "sha256": file_sha256(A312.CAUSAL),
            },
            "A308_protocol": {
                "path": relative(A308.PROTOCOL),
                "sha256": A308_PROTOCOL_SHA256,
            },
            "A308_preflight": {
                "path": relative(A308.PREFLIGHT),
                "sha256": A308_PREFLIGHT_SHA256,
            },
            "A308_order": {
                "path": relative(A308.ORDER),
                "sha256": A308_ORDER_SHA256,
            },
            "A313_runner": {
                "path": relative(Path(__file__)),
                "sha256": file_sha256(Path(__file__)),
            },
            "A313_test": {
                "path": relative(A313_TEST),
                "sha256": file_sha256(A313_TEST),
            },
            "A313_reproducer": {
                "path": relative(A313_REPRO),
                "sha256": file_sha256(A313_REPRO),
            },
        },
    }
    atomic_json(PROTOCOL, protocol)
    return protocol


def load_protocol(expected_protocol_sha256: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A313 protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    if (
        protocol.get("schema")
        != "chacha20-round20-w44-width-conditioned-fine-portfolio-a313-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_before_A308_grouped_candidate_execution_or_reveal"
        or protocol.get("design_sha256") != DESIGN_SHA256
        or protocol.get("public_challenge_sha256") != A312.PUBLIC_CHALLENGE_SHA256
    ):
        raise RuntimeError("A313 protocol semantics differ")
    for row in protocol["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    order = json.loads(ORDER.read_bytes())
    if (
        order.get("execution_branch")
        != "A312_complete_model_free_fine_order_to_A313_three_arm_portfolio"
        or order.get("portfolio_order_uint16be_sha256")
        != protocol["portfolio_order_uint16be_sha256"]
        or order.get("portfolio_guarantee", {}).get("violations") != 0
    ):
        raise RuntimeError("A313 order semantics differ")
    a308_protocol, _preflight, a308_order = A308.load_order(
        A308_PROTOCOL_SHA256,
        A308_PREFLIGHT_SHA256,
        A308_ORDER_SHA256,
    )
    return protocol, order, {"protocol": a308_protocol, "order": a308_order}


def rank_analysis(
    *, prefix: int, order: Mapping[str, Any], a308_order: Mapping[str, Any]
) -> dict[str, Any]:
    components = order["component_orders"]
    a308_components = a308_order["component_orders"]
    orders = {
        "A313_three_arm_portfolio": order["portfolio_order"],
        "width_conditioned_A312_fine_rank_band": components[
            "width_conditioned_A312_fine_rank_band"
        ],
        "A312_fine_selected_channel": components["A312_fine_selected_channel"],
        "A308_two_operator_baseline": components["A308_two_operator_baseline"],
        "A297_coarse_high8_then_reflected_Gray4": a308_components[
            "A297_coarse_high8_then_reflected_Gray4"
        ],
        "numeric_word0_prefix12": a308_components["numeric_word0_prefix12"],
        "public_hash_control": A308.A302.A300.A299.public_hash_order(
            A312.PUBLIC_CHALLENGE_SHA256
        ),
    }
    ranks = {
        name: [int(value) for value in values].index(prefix) + 1
        for name, values in orders.items()
    }
    best_three = min(
        ranks["width_conditioned_A312_fine_rank_band"],
        ranks["A312_fine_selected_channel"],
        ranks["A308_two_operator_baseline"],
    )
    if ranks["A313_three_arm_portfolio"] > 3 * best_three:
        raise RuntimeError("A313 confirmed rank violates factor-three guarantee")
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "best_A313_arm_rank_one_based": best_three,
        "portfolio_regret_factor_vs_best_arm": (
            ranks["A313_three_arm_portfolio"] / best_three
        ),
        "portfolio_regret_bits_vs_best_arm": math.log2(
            ranks["A313_three_arm_portfolio"] / best_three
        ),
        "portfolio_gain_bits_vs_complete_domain": math.log2(
            CELLS / ranks["A313_three_arm_portfolio"]
        ),
        "assignment_upper_bounds": {
            name: rank * GROUP_SIZE for name, rank in ranks.items()
        },
        "rank_guarantee_holds": True,
        "component_ranks_computed_only_after_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A313:confirmed_width_conditioned_fine_W44_recovery"
    writer = CausalWriter(api_id="a313w44")
    writer._rules = []
    writer.add_rule(
        name="A312_fine_field_to_precommitted_W44_portfolio",
        description="The target-label-free A312 fine order is transformed by the pre-reveal W44 rank center and merged with raw fine and A308 baseline orders under a factor-three bound.",
        pattern=["A312_complete_model_free_fine_field", "A313_precommitted_operator"],
        conclusion="A313_frozen_three_arm_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="three_arm_order_to_confirmed_W44_recovery",
        description="Each selected prefix executes two complete 2^31 slabs before outcome evaluation and the sole factual model is confirmed across eight blocks by two implementations.",
        pattern=["A313_frozen_three_arm_order", "A307_complete_W44_group"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A312:complete_model_free_W44_fine_field",
        mechanism="precommitted_width_band_plus_raw_fine_plus_A308_baseline",
        outcome="A313:frozen_three_arm_W44_order",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=json.dumps(payload["portfolio_guarantee"], sort_keys=True),
        domain="AI-native learned ChaCha20-R20 W44 search operator",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A313:frozen_three_arm_W44_order",
        mechanism="complete_two_slab_Metal_search_plus_dual_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="confirmed full-round ChaCha20 W44 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A312:complete_model_free_W44_fine_field",
        mechanism="materialized_A313_order_search_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A313_W44_fine_band_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A313 width-conditioned fine W44 recovery",
        entities=[
            "A312:complete_model_free_W44_fine_field",
            "A313:frozen_three_arm_W44_order",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_W44_replication_or_W45_fine_reader_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the W44 fine-band portfolio replicate on a fresh target or transfer to the qualified A311 W45 engine?"
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
        reader.api_id != "a313w44"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A313 authentic Causal reopen gate failed")
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


def recover(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A313 final artifacts already exist")
    if A308.RESULT.exists() or A308.CAUSAL.exists():
        raise RuntimeError("A308 result exists before A313 candidate execution")
    protocol, order, a308 = load_protocol(expected_protocol_sha256)
    qualification = A308.load_a307_qualification(A307_QUALIFICATION_SHA256)
    challenge = a308["protocol"]["public_challenge"]
    executable_row = json.loads(A308.A307.PROTOCOL.read_bytes())["anchors"][
        "grouped_executable"
    ]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, A308.A307_EXECUTABLE_SHA256)
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A308.A307.A304.GroupedMetalHost(
            executable,
            A308.A307.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    discovery = A308.ordered_discovery(
        host_factory=host_factory,
        challenge=challenge,
        order=[int(value) for value in order["portfolio_order"]],
    )
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A313 matched control produced a candidate")
    confirmation = A308.confirm(challenge, int(discovery["candidate"]))
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A313 dual independent confirmation failed")
    ranks = rank_analysis(
        prefix=int(discovery["prefix12"]),
        order=order,
        a308_order=a308["order"],
    )
    rank = ranks["prefix_ranks_one_based"]["A313_three_arm_portfolio"]
    if rank != discovery["executed_prefix_groups"]:
        raise RuntimeError("A313 discovery rank differs from frozen order")
    strict_subset = rank < CELLS
    evidence_stage = (
        "FULLROUND_R20_W44_WIDTH_CONDITIONED_FINE_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_W44_WIDTH_CONDITIONED_FINE_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w44-width-conditioned-fine-portfolio-a313-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "order_sha256": protocol["order_sha256"],
        "A312_order_sha256": protocol["A312_order_sha256"],
        "A307_qualification_artifact_sha256": A307_QUALIFICATION_SHA256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W44_group_candidates": qualification["complete_group_gate"][
                "logical_candidates"
            ],
            "synthetic_filter_exact": qualification["synthetic_filter_exact"],
            "production_target_used": False,
        },
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "portfolio_guarantee": order["portfolio_guarantee"],
        "strict_subset_of_complete_domain": strict_subset,
        "information_boundary": order["information_boundary"],
        "anchors": protocol["anchors"],
    }
    stable_discovery = {
        key: value for key, value in discovery.items() if not key.startswith("volatile_")
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
            "A307_qualification_artifact_sha256": A307_QUALIFICATION_SHA256,
            "executable_sha256": A308.A307_EXECUTABLE_SHA256,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
            "rank_analysis": ranks,
            "confirmation": confirmation,
            "qualification_gate": payload["qualification_gate"],
            "portfolio_guarantee": payload["portfolio_guarantee"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A313 — width-conditioned fine ChaCha20-R20 W44 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Frozen A313 prefix rank: **{rank} / 4,096**\n"
            f"- Search gain: **{ranks['portfolio_gain_bits_vs_complete_domain']:.6f} bits**\n"
            f"- Executed assignments: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W44 assignment: **0x{int(discovery['candidate']):011x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every prefix: **two complete 2^31 slabs before outcome evaluation**\n"
            "- Matched one-bit control: **zero candidates**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "A312_measurement_complete": A312.ORDER.exists(),
        "order_materialized": ORDER.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "result_complete": RESULT.exists(),
        "predicted_W44_fine_rank_nearest_integer": CENTER,
        "maximum_portfolio_factor": 3,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--materialize", action="store_true")
    action.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-a312-order-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.materialize:
        if not args.expected_a312_order_sha256:
            parser.error("--materialize requires --expected-a312-order-sha256")
        payload = materialize(
            expected_a312_order_sha256=args.expected_a312_order_sha256
        )
    else:
        if not args.expected_protocol_sha256:
            parser.error("--recover requires --expected-protocol-sha256")
        payload = recover(expected_protocol_sha256=args.expected_protocol_sha256)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
