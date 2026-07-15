#!/usr/bin/env python3
"""A310: materialize and evaluate the pre-reveal multicenter W43 order."""

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
REPORTS = RESEARCH / "reports"

DESIGN = (
    CONFIGS
    / "chacha20_round20_w43_empirical_multicenter_band_counterfactual_a310_design_v1.json"
)
COMMITMENT = (
    CONFIGS
    / "chacha20_round20_w43_empirical_multicenter_band_counterfactual_a310_commitment_v1.json"
)
A300_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w43_three_operator_portfolio_a300.py"
)
A309_RESULT = (
    RESULTS / "chacha20_round20_w43_width_conditioned_band_portfolio_a309_v1.json"
)
A310_TEST = (
    ROOT / "tests/test_chacha20_round20_w43_empirical_multicenter_band_counterfactual_a310.py"
)
A310_REPRO = (
    ROOT / "scripts/reproduce_chacha20_round20_w43_empirical_multicenter_band_counterfactual_a310.sh"
)

ORDER = (
    RESULTS
    / "chacha20_round20_w43_empirical_multicenter_band_counterfactual_a310_order_v1.json"
)
RESULT = (
    RESULTS / "chacha20_round20_w43_empirical_multicenter_band_counterfactual_a310_v1.json"
)
CAUSAL = RESULT.with_suffix(".causal")
REPORT = (
    REPORTS
    / "CHACHA20_ROUND20_W43_EMPIRICAL_MULTICENTER_BAND_COUNTERFACTUAL_A310_V1.md"
)

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A310"
DESIGN_SHA256 = "1e886342759d83ae060600d83ce7be81feca90f0ddf4b00cc63618339d478f0f"
COMMITMENT_SHA256 = "327d669a254a7b19e609867ace5c189a5659b4ff834d94ba4a86d6003514295e"
A300_PROTOCOL_SHA256 = "d132e818e598458f0ac2aa53d8032c7c4dc5f2ffed5d863410b76c10c5b43307"
A300_PREFLIGHT_SHA256 = "5479756d446f2a2349e780844a8a8373dde328b7bb448ce85271bf116b46db2d"
A300_ORDER_SHA256 = "76af63fd14613520bda54316e242c16e4530af22ddb2ec9e5a7a6e6df5afefd1"
CELLS = 1 << 12


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A310 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A300 = load_module(A300_RUNNER, "a310_a300_common")
sha256 = A300.sha256
file_sha256 = A300.file_sha256
canonical_sha256 = A300.canonical_sha256
atomic_bytes = A300.atomic_bytes
atomic_json = A300.atomic_json
relative = A300.relative
path_from_ref = A300.path_from_ref
anchor = A300.anchor


def load_frozen_contract() -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A310 design hash differs")
    if file_sha256(COMMITMENT) != COMMITMENT_SHA256:
        raise RuntimeError("A310 exact-order commitment hash differs")
    design = json.loads(DESIGN.read_bytes())
    commitment = json.loads(COMMITMENT.read_bytes())
    boundary = design.get("information_boundary", {})
    operator = design.get("operator_contract", {})
    if (
        design.get("schema")
        != "chacha20-round20-w43-empirical-multicenter-band-counterfactual-a310-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or operator.get("empirical_centers_one_based") != [2114, 2366, 2605]
        or operator.get("training_values_are_not_recomputed_or_extended_after_A300_reveal")
        is not True
        or boundary.get("A300_candidate_available_at_freeze") is not False
        or boundary.get("A309_result_available_at_freeze") is not False
        or boundary.get("target_labels_used_from_A300") != 0
        or commitment.get("schema")
        != "chacha20-round20-w43-empirical-multicenter-band-counterfactual-a310-commitment-v1"
        or commitment.get("attempt_id") != ATTEMPT_ID
        or commitment.get("design_sha256") != DESIGN_SHA256
        or commitment.get("candidate_or_rank_available_at_commitment") is not False
        or commitment.get("cells") != CELLS
        or commitment.get("maximum_observed_factor") != 2.0
    ):
        raise RuntimeError("A310 frozen contract semantics differ")
    for key, expected in design["source_anchors"].items():
        if not key.endswith("_path"):
            continue
        sha_key = key.removesuffix("_path") + "_sha256"
        anchor(path_from_ref(expected), design["source_anchors"][sha_key])
    return design, commitment


def multicenter_band(
    *, fine: Sequence[int], centers: Sequence[int]
) -> list[int]:
    values = [int(value) for value in fine]
    center_values = [int(value) for value in centers]
    if len(values) != CELLS or set(values) != set(range(CELLS)):
        raise ValueError("A310 fine order is not an exact cell cover")
    if (
        not center_values
        or len(center_values) != len(set(center_values))
        or any(not 1 <= value <= CELLS for value in center_values)
    ):
        raise ValueError("A310 empirical centers differ")
    ranks = {cell: rank for rank, cell in enumerate(values, 1)}

    def key(cell: int) -> tuple[int, int, int]:
        rank = ranks[cell]
        distances = [abs(rank - center) for center in center_values]
        minimum = min(distances)
        return minimum, distances.index(minimum), rank

    result = sorted(range(CELLS), key=key)
    if len(result) != CELLS or set(result) != set(range(CELLS)):
        raise RuntimeError("A310 multicenter band is not an exact cover")
    return result


def two_arm_portfolio(
    *, multicenter: Sequence[int], baseline: Sequence[int]
) -> list[int]:
    orders = [
        [int(value) for value in multicenter],
        [int(value) for value in baseline],
    ]
    if any(len(order) != CELLS or set(order) != set(range(CELLS)) for order in orders):
        raise ValueError("A310 component order is not an exact cell cover")
    result: list[int] = []
    seen: set[int] = set()
    for rank in range(CELLS):
        for order in orders:
            value = order[rank]
            if value not in seen:
                seen.add(value)
                result.append(value)
    if len(result) != CELLS or set(result) != set(range(CELLS)):
        raise RuntimeError("A310 portfolio is not an exact cover")
    return result


def guarantee(
    *, portfolio: Sequence[int], multicenter: Sequence[int], baseline: Sequence[int]
) -> dict[str, Any]:
    ranks = {
        "portfolio": {int(value): rank for rank, value in enumerate(portfolio, 1)},
        "multicenter": {
            int(value): rank for rank, value in enumerate(multicenter, 1)
        },
        "baseline": {int(value): rank for rank, value in enumerate(baseline, 1)},
    }
    factors = []
    for cell in range(CELLS):
        best = min(ranks["multicenter"][cell], ranks["baseline"][cell])
        observed = ranks["portfolio"][cell]
        if observed > 2 * best:
            raise RuntimeError("A310 factor-two guarantee failed")
        factors.append(observed / best)
    return {
        "statement": "R_A310 <= 2 * min(R_multicenter_band, R_A300_baseline)",
        "checked_prefix_cells": CELLS,
        "violations": 0,
        "maximum_observed_regret_factor": max(factors),
        "maximum_observed_regret_bits": math.log2(max(factors)),
        "frozen_worst_case_bound_factor": 2,
        "frozen_worst_case_bound_bits": 1.0,
    }


def reconstruct() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    design, commitment = load_frozen_contract()
    a300_protocol, _preflight, a300_order = A300.load_order(
        A300_PROTOCOL_SHA256,
        A300_PREFLIGHT_SHA256,
        A300_ORDER_SHA256,
    )
    if a300_protocol["public_challenge_sha256"] != commitment["public_challenge_sha256"]:
        raise RuntimeError("A310 target challenge differs from commitment")
    fine = a300_order["component_orders"]["A295_fine_selected_channel"]
    baseline = a300_order["portfolio_order"]
    centers = design["operator_contract"]["empirical_centers_one_based"]
    band = multicenter_band(fine=fine, centers=centers)
    portfolio = two_arm_portfolio(multicenter=band, baseline=baseline)
    hashes = {
        "multicenter_band_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in band)
        ),
        "baseline_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in baseline)
        ),
        "portfolio_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in portfolio)
        ),
    }
    for key, observed in hashes.items():
        if observed != commitment[key]:
            raise RuntimeError(f"A310 reconstructed {key} differs from commitment")
    return a300_order, {
        "centers": centers,
        "multicenter": band,
        "baseline": baseline,
        "portfolio": portfolio,
        "hashes": hashes,
        "guarantee": guarantee(
            portfolio=portfolio,
            multicenter=band,
            baseline=baseline,
        ),
    }, commitment


def materialize() -> dict[str, Any]:
    if ORDER.exists():
        raise FileExistsError("A310 order already exists")
    _a300_order, reconstructed, commitment = reconstruct()
    result_available = A309_RESULT.exists()
    payload = {
        "schema": "chacha20-round20-w43-empirical-multicenter-band-counterfactual-a310-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_REVEAL_EXACT_ORDER_COMMITMENT_RECONSTRUCTED",
        "design_sha256": DESIGN_SHA256,
        "commitment_sha256": COMMITMENT_SHA256,
        "public_challenge_sha256": commitment["public_challenge_sha256"],
        "empirical_centers_one_based": reconstructed["centers"],
        "component_orders": {
            "empirical_multicenter_band": reconstructed["multicenter"],
            "A300_three_operator_baseline": reconstructed["baseline"],
        },
        "component_order_sha256": {
            "empirical_multicenter_band": reconstructed["hashes"][
                "multicenter_band_order_uint16be_sha256"
            ],
            "A300_three_operator_baseline": reconstructed["hashes"][
                "baseline_order_uint16be_sha256"
            ],
        },
        "portfolio_order": reconstructed["portfolio"],
        "portfolio_order_uint16be_sha256": reconstructed["hashes"][
            "portfolio_order_uint16be_sha256"
        ],
        "portfolio_guarantee": reconstructed["guarantee"],
        "A309_result_available_at_materialization": result_available,
        "order_bytes_committed_before_A309_reveal": True,
        "information_boundary": json.loads(DESIGN.read_bytes())["information_boundary"],
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "commitment": {
                "path": relative(COMMITMENT),
                "sha256": COMMITMENT_SHA256,
            },
            "A300_order": {
                "path": relative(A300.ORDER),
                "sha256": A300_ORDER_SHA256,
            },
            "runner": {
                "path": relative(Path(__file__)),
                "sha256": file_sha256(Path(__file__)),
            },
            "test": {"path": relative(A310_TEST), "sha256": file_sha256(A310_TEST)},
            "reproducer": {
                "path": relative(A310_REPRO),
                "sha256": file_sha256(A310_REPRO),
            },
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "commitment_sha256": COMMITMENT_SHA256,
            "component_order_sha256": payload["component_order_sha256"],
            "portfolio_order_uint16be_sha256": payload[
                "portfolio_order_uint16be_sha256"
            ],
            "portfolio_guarantee": payload["portfolio_guarantee"],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(ORDER, payload)
    return payload


def load_order(expected_order_sha256: str) -> dict[str, Any]:
    if file_sha256(ORDER) != expected_order_sha256:
        raise RuntimeError("A310 order artifact hash differs")
    value = json.loads(ORDER.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-empirical-multicenter-band-counterfactual-a310-order-v1"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("commitment_sha256") != COMMITMENT_SHA256
        or value.get("order_bytes_committed_before_A309_reveal") is not True
        or value.get("portfolio_order_uint16be_sha256")
        != json.loads(COMMITMENT.read_bytes())["portfolio_order_uint16be_sha256"]
        or value.get("portfolio_guarantee", {}).get("violations") != 0
    ):
        raise RuntimeError("A310 order semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    _a300, reconstructed, _commitment = reconstruct()
    if reconstructed["portfolio"] != value["portfolio_order"]:
        raise RuntimeError("A310 order reconstruction differs")
    return value


def rank_analysis(prefix: int, order: Mapping[str, Any]) -> dict[str, Any]:
    components = order["component_orders"]
    multicenter = [int(value) for value in components["empirical_multicenter_band"]]
    baseline = [int(value) for value in components["A300_three_operator_baseline"]]
    portfolio = [int(value) for value in order["portfolio_order"]]
    ranks = {
        "A310_multicenter_plus_baseline": portfolio.index(prefix) + 1,
        "empirical_multicenter_band": multicenter.index(prefix) + 1,
        "A300_three_operator_baseline": baseline.index(prefix) + 1,
    }
    best = min(
        ranks["empirical_multicenter_band"],
        ranks["A300_three_operator_baseline"],
    )
    if ranks["A310_multicenter_plus_baseline"] > 2 * best:
        raise RuntimeError("A310 observed counterfactual rank violates guarantee")
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "best_arm_rank_one_based": best,
        "portfolio_regret_factor_vs_best_arm": (
            ranks["A310_multicenter_plus_baseline"] / best
        ),
        "portfolio_gain_bits_vs_complete_domain": math.log2(
            CELLS / ranks["A310_multicenter_plus_baseline"]
        ),
        "counterfactual_only_no_duplicate_candidate_execution": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A310:prospective_multicenter_counterfactual_evaluated"
    writer = CausalWriter(api_id="a310w43")
    writer._rules = []
    writer.add_rule(
        name="three_confirmed_ranks_to_multicenter_order",
        description="The three confirmed fine ranks define an exact multicenter order whose byte hash was committed before A300 was revealed.",
        pattern=["A295_A303_A305_confirmed_ranks", "pre_reveal_order_hash"],
        conclusion="A310_frozen_multicenter_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="confirmed_A300_prefix_to_counterfactual_rank",
        description="After independent A309 recovery, the confirmed prefix is located in the unchanged committed order without duplicate candidate execution.",
        pattern=["A310_frozen_multicenter_order", "A309_confirmed_prefix"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A295_A303_A305:confirmed_fine_rank_centers",
        mechanism="pre_reveal_exact_multicenter_order_commitment",
        outcome="A310:frozen_multicenter_plus_baseline_order",
        confidence=1.0,
        source=COMMITMENT_SHA256,
        quantification=json.dumps(payload["order_commitment"], sort_keys=True),
        evidence=json.dumps(payload["portfolio_guarantee"], sort_keys=True),
        domain="AI-native target-blind ChaCha20-R20 rank operator",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A310:frozen_multicenter_plus_baseline_order",
        mechanism="post_confirmation_rank_only_evaluation",
        outcome=terminal,
        confidence=1.0,
        source=payload["A309_result_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="prospective counterfactual search analysis",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A295_A303_A305:confirmed_fine_rank_centers",
        mechanism="materialized_multicenter_commitment_evaluation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A310_multicenter_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A310 prospective multicenter counterfactual",
        entities=[
            "A295_A303_A305:confirmed_fine_rank_centers",
            "A310:frozen_multicenter_plus_baseline_order",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_multicenter_execution_or_width_conditioned_operator_selection",
        confidence=1.0,
        suggested_queries=[
            "Which pre-reveal band operator should be carried into the next fresh W43 or W44 target?"
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
        reader.api_id != "a310w43"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A310 authentic Causal reopen gate failed")
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


def evaluate(*, expected_order_sha256: str, expected_a309_result_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A310 evaluation artifacts already exist")
    order = load_order(expected_order_sha256)
    if file_sha256(A309_RESULT) != expected_a309_result_sha256:
        raise RuntimeError("A310 A309 result hash differs")
    a309 = json.loads(A309_RESULT.read_bytes())
    if (
        a309.get("confirmation", {}).get("all_blocks_match") is not True
        or a309.get("public_challenge_sha256") != order["public_challenge_sha256"]
    ):
        raise RuntimeError("A310 requires the independently confirmed A309 target")
    prefix = int(a309["discovery"]["fine_prefix12"])
    ranks = rank_analysis(prefix, order)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w43-empirical-multicenter-band-counterfactual-a310-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_REVEAL_COMMITTED_MULTICENTER_COUNTERFACTUAL_EVALUATED",
        "design_sha256": DESIGN_SHA256,
        "commitment_sha256": COMMITMENT_SHA256,
        "order_sha256": expected_order_sha256,
        "A309_result_sha256": expected_a309_result_sha256,
        "public_challenge_sha256": order["public_challenge_sha256"],
        "order_commitment": json.loads(COMMITMENT.read_bytes()),
        "rank_analysis": ranks,
        "portfolio_guarantee": order["portfolio_guarantee"],
        "candidate_execution": {
            "performed_by_A310": False,
            "duplicate_candidate_execution": False,
            "confirmed_prefix_source": "A309_dual_independent_confirmation",
        },
        "information_boundary": order["information_boundary"],
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "commitment": {
                "path": relative(COMMITMENT),
                "sha256": COMMITMENT_SHA256,
            },
            "order": {"path": relative(ORDER), "sha256": expected_order_sha256},
            "A309_result": {
                "path": relative(A309_RESULT),
                "sha256": expected_a309_result_sha256,
            },
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "order_commitment": payload["order_commitment"],
            "rank_analysis": ranks,
            "portfolio_guarantee": payload["portfolio_guarantee"],
            "candidate_execution": payload["candidate_execution"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A310 — pre-reveal multicenter counterfactual on A300 W43\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- A310 portfolio rank: **{ranks['prefix_ranks_one_based']['A310_multicenter_plus_baseline']} / 4,096**\n"
            f"- Multicenter-band rank: **{ranks['prefix_ranks_one_based']['empirical_multicenter_band']} / 4,096**\n"
            f"- A300 baseline rank: **{ranks['prefix_ranks_one_based']['A300_three_operator_baseline']} / 4,096**\n"
            "- Exact order bytes committed before A300/A309 reveal: **yes**\n"
            "- Duplicate candidate execution: **none**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode()
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "commitment_sha256": COMMITMENT_SHA256,
        "order_materialized": ORDER.exists(),
        "evaluation_complete": RESULT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--materialize", action="store_true")
    mode.add_argument("--evaluate", action="store_true")
    parser.add_argument("--expected-order-sha256")
    parser.add_argument("--expected-a309-result-sha256")
    args = parser.parse_args()
    if args.analyze:
        output = analyze()
    elif args.materialize:
        value = materialize()
        output = {
            "order": relative(ORDER),
            "order_sha256": file_sha256(ORDER),
            "portfolio_order_uint16be_sha256": value[
                "portfolio_order_uint16be_sha256"
            ],
            "A309_result_available_at_materialization": value[
                "A309_result_available_at_materialization"
            ],
        }
    else:
        if not args.expected_order_sha256 or not args.expected_a309_result_sha256:
            parser.error(
                "--evaluate requires --expected-order-sha256 and --expected-a309-result-sha256"
            )
        value = evaluate(
            expected_order_sha256=args.expected_order_sha256,
            expected_a309_result_sha256=args.expected_a309_result_sha256,
        )
        output = {
            "result": relative(RESULT),
            "result_sha256": file_sha256(RESULT),
            "causal_sha256": value["causal"]["sha256"],
            "rank_analysis": value["rank_analysis"],
        }
    print(json.dumps(output, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
