#!/usr/bin/env python3
"""A322: execute the independent-holdout-selected W45 search order."""

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

DESIGN = CONFIGS / "chacha20_round20_holdout_selected_w45_recovery_a322_design_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
CAUSAL = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.causal"
REPORT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.md"
PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_progress_v1.json"

A321_RUNNER = RESEARCH / "experiments/chacha20_round20_holdout_selected_w45_operator_a321.py"
A314_RUNNER = RESEARCH / "experiments/chacha20_round20_w45_fine_band_recovery_a314.py"
A322_TEST = ROOT / "tests/test_chacha20_round20_holdout_selected_w45_recovery_a322.py"
A322_REPRO = ROOT / "scripts/reproduce_chacha20_round20_holdout_selected_w45_recovery_a322.sh"

ATTEMPT_ID = "A322"
DESIGN_SHA256 = "9480d96e6b51309a23ad29e1b579f17398d97770319410acbadd0b91d476e72a"
A321_DESIGN_SHA256 = "3db5966ca254f8a5342399445d992db672fd0e9e5d40bc8ad401b0ae8cbd1e92"
A314_PROTOCOL_SHA256 = "17877a15624f7ab6fec1333c57260fa447d71d1112b9df5aa8219f8403968574"
A314_PREFLIGHT_SHA256 = "cfb5bacd6e6e17479260d8a2cacd2f9808afc632d82e31f80e8dc6ed2d4159a4"
A314_ORDER_SHA256 = "581c7cbec3900034934525e325ab41f1cc55e79a75aaa1757b0d5bd2ffc3b034"
A311_QUALIFICATION_SHA256 = "37b258ab7c46f78a702ed92b3c1b72c5b5948113cf67a61a4a1f33e938e9b31a"
CELLS = 1 << 12


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A322 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A321 = load_module(A321_RUNNER, "a322_a321_common")
A314 = load_module(A314_RUNNER, "a322_a314_common")
file_sha256 = A314.file_sha256
canonical_sha256 = A314.canonical_sha256
atomic_json = A314.atomic_json
atomic_bytes = A314.atomic_bytes
relative = A314.relative
path_from_ref = A314.path_from_ref
anchor = A314.anchor
DOTCAUSAL_SRC = A314.DOTCAUSAL_SRC


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A322 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    execution = design.get("execution_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-holdout-selected-w45-recovery-a322-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A313_recovery_is_running_before_A321_selection_and_before_any_A313_or_A314_candidate_or_result_exists"
        or execution.get("candidates_per_prefix_group") != A314.GROUP_SIZE
        or execution.get("slabs_per_prefix_group") != 4
        or execution.get("candidates_per_slab") != 1 << 31
        or execution.get("host_refresh_interval_prefix_groups")
        != A314.HOST_REFRESH_GROUPS
        or execution.get("manual_order_override_after_A321_selection") is not False
        or execution.get("A314_target_label_or_candidate_used_for_A321_selection")
        is not False
        or boundary.get("A313_result_available_at_design_freeze") is not False
        or boundary.get("A321_selected_operator_available_at_design_freeze") is not False
        or boundary.get("A314_result_available_at_design_freeze") is not False
        or boundary.get("A314_candidate_available_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A314_for_order_selection") != 0
    ):
        raise RuntimeError("A322 frozen design semantics differ")
    anchors = design["source_anchors"]
    for key, value in anchors.items():
        if key.endswith("_path"):
            anchor(path_from_ref(value), anchors[key.removesuffix("_path") + "_sha256"])
    return design


def all_w45_orders() -> dict[str, list[int]]:
    rows = A321.candidate_pairs()
    orders = {row["name"]: row["W45_order"] for row in rows}
    a314 = json.loads(A314.ORDER.read_bytes())
    orders["A314_three_arm_portfolio"] = [int(value) for value in a314["portfolio_order"]]
    for name, order in orders.items():
        A321._exact_order(order, f"A322 {name}")  # noqa: SLF001
    return orders


def rank_panel(*, prefix: int, selected_operator: str) -> dict[str, Any]:
    orders = all_w45_orders()
    if selected_operator not in A321.CANDIDATE_NAMES:
        raise ValueError("A322 selected operator is outside frozen A321 candidates")
    ranks = {name: order.index(prefix) + 1 for name, order in orders.items()}
    selected_rank = ranks[selected_operator]
    baseline_rank = ranks["A314_three_arm_portfolio"]
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "selected_operator": selected_operator,
        "prefix_ranks_one_based": ranks,
        "selected_rank_one_based": selected_rank,
        "A314_baseline_rank_one_based": baseline_rank,
        "selected_gain_bits_vs_complete_prefix_domain": math.log2(CELLS / selected_rank),
        "selected_speed_factor_vs_A314_baseline": baseline_rank / selected_rank,
        "selected_rank_computed_only_after_independent_confirmation": True,
    }


def materialize(*, expected_a321_commitment_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, RESULT, CAUSAL, REPORT, PROGRESS)):
        raise FileExistsError("A322 artifacts already exist")
    if A314.RESULT.exists():
        raise RuntimeError("A322 protocol must freeze before any A314 result exists")
    design = load_design()
    a321_commitment, a321_order = A321.load_frozen(expected_a321_commitment_sha256)
    selected_order = A321._exact_order(  # noqa: SLF001
        a321_order["selected_W45_order"], "A322 selected W45 order"
    )
    selected_hash = A321._order_sha(selected_order)  # noqa: SLF001
    if selected_hash != a321_order["selection"]["selected_W45_order_uint16be_sha256"]:
        raise RuntimeError("A322 selected order hash differs")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-holdout-selected-w45-recovery-a322-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "frozen_after_A321_holdout_selection_before_any_A314_candidate_execution_or_result",
        "design_sha256": DESIGN_SHA256,
        "A321_commitment_sha256": expected_a321_commitment_sha256,
        "A321_order_sha256": a321_commitment["order_sha256"],
        "selected_operator": a321_order["selection"]["selected_operator"],
        "selected_family": a321_order["selection"]["selected_family"],
        "selected_A313_calibration_rank_one_based": a321_order["selection"][
            "selected_calibration_rank_one_based"
        ],
        "selected_W45_order_uint16be_sha256": selected_hash,
        "selected_W45_order": selected_order,
        "public_challenge_sha256": json.loads(A314.PROTOCOL.read_bytes())[
            "public_challenge_sha256"
        ],
        "execution_contract": design["execution_contract"],
        "information_boundary": {
            **design["information_boundary"],
            "A313_result_used_only_through_frozen_A321_selection": True,
            "A314_result_available_at_protocol_freeze": False,
            "A314_candidate_or_prefix_rank_available_at_protocol_freeze": False,
            "A314_filter_outcome_available_at_protocol_freeze": False,
            "target_labels_used_from_A314_for_order_selection": 0,
        },
        "anchors": {
            "design": {"path": relative(DESIGN), "sha256": DESIGN_SHA256},
            "A321_design": {
                "path": relative(A321.DESIGN),
                "sha256": A321_DESIGN_SHA256,
            },
            "A321_commitment": {
                "path": relative(A321.COMMITMENT),
                "sha256": expected_a321_commitment_sha256,
            },
            "A321_order": {
                "path": relative(A321.ORDER),
                "sha256": a321_commitment["order_sha256"],
            },
            "A314_protocol": {
                "path": relative(A314.PROTOCOL),
                "sha256": A314_PROTOCOL_SHA256,
            },
            "A314_preflight": {
                "path": relative(A314.PREFLIGHT),
                "sha256": A314_PREFLIGHT_SHA256,
            },
            "A314_order": {
                "path": relative(A314.ORDER),
                "sha256": A314_ORDER_SHA256,
            },
            "A311_qualification": {
                "path": relative(A314.A311.QUALIFICATION),
                "sha256": A311_QUALIFICATION_SHA256,
            },
            "runner": {"path": relative(Path(__file__)), "sha256": file_sha256(Path(__file__))},
            "test": {"path": relative(A322_TEST), "sha256": file_sha256(A322_TEST)},
            "reproducer": {"path": relative(A322_REPRO), "sha256": file_sha256(A322_REPRO)},
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "A321_commitment_sha256": expected_a321_commitment_sha256,
            "selected_operator": payload["selected_operator"],
            "selected_A313_calibration_rank_one_based": payload[
                "selected_A313_calibration_rank_one_based"
            ],
            "selected_W45_order_uint16be_sha256": selected_hash,
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "execution_contract": payload["execution_contract"],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return {
        "protocol": relative(PROTOCOL),
        "protocol_sha256": file_sha256(PROTOCOL),
        "selected_operator": payload["selected_operator"],
        "selected_family": payload["selected_family"],
        "selected_A313_calibration_rank_one_based": payload[
            "selected_A313_calibration_rank_one_based"
        ],
        "selected_W45_order_uint16be_sha256": selected_hash,
        "public_challenge_sha256": payload["public_challenge_sha256"],
    }


def load_protocol(expected_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A322 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-holdout-selected-w45-recovery-a322-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "frozen_after_A321_holdout_selection_before_any_A314_candidate_execution_or_result"
        or value.get("information_boundary", {}).get(
            "A314_candidate_or_prefix_rank_available_at_protocol_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get(
            "target_labels_used_from_A314_for_order_selection"
        )
        != 0
    ):
        raise RuntimeError("A322 frozen protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    _commitment, selected = A321.load_frozen(value["A321_commitment_sha256"])
    exact = A321._exact_order(value["selected_W45_order"], "A322 protocol order")  # noqa: SLF001
    if (
        exact != selected["selected_W45_order"]
        or A321._order_sha(exact) != value["selected_W45_order_uint16be_sha256"]  # noqa: SLF001
        or value["selected_operator"] != selected["selection"]["selected_operator"]
    ):
        raise RuntimeError("A322 selected order reconstruction differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A322:confirmed_holdout_selected_fullround_W45_recovery"
    writer = CausalWriter(api_id="a322w45")
    writer._rules = []
    writer.add_rule(
        name="holdout_selected_order_to_complete_W45_grouped_search",
        description="The exact A321-selected order executes four complete 2^31 slabs per prefix before factual and matched-control outcome evaluation.",
        pattern=["A321_frozen_holdout_selected_W45_order", "A311_exact_W45_group_engine"],
        conclusion="A322_sole_factual_W45_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="factual_W45_model_to_dual_fullround_confirmation",
        description="Independent byte and word implementations confirm the recovered 45-bit assignment across eight 20-round-plus-feed-forward blocks.",
        pattern=["A322_sole_factual_W45_model", "dual_eight_block_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A321:frozen_holdout_selected_W45_execution_order",
        mechanism="four_complete_2pow31_slabs_per_selected_prefix",
        outcome="A322:sole_factual_W45_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="holdout-selected full-round ChaCha20 W45 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A322:sole_factual_W45_model",
        mechanism="dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W45 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A321:frozen_holdout_selected_W45_execution_order",
        mechanism="materialized_selected_recovery_and_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A322_holdout_selected_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A322 holdout-selected full-round W45 recovery",
        entities=[
            "A321:frozen_holdout_selected_W45_execution_order",
            "A322:sole_factual_W45_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_holdout_selected_W45_replication_or_W46_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the same frozen holdout-selection rule retain a strict-subset advantage on a second unseen W45 target or W46?"
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
        reader.api_id != "a322w45"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A322 authentic Causal reopen gate failed")
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


def recover(
    *, expected_protocol_sha256: str, expected_a311_qualification_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A322 result artifacts already exist")
    if A314.RESULT.exists():
        raise RuntimeError("A322 selected-order execution must precede A314 result")
    protocol = load_protocol(expected_protocol_sha256)
    if expected_a311_qualification_sha256 != A311_QUALIFICATION_SHA256:
        raise RuntimeError("A322 qualification hash differs from frozen design")
    qualification = A314.load_a311_qualification(expected_a311_qualification_sha256)
    a314_protocol, _preflight, _order = A314.load_order(
        A314_PROTOCOL_SHA256, A314_PREFLIGHT_SHA256, A314_ORDER_SHA256
    )
    challenge = a314_protocol["public_challenge"]
    a311_protocol = A314.A311.load_protocol(A314.A311_PROTOCOL_SHA256)
    executable_row = a311_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A314.A311.A307.A304.GroupedMetalHost(
            executable,
            A314.A311.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            PROGRESS,
            {
                "schema": "chacha20-round20-holdout-selected-w45-recovery-a322-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": expected_protocol_sha256,
                "selected_operator": protocol["selected_operator"],
                "selected_W45_order_uint16be_sha256": protocol[
                    "selected_W45_order_uint16be_sha256"
                ],
                "A311_qualification_sha256": expected_a311_qualification_sha256,
                **dict(row),
            },
        )

    discovery = A314.ordered_discovery(
        host_factory=host_factory,
        challenge=challenge,
        order=protocol["selected_W45_order"],
        host_refresh_groups=A314.HOST_REFRESH_GROUPS,
        progress_callback=write_progress,
    )
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A322 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = A314.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A322 dual independent confirmation failed")
    ranks = rank_panel(
        prefix=int(discovery["prefix12"]),
        selected_operator=protocol["selected_operator"],
    )
    if ranks["selected_rank_one_based"] != discovery["executed_prefix_groups"]:
        raise RuntimeError("A322 discovery rank differs from selected order")
    strict_subset = discovery["executed_prefix_groups"] < CELLS
    evidence_stage = (
        "FULLROUND_R20_HOLDOUT_SELECTED_W45_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_HOLDOUT_SELECTED_W45_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-holdout-selected-w45-recovery-a322-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "execution_branch": "A321_holdout_selected_four_slab_grouped_W45_recovery",
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "A321_commitment_sha256": protocol["A321_commitment_sha256"],
        "A314_order_sha256": A314_ORDER_SHA256,
        "A311_qualification_sha256": expected_a311_qualification_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "selected_operator": protocol["selected_operator"],
        "selected_family": protocol["selected_family"],
        "selected_A313_calibration_rank_one_based": protocol[
            "selected_A313_calibration_rank_one_based"
        ],
        "selected_W45_order_uint16be_sha256": protocol[
            "selected_W45_order_uint16be_sha256"
        ],
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W45_group_candidates": qualification["complete_group_gate"][
                "logical_candidates"
            ],
            "synthetic_filter_exact": qualification["synthetic_filter_exact"],
            "production_target_used": False,
        },
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "strict_subset_of_complete_domain": strict_subset,
        "information_boundary": protocol["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "protocol": anchor(PROTOCOL, expected_protocol_sha256),
            "A321_commitment": anchor(
                A321.COMMITMENT, protocol["A321_commitment_sha256"]
            ),
            "A321_order": anchor(A321.ORDER, protocol["A321_order_sha256"]),
            "A314_protocol": anchor(A314.PROTOCOL, A314_PROTOCOL_SHA256),
            "A314_preflight": anchor(A314.PREFLIGHT, A314_PREFLIGHT_SHA256),
            "A314_order": anchor(A314.ORDER, A314_ORDER_SHA256),
            "A311_qualification": anchor(
                A314.A311.QUALIFICATION, expected_a311_qualification_sha256
            ),
        },
    }
    stable_discovery = {
        key: value for key, value in discovery.items() if not key.startswith("volatile_")
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "selected_operator": protocol["selected_operator"],
            "selected_W45_order_uint16be_sha256": protocol[
                "selected_W45_order_uint16be_sha256"
            ],
            "discovery": stable_discovery,
            "A311_qualification_sha256": expected_a311_qualification_sha256,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
            "rank_analysis": ranks,
            "confirmation": confirmation,
            "qualification_gate": payload["qualification_gate"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A322 — holdout-selected full-round ChaCha20 W45 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Operator selected on independent W44 holdout: **{protocol['selected_operator']}**\n"
            f"- W44 calibration rank: **{protocol['selected_A313_calibration_rank_one_based']} / 4,096**\n"
            f"- W45 execution rank: **{ranks['selected_rank_one_based']} / 4,096**\n"
            f"- Complete candidate evaluations: **{discovery['executed_assignments']:,} / {A314.DOMAIN_SIZE:,}**\n"
            f"- Recovered W45 assignment: **0x{candidate:012x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every executed prefix: **four complete 2^31 slabs before outcome evaluation**\n"
            "- Matched one-bit control: **zero candidates**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    response: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "A321_selection_complete": A321.ORDER.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "A314_result_complete": A314.RESULT.exists(),
        "A322_result_complete": RESULT.exists(),
        "progress_exists": PROGRESS.exists(),
    }
    if PROTOCOL.exists():
        response["protocol_sha256"] = file_sha256(PROTOCOL)
        protocol = json.loads(PROTOCOL.read_bytes())
        response["selected_operator"] = protocol["selected_operator"]
        response["selected_A313_calibration_rank_one_based"] = protocol[
            "selected_A313_calibration_rank_one_based"
        ]
    if PROGRESS.exists():
        response["progress"] = json.loads(PROGRESS.read_bytes())
    if RESULT.exists():
        response["result_sha256"] = file_sha256(RESULT)
        response["evidence_stage"] = json.loads(RESULT.read_bytes())["evidence_stage"]
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--materialize", action="store_true")
    action.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-a321-commitment-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-a311-qualification-sha256")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.materialize:
        if not args.expected_a321_commitment_sha256:
            parser.error("--materialize requires --expected-a321-commitment-sha256")
        payload = materialize(
            expected_a321_commitment_sha256=args.expected_a321_commitment_sha256
        )
    else:
        if not args.expected_protocol_sha256 or not args.expected_a311_qualification_sha256:
            parser.error(
                "--recover requires --expected-protocol-sha256 and --expected-a311-qualification-sha256"
            )
        payload = recover(
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_a311_qualification_sha256=args.expected_a311_qualification_sha256,
        )
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
