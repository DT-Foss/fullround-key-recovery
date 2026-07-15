#!/usr/bin/env python3
"""Prospective full-round W24 transfer of A204's retained reverse operator."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"
ARTIFACTS = RESEARCH / "artifacts/a290_chacha20_r20_w24_reverse_global"

A287_SOURCE = RESEARCH / "experiments/chacha20_round20_w24_global_portfolio_a287.py"
A289_RESULT = RESULTS / "chacha20_round20_w24_cross_solver_portfolio_a289_v1.json"
A204R_SOURCE = (
    RESEARCH
    / "experiments/chacha20_round10_external_cnf_reverse_causal_canonicalize.py"
)
A204R_RESULT = RESULTS / "chacha20_round10_external_cnf_reverse_canonical_v1.json"
A204R_CAUSAL = RESULTS / "chacha20_round10_external_cnf_reverse_canonical_v1.causal"
ROOT_REFERENCE_SOURCE = RESEARCH / "experiments/chacha20_round20_multitarget_root_confirm.py"
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)

PROTOCOL = CONFIGS / "chacha20_round20_w24_reverse_global_transfer_a290_v1.json"
RESULT = RESULTS / "chacha20_round20_w24_reverse_global_transfer_a290_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w24_reverse_global_transfer_a290_v1.causal"
REPORT = REPORTS / "CHACHA20_ROUND20_W24_REVERSE_GLOBAL_TRANSFER_A290_V1.md"

ATTEMPT_ID = "A290"
A204R_RESULT_SHA256 = "51e96cec45484fa7c6d388a1aa53bcf76cd24d0884da83a54ba42140a1a18ada"
A204R_CAUSAL_SHA256 = "6dbf196b9d764e2f21f5e0f3fb89924e90de696bc44990ad43f2b1a16102110f"
EXPECTED_SOURCE_GAP = "prospective_fullround_W24_global_reverse_operator"


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A287 = load_module(A287_SOURCE, "a290_a287_frozen_dependency")


def load_a204r() -> tuple[dict[str, Any], dict[str, Any]]:
    A287.anchor(A204R_RESULT, A204R_RESULT_SHA256)
    A287.anchor(A204R_CAUSAL, A204R_CAUSAL_SHA256)
    payload = json.loads(A204R_RESULT.read_bytes())
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(A204R_CAUSAL), verify_integrity=True)
    gaps = list(reader._gaps)
    if (
        payload.get("schema")
        != "chacha20-round10-external-cnf-reverse-canonical-v1"
        or payload.get("solver_evidence_rerun") is not False
        or payload.get("authentic_causal", {}).get("sha256")
        != A204R_CAUSAL_SHA256
        or reader.version != 1
        or reader.api_id != "a204rv"
        or len(gaps) != 1
        or gaps[0].get("expected_object_type") != EXPECTED_SOURCE_GAP
    ):
        raise RuntimeError("A290 A204R authentic Causal breadcrumb differs")
    return payload, gaps[0]


def execution_plan(preflight: dict[str, Any]) -> dict[str, Any]:
    arms = {}
    for target_name, source_name in (
        ("base_reverse", "base_default"),
        ("bfs_far_reverse", "bfs_far_sat"),
    ):
        source = preflight["arms"][source_name]
        mapping = [int(value) for value in source["model_one_literals_bit0_upward"]]
        if len(mapping) != 24 or len({abs(value) for value in mapping}) != 24:
            raise RuntimeError("A290 W24 literal mapping differs")
        arms[target_name] = {
            "cnf": source["cnf"],
            "model_one_literals_bit0_upward": mapping,
            "source_A287_CNF_arm": source_name,
            "operator": "cadical_reverse_true",
            "cadical_configuration": "reverse=true",
        }
    return {
        "primitive": "standard_ChaCha20_block_function",
        "rounds": 20,
        "feedforward_included": True,
        "unknown_key_bits": 24,
        "known_key_bits": 232,
        "public_input_output_blocks": 8,
        "constrained_output_bits": 4096,
        "source_operator": "A204R_unique_global_cadical_reverse",
        "arms": arms,
        "seconds_per_arm": A287.SOLVER_SECONDS,
        "parallel_solver_processes": 2,
        "first_exact_SAT_terminates_unfinished_sibling": True,
        "no_prefix_or_candidate_label_available": True,
        "no_complete_candidate_enumeration": True,
        "confirmation": "standalone_RFC_operation_reference_all_eight_blocks",
        "control": "one_bit_flipped_first_standard_output_block",
    }


def freeze(expected_a287_preflight_sha256: str) -> dict[str, Any]:
    if PROTOCOL.exists():
        raise FileExistsError(PROTOCOL)
    if A287.RESULT.exists() or A289_RESULT.exists():
        raise RuntimeError("A290 must freeze before either active W24 portfolio returns")
    a204r, source_gap = load_a204r()
    preflight, a287_protocol = A287.load_preflight(expected_a287_preflight_sha256)
    plan = execution_plan(preflight)
    protocol = {
        "schema": "chacha20-round20-w24-reverse-global-transfer-a290-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A204R_reverse_operator_and_two_global_W24_views_frozen_before_execution",
        "public_challenge_sha256": a287_protocol["public_challenge_sha256"],
        "execution_plan": plan,
        "execution_plan_sha256": A287.canonical_sha256(plan),
        "source_causal_gap": source_gap,
        "anchors": {
            "runner": A287.anchor(Path(__file__)),
            "A287_source": A287.anchor(A287_SOURCE),
            "A287_protocol": A287.anchor(
                A287.PROTOCOL, preflight["protocol"]["sha256"]
            ),
            "A287_preflight": A287.anchor(
                A287.PREFLIGHT, expected_a287_preflight_sha256
            ),
            "A204R_source": A287.anchor(A204R_SOURCE),
            "A204R_result": A287.anchor(A204R_RESULT, A204R_RESULT_SHA256),
            "A204R_causal": A287.anchor(A204R_CAUSAL, A204R_CAUSAL_SHA256),
            "cadical": A287.anchor(A287.CADICAL),
            "root_reference": A287.anchor(ROOT_REFERENCE_SOURCE),
        },
        "information_boundary": {
            "A204R_gap_personally_read_before_design": True,
            "A287_or_A289_result_available_at_freeze": False,
            "secret_assignment_target_prefix_or_model_available": False,
            "both_CNF_views_reverse_operator_and_budgets_frozen": True,
            "any_A290_solver_execution_started": False,
            "UNKNOWN_will_not_be_treated_as_UNSAT": True,
            "source_solver_evidence_rerun": a204r["solver_evidence_rerun"],
        },
    }
    protocol["scientific_design_sha256"] = A287.canonical_sha256(
        {
            "public_challenge_sha256": protocol["public_challenge_sha256"],
            "execution_plan": protocol["execution_plan"],
            "source_causal_gap": protocol["source_causal_gap"],
            "information_boundary": protocol["information_boundary"],
            "anchors": protocol["anchors"],
        }
    )
    A287.atomic_json(PROTOCOL, protocol)
    return protocol


def load_protocol(expected_sha256: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if A287.file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A290 protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    if (
        protocol.get("schema")
        != "chacha20-round20-w24-reverse-global-transfer-a290-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "A204R_reverse_operator_and_two_global_W24_views_frozen_before_execution"
        or protocol.get("execution_plan_sha256")
        != A287.canonical_sha256(protocol.get("execution_plan"))
        or protocol.get("source_causal_gap", {}).get("expected_object_type")
        != EXPECTED_SOURCE_GAP
    ):
        raise RuntimeError("A290 protocol semantics differ")
    for row in protocol["anchors"].values():
        A287.anchor(A287.anchored_path(row["path"]), row["sha256"])
    _, source_gap = load_a204r()
    if source_gap != protocol["source_causal_gap"]:
        raise RuntimeError("A290 source gap changed")
    preflight, a287_protocol = A287.load_preflight(
        protocol["anchors"]["A287_preflight"]["sha256"]
    )
    if a287_protocol["public_challenge_sha256"] != protocol["public_challenge_sha256"]:
        raise RuntimeError("A290 public challenge differs")
    return protocol, preflight, a287_protocol


def build_causal(payload: dict[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    reader_source = Path(inspect.getsourcefile(CausalReader) or "")
    retained = payload["confirmation"] is not None
    terminal = (
        "A290:confirmed_fullround_W24_reverse_recovery"
        if retained
        else "A290:measured_fullround_W24_reverse_budget_boundary"
    )
    writer = CausalWriter(api_id="a290rv")
    writer._rules = []
    writer.add_rule(
        name="retained_reverse_operator_to_fullround_confirmation",
        description=(
            "The A204R reverse operator transfers to full-round W24 only when a "
            "returned global model passes exact CNF and 4096-bit confirmation."
        ),
        pattern=["A204R_reverse_operator", "W24_global_model", "4096_bit_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="reverse_global_boundary_to_partition",
        description=(
            "A two-view reverse budget boundary joins the other global boundaries "
            "as input to the exact disjoint W24 partition."
        ),
        pattern=["two_reverse_global_boundaries", "no_model_disclosure"],
        conclusion="A288_exact_disjoint_partition",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A204R:personally_read_reverse_global_operator_gap",
        mechanism="freeze_reverse_true_on_native_and_BFS_far_W24_CNF_views",
        outcome="A290:frozen_reverse_global_portfolio",
        confidence=1.0,
        source=payload["protocol"]["sha256"],
        quantification="24 unknown key bits; 8 blocks; 4096 output bits",
        evidence=payload["evidence_stage"],
        domain="prospective full-round operator transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A290:frozen_reverse_global_portfolio",
        mechanism="parallel_cadical_reverse_true_global_search",
        outcome=("A290:reverse_global_SAT_model" if retained else "A290:two_reverse_global_budget_boundaries"),
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["solver_arms"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="symbolic full-round constraint search",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=("A290:reverse_global_SAT_model" if retained else "A290:two_reverse_global_budget_boundaries"),
        mechanism=(
            "exact_CNF_gate_and_standalone_RFC_recompute_all_eight_blocks"
            if retained
            else "retain_UNKNOWN_as_reverse_operator_budget_boundary"
        ),
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=(
            "all CNF clauses plus 4096 output bits; one-bit control rejected"
            if retained
            else f"two reverse arms x {A287.SOLVER_SECONDS} seconds maximum"
        ),
        evidence=payload["evidence_stage"],
        domain="independent confirmation or measured operator boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A204R:personally_read_reverse_global_operator_gap",
        mechanism="materialized_prospective_reverse_transfer_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A204R_gap_plus_A290_execution",
        quantification="AI-native exact closure retained in-file",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A290 full-round W24 reverse global transfer",
        entities=[
            "A204R:personally_read_reverse_global_operator_gap",
            "A290:frozen_reverse_global_portfolio",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospective_fullround_W28_reverse_global_transfer"
            if retained
            else "A287_A289_A290_conditioned_exact_W24_partition"
        ),
        confidence=1.0,
        suggested_queries=(
            ["Can the retained reverse operator widen directly from W24 to W28?"]
            if retained
            else ["Which exact prefix partition best complements all six global traces?"]
        ),
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a290rv"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A290 authentic Causal gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": A287.relative(CAUSAL),
        "sha256": A287.file_sha256(CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": A287.anchor(reader_source),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def execute(expected_protocol_sha256: str) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A290 result already exists")
    protocol, preflight, a287_protocol = load_protocol(expected_protocol_sha256)
    root_reference = load_module(ROOT_REFERENCE_SOURCE, "a290_root_reference")
    run_preflight = {
        "arms": protocol["execution_plan"]["arms"],
    }
    A287.ARTIFACTS = ARTIFACTS
    solver_rows, winner = A287.run_portfolio(run_preflight, a287_protocol)
    confirmation = (
        None
        if winner is None
        else A287.confirm_winner(
            winner, a287_protocol["public_challenge"], root_reference
        )
    )
    evidence_stage = (
        "FULLROUND_R20_W24_REVERSE_GLOBAL_RECOVERY_CONFIRMED"
        if confirmation is not None
        else "FULLROUND_R20_W24_REVERSE_GLOBAL_BUDGET_BOUNDARY"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w24-reverse-global-transfer-a290-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol": A287.anchor(PROTOCOL, expected_protocol_sha256),
        "A204R_result": protocol["anchors"]["A204R_result"],
        "A204R_causal": protocol["anchors"]["A204R_causal"],
        "A287_preflight": protocol["anchors"]["A287_preflight"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "solver_arms": solver_rows,
        "winner": (
            None
            if winner is None
            else {key: value for key, value in winner.items() if key != "CNF_model_gate"}
        ),
        "confirmation": confirmation,
        "information_boundary": {
            "source_gap_personally_read_before_freeze": True,
            "secret_assignment_available_to_runner": False,
            "target_prefix_or_model_available_before_solver": False,
            "reverse_operator_views_and_budgets_frozen_before_solver": True,
            "unknown_treated_as_UNSAT": False,
            "complete_candidate_domain_enumeration_used": False,
        },
        "rfc8439_gate": root_reference.rfc8439_kat(),
        "runner": A287.anchor(
            Path(__file__), protocol["anchors"]["runner"]["sha256"]
        ),
    }
    payload["execution_sha256"] = A287.canonical_sha256(solver_rows)
    payload["measurement_sha256"] = A287.canonical_sha256(
        {
            "solver_arms": solver_rows,
            "winner": payload["winner"],
            "confirmation": confirmation,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    A287.atomic_json(RESULT, payload)
    report = f"""# A290 — ChaCha20-R20 W24 reverse global transfer

Evidence stage: **{evidence_stage}**

- Source operator: **A204R retained `cadical --reverse=true`**
- Standard rounds plus feed-forward: **20**
- Unknown key bits: **24**
- Public output: **8 blocks / 4096 bits**
- Global CNF views: **native + BFS-far**
- Candidate-domain enumeration: **none**
- Winner: **{payload['winner']}**
- Next AI-native gap: **{payload['causal']['personal_semantic_readback']['next_gap']['expected_object_type']}**
"""
    A287.atomic_bytes(REPORT, report.encode("utf-8"))
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--expected-a287-preflight-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.freeze:
        if not args.expected_a287_preflight_sha256:
            parser.error("--freeze requires --expected-a287-preflight-sha256")
        payload = freeze(args.expected_a287_preflight_sha256)
        print(A287.file_sha256(PROTOCOL))
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if not args.expected_protocol_sha256:
        parser.error("--run requires --expected-protocol-sha256")
    payload = execute(args.expected_protocol_sha256)
    print(A287.file_sha256(RESULT))
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
