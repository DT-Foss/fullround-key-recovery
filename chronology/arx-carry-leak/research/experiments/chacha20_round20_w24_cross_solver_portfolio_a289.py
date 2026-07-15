#!/usr/bin/env python3
"""Prospective ChaCha20-R20 W24 cross-solver portfolio (A289).

A289 reuses the already frozen public A287 challenge and its two exact CNF
views, but transfers them to two solver families that A287 does not execute:
Kissat and CryptoMiniSat.  The protocol is frozen before either solver sees the
target CNF.  A returned model is checked against every DIMACS clause and then
confirmed with the standalone ChaCha20 operation reference over all eight
standard output blocks.
"""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"
ARTIFACTS = RESEARCH / "artifacts/a289_chacha20_r20_w24_cross_solver"

A287_SOURCE = RESEARCH / "experiments/chacha20_round20_w24_global_portfolio_a287.py"
ROOT_REFERENCE_SOURCE = RESEARCH / "experiments/chacha20_round20_multitarget_root_confirm.py"
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
KISSAT = Path("/opt/homebrew/bin/kissat")
CRYPTOMINISAT = Path("/opt/homebrew/bin/cryptominisat5")

PROTOCOL = CONFIGS / "chacha20_round20_w24_cross_solver_portfolio_a289_v1.json"
RESULT = RESULTS / "chacha20_round20_w24_cross_solver_portfolio_a289_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w24_cross_solver_portfolio_a289_v1.causal"
REPORT = REPORTS / "CHACHA20_ROUND20_W24_CROSS_SOLVER_PORTFOLIO_A289_V1.md"

ATTEMPT_ID = "A289"
SOLVER_SECONDS = 7200
POLL_SECONDS = 0.25


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A287 = load_module(A287_SOURCE, "a289_a287_frozen_dependency")


def _solver_identity(path: Path) -> dict[str, Any]:
    result = subprocess.run(
        [str(path), "--version"],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0 or not result.stdout.strip() or result.stderr:
        raise RuntimeError(f"A289 solver identity failed for {path}")
    return {
        "binary": A287.anchor(path),
        "version_stdout": result.stdout.strip(),
        "version_stdout_sha256": A287.sha256(result.stdout.encode()),
    }


def solver_command(
    solver: str, *, cnf: Path, seconds: int = SOLVER_SECONDS
) -> list[str]:
    if solver == "kissat_sat":
        return [
            str(KISSAT),
            "--sat",
            f"--time={seconds}",
            "--quiet",
            str(cnf),
        ]
    if solver == "cryptominisat_default":
        return [
            str(CRYPTOMINISAT),
            "--verb",
            "0",
            "--maxtime",
            str(seconds),
            "--threads",
            "1",
            "--maxsol",
            "1",
            str(cnf),
        ]
    raise ValueError(f"A289 unsupported solver {solver}")


def execution_plan(preflight: dict[str, Any]) -> dict[str, Any]:
    definitions = [
        ("kissat_base_sat", "kissat_sat", "base_default"),
        (
            "cryptominisat_bfs_default",
            "cryptominisat_default",
            "bfs_far_sat",
        ),
    ]
    arms = []
    for name, solver, source_arm in definitions:
        source = preflight["arms"][source_arm]
        cnf = ROOT / source["cnf"]["path"]
        mapping = [int(value) for value in source["model_one_literals_bit0_upward"]]
        if len(mapping) != 24 or len({abs(value) for value in mapping}) != 24:
            raise RuntimeError("A289 source model mapping differs")
        arms.append(
            {
                "arm": name,
                "solver": solver,
                "source_A287_CNF_arm": source_arm,
                "cnf": A287.anchor(cnf, source["cnf"]["sha256"]),
                "model_one_literals_bit0_upward": mapping,
                "model_mapping_sha256": A287.canonical_sha256(mapping),
                "seconds": SOLVER_SECONDS,
                "command": solver_command(solver, cnf=cnf),
            }
        )
    return {
        "primitive": "standard_ChaCha20_block_function",
        "rounds": 20,
        "feedforward_included": True,
        "unknown_key_bits": 24,
        "known_key_bits": 232,
        "public_input_output_blocks": 8,
        "constrained_output_bits": 4096,
        "portfolio": arms,
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
    if A287.RESULT.exists() or A287.CAUSAL.exists():
        raise RuntimeError("A289 must freeze before any A287 outcome is available")
    preflight, a287_protocol = A287.load_preflight(expected_a287_preflight_sha256)
    plan = execution_plan(preflight)
    protocol = {
        "schema": "chacha20-round20-w24-cross-solver-portfolio-a289-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "cross_solver_views_and_budgets_frozen_before_target_solver_execution",
        "public_challenge_sha256": a287_protocol["public_challenge_sha256"],
        "execution_plan": plan,
        "execution_plan_sha256": A287.canonical_sha256(plan),
        "anchors": {
            "runner": A287.anchor(Path(__file__)),
            "A287_source": A287.anchor(A287_SOURCE),
            "A287_protocol": A287.anchor(
                A287.PROTOCOL, preflight["protocol"]["sha256"]
            ),
            "A287_preflight": A287.anchor(
                A287.PREFLIGHT, expected_a287_preflight_sha256
            ),
            "root_reference": A287.anchor(ROOT_REFERENCE_SOURCE),
            "kissat": _solver_identity(KISSAT),
            "cryptominisat": _solver_identity(CRYPTOMINISAT),
        },
        "information_boundary": {
            "A287_result_available_at_freeze": False,
            "secret_assignment_target_prefix_or_model_available": False,
            "solver_families_CNF_views_and_budgets_frozen": True,
            "any_target_solver_execution_started": False,
            "UNKNOWN_will_not_be_treated_as_UNSAT": True,
        },
    }
    protocol["scientific_design_sha256"] = A287.canonical_sha256(
        {
            "public_challenge_sha256": protocol["public_challenge_sha256"],
            "execution_plan": protocol["execution_plan"],
            "information_boundary": protocol["information_boundary"],
            "anchors": protocol["anchors"],
        }
    )
    A287.atomic_json(PROTOCOL, protocol)
    return protocol


def load_protocol(expected_sha256: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if A287.file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A289 protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    if (
        protocol.get("schema")
        != "chacha20-round20-w24-cross-solver-portfolio-a289-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "cross_solver_views_and_budgets_frozen_before_target_solver_execution"
        or protocol.get("execution_plan_sha256")
        != A287.canonical_sha256(protocol.get("execution_plan"))
    ):
        raise RuntimeError("A289 protocol semantics differ")
    for name, row in protocol["anchors"].items():
        if name in {"kissat", "cryptominisat"}:
            A287.anchor(
                Path(row["binary"]["path"]), row["binary"]["sha256"]
            )
        else:
            A287.anchor(A287.anchored_path(row["path"]), row["sha256"])
    preflight, a287_protocol = A287.load_preflight(
        protocol["anchors"]["A287_preflight"]["sha256"]
    )
    if a287_protocol["public_challenge_sha256"] != protocol["public_challenge_sha256"]:
        raise RuntimeError("A289 challenge anchor differs")
    for arm in protocol["execution_plan"]["portfolio"]:
        A287.anchor(A287.anchored_path(arm["cnf"]["path"]), arm["cnf"]["sha256"])
    return protocol, preflight, a287_protocol


def _status(returncode: int, stdout: str, terminated: bool) -> str:
    if terminated:
        return "terminated_after_sibling_sat"
    markers = {line.strip() for line in stdout.splitlines() if line.startswith("s ")}
    if returncode == 10 and "s SATISFIABLE" in markers:
        return "sat"
    if returncode == 20 and "s UNSATISFIABLE" in markers:
        return "unsat"
    if returncode in {0, 15} and (
        not markers or "s UNKNOWN" in markers or "s INDETERMINATE" in markers
    ):
        return "unknown"
    raise RuntimeError(
        f"A289 unexpected solver termination returncode={returncode} markers={sorted(markers)}"
    )


def run_portfolio(
    protocol: dict[str, Any], preflight: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    processes: dict[str, subprocess.Popen[bytes]] = {}
    handles: dict[str, tuple[Any, Any]] = {}
    metadata: dict[str, dict[str, Any]] = {}
    for arm in protocol["execution_plan"]["portfolio"]:
        name = arm["arm"]
        stdout_path = ARTIFACTS / f"{name}.stdout"
        stderr_path = ARTIFACTS / f"{name}.stderr"
        stdout_path.unlink(missing_ok=True)
        stderr_path.unlink(missing_ok=True)
        command = [str(value) for value in arm["command"]]
        if command != solver_command(
            arm["solver"],
            cnf=A287.anchored_path(arm["cnf"]["path"]),
            seconds=int(arm["seconds"]),
        ):
            raise RuntimeError("A289 frozen command differs")
        stdout_handle = stdout_path.open("wb")
        stderr_handle = stderr_path.open("wb")
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=stdout_handle,
            stderr=stderr_handle,
            start_new_session=True,
        )
        processes[name] = process
        handles[name] = (stdout_handle, stderr_handle)
        metadata[name] = {
            "arm": arm,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "started_monotonic": time.monotonic(),
            "terminated_after_sibling_sat": False,
        }
    winner_name: str | None = None
    while True:
        for name, process in processes.items():
            if process.poll() == 10:
                winner_name = name
                break
        if winner_name is not None or all(
            process.poll() is not None for process in processes.values()
        ):
            break
        time.sleep(POLL_SECONDS)
    if winner_name is not None:
        for name, process in processes.items():
            if name == winner_name or process.poll() is not None:
                continue
            metadata[name]["terminated_after_sibling_sat"] = True
            os.killpg(process.pid, signal.SIGTERM)
    for process in processes.values():
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=15)
    for stdout_handle, stderr_handle in handles.values():
        stdout_handle.close()
        stderr_handle.close()

    rows: list[dict[str, Any]] = []
    winner: dict[str, Any] | None = None
    for name, process in processes.items():
        meta = metadata[name]
        arm = meta["arm"]
        stdout_path = Path(meta["stdout_path"])
        stderr_path = Path(meta["stderr_path"])
        stdout = stdout_path.read_text(encoding="ascii")
        status = _status(
            int(process.returncode),
            stdout,
            bool(meta["terminated_after_sibling_sat"]),
        )
        row = {
            "arm": name,
            "solver": arm["solver"],
            "source_A287_CNF_arm": arm["source_A287_CNF_arm"],
            "status": status,
            "returncode": process.returncode,
            "elapsed_seconds": time.monotonic() - float(meta["started_monotonic"]),
            "terminated_after_sibling_sat": meta["terminated_after_sibling_sat"],
            "command_sha256": A287.canonical_sha256(arm["command"]),
            "stdout_sha256": A287.file_sha256(stdout_path),
            "stderr_sha256": A287.file_sha256(stderr_path),
        }
        rows.append(row)
        if status == "unsat":
            raise RuntimeError("A289 solver contradicted the guaranteed-satisfiable challenge")
        if status != "sat":
            continue
        model = A287.parse_witness(stdout_path)
        candidate = A287.decode_candidate(
            model, [int(value) for value in arm["model_one_literals_bit0_upward"]]
        )
        cnf = A287.anchored_path(arm["cnf"]["path"])
        winner = {
            "arm": name,
            "solver": arm["solver"],
            "candidate_low24": candidate,
            "candidate_low24_hex": f"{candidate:06x}",
            "CNF_model_gate": A287.verify_dimacs_model(cnf, model),
        }
    if winner_name is not None and winner is None:
        raise RuntimeError("A289 observed SAT without a parsed model")
    rows.sort(key=lambda row: row["arm"])
    return rows, winner


def build_causal(payload: dict[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    reader_source = Path(inspect.getsourcefile(CausalReader) or "")
    retained = payload["confirmation"] is not None
    terminal = (
        "A289:confirmed_cross_solver_W24_recovery"
        if retained
        else "A289:measured_cross_solver_budget_boundary"
    )
    writer = CausalWriter(api_id="a289xs")
    writer._rules = []
    writer.add_rule(
        name="cross_solver_model_to_full_output_confirmation",
        description=(
            "A model returned by a prospectively frozen independent solver family "
            "is retained only after exact CNF and 4096-bit confirmation."
        ),
        pattern=["frozen_cross_solver_portfolio", "SAT_model", "4096_bit_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="cross_solver_boundary_to_exact_partition",
        description=(
            "If both cross-solver arms exhaust their budgets, combine the measured "
            "boundary with A287 and move to the exact disjoint W24 partition."
        ),
        pattern=["two_cross_solver_budget_boundaries", "no_model_disclosure"],
        conclusion="A288_exact_partition_transfer",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A287:frozen_public_W24_challenge_and_CNF_views",
        mechanism="freeze_Kissat_and_CryptoMiniSat_cross_solver_portfolio",
        outcome="A289:frozen_cross_solver_portfolio",
        confidence=1.0,
        source=payload["protocol"]["sha256"],
        quantification="24 unknown key bits; 8 blocks; 4096 constrained output bits",
        evidence=payload["evidence_stage"],
        domain="prospective full-round ChaCha20-R20 solver transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A289:frozen_cross_solver_portfolio",
        mechanism="parallel_Kissat_and_CryptoMiniSat_global_search",
        outcome=("A289:cross_solver_SAT_model" if retained else "A289:two_cross_solver_budget_boundaries"),
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["solver_arms"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="symbolic full-round constraint search",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=("A289:cross_solver_SAT_model" if retained else "A289:two_cross_solver_budget_boundaries"),
        mechanism=(
            "exact_CNF_gate_and_standalone_RFC_recompute_all_eight_blocks"
            if retained
            else "retain_UNKNOWN_as_solver_family_specific_budget_boundary"
        ),
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=(
            "all CNF clauses plus 4096 output bits; one-bit control rejected"
            if retained
            else f"two solver families x {SOLVER_SECONDS} seconds maximum"
        ),
        evidence=payload["evidence_stage"],
        domain="independent confirmation or measured solver boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A289:frozen_cross_solver_portfolio",
        mechanism=(
            "materialized_cross_solver_confirmation_chain"
            if retained
            else "materialized_cross_solver_boundary_chain"
        ),
        outcome=terminal,
        confidence=1.0,
        source="materialized:A289_cross_solver_execution",
        quantification="AI-native exact closure retained in-file",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A289 ChaCha20-R20 W24 cross-solver portfolio",
        entities=[
            "A287:frozen_public_W24_challenge_and_CNF_views",
            "A289:frozen_cross_solver_portfolio",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospective_W28_cross_solver_transfer"
            if retained
            else "A287_A289_boundary_conditioned_exact_W24_partition"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Can the winning solver family recover a freshly frozen W28 target?",
                "Does the same operator retain across disjoint W24 material?",
            ]
            if retained
            else [
                "Which exact prefix partition best complements all four global traces?",
                "Can retained clauses expose a model inside a strict subset of W24 cells?",
            ]
        ),
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
        reader.version != 1
        or reader.api_id != "a289xs"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A289 authentic Causal gate failed")
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
        raise FileExistsError("A289 result already exists")
    protocol, preflight, a287_protocol = load_protocol(expected_protocol_sha256)
    root_reference = load_module(ROOT_REFERENCE_SOURCE, "a289_root_reference")
    solver_rows, winner = run_portfolio(protocol, preflight)
    confirmation = (
        None
        if winner is None
        else A287.confirm_winner(
            winner, a287_protocol["public_challenge"], root_reference
        )
    )
    evidence_stage = (
        "FULLROUND_R20_W24_CROSS_SOLVER_RECOVERY_CONFIRMED"
        if confirmation is not None
        else "FULLROUND_R20_W24_CROSS_SOLVER_BUDGET_BOUNDARY"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w24-cross-solver-portfolio-a289-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol": A287.anchor(PROTOCOL, expected_protocol_sha256),
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
            "secret_assignment_available_to_runner": False,
            "target_prefix_or_model_available_before_solver": False,
            "cross_solver_operators_and_budgets_frozen_before_solver": True,
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
    lines = [
        "# A289 — ChaCha20-R20 W24 cross-solver portfolio",
        "",
        f"Evidence stage: **{evidence_stage}**",
        "",
        "- Standard rounds plus feed-forward: **20**",
        "- Unknown key bits: **24**",
        "- Public output: **8 blocks / 4096 bits**",
        "- Solvers: **Kissat + CryptoMiniSat**",
        "- Candidate-domain enumeration: **none**",
        f"- Winner: **{payload['winner']}**",
        "",
        "## Solver arms",
        "",
        "```json",
        json.dumps(solver_rows, indent=2, sort_keys=True),
        "```",
        "",
        "## Next AI-native gap",
        "",
        f"`{payload['causal']['personal_semantic_readback']['next_gap']['expected_object_type']}`",
        "",
    ]
    A287.atomic_bytes(REPORT, "\n".join(lines).encode("utf-8"))
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
