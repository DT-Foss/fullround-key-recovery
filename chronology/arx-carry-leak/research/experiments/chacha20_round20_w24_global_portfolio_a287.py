#!/usr/bin/env python3
"""Prospective full-round ChaCha20-R20 W24 global SAT portfolio (A287).

The experiment has three separate processes:

* ``--freeze`` creates a fresh public eight-block W24 challenge and discards
  the secret assignment before exit.
* ``--preflight`` exports and maps two structurally diverse CNFs without
  invoking a SAT solver.
* ``--run`` executes the frozen global portfolio and independently confirms
  any recovered model over all 4096 standard-output bits.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import secrets
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
ARTIFACTS = RESEARCH / "artifacts/a287_chacha20_r20_w24_global"
REPORTS = RESEARCH / "reports"
A223_SOURCE = RESEARCH / "experiments/chacha20_round20_capacity_moonshot_a223.py"
A223_CONFIG = CONFIGS / "chacha20_round20_capacity_moonshot_a223_v1.json"
ROOT_REFERENCE_SOURCE = (
    RESEARCH / "experiments/chacha20_round20_multitarget_root_confirm.py"
)
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
CADICAL = Path("/opt/homebrew/bin/cadical")
BITWUZLA = Path("/opt/homebrew/bin/bitwuzla")

PROTOCOL = CONFIGS / "chacha20_round20_w24_global_portfolio_a287_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_w24_global_portfolio_a287_preflight_v1.json"
RESULT = RESULTS / "chacha20_round20_w24_global_portfolio_a287_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w24_global_portfolio_a287_v1.causal"
REPORT = REPORTS / "CHACHA20_ROUND20_W24_GLOBAL_PORTFOLIO_A287_V1.md"

ATTEMPT_ID = "A287"
WIDTH = 24
ROUNDS = 20
BLOCKS = 8
OUTPUT_BITS = 4096
SOLVER_SECONDS = 7200
POLL_SECONDS = 0.25
MASK32 = (1 << 32) - 1


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_sha256(value: Any) -> str:
    return sha256(canonical_bytes(value))


def atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def atomic_json(path: Path, value: Any) -> None:
    atomic_bytes(
        path,
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n",
    )


def relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:
        return str(resolved)


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    digest = file_sha256(path)
    if expected is not None and digest != expected:
        raise RuntimeError(f"A287 anchor differs: {path}")
    return {"path": relative(path), "sha256": digest}


def anchored_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def execution_plan() -> dict[str, Any]:
    return {
        "primitive": "standard_ChaCha20_block_function",
        "rounds": ROUNDS,
        "feedforward_included": True,
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "unknown_global_bit_interval": [0, WIDTH - 1],
        "public_input_output_blocks": BLOCKS,
        "constrained_output_bits": OUTPUT_BITS,
        "split_round": 18,
        "portfolio": [
            {
                "arm": "base_default",
                "cnf_operator": "native_Bitwuzla_export",
                "cadical_configuration": "default",
                "seconds": SOLVER_SECONDS,
            },
            {
                "arm": "bfs_far_sat",
                "cnf_operator": "unit_multisource_BFS_far_variable_reindex",
                "cadical_configuration": "sat",
                "seconds": SOLVER_SECONDS,
            },
        ],
        "parallel_solver_processes": 2,
        "first_exact_SAT_terminates_unfinished_sibling": True,
        "unknown_is_not_unsat": True,
        "no_prefix_or_candidate_label_available": True,
        "no_complete_candidate_enumeration": True,
        "confirmation": "frozen_third_RFC_operation_reference_all_eight_blocks",
        "control": "one_bit_flipped_first_standard_output_block",
    }


def challenge_from_ephemeral_secret(root_reference: Any) -> dict[str, Any]:
    key_words = [secrets.randbits(32) for _ in range(8)]
    nonce_words = [secrets.randbits(32) for _ in range(3)]
    counter = secrets.randbits(32)
    target_words = [
        root_reference.chacha20_block(
            key_words, (counter + block) & MASK32, nonce_words
        )
        for block in range(BLOCKS)
    ]
    control = list(target_words[0])
    control[0] ^= 1
    known_mask = (~((1 << WIDTH) - 1)) & MASK32
    known_values = [key_words[0] & known_mask, *key_words[1:]]
    challenge = {
        "challenge_id": secrets.token_hex(16),
        "rounds": ROUNDS,
        "block_count": BLOCKS,
        "counter_schedule": "base_plus_block_index_mod_2^32",
        "counter_start": counter,
        "nonce_words": nonce_words,
        "known_key_bits": 256 - WIDTH,
        "known_key_mask_words": [known_mask, *([MASK32] * 7)],
        "known_key_value_words": known_values,
        "unknown_key_bits": WIDTH,
        "unknown_global_bit_interval": [0, WIDTH - 1],
        "unknown_bit_numbering": (
            "little_endian_bit0_upward_across_key_words_k0_through_k7"
        ),
        "unknown_assignment_included": False,
        "unknown_assignment_value_included": False,
        "full_key_included": False,
        "secret_used_only_for_target_construction": True,
        "secret_discarded_after_target_construction": True,
        "generation_entropy_source": "python_secrets_token_bytes_OS_CSPRNG",
        "target_words": target_words,
        "target_block_sha256": [
            sha256(root_reference._word_bytes(block))  # noqa: SLF001
            for block in target_words
        ],
        "control_target_words": control,
        "control_target_block_sha256": sha256(
            root_reference._word_bytes(control)  # noqa: SLF001
        ),
    }
    # Explicitly drop the sole in-process secret reference before serialization.
    del key_words
    return challenge


def freeze() -> dict[str, Any]:
    if PROTOCOL.exists():
        raise FileExistsError(PROTOCOL)
    root_reference = load_module(ROOT_REFERENCE_SOURCE, "a287_root_reference_freeze")
    kat = root_reference.rfc8439_kat()
    challenge = challenge_from_ephemeral_secret(root_reference)
    a223 = load_module(A223_SOURCE, "a287_a223_freeze")
    a223._validate_challenge(challenge, width=WIDTH)  # noqa: SLF001
    plan = execution_plan()
    payload = {
        "schema": "chacha20-round20-w24-global-portfolio-a287-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": (
            "fresh_public_challenge_and_two_arm_portfolio_frozen_before_CNF_export_or_solver_execution"
        ),
        "execution_plan": plan,
        "execution_plan_sha256": canonical_sha256(plan),
        "public_challenge": challenge,
        "public_challenge_sha256": canonical_sha256(challenge),
        "information_boundary": {
            "ephemeral_secret_generated_once_from_OS_CSPRNG": True,
            "ephemeral_secret_used_only_for_public_target_construction": True,
            "ephemeral_secret_returned_logged_or_serialized": False,
            "ephemeral_secret_available_to_preflight_or_runner": False,
            "CNF_export_started_before_protocol_freeze": False,
            "solver_execution_started_before_protocol_freeze": False,
            "target_model_or_prefix_available_to_operator_selection": False,
        },
        "anchors": {
            "runner": anchor(Path(__file__)),
            "A223_formula_and_mapping": anchor(A223_SOURCE),
            "standalone_RFC_reference": anchor(ROOT_REFERENCE_SOURCE),
            "A223_toolchain_protocol": anchor(A223_CONFIG),
            "bitwuzla": anchor(BITWUZLA),
            "cadical": anchor(CADICAL),
        },
        "rfc8439_gate": kat,
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "execution_plan": plan,
            "public_challenge": challenge,
            "information_boundary": payload["information_boundary"],
            "anchors": payload["anchors"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A287 protocol hash differs")
    payload = json.loads(PROTOCOL.read_bytes())
    if (
        payload.get("schema")
        != "chacha20-round20-w24-global-portfolio-a287-protocol-v1"
        or payload.get("attempt_id") != ATTEMPT_ID
        or payload.get("execution_plan") != execution_plan()
        or payload.get("execution_plan_sha256")
        != canonical_sha256(execution_plan())
        or payload.get("public_challenge_sha256")
        != canonical_sha256(payload.get("public_challenge"))
    ):
        raise RuntimeError("A287 protocol semantics differ")
    for row in payload["anchors"].values():
        anchor(anchored_path(row["path"]), row["sha256"])
    return payload


def preflight(expected_protocol_sha256: str) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A287 preflight or artifact directory already exists")
    protocol = load_protocol(expected_protocol_sha256)
    a223 = load_module(A223_SOURCE, "a287_a223_preflight")
    challenge = protocol["public_challenge"]
    a223._validate_challenge(challenge, width=WIDTH)  # noqa: SLF001
    a223_config = json.loads(A223_CONFIG.read_bytes())
    ARTIFACTS.mkdir(parents=True)
    context = a223._base_context(  # noqa: SLF001
        width=WIDTH,
        challenge=challenge,
        config=a223_config,
        directory=ARTIFACTS,
    )
    probes = [
        a223._coordinate_probe(  # noqa: SLF001
            context=context,
            dimension=dimension,
            config=a223_config,
            directory=ARTIFACTS,
        )
        for dimension in range(-1, math.ceil(math.log2(WIDTH)))
    ]
    source_one_literals = a223._decode_mapping(  # noqa: SLF001
        [(dimension, units) for _, dimension, units, _ in probes], width=WIDTH
    )
    if (
        len(source_one_literals) != WIDTH
        or len({abs(value) for value in source_one_literals}) != WIDTH
    ):
        raise RuntimeError("A287 source literal mapping differs")
    base_path = Path(context["base_path"])
    bfs_path = ARTIFACTS / "a287_w24_bfs_far.cnf"
    bfs_mapping = a223._build_structural_cnf(  # noqa: SLF001
        context=context,
        source_one_literals=source_one_literals,
        output=bfs_path,
    )
    mapping = {
        "base_default": {
            "cnf": anchor(base_path),
            "model_one_literals_bit0_upward": source_one_literals,
            "operator": "native_Bitwuzla_export",
            "cadical_configuration": "default",
        },
        "bfs_far_sat": {
            "cnf": anchor(bfs_path),
            "model_one_literals_bit0_upward": bfs_mapping[
                "transformed_model_one_literals_bit0_upward"
            ],
            "operator": bfs_mapping,
            "cadical_configuration": "sat",
        },
    }
    payload = {
        "schema": "chacha20-round20-w24-global-portfolio-a287-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "W24_TWO_ARM_GLOBAL_PORTFOLIO_PREFLIGHT_FROZEN",
        "protocol": anchor(PROTOCOL, expected_protocol_sha256),
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "formula": {
            "sha256": context["formula_sha256"],
            "bytes": context["formula_bytes"],
            "variables": context["variable_count"],
            "clauses": context["clause_count"],
            "joint_output_equalities": BLOCKS * 16,
        },
        "coordinate_probes": [row[3] for row in probes],
        "source_one_literals_bit0_upward": source_one_literals,
        "arms": mapping,
        "information_boundary": {
            "secret_assignment_available": False,
            "candidate_model_available": False,
            "any_SAT_solver_invoked": False,
            "both_CNF_operators_fixed": True,
            "both_solver_configurations_fixed": True,
        },
        "anchors": {
            "runner": anchor(Path(__file__)),
            "A223_formula_and_mapping": protocol["anchors"][
                "A223_formula_and_mapping"
            ],
            "cadical": protocol["anchors"]["cadical"],
            "bitwuzla": protocol["anchors"]["bitwuzla"],
        },
    }
    payload["preflight_content_sha256"] = canonical_sha256(payload)
    atomic_json(PREFLIGHT, payload)
    return payload


def load_preflight(expected_preflight_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(PREFLIGHT) != expected_preflight_sha256:
        raise RuntimeError("A287 preflight hash differs")
    preflight_payload = json.loads(PREFLIGHT.read_bytes())
    protocol_sha = preflight_payload["protocol"]["sha256"]
    protocol = load_protocol(protocol_sha)
    if (
        preflight_payload.get("schema")
        != "chacha20-round20-w24-global-portfolio-a287-preflight-v1"
        or preflight_payload.get("attempt_id") != ATTEMPT_ID
        or preflight_payload.get("public_challenge_sha256")
        != protocol["public_challenge_sha256"]
        or preflight_payload.get("information_boundary", {}).get(
            "any_SAT_solver_invoked"
        )
        is not False
    ):
        raise RuntimeError("A287 preflight semantics differ")
    for row in preflight_payload["arms"].values():
        anchor(ROOT / row["cnf"]["path"], row["cnf"]["sha256"])
    return preflight_payload, protocol


def parse_witness(path: Path) -> dict[int, bool]:
    if not path.is_file():
        raise FileNotFoundError(f"A287 SAT witness missing: {path}")
    values: dict[int, bool] = {}
    saw_sat = False
    for line in path.read_text(encoding="ascii").splitlines():
        if line.startswith("s "):
            saw_sat = line.strip() == "s SATISFIABLE"
        if not line.startswith("v "):
            continue
        for raw in line.split()[1:]:
            literal = int(raw)
            if literal == 0:
                continue
            values[abs(literal)] = literal > 0
    if not saw_sat or not values:
        raise RuntimeError("A287 witness is not a complete SAT witness")
    return values


def decode_candidate(model: dict[int, bool], one_literals: list[int]) -> int:
    candidate = 0
    for bit, literal in enumerate(one_literals):
        value = model.get(abs(int(literal)))
        if value is None:
            raise RuntimeError("A287 witness omits a mapped key variable")
        logical = value if int(literal) > 0 else not value
        candidate |= int(logical) << bit
    if not 0 <= candidate < (1 << WIDTH):
        raise RuntimeError("A287 decoded W24 assignment is out of range")
    return candidate


def verify_dimacs_model(path: Path, model: dict[int, bool]) -> dict[str, Any]:
    clauses = 0
    maximum_variable = 0
    pending: list[int] = []
    for line in path.read_text(encoding="ascii").splitlines():
        if not line or line[0] in "cp":
            continue
        for raw in line.split():
            literal = int(raw)
            if literal:
                pending.append(literal)
                maximum_variable = max(maximum_variable, abs(literal))
                continue
            clauses += 1
            if not any(
                model.get(abs(item), False) == (item > 0) for item in pending
            ):
                raise RuntimeError(f"A287 witness violates CNF clause {clauses}")
            pending.clear()
    if pending:
        raise RuntimeError("A287 CNF has an unterminated clause")
    return {
        "all_clauses_satisfied": True,
        "clauses_checked": clauses,
        "maximum_variable": maximum_variable,
        "model_assignments_available": len(model),
    }


def run_portfolio(
    preflight_payload: dict[str, Any], protocol: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    processes: dict[str, subprocess.Popen[bytes]] = {}
    log_handles: dict[str, tuple[Any, Any]] = {}
    metadata: dict[str, dict[str, Any]] = {}
    for arm, row in preflight_payload["arms"].items():
        witness = ARTIFACTS / f"{arm}.witness"
        stdout_path = ARTIFACTS / f"{arm}.stdout"
        stderr_path = ARTIFACTS / f"{arm}.stderr"
        for path in (witness, stdout_path, stderr_path):
            path.unlink(missing_ok=True)
        configuration = row["cadical_configuration"]
        command = [
            str(CADICAL),
            f"--{configuration}",
            "-q",
            "-t",
            str(SOLVER_SECONDS),
            "-w",
            str(witness),
            str(ROOT / row["cnf"]["path"]),
        ]
        stdout_handle = stdout_path.open("wb")
        stderr_handle = stderr_path.open("wb")
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=stdout_handle,
            stderr=stderr_handle,
            start_new_session=True,
        )
        processes[arm] = process
        log_handles[arm] = (stdout_handle, stderr_handle)
        metadata[arm] = {
            "arm": arm,
            "command": command,
            "command_sha256": canonical_sha256(command),
            "witness_path": witness,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "started_monotonic": time.monotonic(),
            "terminated_after_sibling_sat": False,
        }
    winner: str | None = None
    while True:
        for arm, process in processes.items():
            returncode = process.poll()
            if returncode == 10:
                winner = arm
                break
            if returncode not in (None, 0, 20):
                raise RuntimeError(f"A287 {arm} unexpected CaDiCaL return code {returncode}")
        if winner is not None or all(process.poll() is not None for process in processes.values()):
            break
        time.sleep(POLL_SECONDS)
    if winner is not None:
        for arm, process in processes.items():
            if arm == winner or process.poll() is not None:
                continue
            metadata[arm]["terminated_after_sibling_sat"] = True
            os.killpg(process.pid, signal.SIGTERM)
    for process in processes.values():
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=15)
    for stdout_handle, stderr_handle in log_handles.values():
        stdout_handle.close()
        stderr_handle.close()
    rows: list[dict[str, Any]] = []
    winner_payload: dict[str, Any] | None = None
    for arm, process in processes.items():
        meta = metadata[arm]
        witness_path = Path(meta["witness_path"])
        status = (
            "sat"
            if process.returncode == 10
            else "unsat"
            if process.returncode == 20
            else "terminated_after_sibling_sat"
            if meta["terminated_after_sibling_sat"]
            else "unknown"
        )
        row = {
            "arm": arm,
            "status": status,
            "returncode": process.returncode,
            "elapsed_seconds": time.monotonic() - float(meta["started_monotonic"]),
            "terminated_after_sibling_sat": meta["terminated_after_sibling_sat"],
            "command_sha256": meta["command_sha256"],
            "stdout_sha256": file_sha256(Path(meta["stdout_path"])),
            "stderr_sha256": file_sha256(Path(meta["stderr_path"])),
            "witness_exists": witness_path.is_file(),
            "witness_sha256": file_sha256(witness_path) if witness_path.is_file() else None,
        }
        rows.append(row)
        if status != "sat":
            continue
        model = parse_witness(witness_path)
        arm_preflight = preflight_payload["arms"][arm]
        candidate = decode_candidate(
            model, arm_preflight["model_one_literals_bit0_upward"]
        )
        cnf_path = ROOT / arm_preflight["cnf"]["path"]
        winner_payload = {
            "arm": arm,
            "candidate_low24": candidate,
            "candidate_low24_hex": f"{candidate:06x}",
            "CNF_model_gate": verify_dimacs_model(cnf_path, model),
        }
    if winner is not None and winner_payload is None:
        raise RuntimeError("A287 observed SAT without a parsed winner")
    rows.sort(key=lambda row: row["arm"])
    return rows, winner_payload


def confirm_winner(
    winner: dict[str, Any], challenge: dict[str, Any], root_reference: Any
) -> dict[str, Any]:
    candidate = int(winner["candidate_low24"])
    key_words = [
        int(challenge["known_key_value_words"][0]) | candidate,
        *[int(word) for word in challenge["known_key_value_words"][1:]],
    ]
    observed = [
        root_reference.chacha20_block(
            key_words,
            (int(challenge["counter_start"]) + block) & MASK32,
            challenge["nonce_words"],
        )
        for block in range(BLOCKS)
    ]
    hashes = [
        sha256(root_reference._word_bytes(block))  # noqa: SLF001
        for block in observed
    ]
    if (
        observed != challenge["target_words"]
        or hashes != challenge["target_block_sha256"]
        or observed[0] == challenge["control_target_words"]
    ):
        raise RuntimeError("A287 standalone full-output confirmation failed")
    return {
        "recovered_unknown_low24": candidate,
        "recovered_unknown_low24_hex": f"{candidate:06x}",
        "standalone_direct_RFC_operation_all_eight_blocks_match": True,
        "output_bits_checked": OUTPUT_BITS,
        "block_sha256": hashes,
        "one_bit_control_rejected": True,
        "complete_candidate_domain_enumeration_used": False,
        "CNF_model_gate": winner["CNF_model_gate"],
    }


def build_causal(payload: dict[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    reader_source = Path(inspect.getsourcefile(CausalReader) or "")
    confirmation = payload.get("confirmation")
    retained = confirmation is not None
    terminal = (
        "A287:confirmed_fullround_W24_recovery"
        if retained
        else "A287:measured_W24_global_budget_boundary"
    )
    writer = CausalWriter(api_id="a287w24")
    writer._rules = []
    writer.add_rule(
        name="frozen_global_portfolio_to_independent_confirmation",
        description=(
            "A prospectively frozen symbolic portfolio followed by exact third-reference "
            "confirmation establishes a W24 recovery when a SAT model is returned."
        ),
        pattern=["frozen_W24_portfolio", "global_SAT_model", "4096_bit_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="diverse_global_boundary_to_partition",
        description=(
            "If both global views exhaust their budgets, preserve the boundary and "
            "move to an exact disjoint prefix partition without treating UNKNOWN as UNSAT."
        ),
        pattern=["two_global_budget_boundaries", "no_model_disclosure"],
        conclusion="A288_partitioned_W24",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A286:retained_four_target_panel",
        mechanism="freeze_fresh_W24_public_material_and_two_diverse_global_views",
        outcome="A287:frozen_W24_global_portfolio",
        confidence=1.0,
        source=payload["preflight"]["sha256"],
        quantification="24 unknown key bits; 8 blocks; 4096 constrained output bits",
        evidence=payload["evidence_stage"],
        domain="prospective full-round ChaCha20-R20 transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A287:frozen_W24_global_portfolio",
        mechanism="parallel_default_and_BFS_far_SAT_CaDiCaL",
        outcome=("A287:global_SAT_model" if retained else "A287:two_global_budget_boundaries"),
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["solver_arms"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="symbolic full-round constraint search",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=("A287:global_SAT_model" if retained else "A287:two_global_budget_boundaries"),
        mechanism=(
            "standalone_RFC_operation_recompute_all_eight_blocks"
            if retained
            else "retain_UNKNOWN_as_exact_budget_boundary"
        ),
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=(
            "4096 exact bits; one-bit control rejected"
            if retained
            else f"two arms x {SOLVER_SECONDS} seconds maximum"
        ),
        evidence=payload["evidence_stage"],
        domain="independent confirmation or measured solver boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A287:frozen_W24_global_portfolio",
        mechanism=(
            "materialized_global_search_confirmation_chain"
            if retained
            else "materialized_diverse_global_boundary_chain"
        ),
        outcome=terminal,
        confidence=1.0,
        source="materialized:A287_portfolio_execution",
        quantification="AI-native exact closure retained in-file",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A287 ChaCha20-R20 W24 global portfolio",
        entities=[
            "A286:retained_four_target_panel",
            "A287:frozen_W24_global_portfolio",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospective_W28_or_disjoint_W24_replication"
            if retained
            else "exact_disjoint_partitioned_W24_transfer"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Can the confirmed global mechanism widen to W28?",
                "Does the same frozen portfolio recover a disjoint W24 target?",
            ]
            if retained
            else [
                "Which frozen prefix operator maximizes diversity from both global traces?",
                "Can retained-state prefix cells expose a W24 model within a strict subset?",
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
        or reader.api_id != "a287w24"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A287 authentic Causal gate failed")
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


def execute(expected_preflight_sha256: str) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A287 result already exists")
    preflight_payload, protocol = load_preflight(expected_preflight_sha256)
    root_reference = load_module(ROOT_REFERENCE_SOURCE, "a287_root_reference_run")
    solver_rows, winner = run_portfolio(preflight_payload, protocol)
    confirmation = (
        None
        if winner is None
        else confirm_winner(winner, protocol["public_challenge"], root_reference)
    )
    evidence_stage = (
        "FULLROUND_R20_W24_GLOBAL_SYMBOLIC_RECOVERY_CONFIRMED"
        if confirmation is not None
        else "FULLROUND_R20_W24_DIVERSE_GLOBAL_BUDGET_BOUNDARY"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w24-global-portfolio-a287-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol": preflight_payload["protocol"],
        "preflight": anchor(PREFLIGHT, expected_preflight_sha256),
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "solver_arms": solver_rows,
        "winner": None if winner is None else {key: value for key, value in winner.items() if key != "CNF_model_gate"},
        "confirmation": confirmation,
        "information_boundary": {
            "secret_assignment_available_to_runner": False,
            "target_prefix_or_model_available_before_solver": False,
            "operators_and_budgets_frozen_before_solver": True,
            "unknown_treated_as_UNSAT": False,
            "complete_candidate_domain_enumeration_used": False,
        },
        "rfc8439_gate": root_reference.rfc8439_kat(),
        "runner": anchor(Path(__file__)),
    }
    payload["execution_sha256"] = canonical_sha256(solver_rows)
    payload["measurement_sha256"] = canonical_sha256(
        {
            "solver_arms": solver_rows,
            "winner": payload["winner"],
            "confirmation": confirmation,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    lines = [
        "# A287 — ChaCha20-R20 W24 global portfolio",
        "",
        f"Evidence stage: **{evidence_stage}**",
        "",
        "- Standard rounds plus feed-forward: **20**",
        "- Unknown key bits: **24**",
        "- Public standard-output blocks: **8 / 4,096 bits**",
        "- Frozen global operators: **base/default and BFS-far/SAT**",
        f"- Solver outcomes: **{[(row['arm'], row['status']) for row in solver_rows]}**",
        f"- Independent recovery confirmation: **{confirmation is not None}**",
        "- Complete candidate-domain enumeration: **False**",
        "",
        "## Authentic AI-native Causal readback",
        "",
        f"- Terminal: **{payload['causal']['personal_semantic_readback']['terminal_chain']['outcome']}**",
        f"- Next gap: **{payload['causal']['personal_semantic_readback']['next_gap']['expected_object_type']}**",
        "",
    ]
    atomic_bytes(REPORT, ("\n".join(lines) + "\n").encode("utf-8"))
    return payload


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze", action="store_true")
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--run", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-preflight-sha256")
    args = parser.parse_args(argv)
    if args.freeze:
        payload = freeze()
        output = {
            "protocol": str(PROTOCOL),
            "protocol_sha256": file_sha256(PROTOCOL),
            "public_challenge_sha256": payload["public_challenge_sha256"],
        }
    elif args.preflight:
        if not args.expected_protocol_sha256:
            parser.error("--preflight requires --expected-protocol-sha256")
        payload = preflight(args.expected_protocol_sha256)
        output = {
            "preflight": str(PREFLIGHT),
            "preflight_sha256": file_sha256(PREFLIGHT),
            "variables": payload["formula"]["variables"],
            "clauses": payload["formula"]["clauses"],
            "solver_execution_started": False,
        }
    else:
        if not args.expected_preflight_sha256:
            parser.error("--run requires --expected-preflight-sha256")
        payload = execute(args.expected_preflight_sha256)
        output = {
            "result": str(RESULT),
            "result_sha256": file_sha256(RESULT),
            "causal_sha256": payload["causal"]["sha256"],
            "evidence_stage": payload["evidence_stage"],
            "confirmation": payload["confirmation"],
        }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
