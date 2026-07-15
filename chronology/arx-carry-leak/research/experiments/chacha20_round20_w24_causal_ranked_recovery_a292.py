#!/usr/bin/env python3
"""Execute A291's zero-refit Causal W24 order as a retained-state recovery."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"
ARTIFACTS = RESEARCH / "artifacts/a292_chacha20_r20_w24_causal_ranked"

DESIGN = CONFIGS / "chacha20_round20_w24_causal_ranked_recovery_a292_design_v1.json"
A291_SOURCE = RESEARCH / "experiments/chacha20_round20_w24_selected_channel_transfer_a291.py"
A291_PROTOCOL = CONFIGS / "chacha20_round20_w24_selected_channel_transfer_a291_v1.json"
A291_RESULT = RESULTS / "chacha20_round20_w24_selected_channel_transfer_a291_v1.json"
A291_CAUSAL = RESULTS / "chacha20_round20_w24_selected_channel_transfer_a291_v1.causal"
A287_SOURCE = RESEARCH / "experiments/chacha20_round20_w24_global_portfolio_a287.py"
A287_PROTOCOL = CONFIGS / "chacha20_round20_w24_global_portfolio_a287_v1.json"
A287_PREFLIGHT = RESULTS / "chacha20_round20_w24_global_portfolio_a287_preflight_v1.json"
REVERSE_WRAPPER = RESEARCH / "experiments/cadical_ranked_partition_reverse.py"
BASE_PARTITION_WRAPPER = RESEARCH / "experiments/cadical_ranked_partition.py"
BASE_PARTITION_NATIVE = RESEARCH / "native/cadical_ranked_partition_until_sat.cpp"
REVERSE_DERIVED_SOURCE = RESEARCH / "native/build/cadical_ranked_partition_reverse_derived.cpp"
REVERSE_BINARY = RESEARCH / "native/build/cadical_ranked_partition_reverse"
ROOT_REFERENCE_SOURCE = RESEARCH / "experiments/chacha20_round20_multitarget_root_confirm.py"
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)

PROTOCOL = CONFIGS / "chacha20_round20_w24_causal_ranked_recovery_a292_v1.json"
RESULT = RESULTS / "chacha20_round20_w24_causal_ranked_recovery_a292_v1.json"
CAUSAL = RESULTS / "chacha20_round20_w24_causal_ranked_recovery_a292_v1.causal"
MEASUREMENT = RESULTS / "chacha20_round20_w24_causal_ranked_recovery_a292_v1.measurement.json.zst"
REPORT = REPORTS / "CHACHA20_ROUND20_W24_CAUSAL_RANKED_RECOVERY_A292_V1.md"

ATTEMPT_ID = "A292"
WIDTH = 24
PREFIX_BITS = 8
SUFFIX_BITS = 16
CELLS = 256
SECONDS_PER_CELL = 60.0
BLOCKS = 8
OUTPUT_BITS = 4096
ZSTD_LEVEL = 19
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


def anchored_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    digest = file_sha256(path)
    if expected is not None and digest != expected:
        raise RuntimeError(f"A292 anchor differs: {path}")
    return {"path": relative(path), "sha256": digest}


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def gray_values() -> list[int]:
    return [value ^ (value >> 1) for value in range(CELLS)]


def _load_frozen_inputs(
    expected_design_sha256: str,
    expected_a291_result_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if file_sha256(DESIGN) != expected_design_sha256:
        raise RuntimeError("A292 prospective design hash differs")
    design = json.loads(DESIGN.read_bytes())
    if (
        design.get("schema")
        != "chacha20-round20-w24-causal-ranked-recovery-a292-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "prospectively_frozen_before_reading_any_A287_A289_A290_outcome"
        or design.get("frozen_inputs", {}).get("A291_result_sha256")
        != expected_a291_result_sha256
    ):
        raise RuntimeError("A292 prospective design semantics differ")
    if file_sha256(A291_RESULT) != expected_a291_result_sha256:
        raise RuntimeError("A292 A291 result hash differs")
    a291 = json.loads(A291_RESULT.read_bytes())
    analysis = a291.get("analysis", {})
    order = analysis.get("complete_cell_order", [])
    if (
        a291.get("schema")
        != "chacha20-round20-w24-selected-channel-transfer-a291-result-v1"
        or a291.get("attempt_id") != "A291"
        or a291.get("evidence_stage")
        != "FULLROUND_R20_W24_ZERO_REFIT_SELECTED_CHANNEL_ORDER_FROZEN"
        or a291.get("protocol_sha256") != file_sha256(A291_PROTOCOL)
        or analysis.get("model_refits") != 0
        or analysis.get("target_labels_used") != 0
        or len(order) != CELLS
        or set(order) != set(range(CELLS))
        or sha256(bytes(order))
        != analysis.get("complete_cell_order_uint8_sha256")
        or analysis.get("complete_cell_order_uint8_sha256")
        != design["frozen_inputs"]["A291_complete_order_uint8_sha256"]
        or file_sha256(A291_CAUSAL) != a291.get("causal", {}).get("sha256")
    ):
        raise RuntimeError("A292 A291 zero-refit order boundary differs")

    if file_sha256(A287_PREFLIGHT) != design["frozen_inputs"]["A287_preflight_sha256"]:
        raise RuntimeError("A292 A287 preflight hash differs")
    preflight = json.loads(A287_PREFLIGHT.read_bytes())
    if (
        preflight.get("schema")
        != "chacha20-round20-w24-global-portfolio-a287-preflight-v1"
        or preflight.get("public_challenge_sha256")
        != a291.get("public_challenge_sha256")
        or preflight.get("public_challenge_sha256")
        != design["frozen_inputs"]["public_challenge_sha256"]
    ):
        raise RuntimeError("A292 A287 public challenge differs")
    source = preflight.get("arms", {}).get("base_default", {})
    mapping = [int(value) for value in source.get("model_one_literals_bit0_upward", [])]
    cnf = anchored_path(source.get("cnf", {}).get("path", ""))
    if (
        len(mapping) != WIDTH
        or len({abs(value) for value in mapping}) != WIDTH
        or file_sha256(cnf) != source.get("cnf", {}).get("sha256")
        or source.get("cnf", {}).get("sha256")
        != design["frozen_inputs"]["A287_base_CNF_sha256"]
    ):
        raise RuntimeError("A292 full W24 mapping or eight-block CNF differs")

    a287_protocol = json.loads(A287_PROTOCOL.read_bytes())
    challenge = a287_protocol.get("public_challenge", {})
    if (
        canonical_sha256(challenge) != preflight["public_challenge_sha256"]
        or a287_protocol.get("schema")
        != "chacha20-round20-w24-global-portfolio-a287-protocol-v1"
    ):
        raise RuntimeError("A292 frozen public challenge payload differs")

    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(A291_CAUSAL), verify_integrity=True)
    gaps = list(reader._gaps)
    if (
        reader.api_id != "a291w24"
        or len(gaps) != 1
        or gaps[0].get("expected_object_type")
        != "ranked_W24_partition_recovery_with_16_free_bits_per_cell"
    ):
        raise RuntimeError("A292 authentic A291 Causal gap differs")
    return design, a291, preflight, a287_protocol


def execution_plan(a291: Mapping[str, Any], preflight: Mapping[str, Any]) -> dict[str, Any]:
    source = preflight["arms"]["base_default"]
    order = [int(value) for value in a291["analysis"]["complete_cell_order"]]
    return {
        "primitive": "standard_ChaCha20_block_function",
        "rounds": 20,
        "feedforward_included": True,
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "public_input_output_blocks": BLOCKS,
        "constrained_output_bits": OUTPUT_BITS,
        "partition_prefix_bits": PREFIX_BITS,
        "suffix_bits_per_cell": SUFFIX_BITS,
        "prefix_cells": CELLS,
        "cell_order": [f"{value:08b}" for value in order],
        "cell_order_uint8_sha256": sha256(bytes(order)),
        "order_source": "A291_zero_refit_selected_channel_Causal_Reader",
        "target_labels_used_for_order": 0,
        "reader_refits": 0,
        "cadical_configuration": "default",
        "reverse_operator_enabled": True,
        "retained_solver_state_across_cells": True,
        "seconds_per_cell": SECONDS_PER_CELL,
        "max_cells": CELLS,
        "cnf": source["cnf"],
        "model_one_literals_bit0_upward": source[
            "model_one_literals_bit0_upward"
        ],
        "model_mapping_sha256": canonical_sha256(
            source["model_one_literals_bit0_upward"]
        ),
        "first_SAT_terminates": True,
        "UNKNOWN_is_not_UNSAT_or_elimination": True,
        "complete_candidate_domain_enumeration_used": False,
        "confirmation": "frozen_third_RFC_operation_reference_all_eight_blocks",
        "control": "one_bit_flipped_first_standard_output_block",
    }


def freeze(
    expected_design_sha256: str,
    expected_a291_result_sha256: str,
) -> dict[str, Any]:
    if PROTOCOL.exists():
        raise FileExistsError(PROTOCOL)
    design, a291, preflight, _ = _load_frozen_inputs(
        expected_design_sha256, expected_a291_result_sha256
    )
    reverse = load_module(REVERSE_WRAPPER, "a292_reverse_compile")
    build = reverse.compile_helper(
        output=REVERSE_BINARY,
        derived_source=REVERSE_DERIVED_SOURCE,
    )
    plan = execution_plan(a291, preflight)
    protocol = {
        "schema": "chacha20-round20-w24-causal-ranked-recovery-a292-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A291_ranked_reverse_retained_state_frozen_before_any_A292_solver_execution",
        "execution_plan": plan,
        "execution_plan_sha256": canonical_sha256(plan),
        "public_challenge_sha256": a291["public_challenge_sha256"],
        "anchors": {
            "prospective_design": anchor(DESIGN, expected_design_sha256),
            "A291_source": anchor(A291_SOURCE),
            "A291_protocol": anchor(A291_PROTOCOL, a291["protocol_sha256"]),
            "A291_result": anchor(A291_RESULT, expected_a291_result_sha256),
            "A291_causal": anchor(A291_CAUSAL, a291["causal"]["sha256"]),
            "A287_source": anchor(A287_SOURCE),
            "A287_protocol": anchor(A287_PROTOCOL, preflight["protocol"]["sha256"]),
            "A287_preflight": anchor(A287_PREFLIGHT),
            "base_partition_wrapper": anchor(BASE_PARTITION_WRAPPER),
            "reverse_partition_wrapper": anchor(REVERSE_WRAPPER),
            "base_partition_native": anchor(
                BASE_PARTITION_NATIVE, build["base_source_sha256"]
            ),
            "reverse_derived_source": anchor(
                REVERSE_DERIVED_SOURCE, build["derived_source_sha256"]
            ),
            "reverse_binary": anchor(REVERSE_BINARY, build["binary_sha256"]),
            "standalone_RFC_reference": anchor(ROOT_REFERENCE_SOURCE),
            "runner": anchor(Path(__file__)),
        },
        "information_boundary": {
            **design["information_boundary"],
            "prospective_design_precedes_A287_result_materialization": True,
            "A287_A289_A290_outcomes_loaded_by_A292": False,
            "all_order_solver_configuration_and_budgets_frozen": True,
            "any_A292_solver_execution_started": False,
        },
    }
    protocol["scientific_design_sha256"] = canonical_sha256(
        {
            "execution_plan": plan,
            "public_challenge_sha256": protocol["public_challenge_sha256"],
            "information_boundary": protocol["information_boundary"],
            "anchors": protocol["anchors"],
        }
    )
    atomic_json(PROTOCOL, protocol)
    return protocol


def load_protocol(
    expected_protocol_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A292 protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    if (
        protocol.get("schema")
        != "chacha20-round20-w24-causal-ranked-recovery-a292-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "A291_ranked_reverse_retained_state_frozen_before_any_A292_solver_execution"
        or protocol.get("execution_plan_sha256")
        != canonical_sha256(protocol.get("execution_plan"))
    ):
        raise RuntimeError("A292 protocol semantics differ")
    for row in protocol["anchors"].values():
        anchor(anchored_path(row["path"]), row["sha256"])
    design, a291, preflight, a287_protocol = _load_frozen_inputs(
        protocol["anchors"]["prospective_design"]["sha256"],
        protocol["anchors"]["A291_result"]["sha256"],
    )
    if execution_plan(a291, preflight) != protocol["execution_plan"]:
        raise RuntimeError("A292 recomputed execution plan differs")
    return protocol, design, a291, a287_protocol


def _write_measurement(value: Mapping[str, Any]) -> dict[str, Any]:
    raw = canonical_bytes(value)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    atomic_bytes(MEASUREMENT, compressed)
    return {
        "path": relative(MEASUREMENT),
        "raw_bytes": len(raw),
        "raw_sha256": sha256(raw),
        "compressed_bytes": len(compressed),
        "compressed_sha256": sha256(compressed),
    }


def run_ranked(protocol: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    reverse = load_module(REVERSE_WRAPPER, "a292_reverse_run")
    plan = protocol["execution_plan"]
    parsed = reverse.run_ranked(
        helper=REVERSE_BINARY,
        cnf=anchored_path(plan["cnf"]["path"]),
        mode="A292_A291_Causal_ranked_reverse",
        configuration=plan["cadical_configuration"],
        order=plan["cell_order"],
        model_one_literals_bit0_upward=plan[
            "model_one_literals_bit0_upward"
        ],
        seconds=float(plan["seconds_per_cell"]),
        max_cells=int(plan["max_cells"]),
    )
    measurement = {
        "schema": "chacha20-round20-w24-causal-ranked-recovery-a292-measurement-v1",
        "protocol_sha256": file_sha256(PROTOCOL),
        "parsed": parsed,
    }
    measurement_anchor = _write_measurement(measurement)
    summary = parsed["summary"]
    return parsed, {
        "measurement": measurement_anchor,
        "process_elapsed_seconds": parsed["process_elapsed_seconds"],
        "helper_returncode": parsed["helper_returncode"],
        "stdout_sha256": parsed["stdout_sha256"],
        "stderr_sha256": parsed["stderr_sha256"],
        "reverse_helper_sha256": parsed["reverse_helper_sha256"],
        "reverse_source_derivation_sha256": parsed[
            "reverse_source_derivation_sha256"
        ],
        "retained_state_continuity_verified": parsed[
            "retained_state_continuity_verified"
        ],
        "attempted_cells": summary["attempted_cells"],
        "status_counts": {
            status: summary[status] for status in ("sat", "unsat", "unknown")
        },
        "terminator_fires": summary["terminator_fires"],
        "stopped_after_sat": summary["stopped_after_sat"],
    }


def confirm_candidate(
    candidate: int,
    a287_protocol: Mapping[str, Any],
    root_reference: Any,
) -> dict[str, Any]:
    challenge = a287_protocol["public_challenge"]
    if challenge["target_block_sha256"] != [
        sha256(root_reference._word_bytes(block))  # noqa: SLF001
        for block in challenge["target_words"]
    ]:
        raise RuntimeError("A292 frozen target block hashes differ")
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
        raise RuntimeError("A292 standalone all-output confirmation failed")
    return {
        "recovered_unknown_low24": candidate,
        "recovered_unknown_low24_hex": f"{candidate:06x}",
        "standalone_direct_RFC_operation_all_eight_blocks_match": True,
        "output_bits_checked": OUTPUT_BITS,
        "block_sha256": hashes,
        "one_bit_control_rejected": True,
        "complete_candidate_domain_enumeration_used": False,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    reader_source = Path(inspect.getsourcefile(CausalReader) or "")
    recovered = payload.get("confirmation") is not None
    terminal = (
        "A292:confirmed_Causal_ranked_fullround_W24_recovery"
        if recovered
        else "A292:complete_Causal_ranked_budget_boundary"
    )
    writer = CausalWriter(api_id="a292w24")
    writer._rules = []
    writer.add_rule(
        name="zero_refit_reader_order_to_symbolic_recovery",
        description="The hash-frozen A291 zero-refit Reader order controls only W24 prefix order; one reverse CaDiCaL state is retained until SAT or complete cover.",
        pattern=["A291_hash_frozen_order", "retained_reverse_partition", "independent_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="unknown_cells_preserve_search_boundary",
        description="Timed UNKNOWN cells are measurements, never exclusions; their exact order and retained-state deltas remain in the compressed measurement artifact.",
        pattern=["UNKNOWN_not_UNSAT", "hash_anchored_measurement"],
        conclusion="ranked_budget_boundary",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A291:hash_frozen_W24_prefix_order",
        mechanism="apply_order_to_eight_block_reverse_retained_state_partition",
        outcome="A292:frozen_Causal_ranked_recovery",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification="256 prefix cells; 16 free bits each; 60 seconds per cell",
        evidence=payload["evidence_stage"],
        domain="AI-native selected full-round ChaCha20 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A292:frozen_Causal_ranked_recovery",
        mechanism="single_reverse_CaDiCaL_state_with_ranked_assumptions",
        outcome=("A292:partition_SAT_model" if recovered else terminal),
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["coverage"], sort_keys=True),
        evidence=json.dumps(payload["solver"], sort_keys=True),
        domain="retained-state symbolic full-round search",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=("A292:partition_SAT_model" if recovered else terminal),
        mechanism=(
            "standalone_RFC_operation_recompute_all_eight_blocks"
            if recovered
            else "retain_complete_ranked_UNKNOWN_boundary"
        ),
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=(
            "4096 exact output bits; one-bit control rejected"
            if recovered
            else "all 256 Reader-ranked cells measured under frozen budgets"
        ),
        evidence=payload["evidence_stage"],
        domain="independent confirmation or exact solver boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A291:hash_frozen_W24_prefix_order",
        mechanism="materialized_reader_order_recovery_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A291_order_plus_A292_recovery",
        quantification="AI-native exact continuation retained in-file",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A292 Causal-ranked ChaCha20-R20 W24 recovery",
        entities=[
            "A291:hash_frozen_W24_prefix_order",
            "A292:frozen_Causal_ranked_recovery",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospectively_frozen_W28_Causal_ranked_transfer"
            if recovered
            else "Causal_ranked_budget_or_partition_intervention"
        ),
        confidence=1.0,
        suggested_queries=(
            ["Does the unchanged confirmed A291/A292 mechanism widen to W28?"]
            if recovered
            else [
                "Which Reader-ranked cells accumulated the strongest retained clause-state gain?",
                "Does the frozen order improve under a 12+12 partition without refitting?",
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
        or reader.api_id != "a292w24"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A292 authentic Causal gate failed")
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


def execute(expected_protocol_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, MEASUREMENT, REPORT)):
        raise FileExistsError("A292 result artifact already exists")
    protocol, _, _, a287_protocol = load_protocol(expected_protocol_sha256)
    root_reference = load_module(ROOT_REFERENCE_SOURCE, "a292_root_reference")
    parsed, solver = run_ranked(protocol)
    sat_row = parsed["sat_row"]
    winner: dict[str, Any] | None = None
    confirmation: dict[str, Any] | None = None
    if sat_row is not None:
        bits = sat_row["model_bits_bit0_upward"]
        candidate = sum(int(bit) << index for index, bit in enumerate(bits))
        prefix = candidate >> SUFFIX_BITS
        if prefix != int(sat_row["prefix8"], 2):
            raise RuntimeError("A292 SAT model prefix differs")
        numeric_rank = prefix + 1
        gray_rank = gray_values().index(prefix) + 1
        causal_rank = int(sat_row["cell_index"]) + 1
        winner = {
            "candidate_low24": candidate,
            "candidate_low24_hex": f"{candidate:06x}",
            "prefix8": sat_row["prefix8"],
            "causal_reader_discovery_rank_one_based": causal_rank,
            "numeric_rank_one_based": numeric_rank,
            "gray_rank_one_based": gray_rank,
            "causal_rank_minus_numeric_rank": causal_rank - numeric_rank,
            "causal_rank_minus_gray_rank": causal_rank - gray_rank,
        }
        confirmation = confirm_candidate(candidate, a287_protocol, root_reference)
    attempted = int(solver["attempted_cells"])
    coverage = {
        "executed_prefix_cells": attempted,
        "total_prefix_cells": CELLS,
        "executed_prefix_fraction": attempted / CELLS,
        "prefix_domain_upper_bound_assignments": attempted * (1 << SUFFIX_BITS),
        "full_W24_assignment_domain": 1 << WIDTH,
        "strict_prefix_subset_before_recovery": (
            confirmation is not None and attempted < CELLS
        ),
        "complete_prefix_cover_if_no_recovery": (
            confirmation is None and attempted == CELLS
        ),
        "complete_candidate_domain_enumeration_used": False,
    }
    evidence_stage = (
        "FULLROUND_R20_W24_CAUSAL_RANKED_SYMBOLIC_RECOVERY_CONFIRMED"
        if confirmation is not None
        else "FULLROUND_R20_W24_COMPLETE_CAUSAL_RANKED_BUDGET_BOUNDARY"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w24-causal-ranked-recovery-a292-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "solver": solver,
        "winner": winner,
        "confirmation": confirmation,
        "coverage": coverage,
        "information_boundary": {
            "prospective_design_precedes_A287_result_materialization": True,
            "A287_A289_A290_outcomes_loaded_by_A292": False,
            "target_prefix_or_model_available_to_A292_order": False,
            "A291_reader_refits": 0,
            "A291_target_labels_used": 0,
            "unknown_treated_as_UNSAT": False,
            "complete_candidate_domain_enumeration_used": False,
        },
        "rfc8439_gate": root_reference.rfc8439_kat(),
        "runner": anchor(Path(__file__)),
    }
    payload["execution_sha256"] = canonical_sha256(solver)
    payload["measurement_sha256"] = canonical_sha256(
        {
            "solver": solver,
            "winner": winner,
            "confirmation": confirmation,
            "coverage": coverage,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    lines = [
        "# A292 — ChaCha20-R20 W24 Causal-ranked recovery",
        "",
        f"Evidence stage: **{evidence_stage}**",
        "",
        "- Standard rounds plus feed-forward: **20**",
        "- Unknown key bits: **24**",
        "- Public standard-output blocks: **8 / 4,096 bits**",
        "- Reader refits / target labels: **0 / 0**",
        "- Reverse retained-state budget: **60 seconds per prefix cell**",
        f"- Prefix cells attempted: **{attempted} / 256**",
        f"- Independently confirmed recovery: **{confirmation is not None}**",
        "- Complete candidate-domain enumeration: **False**",
        "",
        "## Authentic AI-native Causal readback",
        "",
        f"- Terminal: **{payload['causal']['personal_semantic_readback']['terminal_chain']['outcome']}**",
        f"- Next gap: **{payload['causal']['personal_semantic_readback']['next_gap']['expected_object_type']}**",
        "",
    ]
    if winner is not None:
        lines.extend(
            [
                "## Discovery ranks",
                "",
                f"- Causal Reader order: **{winner['causal_reader_discovery_rank_one_based']}**",
                f"- Numeric order: **{winner['numeric_rank_one_based']}**",
                f"- Gray order: **{winner['gray_rank_one_based']}**",
                "",
            ]
        )
    atomic_bytes(REPORT, ("\n".join(lines) + "\n").encode("utf-8"))
    return payload


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze", action="store_true")
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--run", action="store_true")
    parser.add_argument("--expected-design-sha256")
    parser.add_argument("--expected-a291-result-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args(argv)
    if args.freeze:
        if not args.expected_design_sha256 or not args.expected_a291_result_sha256:
            parser.error(
                "--freeze requires --expected-design-sha256 and --expected-a291-result-sha256"
            )
        payload = freeze(
            args.expected_design_sha256,
            args.expected_a291_result_sha256,
        )
        output = {
            "protocol": str(PROTOCOL),
            "protocol_sha256": file_sha256(PROTOCOL),
            "execution_plan_sha256": payload["execution_plan_sha256"],
            "A292_solver_execution_started": False,
        }
    else:
        if not args.expected_protocol_sha256:
            parser.error("--analyze/--run requires --expected-protocol-sha256")
        protocol, _, _, _ = load_protocol(args.expected_protocol_sha256)
        if args.analyze:
            output = {
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": args.expected_protocol_sha256,
                "public_challenge_sha256": protocol["public_challenge_sha256"],
                "prefix_cells": protocol["execution_plan"]["prefix_cells"],
                "first_prefixes": protocol["execution_plan"]["cell_order"][:16],
                "A292_solver_execution_started": False,
            }
        else:
            payload = execute(args.expected_protocol_sha256)
            output = {
                "result": str(RESULT),
                "result_sha256": file_sha256(RESULT),
                "causal_sha256": payload["causal"]["sha256"],
                "evidence_stage": payload["evidence_stage"],
                "confirmation": payload["confirmation"],
                "coverage": payload["coverage"],
            }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
