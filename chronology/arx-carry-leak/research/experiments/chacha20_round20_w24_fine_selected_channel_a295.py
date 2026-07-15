#!/usr/bin/env python3
"""Use A293's frozen fine-cell traces as A295's target-blind W24 order."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.xor_prefix_orbit import (
    descending_order,
    frozen_a272_single_horizon_score,
)

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"

DESIGN = CONFIGS / "chacha20_round20_w24_fine_selected_channel_a295_design_v1.json"
A293_PROTOCOL = CONFIGS / "chacha20_round20_w24_causal_refinement_a293_v1.json"
A293_RESULT = RESULTS / "chacha20_round20_w24_causal_refinement_a293_v1.json"
A293_CAUSAL = RESULTS / "chacha20_round20_w24_causal_refinement_a293_v1.causal"
A293_ARTIFACTS = RESEARCH / "artifacts/a293_chacha20_r20_w24_causal_refinement"
A294_PROTOCOL = CONFIGS / "chacha20_round20_w24_causal_ordered_metal_a294_v1.json"
A294_RUNNER = RESEARCH / "experiments/chacha20_round20_w24_causal_ordered_metal_a294.py"
ORBIT_SOURCE = ROOT / "src/arx_carry_leak/xor_prefix_orbit.py"

PROTOCOL = CONFIGS / "chacha20_round20_w24_fine_selected_channel_a295_v1.json"
RESULT = RESULTS / "chacha20_round20_w24_fine_selected_channel_a295_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_W24_FINE_SELECTED_CHANNEL_A295_V1.md"
BUILD = RESEARCH / "build/chacha20_round20_w24_fine_selected_channel_a295"

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A295"
DESIGN_SHA256 = "8dfd07e548daffe01ba7262e02a8e9d16754ef8765c3a9169e8f98b2d0014121"
CELLS = 1 << 12
GROUP_SIZE = 1 << 12
DOMAIN_SIZE = 1 << 24


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


def path_from_ref(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    digest = file_sha256(path)
    if expected is not None and digest != expected:
        raise RuntimeError(f"A295 anchor differs: {path}")
    return {"path": relative(path), "sha256": digest}


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A295 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A295 prospective design hash differs")
    value = json.loads(DESIGN.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w24-fine-selected-channel-a295-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("launch_gate")
        != "execute_only_if_A293_completes_all_4096_prefixes_without_a_confirmed_model"
        or value.get("information_boundary", {}).get("A293_result_available_at_design_freeze")
        is not False
    ):
        raise RuntimeError("A295 prospective design semantics differ")
    return value


def parse_trace_rows() -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    rows: list[dict[str, Any]] = []
    anchors: list[dict[str, str]] = []
    for lane in range(8):
        path = A293_ARTIFACTS / f"causal_gray12_lane{lane}.stdout"
        anchors.append(anchor(path))
        for line in path.read_text(encoding="ascii").splitlines():
            if line.startswith("PARTITION_RESULT "):
                rows.append(json.loads(line.removeprefix("PARTITION_RESULT ")))
    prefixes = [str(row.get("prefix")) for row in rows]
    if (
        len(rows) != CELLS
        or len(set(prefixes)) != CELLS
        or set(prefixes) != {f"{value:012b}" for value in range(CELLS)}
        or any(
            row.get("status") != "unknown"
            or row.get("model_bits_bit0_upward") != []
            or row.get("metric_names")
            != ["conflicts", "decisions", "search_propagations"]
            for row in rows
        )
    ):
        raise RuntimeError("A295 requires A293's complete model-free trace cover")
    return rows, anchors


def metric_fields(rows: Sequence[Mapping[str, Any]]) -> tuple[np.ndarray, np.ndarray]:
    accepted = np.zeros(CELLS, dtype=np.float64)
    conflicts = np.zeros(CELLS, dtype=np.float64)
    for row in rows:
        prefix = int(str(row["prefix"]), 2)
        accepted[prefix] = max(float(row["redundant_clauses_delta"]), 0.0)
        names = [str(value) for value in row["metric_names"]]
        deltas = [float(value) for value in row["metrics_delta"]]
        conflicts[prefix] = max(deltas[names.index("conflicts")], 0.0)
    if not np.isfinite(accepted).all() or not np.isfinite(conflicts).all():
        raise RuntimeError("A295 trace channels are not finite")
    return accepted, conflicts


def frozen_order(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    accepted, conflicts = metric_fields(rows)
    scores = frozen_a272_single_horizon_score(accepted, conflicts, bits=12)
    order = descending_order(scores)
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise RuntimeError("A295 selected-channel order is not an exact cover")
    return {
        "complete_order": order,
        "complete_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in order)
        ),
        "score_field": scores.tolist(),
        "score_field_sha256": canonical_sha256(scores.tolist()),
        "accepted_clause_proxy_field_sha256": canonical_sha256(accepted.tolist()),
        "conflict_field_sha256": canonical_sha256(conflicts.tolist()),
        "selected_feature_indices": [502, 504, 505, 508, 509, 510, 511, 514],
        "model_refits": 0,
        "target_labels_used": 0,
        "tiebreak": "descending_score_then_ascending_prefix",
    }


def public_hash_order(public_challenge_sha256: str) -> list[int]:
    seed = bytes.fromhex(public_challenge_sha256)
    order = sorted(
        range(CELLS),
        key=lambda value: hashlib.sha256(
            b"A295|public-hash-control|" + seed + value.to_bytes(2, "big")
        ).digest(),
    )
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise RuntimeError("A295 public hash order differs")
    return order


def freeze(expected_a293_result_sha256: str) -> dict[str, Any]:
    if PROTOCOL.exists():
        raise FileExistsError(PROTOCOL)
    frozen_design = load_design()
    if file_sha256(A293_RESULT) != expected_a293_result_sha256:
        raise RuntimeError("A295 A293 result hash differs")
    a293 = json.loads(A293_RESULT.read_bytes())
    coverage = a293.get("coverage", {})
    if (
        a293.get("schema")
        != "chacha20-round20-w24-causal-refinement-a293-result-v1"
        or a293.get("evidence_stage")
        != "FULLROUND_R20_W24_COMPLETE_CAUSAL_REFINED_BUDGET_BOUNDARY"
        or a293.get("winner") is not None
        or a293.get("confirmation") is not None
        or coverage.get("executed_prefix_cells") != CELLS
        or coverage.get("complete_prefix_cover_if_no_recovery") is not True
    ):
        raise RuntimeError("A295 launch gate is not open")
    if file_sha256(A293_CAUSAL) != a293.get("causal", {}).get("sha256"):
        raise RuntimeError("A295 A293 Causal hash differs")
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(A293_CAUSAL), verify_integrity=True)
    if (
        reader.api_id != "a293w24"
        or len(reader._gaps) != 1
        or reader._gaps[0].get("expected_object_type")
        != "retained_state_depth_or_16plus8_refinement"
    ):
        raise RuntimeError("A295 authentic A293 Reader gap differs")
    a294_protocol = json.loads(A294_PROTOCOL.read_bytes())
    if (
        file_sha256(A294_PROTOCOL)
        != frozen_design["frozen_inputs"]["A294_protocol_sha256"]
        or a294_protocol.get("attempt_id") != "A294"
    ):
        raise RuntimeError("A295 A294 public challenge anchor differs")
    rows, trace_anchors = parse_trace_rows()
    analysis = frozen_order(rows)
    payload = {
        "schema": "chacha20-round20-w24-fine-selected-channel-a295-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "complete_A293_trace_field_and_unchanged_A272_fine_order_frozen_before_A295_candidate_discovery",
        "public_challenge": a294_protocol["public_challenge"],
        "public_challenge_sha256": a294_protocol["public_challenge_sha256"],
        "fine_readout": analysis,
        "public_hash_control_order": public_hash_order(
            a294_protocol["public_challenge_sha256"]
        ),
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A293_protocol": anchor(
                A293_PROTOCOL,
                frozen_design["frozen_inputs"]["A293_protocol_sha256"],
            ),
            "A293_result": anchor(A293_RESULT, expected_a293_result_sha256),
            "A293_causal": anchor(A293_CAUSAL),
            "A294_protocol": anchor(A294_PROTOCOL),
            "A294_runner": anchor(A294_RUNNER),
            "orbit_source": anchor(
                ORBIT_SOURCE,
                frozen_design["frozen_inputs"]["orbit_source_sha256"],
            ),
            "runner": anchor(Path(__file__)),
        },
        "trace_artifacts": trace_anchors,
        "authentic_causal_readback": {
            "source_api_id": reader.api_id,
            "source_gap": reader._gaps[0],
            "read_by_main_before_protocol_freeze": True,
        },
        "information_boundary": {
            "fine_order_formula_frozen_before_A293_completion": True,
            "A294_result_read_or_imported_by_A295_runner": False,
            "target_prefix_model_or_filter_outcome_used_by_readout": False,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "fine_readout": analysis,
            "information_boundary": payload["information_boundary"],
            "anchors": payload["anchors"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A295 protocol hash differs")
    payload = json.loads(PROTOCOL.read_bytes())
    if (
        payload.get("schema")
        != "chacha20-round20-w24-fine-selected-channel-a295-protocol-v1"
        or payload.get("attempt_id") != ATTEMPT_ID
        or len(payload.get("fine_readout", {}).get("complete_order", [])) != CELLS
        or payload.get("anchors", {}).get("runner", {}).get("sha256")
        != file_sha256(Path(__file__))
    ):
        raise RuntimeError("A295 protocol semantics differ")
    for row in payload["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    for row in payload["trace_artifacts"]:
        anchor(path_from_ref(row["path"]), row["sha256"])
    return payload


def rank_analysis(discovery: Mapping[str, Any], protocol: Mapping[str, Any]) -> dict[str, Any]:
    prefix = int(discovery["discovery_prefix12"])
    causal = [int(value) for value in protocol["fine_readout"]["complete_order"]]
    hashed = [int(value) for value in protocol["public_hash_control_order"]]
    a294 = json.loads(A294_PROTOCOL.read_bytes())["execution_plan"]["Causal_order"]
    ranks = {
        "A295_fine_selected_channel": causal.index(prefix) + 1,
        "A294_coarse_Causal_Gray4": [int(value) for value in a294].index(prefix) + 1,
        "numeric": prefix + 1,
        "public_hash_control": hashed.index(prefix) + 1,
    }
    return {
        "prefix12": prefix,
        "prefix_ranks_one_based": ranks,
        "A295_search_gain_bits": math.log2(CELLS / ranks["A295_fine_selected_channel"]),
        "A295_speedup_vs_A294_rank": (
            ranks["A294_coarse_Causal_Gray4"]
            / ranks["A295_fine_selected_channel"]
        ),
        "A295_speedup_vs_numeric_rank": (
            ranks["numeric"] / ranks["A295_fine_selected_channel"]
        ),
        "A295_speedup_vs_public_hash_rank": (
            ranks["public_hash_control"]
            / ranks["A295_fine_selected_channel"]
        ),
        "ranks_computed_only_after_independent_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A295:confirmed_fine_selected_channel_W24_recovery"
    writer = CausalWriter(api_id="a295w24")
    writer._rules = []
    writer.add_rule(
        name="complete_A293_trace_to_fine_selected_channel_order",
        description="The prospectively frozen A295 rule converts all 4,096 model-free A293 traces into one exact fine-prefix order without a target label or refit.",
        pattern=["A293_complete_trace_cover", "A272_frozen_positive_terms"],
        conclusion="A295_frozen_fine_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="fine_order_to_dual_confirmed_discovery",
        description="The fine order is scanned until the first factual Metal filter match and retained only after two full eight-block RFC implementations agree.",
        pattern=["A295_frozen_fine_order", "A295_dual_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A293:complete_Causal_refined_budget_boundary",
        mechanism="A272_positive_selected_channel_over_12bit_XOR_orbit",
        outcome="A295:frozen_fine_prefix_order",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=payload["protocol_sha256"],
        domain="AI-native fine-prefix full-round ChaCha20 readout",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A295:frozen_fine_prefix_order",
        mechanism="ordered_Metal_discovery_then_dual_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="confirmed full-round ChaCha20 W24 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A293:complete_Causal_refined_budget_boundary",
        mechanism="materialized_fine_trace_readout_discovery_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A293_traces_plus_A295_reader",
        quantification="AI-native exact closure retained in-file",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A295 fine selected-channel W24 recovery",
        entities=[
            "A293:complete_Causal_refined_budget_boundary",
            "A295:frozen_fine_prefix_order",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_target_fine_selected_channel_replication_or_W28_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the frozen fine-channel construction replicate on fresh targets or widen to W28?"
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
        reader.api_id != "a295w24"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A295 authentic Causal reopen gate failed")
    source = Path(inspect.getsourcefile(CausalReader) or "")
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
        "reader_source": anchor(source),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def execute(expected_protocol_sha256: str, swiftc: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A295 result already exists")
    protocol = load_protocol(expected_protocol_sha256)
    a294 = load_module(A294_RUNNER, "a295_a294_run")
    metal = load_module(a294.METAL_ANCHOR, "a295_metal_run")
    root_reference = load_module(a294.ROOT_REFERENCE, "a295_root_run")
    executable, build = metal.A184._A181._compile_native(BUILD, swiftc)
    challenge = protocol["public_challenge"]
    host = metal.A184.SliceMetalHost(
        executable,
        a294.initial_state(challenge, metal.A119.CONSTANTS),
        np.asarray(challenge["target_words"][0], dtype=np.uint32),
        np.asarray(challenge["control_target_words"], dtype=np.uint32),
    )
    try:
        mapping = a294.mapping_gate(host, challenge, root_reference)
        discovery = a294.ordered_discovery(
            host=host,
            challenge=challenge,
            order=protocol["fine_readout"]["complete_order"],
        )
        metal_identity = host.identity
    finally:
        host.close()
    confirmation = a294.confirm(discovery, challenge, root_reference)
    ranks = rank_analysis(discovery, protocol)
    evidence_stage = "FULLROUND_R20_W24_FINE_SELECTED_CHANNEL_ORDERED_RECOVERY_CONFIRMED"
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w24-fine-selected-channel-a295-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "native_build": build,
        "metal_identity": metal_identity,
        "mapping_gate": mapping,
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "information_boundary": protocol["information_boundary"],
        "anchors": protocol["anchors"],
    }
    payload["execution_sha256"] = canonical_sha256(
        {"mapping_gate": mapping, "discovery": discovery, "metal_identity": metal_identity}
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": discovery,
            "rank_analysis": ranks,
            "confirmation": confirmation,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    lines = [
        "# A295 — fine selected-channel ChaCha20-R20 W24 recovery",
        "",
        f"Evidence stage: **{evidence_stage}**",
        "",
        f"- A295 prefix rank: **{ranks['prefix_ranks_one_based']['A295_fine_selected_channel']} / 4,096**",
        f"- Search gain: **{ranks['A295_search_gain_bits']:.6f} bits**",
        f"- Recovered low 24 bits: **0x{confirmation['recovered_unknown_low24_hex']}**",
        "- Reader refits / target labels: **0 / 0**",
        "- Dual independent confirmation: **8,192 checked bits**",
        "",
    ]
    atomic_bytes(REPORT, ("\n".join(lines) + "\n").encode("utf-8"))
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "launch_gate_open": A293_RESULT.exists()
        and json.loads(A293_RESULT.read_bytes()).get("winner") is None,
        "protocol_frozen": PROTOCOL.exists(),
        "result_complete": RESULT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--expected-a293-result-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--swiftc", default="/usr/bin/swiftc")
    args = parser.parse_args()
    if args.analyze:
        payload = analyze()
    elif args.freeze:
        if not args.expected_a293_result_sha256:
            parser.error("--freeze requires --expected-a293-result-sha256")
        value = freeze(args.expected_a293_result_sha256)
        payload = {
            "protocol": relative(PROTOCOL),
            "protocol_sha256": file_sha256(PROTOCOL),
            "scientific_design_sha256": value["scientific_design_sha256"],
            "complete_order_uint16be_sha256": value["fine_readout"][
                "complete_order_uint16be_sha256"
            ],
        }
    else:
        if not args.expected_protocol_sha256:
            parser.error("--run requires --expected-protocol-sha256")
        value = execute(args.expected_protocol_sha256, args.swiftc)
        payload = {
            "evidence_stage": value["evidence_stage"],
            "result": relative(RESULT),
            "result_sha256": file_sha256(RESULT),
            "causal": relative(CAUSAL),
            "causal_sha256": file_sha256(CAUSAL),
            "rank_analysis": value["rank_analysis"],
        }
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
