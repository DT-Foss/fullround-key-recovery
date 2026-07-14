#!/usr/bin/env python3
"""Finalize and independently confirm the completed A285 four-target panel.

This finalizer performs no solver work.  It binds the four immutable A285
results, recomputes every recovered target with the already frozen standalone
RFC-operation implementation, reads every canonical graph with the
authoritative CausalReader, and emits a corrected aggregate graph whose API id
fits the format's eight-byte header field.
"""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESULTS = ROOT / "research/results/v1"
CONFIGS = ROOT / "research/configs"
REPORTS = ROOT / "research/reports"
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ROOT_CONFIRM_SOURCE = (
    ROOT / "research/experiments/chacha20_round20_multitarget_root_confirm.py"
)
OUTPUT = RESULTS / "chacha20_round20_multitarget_panel_root_confirmation_a286_v1.json"
CAUSAL_OUTPUT = (
    RESULTS / "chacha20_round20_multitarget_panel_root_confirmation_a286_v1.causal"
)
REPORT_OUTPUT = (
    REPORTS / "CHACHA20_ROUND20_MULTITARGET_PANEL_ROOT_CONFIRMATION_A286_V1.md"
)

EXPECTED_SHARED = {
    CONFIGS / "chacha20_round20_multitarget_panel_master_v1.json": (
        "79a7c1527dfa91aa623ebb26df563883be457b81ea9b9d1b6731f5950f22b4ef"
    ),
    RESULTS / "chacha20_round20_multitarget_orders_v1.json": (
        "41ea2494a75ad3f2dd49ca43e408b03580fdf498d935bfc03dedf3b5c1d8c1d3"
    ),
    CONFIGS / "chacha20_round20_multitarget_recovery_protocols_v1.json": (
        "8ec1971642f617f0fa85ef6800fdfacaaa7019f9acb66f7b22c8f51ccc223180"
    ),
    ROOT_CONFIRM_SOURCE: (
        "3911002cdeff7f4705e82fd62ed293bbe675c7d02791aa7aa8770ed4d7d2891e"
    ),
}

EXPECTED_TARGETS = {
    "t01": {
        "protocol": "40b01fbe337faeb62d74bbe52609d658e3f773b6c985b59febae1bf99aa62872",
        "result": "3ee79b2fbffd2a6afdf594e948260f7d93c098d04a846796b8f06f402c8e90ad",
        "canonical": "41758070f708ab46f2ea390b7ca80d1950a321d345650c130152b976824de5d5",
        "causal": "3bff9a192ed4e00f674d5aff48f9b30707cf5e705b0f28042c42c1c54276d87e",
    },
    "t02": {
        "protocol": "b986dc7d9bf5e3a0a17d569cc4fe5c224858aa79fe9dc6a579db9db696ca531a",
        "result": "3f04e0048a9089c15ae7c69739134a60dd8874eb17c76d3f7ff33235781f7d95",
        "canonical": "ab5b271ded021bc23ee4cdd367b4c91a9395bae2bb38079d7407deda446371ea",
        "causal": "0aa516b7de78e45393ea4aa1ab2c46b2dc537c72d18fd10aed0e0273744ff93f",
    },
    "t03": {
        "protocol": "4c993c83ed66bba802f0f8a49db47301dae0fba949d7e1ff66053dc22e21c491",
        "result": "e5349ccf5d75c626adeb1cc5691d7039b2b0ddab5ace6dc98a1670773b702e8a",
        "canonical": "e777c123dee1fba990989f2bfa8040cc67b0815d1b78bd9ce821192f9d86cee7",
        "causal": "d122b8b6100f5648989ecda2ff211b753583be64ceb91192465a2d5b6a9ae1ca",
    },
    "t04": {
        "protocol": "cb60e905cb55472cbe91bf9c6521d68483f9e025ee5199a46fce206533cb1a01",
        "result": "8c8727bb2b922b8a2f39af9d770b221066afc1b42af7dda3041c44d2a2c6dfd7",
        "canonical": "669c1746144515c9cbf57b9bcf9a3f367c8e9fcc6443300627dc190125a5afd9",
        "causal": "6b4fa079e7e3a6bd14d91176a9831f7aee70780abac287e272b7fe779b54887a",
    },
}


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def canonical_sha256(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    )


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


def ref(path: Path, expected: str | None = None) -> dict[str, str]:
    digest = file_sha256(path)
    if expected is not None and digest != expected:
        raise RuntimeError(f"A286 immutable anchor differs: {path.name}")
    return {"path": str(path.relative_to(ROOT)), "sha256": digest}


def load_root_reference() -> Any:
    spec = importlib.util.spec_from_file_location("a285_root_reference", ROOT_CONFIRM_SOURCE)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load frozen A285 root reference")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_dotcausal() -> tuple[Any, Any, dict[str, str]]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    source = Path(inspect.getsourcefile(CausalReader) or "")
    return CausalWriter, CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": file_sha256(source),
    }


def target_paths(target_id: str) -> dict[str, Path]:
    return {
        "protocol": CONFIGS / f"chacha20_round20_multitarget_{target_id}_recovery_v1.json",
        "result": RESULTS / f"chacha20_round20_multitarget_{target_id}_composite_recovery_v1.json",
        "canonical": RESULTS / f"chacha20_round20_multitarget_{target_id}_composite_recovery_canonical_v1.json",
        "causal": RESULTS / f"chacha20_round20_multitarget_{target_id}_composite_recovery_canonical_v1.causal",
    }


def confirm_target(
    target_id: str, root_reference: Any, CausalReader: Any
) -> dict[str, Any]:
    expected = EXPECTED_TARGETS[target_id]
    paths = target_paths(target_id)
    anchors = {name: ref(path, expected[name]) for name, path in paths.items()}
    protocol = json.loads(paths["protocol"].read_bytes())
    result = json.loads(paths["result"].read_bytes())
    canonical = json.loads(paths["canonical"].read_bytes())
    target_anchor = protocol.get("anchors", {}).get("A279_target", {})
    target_path = ROOT / str(target_anchor.get("path", ""))
    target_payload = json.loads(target_path.read_bytes())
    anchors["target"] = ref(target_path, str(target_anchor.get("sha256", "")))
    challenge = target_payload["public_challenge"]
    confirmation = result.get("confirmation")
    if (
        challenge.get("rounds") != 20
        or challenge.get("block_count") != 8
        or challenge.get("unknown_assignment_included") is not False
        or not isinstance(confirmation, dict)
        or confirmation.get("output_bits_checked") != 4096
        or canonical.get("target_id") != target_id
        or canonical.get("confirmed") is not True
        or canonical.get("source_result", {}).get("sha256") != expected["result"]
        or canonical.get("causal", {}).get("sha256") != expected["causal"]
    ):
        raise RuntimeError(f"A286 {target_id} input semantics differ")
    recovered = int(confirmation["recovered_unknown_low20"])
    key_words = [
        int(challenge["known_key_word0_upper12"]) | recovered,
        *[int(word) for word in challenge["known_key_words_1_through_7"]],
    ]
    observed = [
        root_reference.chacha20_block(
            key_words,
            int(challenge["counter_start"]) + block_index,
            challenge["nonce_words"],
        )
        for block_index in range(8)
    ]
    block_hashes = [
        sha256(root_reference._word_bytes(block))  # noqa: SLF001
        for block in observed
    ]
    if (
        observed != challenge["target_words"]
        or block_hashes != challenge["target_block_sha256"]
        or observed[0] == challenge["control_target_words"]
        or block_hashes != confirmation["candidate_block_sha256"]
        or confirmation.get("all_cross_implementation_blocks_match") is not True
    ):
        raise RuntimeError(f"A286 {target_id} standalone confirmation failed")
    reader = CausalReader(str(paths["causal"]), verify_integrity=True)
    rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    terminal = f"A285:{target_id}_confirmed_cross_material_R20_recovery"
    if (
        reader.version != 1
        or reader.api_id != f"a285{target_id}"
        or len(reader.get_all_triplets(include_inferred=False)) != 3
        or len(rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError(f"A286 {target_id} canonical Causal gate failed")
    stage = str(result["residual_execution_summary"]["model_discovery_stage"])
    return {
        "target_id": target_id,
        "evidence_stage": result["evidence_stage"],
        "discovery_stage": stage,
        "frozen_order_rank": canonical["order_rank"],
        "prefix8": canonical["prefix8"],
        "recovered_unknown_low20": recovered,
        "recovered_unknown_low20_hex": f"{recovered:05x}",
        "standalone_direct_spec_all_8_blocks_match": True,
        "standalone_output_bits_checked": 4096,
        "standalone_block_sha256": block_hashes,
        "one_bit_control_rejected": True,
        "complete_full_domain_enumeration_used": False,
        "anchors": anchors,
        "authentic_causal_readback": {
            "api_id": reader.api_id,
            "triplets": len(rows),
            "rules": len(reader._rules),
            "clusters": len(reader._clusters),
            "terminal_chain": rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def build_panel_causal(
    payload: dict[str, Any], CausalWriter: Any, CausalReader: Any, reader_source: dict[str, str]
) -> dict[str, Any]:
    writer = CausalWriter(api_id="a286pan")
    writer._rules = []
    writer.add_rule(
        name="four_disjoint_targets_confirm_panel_transfer",
        description=(
            "Four independently frozen public-material targets, each recovered and "
            "confirmed over 4096 output bits, establish the panel transfer result."
        ),
        pattern=["A282_A285_frozen_panel", "four_third_reference_confirmations"],
        conclusion="A286_retained_four_target_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="panel_distribution_selects_wider_transfer",
        description=(
            "The material-specific top128, fallback, and global discoveries select "
            "a wider-domain transfer rather than a same-width refit."
        ),
        pattern=["A286_retained_four_target_panel", "heterogeneous_discovery_modes"],
        conclusion="A287_W24_transfer",
        confidence_modifier=1.0,
    )
    for row in payload["targets"]:
        writer.add_triplet(
            trigger=f"A285:{row['target_id']}_canonical_recovery",
            mechanism="third_RFC_operation_implementation_all_eight_blocks",
            outcome=f"A286:{row['target_id']}_independently_confirmed",
            confidence=1.0,
            source=row["anchors"]["result"]["sha256"],
            quantification=(
                f"4096 bits; discovery={row['discovery_stage']}; "
                f"rank={row['frozen_order_rank']}"
            ),
            evidence=row["evidence_stage"],
            domain="full-round ChaCha20-R20 cross-material recovery",
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger="A282_A285_frozen_panel",
        mechanism="four_third_reference_confirmations",
        outcome="A286:retained_four_target_panel",
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="4/4 recoveries; 16384 independently recomputed output bits",
        evidence=payload["evidence_stage"],
        domain="AI-native retained panel inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A286 retained four-target ChaCha20-R20 panel",
        entities=[
            "A282_A285_frozen_panel",
            *[f"A286:{target_id}_independently_confirmed" for target_id in EXPECTED_TARGETS],
            "A286:retained_four_target_panel",
        ],
    )
    writer.add_gap(
        subject="A286:retained_four_target_panel",
        predicate="next_required_object",
        expected_object_type="prospectively_frozen_W24_cross_material_transfer",
        confidence=1.0,
        suggested_queries=[
            "Can the frozen panel evidence guide a 24-unknown-bit R20 recovery?",
            "Which target-blind operator preserves advantage after widening from W20 to W24?",
        ],
    )
    temporary = CAUSAL_OUTPUT.with_name(f".{CAUSAL_OUTPUT.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL_OUTPUT)
    reader = CausalReader(str(CAUSAL_OUTPUT), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a286pan"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != "A286:retained_four_target_panel"
    ):
        raise RuntimeError("A286 aggregate Causal Reader gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": str(CAUSAL_OUTPUT.relative_to(ROOT)),
        "sha256": file_sha256(CAUSAL_OUTPUT),
        "bytes": CAUSAL_OUTPUT.stat().st_size,
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": reader_source,
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def main() -> None:
    if OUTPUT.exists() or CAUSAL_OUTPUT.exists() or REPORT_OUTPUT.exists():
        raise FileExistsError("A286 output already exists")
    shared_anchors = {str(path.relative_to(ROOT)): ref(path, digest) for path, digest in EXPECTED_SHARED.items()}
    root_reference = load_root_reference()
    kat = root_reference.rfc8439_kat()
    CausalWriter, CausalReader, reader_source = load_dotcausal()
    targets = [
        confirm_target(target_id, root_reference, CausalReader)
        for target_id in EXPECTED_TARGETS
    ]
    ranks = [int(row["frozen_order_rank"]) for row in targets if row["frozen_order_rank"] is not None]
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-multitarget-panel-root-confirmation-a286-v1",
        "attempt_id": "A286",
        "evidence_stage": "FULLROUND_R20_FOUR_OF_FOUR_CROSS_MATERIAL_RECOVERIES_INDEPENDENTLY_CONFIRMED",
        "solver_or_measurement_reexecuted": False,
        "panel_finalize_bug": {
            "scientific_results_affected": False,
            "cause": "A285 requested a nine-byte API id in an eight-byte Causal header field",
            "preserved_original_causal": ref(RESULTS / "chacha20_round20_multitarget_recovery_panel_v1.causal"),
            "fix": "new aggregate artifact with seven-byte api_id a286pan",
        },
        "shared_anchors": shared_anchors,
        "rfc8439_gate": kat,
        "targets": targets,
        "headline": {
            "fresh_public_material_targets": 4,
            "confirmed_recoveries": 4,
            "independently_recomputed_output_bits": 16384,
            "frozen_order_ranks_when_applicable": ranks,
            "minimum_rank": min(ranks),
            "median_rank": statistics.median(ranks),
            "maximum_rank": max(ranks),
            "discovery_modes": [row["discovery_stage"] for row in targets],
            "complete_full_domain_enumeration_used": False,
            "reader_refits": 0,
            "target_labels_used": 0,
            "all_one_bit_controls_rejected": True,
        },
    }
    payload["confirmation_sha256"] = canonical_sha256(
        {
            "shared_anchors": shared_anchors,
            "rfc8439_gate": kat,
            "targets": targets,
            "headline": payload["headline"],
        }
    )
    payload["causal"] = build_panel_causal(
        payload, CausalWriter, CausalReader, reader_source
    )
    payload["source"] = ref(Path(__file__))
    atomic_json(OUTPUT, payload)
    report = [
        "# A286 — Four-target ChaCha20-R20 panel retained",
        "",
        f"Evidence stage: **{payload['evidence_stage']}**",
        "",
        "- Fresh, independently frozen public-material targets: **4**",
        "- Full-round recoveries: **4/4**",
        "- Third-reference output bits recomputed: **16,384**",
        f"- Applicable frozen-order ranks: **{ranks}**",
        f"- Discovery modes: **{payload['headline']['discovery_modes']}**",
        "- Complete residual-domain enumeration used: **False**",
        "- Reader refits / target labels used: **0 / 0**",
        "- One-bit controls rejected: **4/4**",
        "",
        "The failed A285 aggregate gate was a header-width finalization bug: the requested nine-byte API id was truncated by the format's eight-byte field. It did not affect any target execution or scientific result. A286 preserves that diagnostic artifact and emits the corrected aggregate graph.",
        "",
        "## Authentic AI-native Causal readback",
        "",
        f"- Terminal: **{payload['causal']['personal_semantic_readback']['terminal_chain']['outcome']}**",
        f"- Next gap: **{payload['causal']['personal_semantic_readback']['next_gap']['expected_object_type']}**",
        "",
        f"Result SHA-256: `{file_sha256(OUTPUT) if OUTPUT.exists() else 'written-after-report'}`",
    ]
    atomic_bytes(REPORT_OUTPUT, ("\n".join(report) + "\n").encode("utf-8"))
    print(
        json.dumps(
            {
                "output": str(OUTPUT),
                "output_sha256": file_sha256(OUTPUT),
                "causal": str(CAUSAL_OUTPUT),
                "causal_sha256": file_sha256(CAUSAL_OUTPUT),
                "confirmed_recoveries": 4,
                "independently_recomputed_output_bits": 16384,
                "frozen_order_ranks": ranks,
                "next_gap": payload["causal"]["personal_semantic_readback"]["next_gap"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
