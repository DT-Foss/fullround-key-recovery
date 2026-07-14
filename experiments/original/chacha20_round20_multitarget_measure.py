#!/usr/bin/env python3
"""Execute A284's four complete target-blind measurements before any recovery."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from chacha20_round20_multitarget_common import (
    DEFAULT_DOTCAUSAL_SRC,
    ROOT,
    anchor,
    assert_label_free,
    atomic_bytes,
    atomic_json,
    canonical_sha256,
    file_sha256,
    load_dotcausal,
    path_from_ref,
    path_ref,
    sha256,
    verify_anchors,
)

ATTEMPT_ID = "A284"
DEFAULT_MASTER = (
    ROOT / "research/configs/chacha20_round20_multitarget_panel_master_v1.json"
)
DEFAULT_TARGETS = (
    ROOT / "research/configs/chacha20_round20_multitarget_targets_v1.json"
)
DEFAULT_OUTPUT = (
    ROOT / "research/results/v1/chacha20_round20_multitarget_orders_v1.json"
)
DEFAULT_REPORT = (
    ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_MULTITARGET_ORDER_PANEL_V1.md"
)
RECOVERY_LEDGER = (
    ROOT
    / "research/configs/chacha20_round20_multitarget_recovery_protocols_v1.json"
)


def _paths(index: int) -> dict[str, Path]:
    stem = f"chacha20_round20_multitarget_t{index:02d}_order_v1"
    result = ROOT / f"research/results/v1/{stem}.json"
    return {
        "result": result,
        "measurement": ROOT / f"research/results/v1/{stem}/target.numeric.measurement.json.zst",
        "causal": result.with_suffix(".causal"),
        "report": ROOT / f"research/reports/{stem.upper()}.md",
    }


def _future_recovery_artifacts() -> list[Path]:
    paths = [RECOVERY_LEDGER]
    for index in range(1, 5):
        paths.extend(
            [
                ROOT
                / f"research/configs/chacha20_round20_multitarget_t{index:02d}_recovery_v1.json",
                ROOT
                / f"research/results/v1/chacha20_round20_multitarget_t{index:02d}_composite_recovery_v1.json",
            ]
        )
    return paths


def _load_inputs(
    *,
    master_path: Path,
    expected_master_sha256: str,
    targets_path: Path,
    expected_targets_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(master_path) != expected_master_sha256:
        raise RuntimeError("A284 panel-master hash differs")
    if file_sha256(targets_path) != expected_targets_sha256:
        raise RuntimeError("A284 target-ledger hash differs")
    panel = json.loads(master_path.read_bytes())
    targets = json.loads(targets_path.read_bytes())
    if (
        panel.get("schema") != "chacha20-round20-multitarget-panel-master-v1"
        or panel.get("attempt_id") != "A282"
        or panel.get("frozen_execution_schedule", {}).get(
            "measurement_parallel_workers"
        )
        != 2
        or targets.get("schema")
        != "chacha20-round20-multitarget-target-ledger-v1"
        or targets.get("attempt_id") != "A283"
        or targets.get("protocol_state")
        != "all_four_targets_frozen_and_labels_discarded_before_any_measurement"
        or targets.get("target_count") != 4
        or len(targets.get("targets", [])) != 4
        or targets.get("information_boundary", {}).get("any_measurement_started")
        is not False
        or targets.get("information_boundary", {}).get("any_recovery_started")
        is not False
    ):
        raise RuntimeError("A284 frozen input semantic gate failed")
    verify_anchors(panel["source_anchors"], context="A284 panel sources")
    verify_anchors(
        {row["target_id"]: row["target_protocol"] for row in targets["targets"]},
        context="A284 targets",
    )
    if [row["target_id"] for row in panel["panel_rows"]] != [
        row["target_id"] for row in targets["targets"]
    ]:
        raise RuntimeError("A284 panel and target row order differs")
    return panel, targets


def _execute_one(
    *,
    panel: dict[str, Any],
    target_row: dict[str, Any],
    dotcausal_src: Path,
) -> dict[str, Any]:
    index = int(target_row["panel_index"])
    target_id = str(target_row["target_id"])
    panel_row = panel["panel_rows"][index - 1]
    artifacts = _paths(index)
    runner_anchor = panel["source_anchors"]["A280_order_runner"]
    runner = path_from_ref(runner_anchor["path"])
    master_anchor = panel_row["master_protocol"]
    symbolic_anchor = panel_row["symbolic_protocol"]
    target_anchor = target_row["target_protocol"]
    if not artifacts["result"].exists():
        command = [
            sys.executable,
            str(runner),
            "--master",
            str(path_from_ref(master_anchor["path"])),
            "--expected-master-sha256",
            master_anchor["sha256"],
            "--target",
            str(path_from_ref(target_anchor["path"])),
            "--expected-target-sha256",
            target_anchor["sha256"],
            "--symbolic",
            str(path_from_ref(symbolic_anchor["path"])),
            "--expected-symbolic-sha256",
            symbolic_anchor["sha256"],
            "--run",
            "--output",
            str(artifacts["result"]),
            "--measurement-output",
            str(artifacts["measurement"]),
            "--causal-output",
            str(artifacts["causal"]),
            "--report-output",
            str(artifacts["report"]),
            "--dotcausal-src",
            str(dotcausal_src),
        ]
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=7200,
            env={**os.environ, "PYTHONHASHSEED": "0"},
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"A284 {target_id} measurement failed: "
                f"stdout={completed.stdout[-2000:]!r} stderr={completed.stderr[-2000:]!r}"
            )
        process = {
            "returncode": completed.returncode,
            "stdout_sha256": sha256(completed.stdout.encode()),
            "stderr_sha256": sha256(completed.stderr.encode()),
            "resumed_existing_result": False,
        }
    else:
        process = {
            "returncode": 0,
            "stdout_sha256": None,
            "stderr_sha256": None,
            "resumed_existing_result": True,
        }

    for name, path in artifacts.items():
        if not path.is_file():
            raise RuntimeError(f"A284 {target_id} missing {name} artifact")
    result = json.loads(artifacts["result"].read_bytes())
    measurement = result.get("measurement", {})
    analysis = result.get("analysis", {})
    if (
        result.get("schema") != "chacha20-round20-cross-material-order-result-v1"
        or result.get("attempt_id") != "A280"
        or result.get("evidence_stage")
        != "FULLROUND_R20_CROSS_MATERIAL_TARGET_BLIND_ORDER_FROZEN"
        or result.get("master_protocol_sha256") != master_anchor["sha256"]
        or result.get("target_protocol_sha256") != target_anchor["sha256"]
        or result.get("symbolic_protocol_sha256") != symbolic_anchor["sha256"]
        or result.get("public_challenge_sha256")
        != target_row["public_challenge_sha256"]
        or result.get("headline", {}).get("complete_candidate_cells") != 256
        or result.get("headline", {}).get("model_free_unknown_stages") != 1024
        or measurement.get("complete_candidate_cover") is not True
        or len(analysis.get("complete_cell_order", [])) != 256
        or set(analysis.get("complete_cell_order", [])) != set(range(256))
        or analysis.get("model_refits") != 0
        or analysis.get("target_labels_used") != 0
        or result.get("runner_sha256") != runner_anchor["sha256"]
        or file_sha256(artifacts["measurement"]) != measurement.get("compressed_sha256")
    ):
        raise RuntimeError(f"A284 {target_id} result semantic gate failed")
    assert_label_free(result)
    _, CausalReader, reader_source = load_dotcausal(dotcausal_src)
    reader = CausalReader(str(artifacts["causal"]), verify_integrity=True)
    gaps = list(reader._gaps)
    if (
        reader.version != 1
        or reader.api_id != "a280"
        or len(gaps) != 1
        or gaps[0].get("expected_object_type")
        != "execute_frozen_top128_then_exact_residual_schedule_on_cross_material_target"
    ):
        raise RuntimeError(f"A284 {target_id} Causal readback gate failed")
    return {
        "target_id": target_id,
        "panel_index": index,
        "master_protocol": master_anchor,
        "target_protocol": target_anchor,
        "symbolic_protocol": symbolic_anchor,
        "public_challenge_sha256": target_row["public_challenge_sha256"],
        "result": anchor(artifacts["result"]),
        "measurement": anchor(artifacts["measurement"]),
        "causal": anchor(artifacts["causal"]),
        "report": anchor(artifacts["report"]),
        "complete_order_uint8_sha256": analysis[
            "complete_cell_order_uint8_sha256"
        ],
        "top128_order_uint8_sha256": analysis[
            "top128_cell_order_uint8_sha256"
        ],
        "complete_candidate_cells": 256,
        "model_free_unknown_stages": 1024,
        "reader_refits": 0,
        "target_labels_used": 0,
        "authentic_causal_gap": gaps[0],
        "reader_source": reader_source,
        "process": process,
    }


def execute(
    *,
    master_path: Path,
    expected_master_sha256: str,
    targets_path: Path,
    expected_targets_sha256: str,
    output: Path,
    report_output: Path,
    dotcausal_src: Path,
) -> dict[str, Any]:
    panel, targets = _load_inputs(
        master_path=master_path,
        expected_master_sha256=expected_master_sha256,
        targets_path=targets_path,
        expected_targets_sha256=expected_targets_sha256,
    )
    premature = [path for path in _future_recovery_artifacts() if path.exists()]
    if premature:
        raise RuntimeError(f"A284 recovery artifact predates all-order freeze: {premature[0]}")
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                _execute_one,
                panel=panel,
                target_row=row,
                dotcausal_src=dotcausal_src,
            )
            for row in targets["targets"]
        ]
        rows = [future.result() for future in futures]
    rows.sort(key=lambda row: row["panel_index"])
    if any(path.exists() for path in _future_recovery_artifacts()):
        raise RuntimeError("A284 recovery artifact appeared before the order ledger freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-multitarget-order-ledger-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FOUR_CROSS_MATERIAL_TARGET_BLIND_ORDERS_FROZEN",
        "panel_master": anchor(master_path, expected_master_sha256),
        "target_ledger": anchor(targets_path, expected_targets_sha256),
        "runner": anchor(Path(__file__)),
        "target_count": len(rows),
        "orders": rows,
        "headline": {
            "complete_candidate_cells": 4 * 256,
            "model_free_unknown_stages": 4 * 1024,
            "reader_refits": 0,
            "target_labels_used": 0,
            "all_orders_frozen_before_any_recovery": True,
        },
        "information_boundary": {
            "all_targets_frozen_before_first_measurement": True,
            "all_256_cells_complete_per_target_before_scoring": True,
            "all_four_orders_complete_before_any_recovery_protocol": True,
            "all_four_orders_complete_before_any_recovery_execution": True,
            "cross_target_adaptation_permitted": False,
            "any_recovery_started": False,
        },
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "panel_master_sha256": expected_master_sha256,
            "target_ledger_sha256": expected_targets_sha256,
            "orders": [
                {
                    "target_id": row["target_id"],
                    "public_challenge_sha256": row["public_challenge_sha256"],
                    "complete_order_uint8_sha256": row[
                        "complete_order_uint8_sha256"
                    ],
                    "top128_order_uint8_sha256": row[
                        "top128_order_uint8_sha256"
                    ],
                }
                for row in rows
            ],
            "information_boundary": payload["information_boundary"],
        }
    )
    assert_label_free(payload)
    atomic_json(output, payload)
    report = [
        "# A284 — Four frozen cross-material ChaCha20-R20 orders",
        "",
        "All four targets existed before the first measurement; all four complete 256-cell orders existed before any recovery protocol or solver execution.",
        "",
        f"- Complete cells: **{payload['headline']['complete_candidate_cells']}**",
        f"- Model-free shallow stages: **{payload['headline']['model_free_unknown_stages']}**",
        "- Reader refits: **0**",
        "- Target labels used: **0**",
        "",
    ]
    report.extend(
        f"- {row['target_id']}: `{row['complete_order_uint8_sha256']}`"
        for row in rows
    )
    atomic_bytes(report_output, "\n".join(report).encode("utf-8"))
    return payload


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--master", type=Path, default=DEFAULT_MASTER)
    parser.add_argument("--expected-master-sha256", required=True)
    parser.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    parser.add_argument("--expected-targets-sha256", required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args(argv)
    if not args.run:
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "output": path_ref(args.output),
                    "recovery_started": False,
                }
            )
        )
        return
    if args.output.exists():
        raise FileExistsError(f"A284 order ledger already exists: {args.output}")
    payload = execute(
        master_path=args.master,
        expected_master_sha256=args.expected_master_sha256,
        targets_path=args.targets,
        expected_targets_sha256=args.expected_targets_sha256,
        output=args.output,
        report_output=args.report_output,
        dotcausal_src=args.dotcausal_src,
    )
    print(
        json.dumps(
            {
                "attempt_id": ATTEMPT_ID,
                "evidence_stage": payload["evidence_stage"],
                "result": path_ref(args.output),
                "result_sha256": file_sha256(args.output),
                "target_count": payload["target_count"],
                "complete_candidate_cells": payload["headline"][
                    "complete_candidate_cells"
                ],
                "model_free_unknown_stages": payload["headline"][
                    "model_free_unknown_stages"
                ],
                "recovery_started": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
