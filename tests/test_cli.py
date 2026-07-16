from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_module_cli_emits_machine_readable_verified_summary() -> None:
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    process = subprocess.run(
        [sys.executable, "-m", "fullround_key_recovery.cli", "all"],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    value = json.loads(process.stdout)
    assert value["status"] == "verified"
    assert value["artifact_count"] == len(value["artifacts"])
    assert [row["attempt_id"] for row in value["results"]] == [
        "A184",
        "A237",
        "A240",
        "A244",
        "A246",
        "A248",
        "A253",
        "A256",
        "AES-W41",
        "A264",
        "P128R1",
        "AES256R1",
        "A281",
        "A286",
        "CHACHA20KR43",
        "A294",
        "A295",
        "A296",
        "A297",
        "A303",
        "A304",
        "A305",
        "A309",
        "A313",
        "B3KR1",
        "SIPKR1",
        "TEAKR1",
        "XTEAKR1",
        "TF1024KR1",
        "A322",
        "A325",
        "A350",
        "A374",
    ]
