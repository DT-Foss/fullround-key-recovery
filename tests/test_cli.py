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
    assert value["artifact_count"] == 17
    assert [row["attempt_id"] for row in value["results"]] == ["A184", "A237", "A240"]
