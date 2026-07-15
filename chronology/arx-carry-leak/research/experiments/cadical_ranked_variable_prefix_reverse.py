"""Build and validate a variable-prefix retained-state reverse CaDiCaL helper.

The canonical helper fixes eight assumption bits and 256 cells.  This audited
derivation preserves its solver and metric semantics while permitting one to
sixteen prefix bits, up to 65,536 cells, and enabling CaDiCaL's reverse
operator.  Both the canonical and derived sources remain content-hashed.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
BASE_SOURCE = ROOT / "research/native/cadical_ranked_partition_until_sat.cpp"
DEFAULT_DERIVED_SOURCE = (
    ROOT / "research/native/build/cadical_ranked_variable_prefix_reverse_derived.cpp"
)
DEFAULT_BINARY = ROOT / "research/native/build/cadical_ranked_variable_prefix_reverse"
COMPILER = Path("/usr/bin/clang++")
CADICAL_HEADER = Path("/opt/homebrew/include/cadical.hpp")
CADICAL_LIBRARY = Path("/opt/homebrew/lib/libcadical.a")

RESULT_PREFIX = "PARTITION_RESULT "
SUMMARY_PREFIX = "PARTITION_SUMMARY "
METRIC_NAMES = ("conflicts", "decisions", "search_propagations")
CONFIGURATIONS = {"default", "sat", "unsat", "plain"}

TRANSFORMATIONS = (
    (
        b"  int max_cells = 256;\n",
        b"  int max_cells = 65536;\n",
    ),
    (
        b"  if (consumed != raw.size() || value <= 0 || value > 256)\n"
        b"    throw std::runtime_error(std::string(label) + \" must be in 1 through 256\");\n",
        b"  if (consumed != raw.size() || value <= 0 || value > 65536)\n"
        b"    throw std::runtime_error(std::string(label) + \" must be in 1 through 65536\");\n",
    ),
    (
        b"  if (result.assumption_one_literals.size() != 8)\n"
        b"    throw std::runtime_error(\n"
        b"        \"exactly eight assumption-one-literals are required\");\n",
        b"  if (result.assumption_one_literals.empty() ||\n"
        b"      result.assumption_one_literals.size() > 16)\n"
        b"    throw std::runtime_error(\n"
        b"        \"one through sixteen assumption-one-literals are required\");\n",
    ),
    (
        b"  if (assumption_variables.size() != 8 ||\n"
        b"      model_variables.size() != result.model_one_literals.size())\n",
        b"  if (assumption_variables.size() !=\n"
        b"          result.assumption_one_literals.size() ||\n"
        b"      model_variables.size() != result.model_one_literals.size())\n",
    ),
    (
        b"  if (result.cell_order.size() != 256)\n"
        b"    throw std::runtime_error(\"cell order must contain 256 entries\");\n"
        b"  std::set<std::string> observed;\n",
        b"  const std::size_t expected_cells =\n"
        b"      std::size_t{1} << result.assumption_one_literals.size();\n"
        b"  if (result.cell_order.size() != expected_cells)\n"
        b"    throw std::runtime_error(\"cell order has the wrong cardinality\");\n"
        b"  if (result.max_cells > static_cast<int>(expected_cells))\n"
        b"    throw std::runtime_error(\"max-cells exceeds the cell order\");\n"
        b"  std::set<std::string> observed;\n",
    ),
    (
        b"    if (!is_binary_width(cell, 8))\n"
        b"      throw std::runtime_error(\n"
        b"          \"cell order entries must be eight-bit binary\");\n",
        b"    if (!is_binary_width(cell, result.assumption_one_literals.size()))\n"
        b"      throw std::runtime_error(\n"
        b"          \"cell order entries have the wrong binary width\");\n",
    ),
    (
        b"  if (observed.size() != 256)\n"
        b"    throw std::runtime_error(\n"
        b"        \"cell order must cover every eight-bit value exactly once\");\n",
        b"  if (observed.size() != expected_cells)\n"
        b"    throw std::runtime_error(\n"
        b"        \"cell order must cover every prefix exactly once\");\n",
    ),
    (
        b"    if (!solver.configure(arguments.configuration.c_str()) ||\n"
        b"        !solver.set(\"quiet\", 1))\n"
        b"      throw std::runtime_error(\"required CaDiCaL configuration is unavailable\");\n",
        b"    if (!solver.configure(arguments.configuration.c_str()) ||\n"
        b"        !solver.set(\"quiet\", 1) || !solver.set(\"reverse\", 1))\n"
        b"      throw std::runtime_error(\"required CaDiCaL configuration or reverse operator is unavailable\");\n",
    ),
    (
        b"      const std::string &prefix8 = arguments.cell_order[cell_index];\n"
        b"      std::vector<int> assumptions;\n"
        b"      for (std::size_t bit = 0; bit < 8; ++bit) {\n"
        b"        const int one_literal = arguments.assumption_one_literals[bit];\n"
        b"        assumptions.push_back(prefix8[bit] == '1' ? one_literal : -one_literal);\n"
        b"      }\n",
        b"      const std::string &prefix = arguments.cell_order[cell_index];\n"
        b"      std::vector<int> assumptions;\n"
        b"      for (std::size_t bit = 0;\n"
        b"           bit < arguments.assumption_one_literals.size(); ++bit) {\n"
        b"        const int one_literal = arguments.assumption_one_literals[bit];\n"
        b"        assumptions.push_back(prefix[bit] == '1' ? one_literal : -one_literal);\n"
        b"      }\n",
    ),
    (
        b"                << \"\\\",\\\"prefix8\\\":\\\"\" << prefix8\n",
        b"                << \"\\\",\\\"prefix\\\":\\\"\" << prefix\n",
    ),
)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def derive_source_bytes() -> bytes:
    raw = BASE_SOURCE.read_bytes()
    for old, new in TRANSFORMATIONS:
        if raw.count(old) != 1 or new in raw:
            raise RuntimeError("variable-prefix source transformation boundary differs")
        raw = raw.replace(old, new, 1)
    return raw


def _atomic_bytes(path: Path, raw: bytes, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    if executable:
        temporary.chmod(0o755)
    os.replace(temporary, path)


def compile_helper(
    *,
    output: Path = DEFAULT_BINARY,
    derived_source: Path = DEFAULT_DERIVED_SOURCE,
) -> dict[str, Any]:
    raw = derive_source_bytes()
    _atomic_bytes(derived_source, raw)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.unlink(missing_ok=True)
    command = [
        str(COMPILER),
        "-std=c++17",
        "-O3",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I/opt/homebrew/include",
        str(derived_source),
        str(CADICAL_LIBRARY),
        "-lpthread",
        "-o",
        str(temporary),
    ]
    started = time.perf_counter()
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    observation = {
        "command": command,
        "returncode": completed.returncode,
        "elapsed_seconds": time.perf_counter() - started,
        "stdout_sha256": sha256(completed.stdout.encode()),
        "stderr_sha256": sha256(completed.stderr.encode()),
        "base_source_path": str(BASE_SOURCE),
        "base_source_sha256": file_sha256(BASE_SOURCE),
        "derived_source_path": str(derived_source),
        "derived_source_sha256": file_sha256(derived_source),
        "transformation_sha256": sha256(
            b"".join(old + b"\x00" + new + b"\x00" for old, new in TRANSFORMATIONS)
        ),
        "compiler_sha256": file_sha256(COMPILER),
        "cadical_header_sha256": file_sha256(CADICAL_HEADER),
        "cadical_library_sha256": file_sha256(CADICAL_LIBRARY),
        "binary_sha256": file_sha256(temporary) if temporary.exists() else None,
        "prefix_bits_min": 1,
        "prefix_bits_max": 16,
        "reverse_operator_enabled": True,
    }
    if (
        completed.returncode != 0
        or completed.stdout
        or completed.stderr
        or not temporary.exists()
    ):
        raise RuntimeError(f"variable-prefix helper build failed: {observation}")
    _atomic_bytes(output, temporary.read_bytes(), executable=True)
    temporary.unlink(missing_ok=True)
    if file_sha256(output) != observation["binary_sha256"]:
        raise RuntimeError("variable-prefix binary readback differs")
    observation["binary_path"] = str(output)
    return observation


def _records(stdout: str, prefix: str) -> list[dict[str, Any]]:
    return [
        json.loads(line.removeprefix(prefix))
        for line in stdout.splitlines()
        if line.startswith(prefix)
    ]


def _mapping_arguments(
    model_one_literals_bit0_upward: Sequence[int], prefix_bits: int
) -> list[str]:
    mapping = [int(value) for value in model_one_literals_bit0_upward]
    width = len(mapping)
    if (
        not 1 <= prefix_bits < width <= 32
        or width < 9
        or len({abs(value) for value in mapping}) != width
    ):
        raise ValueError("invalid variable-prefix model mapping")
    assumption_one = [
        mapping[bit] for bit in range(width - 1, width - prefix_bits - 1, -1)
    ]
    return [
        "--assumption-one-literals",
        ",".join(str(value) for value in assumption_one),
        "--model-one-literals",
        ",".join(str(value) for value in mapping),
    ]


def parse_ranked_output(
    *,
    stdout: str,
    returncode: int,
    mode: str,
    configuration: str,
    order: Sequence[str],
    model_one_literals_bit0_upward: Sequence[int],
    prefix_bits: int,
    seconds: float,
    max_cells: int,
) -> dict[str, Any]:
    expected_order = list(order)
    complete = {f"{value:0{prefix_bits}b}" for value in range(1 << prefix_bits)}
    if len(expected_order) != 1 << prefix_bits or set(expected_order) != complete:
        raise ValueError("partition order must cover every prefix")
    if configuration not in CONFIGURATIONS:
        raise ValueError("unsupported CaDiCaL configuration")
    if seconds <= 0.0 or not 1 <= max_cells <= len(expected_order):
        raise ValueError("invalid partition budget")
    if returncode != 0:
        raise RuntimeError(f"partition helper returned {returncode}")
    rows = _records(stdout, RESULT_PREFIX)
    summaries = _records(stdout, SUMMARY_PREFIX)
    if len(summaries) != 1 or not rows or len(rows) > max_cells:
        raise RuntimeError("variable-prefix helper output is incomplete")
    mapping = [int(value) for value in model_one_literals_bit0_upward]
    width = len(mapping)
    assumption_one = [
        mapping[bit] for bit in range(width - 1, width - prefix_bits - 1, -1)
    ]
    previous: dict[str, Any] | None = None
    for index, row in enumerate(rows):
        prefix = expected_order[index]
        assumptions = [
            literal if bit == "1" else -literal
            for bit, literal in zip(prefix, assumption_one, strict=True)
        ]
        status = row.get("status")
        before = row.get("metrics_before")
        after = row.get("metrics_after")
        delta = row.get("metrics_delta")
        if (
            row.get("mode") != mode
            or row.get("configuration") != configuration
            or row.get("prefix") != prefix
            or row.get("cell_index") != index
            or status not in {"sat", "unsat", "unknown"}
            or row.get("returncode") != {"sat": 10, "unsat": 20, "unknown": 0}[status]
            or float(row.get("seconds_budget", -1)) != float(seconds)
            or row.get("metric_names") != list(METRIC_NAMES)
            or row.get("model_width") != width
            or row.get("assumptions") != assumptions
            or not all(
                isinstance(values, list) and len(values) == 3
                for values in (before, after, delta)
            )
            or any(
                right - left != change
                for left, right, change in zip(before, after, delta, strict=True)
            )
            or (status == "unknown") != (row.get("terminator_fired") is True)
        ):
            raise RuntimeError(f"variable-prefix row gate failed at {index}")
        failed = row.get("failed_assumptions")
        model = row.get("model_bits_bit0_upward")
        if (
            not isinstance(failed, list)
            or not isinstance(model, list)
            or len(set(failed)) != len(failed)
            or any(literal not in assumptions for literal in failed)
            or (status != "unsat" and failed)
            or (status == "sat" and (len(model) != width or set(model) - {0, 1}))
            or (status != "sat" and model)
        ):
            raise RuntimeError(f"variable-prefix outcome gate failed at {index}")
        if previous is not None and (
            before != previous["metrics_after"]
            or row["active_variables_before"] != previous["active_variables_after"]
            or row["irredundant_clauses_before"]
            != previous["irredundant_clauses_after"]
            or row["redundant_clauses_before"] != previous["redundant_clauses_after"]
        ):
            raise RuntimeError(f"variable-prefix retained state failed at {index}")
        for stem in ("active_variables", "irredundant_clauses", "redundant_clauses"):
            if row[f"{stem}_after"] - row[f"{stem}_before"] != row[f"{stem}_delta"]:
                raise RuntimeError(f"variable-prefix {stem} delta failed at {index}")
        previous = row
    summary = summaries[0]
    counts = Counter(row["status"] for row in rows)
    sat_rows = [row for row in rows if row["status"] == "sat"]
    stopped = bool(sat_rows)
    if (
        summary.get("signature") != "cadical-3.0.0"
        or summary.get("version") != "3.0.0"
        or summary.get("mode") != mode
        or summary.get("configuration") != configuration
        or summary.get("model_width") != width
        or summary.get("planned_max_cells") != max_cells
        or summary.get("attempted_cells") != len(rows)
        or summary.get("sat") != counts["sat"]
        or summary.get("unsat") != counts["unsat"]
        or summary.get("unknown") != counts["unknown"]
        or summary.get("terminator_fires")
        != sum(row["terminator_fired"] for row in rows)
        or summary.get("stopped_after_sat") is not stopped
        or float(summary.get("seconds_budget", -1)) != float(seconds)
        or summary.get("metric_names") != list(METRIC_NAMES)
        or len(sat_rows) > 1
        or (stopped and rows[-1]["status"] != "sat")
        or (not stopped and len(rows) != max_cells)
    ):
        raise RuntimeError("variable-prefix helper summary gate failed")
    return {
        "mode": mode,
        "configuration": configuration,
        "model_width": width,
        "prefix_bits": prefix_bits,
        "order": expected_order,
        "seconds_budget_per_cell": seconds,
        "max_cells": max_cells,
        "rows": rows,
        "summary": summary,
        "sat_found": stopped,
        "sat_row": sat_rows[0] if sat_rows else None,
        "retained_state_continuity_verified": True,
    }


def run_ranked(
    *,
    helper: Path,
    cnf: Path,
    mode: str,
    configuration: str,
    order: Sequence[str],
    model_one_literals_bit0_upward: Sequence[int],
    prefix_bits: int,
    seconds: float,
    max_cells: int,
    external_timeout_seconds: float | None = None,
) -> dict[str, Any]:
    command = [
        str(helper),
        "--cnf",
        str(cnf),
        "--mode",
        mode,
        "--configuration",
        configuration,
        *_mapping_arguments(model_one_literals_bit0_upward, prefix_bits),
        "--cell-order",
        ",".join(order),
        "--seconds",
        str(seconds),
        "--max-cells",
        str(max_cells),
    ]
    timeout = external_timeout_seconds or max_cells * seconds + 120.0
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    parsed = parse_ranked_output(
        stdout=completed.stdout,
        returncode=completed.returncode,
        mode=mode,
        configuration=configuration,
        order=order,
        model_one_literals_bit0_upward=model_one_literals_bit0_upward,
        prefix_bits=prefix_bits,
        seconds=seconds,
        max_cells=max_cells,
    )
    return {
        **parsed,
        "command": command,
        "process_elapsed_seconds": time.perf_counter() - started,
        "stdout_sha256": sha256(completed.stdout.encode()),
        "stderr_sha256": sha256(completed.stderr.encode()),
        "helper_returncode": completed.returncode,
        "helper_sha256": file_sha256(helper),
        "derived_source_sha256": sha256(derive_source_bytes()),
        "reverse_operator_enabled": True,
    }
