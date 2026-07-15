"""Derive a width-generic retained-state partition helper with reverse enabled.

The canonical generic helper already supports 9..32 model literals.  This
module makes one audited source transformation: it adds
``solver.set("reverse", 1)`` after the selected CaDiCaL configuration.  The
original source, derived source, compiler inputs, and resulting binary are all
content-hashed.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
BASE_WRAPPER = ROOT / "research/experiments/cadical_ranked_partition.py"
BASE_SOURCE = ROOT / "research/native/cadical_ranked_partition_until_sat.cpp"
DEFAULT_DERIVED_SOURCE = ROOT / "research/native/build/cadical_ranked_partition_reverse_derived.cpp"
DEFAULT_BINARY = ROOT / "research/native/build/cadical_ranked_partition_reverse"
COMPILER = Path("/usr/bin/clang++")
CADICAL_HEADER = Path("/opt/homebrew/include/cadical.hpp")
CADICAL_LIBRARY = Path("/opt/homebrew/lib/libcadical.a")

OLD_FRAGMENT = b"""    if (!solver.configure(arguments.configuration.c_str()) ||
        !solver.set(\"quiet\", 1))
      throw std::runtime_error(\"required CaDiCaL configuration is unavailable\");
"""
NEW_FRAGMENT = b"""    if (!solver.configure(arguments.configuration.c_str()) ||
        !solver.set(\"quiet\", 1) || !solver.set(\"reverse\", 1))
      throw std::runtime_error(\"required CaDiCaL configuration or reverse operator is unavailable\");
"""


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def derive_source_bytes() -> bytes:
    raw = BASE_SOURCE.read_bytes()
    if raw.count(OLD_FRAGMENT) != 1 or NEW_FRAGMENT in raw:
        raise RuntimeError("reverse partition source transformation boundary differs")
    derived = raw.replace(OLD_FRAGMENT, NEW_FRAGMENT, 1)
    if derived.count(NEW_FRAGMENT) != 1 or derived.count(OLD_FRAGMENT) != 0:
        raise RuntimeError("reverse partition source transformation failed")
    return derived


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
        "transformation_old_fragment_sha256": sha256(OLD_FRAGMENT),
        "transformation_new_fragment_sha256": sha256(NEW_FRAGMENT),
        "compiler_sha256": file_sha256(COMPILER),
        "cadical_header_sha256": file_sha256(CADICAL_HEADER),
        "cadical_library_sha256": file_sha256(CADICAL_LIBRARY),
        "binary_sha256": file_sha256(temporary) if temporary.exists() else None,
        "reverse_operator_enabled": True,
    }
    if completed.returncode != 0 or completed.stdout or completed.stderr or not temporary.exists():
        raise RuntimeError(f"reverse partition helper build failed: {observation}")
    _atomic_bytes(output, temporary.read_bytes(), executable=True)
    temporary.unlink(missing_ok=True)
    if file_sha256(output) != observation["binary_sha256"]:
        raise RuntimeError("reverse partition binary readback differs")
    observation["binary_path"] = str(output)
    return observation


def load_base_wrapper() -> Any:
    spec = importlib.util.spec_from_file_location(
        "cadical_ranked_partition_reverse_base", BASE_WRAPPER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("generic partition wrapper is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_ranked(**kwargs: Any) -> dict[str, Any]:
    """Run through the canonical width-generic parser using the reverse binary."""

    helper = Path(kwargs.pop("helper", DEFAULT_BINARY))
    if not helper.is_file():
        raise FileNotFoundError(helper)
    base = load_base_wrapper()
    result = base.run_ranked(helper=helper, **kwargs)
    return {
        **result,
        "reverse_operator_enabled": True,
        "reverse_helper_sha256": file_sha256(helper),
        "reverse_source_derivation_sha256": sha256(derive_source_bytes()),
    }
