"""Per-target binary adapter for parallel A285 residual CaDiCaL executions."""

from __future__ import annotations

import importlib.util
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
BASE_WRAPPER = ROOT / "research/experiments/chacha20_residual_two_pass.py"
_SUFFIX = os.environ.get("F8_CAUSAL_RESIDUAL_BINARY_SUFFIX", "serial")
if re.fullmatch(r"[a-z0-9_]{1,32}", _SUFFIX) is None:
    raise RuntimeError("invalid per-target residual binary suffix")
BINARY = ROOT / f"research/native/build/cadical_residual_two_pass_{_SUFFIX}"


def _load_base() -> Any:
    name = f"a285_residual_base_{_SUFFIX}"
    spec = importlib.util.spec_from_file_location(name, BASE_WRAPPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("base residual wrapper is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_BASE = _load_base()


def compile_helper(*, output: Path = BINARY) -> dict[str, Any]:
    return _BASE.compile_helper(output=output)


def run_two_pass(**kwargs: Any) -> dict[str, Any]:
    return _BASE.run_two_pass(**kwargs)

