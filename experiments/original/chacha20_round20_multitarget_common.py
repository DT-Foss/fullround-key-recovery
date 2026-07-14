"""Shared strict I/O and provenance helpers for the A282--A285 R20 panel."""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
FORBIDDEN_SERIALIZED_KEYS = {
    "known_low20",
    "low20",
    "low20_hex",
    "recovered_unknown_low20",
    "recovered_unknown_low20_hex",
    "salt",
    "salt_hex",
    "secret_low20",
    "target_prefix8",
    "true_prefix",
    "unknown_assignment",
    "unknown_key_word0_low_value",
}


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


def path_from_ref(value: str | Path) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else ROOT / candidate


def path_ref(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:
        return str(resolved)


def anchor(path: Path, digest: str | None = None) -> dict[str, str]:
    return {"path": path_ref(path), "sha256": digest or file_sha256(path)}


def verify_anchor(value: Mapping[str, Any], *, context: str) -> Path:
    if set(value) != {"path", "sha256"}:
        raise RuntimeError(f"{context} anchor shape differs")
    path = path_from_ref(str(value["path"]))
    if file_sha256(path) != value["sha256"]:
        raise RuntimeError(f"{context} anchor hash differs")
    return path


def verify_anchors(values: Mapping[str, Any], *, context: str) -> None:
    for name, value in values.items():
        if not isinstance(value, Mapping):
            raise RuntimeError(f"{context} anchor is not a mapping: {name}")
        verify_anchor(value, context=f"{context}/{name}")


def import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import panel dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def assert_label_free(value: Any) -> None:
    """Reject target-label fields at any depth while permitting post-model results."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in FORBIDDEN_SERIALIZED_KEYS:
                raise RuntimeError(f"target-label field is forbidden: {key}")
            assert_label_free(child)
    elif isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        for child in value:
            assert_label_free(child)


def load_dotcausal(
    dotcausal_src: Path = DEFAULT_DOTCAUSAL_SRC,
) -> tuple[Any, Any, dict[str, Any]]:
    try:
        module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(module.CausalReader) or "")
    return module.CausalWriter, module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": file_sha256(source),
    }


def iter_json_values(directory: Path, pattern: str) -> list[tuple[Path, Any]]:
    rows: list[tuple[Path, Any]] = []
    for path in sorted(directory.glob(pattern)):
        try:
            rows.append((path, json.loads(path.read_bytes())))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            continue
    return rows


def recursive_values(value: Any, key_name: str) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key) == key_name:
                found.append(child)
            found.extend(recursive_values(child, key_name))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            found.extend(recursive_values(child, key_name))
    return found


def existing_public_seeds() -> set[str]:
    seeds: set[str] = set()
    for directory in (ROOT / "research/configs", ROOT / "research/results/v1"):
        for _, value in iter_json_values(directory, "chacha20*.json"):
            for candidate in recursive_values(value, "public_seed_hex"):
                if isinstance(candidate, str) and len(candidate) == 64:
                    seeds.add(candidate)
    return seeds


def prior_challenge_hashes() -> set[str]:
    hashes: set[str] = set()
    for directory in (ROOT / "research/configs", ROOT / "research/results/v1"):
        for _, value in iter_json_values(directory, "chacha20*.json"):
            for candidate in recursive_values(value, "public_challenge_sha256"):
                if isinstance(candidate, str) and len(candidate) == 64:
                    hashes.add(candidate)
    return hashes


def prior_recovered_low20() -> set[int]:
    labels: set[int] = set()
    for _, value in iter_json_values(ROOT / "research/results/v1", "chacha20*.json"):
        for candidate in recursive_values(value, "recovered_unknown_low20"):
            if isinstance(candidate, int) and not isinstance(candidate, bool):
                if 0 <= candidate < 2**20:
                    labels.add(candidate)
    return labels

