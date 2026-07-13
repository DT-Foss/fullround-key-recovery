"""Immutable artifact inventory and byte-integrity gates."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

EXPECTED_SHA256: dict[str, str] = {
    "configs/chacha20_metal_width40_partial_key_recovery_v1.json": "a6c904e07bc56b08994a9cf4c36c86cd43b468f6c23f9e0d81f3cd52317c6ecf",
    "configs/speck32_64_metal_width42_recovery_v1.json": "d8a657c4f46f0fc913b012331ad58791d577bc10a94f1f9146d01df00e1e93ca",
    "configs/threefish256_metal_width38_recovery_v1.json": "8e3c9811d7c588a0d6f89feeec7b5d0233c970c12d6d2f0db66a78f3cd9e3d32",
    "results/chacha20_metal_width40_partial_key_recovery_v1.json": "d467c06105d4a4afba9efaa7bdf6c4e58754b034d4640907486c778ad17e12a9",
    "results/speck32_64_metal_qualification_v1.json": "e3a6c816adc246b1e6c264183557430e45c94e418179699bee9531125ffe5f44",
    "results/speck32_64_metal_width42_recovery_v1.json": "2b8f77c219b4291d6eaa70418ae70c5501deca6acebba62aaf04bf28f7ad59c2",
    "results/threefish256_metal_qualification_v1.json": "1ef2c82a70f4fbb394c6b0cd490ec2e38c57222812a66d8002ff0fd1c2d52a1b",
    "results/threefish256_metal_width38_recovery_v1.json": "bde3c083d911d638fa54f78551c05c138d65a8764dfbbfef58dbd58fadb25e6a",
    "causal/chacha20_metal_width40_partial_key_recovery_v1.causal": "b37bc0234966185e06eb15ae6926502535b0c50271b01f0b6bd8fe5394dabd0f",
    "causal/speck32_64_metal_width42_recovery_v1.causal": "3c768ff374a5c71fb6a80346017ff1467ea44f7218f3e2d554e4fd3afc404130",
    "causal/threefish256_metal_width38_recovery_v1.causal": "3c7853c5728c6a98d87599d41585bb6af5cc25bb755a8919fc4e0b1745c2a813",
    "reports/original/FULLROUND_CAUSAL_CHACHA20_METAL_WIDTH40_PARTIAL_KEY_RECOVERY_V1.md": "dfd7282bb9fc002517e5ca5d6c91d2daca221e0f731806ab00817a317b255768",
    "reports/original/FULLROUND_SPECK32_64_METAL_WIDTH42_RECOVERY_V1.md": "2c399cb402e0d8462f9e6a1e6e0dfbf451b264741d42df416b37b581759fb791",
    "reports/original/FULLROUND_THREEFISH256_METAL_WIDTH38_RECOVERY_V1.md": "1e64356be44bf379728b7846831997621bd994c3f5f95d1bc01efbfbc707f23b",
    "experiments/native/chacha20_metal_native.swift": "ac06b2b6131b9d7edbaf669b4df8fb78298a5920493e10a39cd2d34b1d808816",
    "experiments/native/speck32_64_metal_native.swift": "219d40e02c434219e2e387516d18f4d82736816206d729961a64aea5a6cd9d9c",
    "experiments/native/threefish256_metal_native.swift": "bcab26af8232b08324165b93f751d48ecdf1895ce6959924293fbfd15e44fbda",
}

RESULT_FILES = {
    "chacha20": "chacha20_metal_width40_partial_key_recovery_v1.json",
    "speck32_64": "speck32_64_metal_width42_recovery_v1.json",
    "threefish256": "threefish256_metal_width38_recovery_v1.json",
}


def repository_root(start: Path | None = None) -> Path:
    starts = [start.resolve()] if start else [Path.cwd().resolve(), Path(__file__).resolve()]
    for path in starts:
        for candidate in [path, *path.parents]:
            if (candidate / "provenance" / "ARTIFACTS.sha256").is_file():
                return candidate
    raise FileNotFoundError("could not locate fullround-key-recovery repository root")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_artifact_hashes(root: Path | None = None) -> dict[str, str]:
    base = root or repository_root()
    observed: dict[str, str] = {}
    for relative, expected in EXPECTED_SHA256.items():
        path = base / relative
        if not path.is_file():
            raise FileNotFoundError(f"missing immutable artifact: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(f"artifact hash mismatch: {relative}: {actual} != {expected}")
        observed[relative] = actual
    return observed


def load_result(name: str, root: Path | None = None) -> dict[str, Any]:
    if name not in RESULT_FILES:
        raise KeyError(f"unknown retained result: {name}")
    base = root or repository_root()
    value = json.loads((base / "results" / RESULT_FILES[name]).read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"retained result is not an object: {name}")
    return value
