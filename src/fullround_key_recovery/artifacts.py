"""Immutable artifact inventory and byte-integrity gates."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

_BASE_SHA256: dict[str, str] = {
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


def _load_manifest() -> dict[str, str]:
    manifest = Path(__file__).resolve().parents[2] / "provenance" / "ARTIFACTS.sha256"
    values: dict[str, str] = {}
    for line_number, raw in enumerate(manifest.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            digest, relative = line.split(maxsplit=1)
        except ValueError as error:
            raise RuntimeError(f"malformed artifact manifest line {line_number}") from error
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or relative in values
        ):
            raise RuntimeError(f"invalid artifact manifest line {line_number}")
        values[relative] = digest
    if not values:
        raise RuntimeError("artifact manifest is empty")
    for relative, digest in _BASE_SHA256.items():
        if values.get(relative) != digest:
            raise RuntimeError(f"base artifact pin differs: {relative}")
    return values


EXPECTED_SHA256 = _load_manifest()

RESULT_FILES = {
    "chacha20": "chacha20_metal_width40_partial_key_recovery_v1.json",
    "speck32_64": "speck32_64_metal_width42_recovery_v1.json",
    "threefish256": "threefish256_metal_width38_recovery_v1.json",
    "speck64_128": "speck64_128_metal_width44_recovery_v1.json",
    "simon64_128": "simon64_128_metal_width43_recovery_v1.json",
    "rc5_32_12_16": "rc5_32_12_16_metal_width40_recovery_v1.json",
    "present80": "present80_metal_width38_recovery_v1.json",
    "ascon_aead128": "ascon_aead128_metal_width40_a256_recovery_v1.json",
    "aes128": "aes128_fips197_metal_width41_recovery_v1.json",
    "salsa20_20": "salsa20_20_metal_width42_recovery_v1.json",
    "present128": "present128_metal_width38_recovery_v1.json",
    "aes256": "aes256_fips197_metal_width41_recovery_v1.json",
    "chacha20_cross_material": "chacha20_round20_cross_material_composite_recovery_v1.json",
    "chacha20_multitarget_panel": "chacha20_round20_multitarget_panel_root_confirmation_a286_v1.json",
    "chacha20_w43_complete": "chacha20_round20_w43_metal_record_v1.json",
    "chacha20_a294": "chacha20_round20_w24_causal_ordered_metal_a294_v1.json",
    "chacha20_a295": "chacha20_round20_w24_fine_selected_channel_a295_v1.json",
    "chacha20_a296": "chacha20_round20_causal_search_gain_panel_a296_v1.json",
    "chacha20_a297": "chacha20_round20_w32_causal_search_gain_panel_a297_v1.json",
    "chacha20_a303": "chacha20_round20_w32_dominance_pruned_companion_a303_v1.json",
    "chacha20_a304": "chacha20_round20_w43_grouped_engine_a304_v1.json",
    "chacha20_a305": "chacha20_round20_w43_a299_grouped_replay_a305_v1.json",
    "chacha20_a309": "chacha20_round20_w43_width_conditioned_band_portfolio_a309_v1.json",
    "chacha20_a313": "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.json",
    "blake3_keyed": "blake3_keyed_metal_recovery_v1.json",
    "siphash24": "siphash24_metal_recovery_v1.json",
    "tea": "tea_metal_recovery_v1.json",
    "xtea": "xtea_metal_recovery_v1.json",
    "threefish1024": "threefish1024_metal_record_v1.json",
    "chacha20_a322": "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json",
    "chacha20_a325": "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json",
    "chacha20_a350": "chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.json",
    "chacha20_a374": "chacha20_round20_w48_target_conditioned_recovery_a374_v1.json",
}

CONFIG_FILES = {
    **{name: filename for name, filename in RESULT_FILES.items()},
    "aes256": "aes256_metal_width41_recovery_v1.json",
    "chacha20_cross_material": "chacha20_round20_cross_material_target_v1.json",
    "chacha20_multitarget_panel": "chacha20_round20_multitarget_panel_master_v1.json",
    "chacha20_a303": "chacha20_round20_w32_fine_selected_channel_transfer_a298_v1.json",
    "chacha20_a304": "chacha20_round20_w43_calibrated_coarse_numeric_replication_a302_v1.json",
    "chacha20_a305": "chacha20_round20_w43_fine_selected_channel_transfer_a299_v1.json",
    "chacha20_a309": "chacha20_round20_w43_three_operator_portfolio_a300_v1.json",
    "chacha20_a313": "chacha20_round20_w44_calibrated_coarse_numeric_a308_v1.json",
    "chacha20_a322": "chacha20_round20_w45_fine_band_recovery_a314_v1.json",
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
