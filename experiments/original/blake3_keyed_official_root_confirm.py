#!/usr/bin/env python3
"""Third-party root confirmation for the completed B3KR1 recovery."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RUNNER = ROOT / "research/experiments/blake3_keyed_metal_record.py"
PROTOCOL = ROOT / "research/configs/blake3_keyed_metal_recovery_v1.json"
RESULT = ROOT / "research/results/v1/blake3_keyed_metal_recovery_v1.json"
OUTPUT = (
    ROOT
    / "research/results/v1/blake3_keyed_official_b3sum_root_confirmation_v1.json"
)
CAUSAL = OUTPUT.with_suffix(".causal")
REPORT = (
    ROOT
    / "research/reports/BLAKE3_KEYED_OFFICIAL_B3SUM_ROOT_CONFIRMATION_V1.md"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
OFFICIAL_REPOSITORY = "https://github.com/BLAKE3-team/BLAKE3"
OFFICIAL_KEY = b"whats the Elvish word for friend"
OFFICIAL_MESSAGE64 = bytes(range(64))
OFFICIAL_KEYED64_HEX = (
    "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6"
)


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


def relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:
        return str(resolved)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def official_commit(source: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    commit = completed.stdout.strip()
    if completed.returncode != 0 or len(commit) != 40:
        raise RuntimeError("official BLAKE3 source commit gate failed")
    return commit


def b3sum_keyed(binary: Path, key: bytes, message: bytes) -> str:
    if len(key) != 32:
        raise ValueError("official b3sum keyed mode requires 32 key bytes")
    with tempfile.NamedTemporaryFile(prefix="b3off1-message-", delete=False) as handle:
        handle.write(message)
        message_path = Path(handle.name)
    try:
        completed = subprocess.run(
            [str(binary), "--keyed", "--no-names", str(message_path)],
            input=key,
            check=False,
            capture_output=True,
        )
    finally:
        message_path.unlink(missing_ok=True)
    output = completed.stdout.decode("ascii", errors="strict").strip()
    if (
        completed.returncode != 0
        or completed.stderr
        or len(output) != 64
        or any(character not in "0123456789abcdef" for character in output)
    ):
        raise RuntimeError("official b3sum keyed execution gate failed")
    return output


def official_tool_gate(source: Path, binary: Path) -> dict[str, Any]:
    commit = official_commit(source)
    version = subprocess.run(
        [str(binary), "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    observed = b3sum_keyed(binary, OFFICIAL_KEY, OFFICIAL_MESSAGE64)
    if observed != OFFICIAL_KEYED64_HEX:
        raise RuntimeError("official b3sum keyed KAT differs")
    cargo_lock = source / "b3sum/Cargo.lock"
    cargo_manifest = source / "b3sum/Cargo.toml"
    if not cargo_lock.is_file() or not cargo_manifest.is_file():
        raise RuntimeError("official b3sum build manifests are unavailable")
    return {
        "repository": OFFICIAL_REPOSITORY,
        "commit": commit,
        "version": version,
        "binary_path": str(binary.resolve()),
        "binary_sha256": file_sha256(binary),
        "cargo_lock_sha256": file_sha256(cargo_lock),
        "cargo_manifest_sha256": file_sha256(cargo_manifest),
        "official_keyed_64_byte_message_KAT_expected_hex": OFFICIAL_KEYED64_HEX,
        "official_keyed_64_byte_message_KAT_observed_hex": observed,
        "official_KAT_exact": True,
    }


def load_completed_recovery(expected_result_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(RESULT) != expected_result_sha256:
        raise RuntimeError("B3OFF1 recovery result hash differs")
    result = json.loads(RESULT.read_bytes())
    if file_sha256(PROTOCOL) != result.get("protocol_sha256"):
        raise RuntimeError("B3OFF1 protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    execution = result.get("execution", {})
    confirmations = execution.get("factual_confirmations", [])
    if (
        result.get("schema") != "blake3-keyed-metal-recovery-result-v1"
        or result.get("evidence_stage")
        != "FULLROUND_KEYED_BLAKE3_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
        or execution.get("complete_domain_executed") is not True
        or execution.get("unique_exact_assignment") is not True
        or execution.get("control_target_rejected") is not True
        or len(confirmations) != 1
        or confirmations[0].get("complete_256_bit_match") is not True
        or protocol.get("public_challenge_sha256")
        != result.get("public_challenge_sha256")
    ):
        raise RuntimeError("B3OFF1 completed recovery gate failed")
    return result, protocol


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("authoritative dotcausal.io is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(module.CausalReader) or "")
    return module.CausalWriter, module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": file_sha256(source),
    }


def build_causal(
    *, path: Path, payload: dict[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, reader_source = _load_dotcausal(dotcausal_src)
    width = int(payload["unknown_key_bits"])
    terminal = f"BLAKE3:official_b3sum_confirmed_W{width}_recovery"
    writer = CausalWriter(api_id="b3off1")
    writer._rules = []
    writer.add_rule(
        name="independent_official_implementation_confirmation",
        description="A commit- and binary-bound official b3sum build reproduces the complete target output under the recovered key.",
        pattern=["verified_recovery", "official_b3sum_KAT", "target_recompute"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger=f"BLAKE3:unique_verified_W{width}_keyed_residual",
        mechanism="bind_official_BLAKE3_commit_binary_and_KAT",
        outcome="BLAKE3:official_b3sum_verified_tool",
        confidence=1.0,
        source=payload["official_tool"]["commit"],
        quantification=payload["official_tool"]["version"],
        evidence=json.dumps(payload["official_tool"], sort_keys=True),
        domain="independent implementation provenance",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="BLAKE3:official_b3sum_verified_tool",
        mechanism="recompute_keyed_hash_with_recovered_key_and_frozen_message",
        outcome=terminal,
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="256/256 output bits",
        evidence=payload["official_target_output_hex"],
        domain="official third-implementation confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"BLAKE3:unique_verified_W{width}_keyed_residual",
        mechanism="materialized_official_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:B3OFF1",
        quantification="AI-native exact closure retained in-file",
        evidence=payload["confirmation_sha256"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="BLAKE3 official third-implementation confirmation",
        entities=[
            f"BLAKE3:unique_verified_W{width}_keyed_residual",
            "BLAKE3:official_b3sum_verified_tool",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_gain",
        expected_object_type=f"prospectively_selected_strict_subset_of_W{width}_domain",
        confidence=1.0,
        suggested_queries=[
            f"Which frozen operator concentrates the W{width} residual search?"
        ],
    )
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    if (
        reader.api_id != "b3off1"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(reader._rules) != 1
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("B3OFF1 authentic Causal gate failed")
    return {
        "path": relative(path),
        "sha256": file_sha256(path),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(all_rows) - len(explicit),
        "rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": reader_source,
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def execute(
    *,
    expected_result_sha256: str,
    official_source: Path,
    b3sum: Path,
    output: Path,
    causal: Path,
    report: Path,
    dotcausal_src: Path,
) -> dict[str, Any]:
    if output.exists() or causal.exists() or report.exists():
        raise FileExistsError("B3OFF1 final artifact already exists")
    result, protocol = load_completed_recovery(expected_result_sha256)
    tool = official_tool_gate(official_source, b3sum)
    confirmation = result["execution"]["factual_confirmations"][0]
    key = bytes.fromhex(confirmation["recovered_key_hex"])
    challenge = protocol["challenge"]
    message = bytes.fromhex(challenge["message_hex"])
    target = str(challenge["target_256_hex"])
    official_output = b3sum_keyed(b3sum, key, message)
    runner = load_module(RUNNER, "b3off1_runner_reference")
    scalar_output = runner.scalar_keyed_root(key, message).hex()
    numpy_output = runner.numpy_keyed_root(key, message).hex()
    if official_output != scalar_output or official_output != numpy_output or official_output != target:
        raise RuntimeError("B3OFF1 recovered target confirmation differs")
    payload: dict[str, Any] = {
        "schema": "blake3-keyed-official-b3sum-root-confirmation-v1",
        "attempt_id": "B3OFF1",
        "evidence_stage": "OFFICIAL_BLAKE3_THIRD_IMPLEMENTATION_RECOVERY_CONFIRMED",
        "source_recovery": {
            "path": relative(RESULT),
            "sha256": expected_result_sha256,
        },
        "source_protocol": {
            "path": relative(PROTOCOL),
            "sha256": result["protocol_sha256"],
        },
        "unknown_key_bits": result["execution"]["unknown_key_bits"],
        "recovered_assignment": confirmation["assignment"],
        "recovered_key_hex": confirmation["recovered_key_hex"],
        "official_tool": tool,
        "official_target_output_hex": official_output,
        "scalar_target_output_hex": scalar_output,
        "independent_numpy_target_output_hex": numpy_output,
        "three_implementation_identity": True,
        "complete_256_bit_target_match": True,
        "control_target_rejected_in_complete_source_execution": result["execution"][
            "control_target_rejected"
        ],
    }
    payload["confirmation_sha256"] = canonical_sha256(
        {
            "source_recovery_sha256": expected_result_sha256,
            "official_tool": tool,
            "recovered_assignment": confirmation["assignment"],
            "official_target_output_hex": official_output,
            "scalar_target_output_hex": scalar_output,
            "independent_numpy_target_output_hex": numpy_output,
        }
    )
    payload["authentic_causal"] = build_causal(
        path=causal, payload=payload, dotcausal_src=dotcausal_src
    )
    atomic_json(output, payload)
    atomic_bytes(
        report,
        (
            "# B3OFF1 — official BLAKE3 third-implementation confirmation\n\n"
            f"- Recovery width: **W{payload['unknown_key_bits']}**\n"
            f"- Official source commit: `{tool['commit']}`\n"
            "- Official b3sum keyed KAT: **exact**\n"
            "- Official / scalar / independent NumPy target: **256/256 bits identical**\n"
            f"- Authentic Causal SHA-256: `{payload['authentic_causal']['sha256']}`\n"
        ).encode(),
    )
    return payload


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-result-sha256", required=True)
    parser.add_argument("--official-source", type=Path, required=True)
    parser.add_argument("--b3sum", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--causal", type=Path, default=CAUSAL)
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    payload = execute(
        expected_result_sha256=args.expected_result_sha256,
        official_source=args.official_source,
        b3sum=args.b3sum,
        output=args.output,
        causal=args.causal,
        report=args.report,
        dotcausal_src=args.dotcausal_src,
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "output_sha256": file_sha256(args.output),
                "causal_sha256": payload["authentic_causal"]["sha256"],
                "evidence_stage": payload["evidence_stage"],
                "official_commit": payload["official_tool"]["commit"],
                "three_implementation_identity": payload[
                    "three_implementation_identity"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
