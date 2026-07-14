#!/usr/bin/env python3
"""Hash-gated, resumable complete-domain Salsa20/20 residual recovery."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from arx_carry_leak.salsa20_reference import ROUNDS, block


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_QUAL = _import_sibling("salsa20_20_metal_qualification.py", "salsa20_20_a263_qualification")
_FACTORY = _import_sibling("salsa20_20_metal_protocol_factory.py", "salsa20_20_a264_factory")

ATTEMPT_ID = "A264"
QUALIFICATION_ATTEMPT_ID = "A263"
QUALIFICATION_SCHEMA = "salsa20-20-metal-qualification-v1"
NATIVE_SOURCE_FILENAME = "salsa20_20_metal_native.swift"
REFERENCE_SOURCE_FILENAME = "salsa20_reference.py"
QUALIFICATION_SOURCE_FILENAME = "salsa20_20_metal_qualification.py"
PROTOCOL_FACTORY_FILENAME = "salsa20_20_metal_protocol_factory.py"
RESULT_CAPACITY = 64
FILTER_WORDS = 16
FILTER_BITS = 512
FULL_ROUNDS = ROUNDS
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    )


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _atomic_text(path: Path, value: str) -> None:
    raw = value.encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _words(raw: bytes) -> list[int]:
    if len(raw) % 4:
        raise ValueError("Salsa20 block is not word aligned")
    return [int.from_bytes(raw[offset : offset + 4], "little") for offset in range(0, len(raw), 4)]


def _bytes(words: Sequence[int]) -> bytes:
    return b"".join(int(word).to_bytes(4, "little") for word in words)


def _validate_challenge(challenge: dict[str, Any], context: dict[str, int]) -> None:
    width = context["width"]
    target = bytes.fromhex(str(challenge.get("target_block_hex", "")))
    control = bytes.fromhex(str(challenge.get("control_block_hex", "")))
    known_key = bytes.fromhex(str(challenge.get("known_key_zeroed_residual_hex", "")))
    nonce = bytes.fromhex(str(challenge.get("nonce_hex", "")))
    if (
        challenge.get("algorithm") != "Salsa20/20"
        or challenge.get("rounds") != FULL_ROUNDS
        or challenge.get("key_bits") != 256
        or challenge.get("nonce_bits") != 64
        or challenge.get("counter_bits") != 64
        or challenge.get("byte_semantics") != "Bernstein_little_endian"
        or len(known_key) != 32
        or len(nonce) != 8
        or len(target) != 64
        or len(control) != 64
        or challenge.get("filter_bits") != FILTER_BITS
        or challenge.get("unknown_assignment_bits") != width
        or challenge.get("known_master_key_bits") != context["known_key_bits"]
        or challenge.get("unknown_key_word0_bits") != 32
        or challenge.get("unknown_key_word1_low_bits") != context["outer_bits"]
        or challenge.get("known_key_word1_mask") != context["key_word1_known_mask"]
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("unknown_key_word0_included") is not False
        or challenge.get("unknown_key_word1_low_bits_included") is not False
        or int.from_bytes(known_key, "little") & ~context["key_known_mask_256"]
    ):
        raise RuntimeError("A264 public challenge semantic gate failed")
    expected_words = _words(known_key)
    if expected_words != challenge.get("known_key_words_little_endian"):
        raise RuntimeError("A264 public key word orientation gate failed")
    counter = int(challenge.get("counter", -1))
    if (
        counter < 0
        or counter >= 1 << 64
        or challenge.get("counter_words_little_endian") != [counter & 0xFFFFFFFF, counter >> 32]
    ):
        raise RuntimeError("A264 counter orientation gate failed")
    derived_key, derived_nonce, derived_counter, label, digest = _FACTORY._known_material(
        width, context["stream_candidates"]
    )
    if (
        challenge.get("known_material_derivation_label") != label
        or challenge.get("known_material_derivation_sha256") != digest
        or derived_key != known_key
        or derived_nonce != nonce
        or derived_counter != counter
        or _sha256(target) != challenge.get("target_block_sha256")
        or _sha256(control) != challenge.get("control_block_sha256")
        or control[:-1] != target[:-1]
        or control[-1] != target[-1] ^ 1
    ):
        raise RuntimeError("A264 known-material or target/control gate failed")


def analyze(
    *, protocol_path: Path, expected_protocol_sha256: str, results_dir: Path
) -> dict[str, Any]:
    protocol_sha256 = _file_sha256(protocol_path)
    if protocol_sha256 != expected_protocol_sha256:
        raise RuntimeError("A264 protocol hash differs from explicit CLI anchor")
    protocol = json.loads(protocol_path.read_text())
    if (
        protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("qualification_attempt_id") != QUALIFICATION_ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A264_candidate_execution"
        or protocol.get("information_boundary", {}).get(
            "unknown_assignment_available_to_runner_before_execution"
        )
        is not False
    ):
        raise RuntimeError("A264 frozen protocol state gate failed")
    plan = protocol.get("execution_plan", {})
    width = plan.get("unknown_key_bits")
    stream = plan.get("stream_candidate_count")
    if not isinstance(width, int) or not isinstance(stream, int):
        raise RuntimeError("A264 execution plan parameter types differ")
    context = _FACTORY._width_context(width, stream)
    expected_plan = {
        "primitive": "Salsa20/20_stream_block_function",
        "rounds": 20,
        "unknown_key_bits": width,
        "known_key_bits": context["known_key_bits"],
        "logical_candidate_count": context["logical_candidates"],
        "outer_key_word1_low_bit_count": context["outer_bits"],
        "outer_slice_count": context["outer_slices"],
        "inner_key_word0_candidate_count_per_slice": 1 << 32,
        "stream_candidate_count": stream,
        "stream_batch_count": context["stream_batches"],
        "gpu_threads_per_candidate": 1,
        "gpu_logical_thread_count": context["logical_candidates"],
        "filter_output_bits": FILTER_BITS,
        "factual_and_control_computed_by_same_kernel_invocation": True,
        "result_capacity_per_batch": RESULT_CAPACITY,
        "complete_domain_required": True,
        "early_stop_used": False,
        "early_stop_forbidden": True,
        "checkpoint_resume_enabled": True,
        "persistent_host_process": True,
        "host_reconfiguration_per_outer_slice": True,
        "runtime_shader_compilation": True,
        "independent_confirmation": (
            "separate_direct_schedule_Python_Salsa20/20_full_512_bit_block"
        ),
        "control_target_required": True,
        "fresh_public_challenge": True,
        "unknown_assignment_available_to_runner_before_execution": False,
        "volatile_wallclock_excluded_from_success_rule": True,
    }
    if plan != expected_plan or _canonical_sha256(plan) != protocol.get("execution_plan_sha256"):
        raise RuntimeError("A264 execution plan gate failed")
    challenge = protocol.get("public_challenge", {})
    _validate_challenge(challenge, context)
    if _canonical_sha256(challenge) != protocol.get("public_challenge_sha256"):
        raise RuntimeError("A264 public challenge hash gate failed")

    root = Path(__file__).parents[2]
    experiments = Path(__file__).parent
    qualification_anchor = protocol.get("anchors", {}).get("qualification", {})
    qualification_path = results_dir / str(qualification_anchor.get("filename", ""))
    local_paths = {
        "qualification_source": experiments / QUALIFICATION_SOURCE_FILENAME,
        "native_source": experiments / NATIVE_SOURCE_FILENAME,
        "cpu_reference": root / "src" / "arx_carry_leak" / REFERENCE_SOURCE_FILENAME,
        "protocol_factory": experiments / PROTOCOL_FACTORY_FILENAME,
        "recovery_source": Path(__file__),
    }
    if not qualification_path.is_file() or _file_sha256(
        qualification_path
    ) != qualification_anchor.get("sha256"):
        raise RuntimeError("A264 qualification artifact anchor gate failed")
    for name, path in local_paths.items():
        anchor = protocol.get("anchors", {}).get(name, {})
        if anchor.get("filename") != path.name or anchor.get("sha256") != _file_sha256(path):
            raise RuntimeError(f"A264 {name} anchor gate failed")
    qualification = json.loads(qualification_path.read_text())
    qualified_width, qualified_stream = _FACTORY._qualification_gate(qualification)
    metal_evidence_ledger_sha256 = _QUAL.validate_metal_evidence_ledger(qualification)
    ledger_anchor = protocol.get("metal_evidence_ledger_anchor", {})
    if (qualified_width, qualified_stream) != (width, stream):
        raise RuntimeError("A263/A264 selected parameter gate failed")
    if (
        ledger_anchor.get("schema") != _QUAL.METAL_EVIDENCE_LEDGER_SCHEMA
        or ledger_anchor.get("sha256") != metal_evidence_ledger_sha256
        or ledger_anchor.get("embedded_in_qualification") != qualification_path.name
        or ledger_anchor.get("provenance_scope")
        != "semantic_execution_provenance_not_hardware_attestation"
    ):
        raise RuntimeError("A263/A264 Metal evidence ledger anchor gate failed")
    return {
        "candidate_execution_started": False,
        "protocol": protocol,
        "public_challenge": challenge,
        "execution_plan": plan,
        "context": context,
        "anchor_gates": {
            "protocol_sha256": protocol_sha256,
            "public_challenge_sha256": protocol["public_challenge_sha256"],
            "qualification_sha256": _file_sha256(qualification_path),
            "metal_evidence_ledger_sha256": metal_evidence_ledger_sha256,
            **{f"{name}_sha256": _file_sha256(path) for name, path in local_paths.items()},
        },
        "information_boundary": {
            "analysis_uses_public_relation_only": True,
            "unknown_assignment_present": False,
            "candidate_execution_started": False,
        },
    }


def _rol32(value: int, shift: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def _independent_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    """Independent direct-register transcription of Bernstein's C schedule."""

    if len(key) != 32 or len(nonce) != 8 or counter < 0 or counter >= 1 << 64:
        raise ValueError("independent Salsa20 block input differs")
    constants = _words(b"expand 32-byte k")
    key_words = _words(key)
    nonce_words = _words(nonce)
    initial = [
        constants[0],
        *key_words[:4],
        constants[1],
        *nonce_words,
        counter & 0xFFFFFFFF,
        counter >> 32,
        constants[2],
        *key_words[4:],
        constants[3],
    ]
    x = list(initial)
    for _ in range(10):
        x[4] ^= _rol32(x[0] + x[12], 7)
        x[8] ^= _rol32(x[4] + x[0], 9)
        x[12] ^= _rol32(x[8] + x[4], 13)
        x[0] ^= _rol32(x[12] + x[8], 18)
        x[9] ^= _rol32(x[5] + x[1], 7)
        x[13] ^= _rol32(x[9] + x[5], 9)
        x[1] ^= _rol32(x[13] + x[9], 13)
        x[5] ^= _rol32(x[1] + x[13], 18)
        x[14] ^= _rol32(x[10] + x[6], 7)
        x[2] ^= _rol32(x[14] + x[10], 9)
        x[6] ^= _rol32(x[2] + x[14], 13)
        x[10] ^= _rol32(x[6] + x[2], 18)
        x[3] ^= _rol32(x[15] + x[11], 7)
        x[7] ^= _rol32(x[3] + x[15], 9)
        x[11] ^= _rol32(x[7] + x[3], 13)
        x[15] ^= _rol32(x[11] + x[7], 18)
        x[1] ^= _rol32(x[0] + x[3], 7)
        x[2] ^= _rol32(x[1] + x[0], 9)
        x[3] ^= _rol32(x[2] + x[1], 13)
        x[0] ^= _rol32(x[3] + x[2], 18)
        x[6] ^= _rol32(x[5] + x[4], 7)
        x[7] ^= _rol32(x[6] + x[5], 9)
        x[4] ^= _rol32(x[7] + x[6], 13)
        x[5] ^= _rol32(x[4] + x[7], 18)
        x[11] ^= _rol32(x[10] + x[9], 7)
        x[8] ^= _rol32(x[11] + x[10], 9)
        x[9] ^= _rol32(x[8] + x[11], 13)
        x[10] ^= _rol32(x[9] + x[8], 18)
        x[12] ^= _rol32(x[15] + x[14], 7)
        x[13] ^= _rol32(x[12] + x[15], 9)
        x[14] ^= _rol32(x[13] + x[12], 13)
        x[15] ^= _rol32(x[14] + x[13], 18)
    return _bytes([(value + initial[index]) & 0xFFFFFFFF for index, value in enumerate(x)])


def _candidate_key(challenge: dict[str, Any], context: dict[str, int], assignment: int) -> bytes:
    if assignment < 0 or assignment >= context["logical_candidates"]:
        raise ValueError("A264 candidate is outside the frozen domain")
    known = int.from_bytes(bytes.fromhex(challenge["known_key_zeroed_residual_hex"]), "little")
    return (known | assignment).to_bytes(32, "little")


def _scalar_block(challenge: dict[str, Any], context: dict[str, int], assignment: int) -> bytes:
    return block(
        _candidate_key(challenge, context, assignment),
        bytes.fromhex(challenge["nonce_hex"]),
        int(challenge["counter"]),
    )


def _configure_outer(
    host: Any,
    challenge: dict[str, Any],
    context: dict[str, int],
    outer: int,
) -> None:
    if outer < 0 or outer >= context["outer_slices"]:
        raise ValueError("A264 outer slice is outside the frozen domain")
    key_words = list(challenge["known_key_words_little_endian"])
    key_words[1] |= outer
    host.configure(
        target=_words(bytes.fromhex(challenge["target_block_hex"])),
        control=_words(bytes.fromhex(challenge["control_block_hex"])),
        key_words_1_to_7=key_words[1:],
        nonce=_words(bytes.fromhex(challenge["nonce_hex"])),
        counter=list(challenge["counter_words_little_endian"]),
    )


def _mapping_gate(host: Any, challenge: dict[str, Any], context: dict[str, int]) -> dict[str, Any]:
    logical = context["logical_candidates"]
    assignments = sorted(
        {
            0,
            1,
            min(logical - 1, 0x7FFFFFFF),
            min(logical - 1, 0x80000000),
            min(logical - 1, (1 << 32) + 1),
            logical - 1,
        }
    )
    rows = []
    for assignment in assignments:
        outer, inner = divmod(assignment, 1 << 32)
        _configure_outer(host, challenge, context, outer)
        native = host.blocks(inner, 1)
        native_bytes = _bytes(native["words"])
        scalar = _scalar_block(challenge, context, assignment)
        independent = _independent_block(
            _candidate_key(challenge, context, assignment),
            bytes.fromhex(challenge["nonce_hex"]),
            int(challenge["counter"]),
        )
        exact = native_bytes == scalar == independent
        rows.append(
            {
                "combined_assignment": assignment,
                "outer_slice": outer,
                "inner_key_word0": inner,
                "exact_native_scalar_independent_identity": exact,
                "block_sha256": _sha256(scalar),
            }
        )
    if not all(row["exact_native_scalar_independent_identity"] for row in rows):
        raise RuntimeError("A264 full mapping gate failed")
    return {
        "rows": rows,
        "exact_scalar_filter_and_mapping_identity": True,
        "full_block_bits_per_row": FILTER_BITS,
    }


def _confirm(
    challenge: dict[str, Any],
    context: dict[str, int],
    expected: bytes,
    assignment: int,
    relation: str,
) -> dict[str, Any]:
    key = _candidate_key(challenge, context, assignment)
    actual = _independent_block(
        key,
        bytes.fromhex(challenge["nonce_hex"]),
        int(challenge["counter"]),
    )
    return {
        "combined_assignment": assignment,
        "key_word0": assignment & 0xFFFFFFFF,
        "key_word1_low_bits": assignment >> 32,
        "relation": relation,
        "expected_block_sha256": _sha256(expected),
        "actual_block_sha256": _sha256(actual),
        "complete_512_bit_block_match": actual == expected,
        "implementation": "independent_direct_register_schedule_python",
    }


def _checkpoint_fingerprint(
    challenge: dict[str, Any], context: dict[str, int], anchors: dict[str, Any]
) -> str:
    return _canonical_sha256(
        {
            "protocol_sha256": anchors["protocol_sha256"],
            "public_challenge_sha256": anchors["public_challenge_sha256"],
            "native_source_sha256": anchors["native_source_sha256"],
            "width": context["width"],
            "stream_candidates": context["stream_candidates"],
            "target_block_sha256": challenge["target_block_sha256"],
            "control_block_sha256": challenge["control_block_sha256"],
        }
    )


def _enumerate_domain(
    *,
    host: Any,
    challenge: dict[str, Any],
    context: dict[str, int],
    anchors: dict[str, Any],
    checkpoint_path: Path,
    resume: bool,
) -> dict[str, Any]:
    logical = context["logical_candidates"]
    stream = context["stream_candidates"]
    fingerprint = _checkpoint_fingerprint(challenge, context, anchors)
    if resume and checkpoint_path.is_file():
        checkpoint = json.loads(checkpoint_path.read_text())
        if (
            checkpoint.get("schema") != "salsa20-20-a264-checkpoint-v1"
            or checkpoint.get("fingerprint") != fingerprint
            or checkpoint.get("logical_candidate_count") != logical
            or checkpoint.get("stream_candidate_count") != stream
        ):
            raise RuntimeError("A264 checkpoint fingerprint gate failed")
    else:
        if checkpoint_path.exists():
            raise FileExistsError("A264 checkpoint exists; pass resume=True or choose another path")
        checkpoint = {
            "schema": "salsa20-20-a264-checkpoint-v1",
            "fingerprint": fingerprint,
            "logical_candidate_count": logical,
            "stream_candidate_count": stream,
            "next_assignment": 0,
            "completed_batches": 0,
            "gpu_seconds": 0.0,
            "factual_filter_matches": [],
            "control_filter_matches": [],
        }
        _atomic_json(checkpoint_path, checkpoint)
    resumed_count = int(checkpoint["next_assignment"])
    if resumed_count < 0 or resumed_count > logical:
        raise RuntimeError("A264 checkpoint progress is outside the domain")
    started = time.monotonic()
    active_outer: int | None = None
    while int(checkpoint["next_assignment"]) < logical:
        assignment = int(checkpoint["next_assignment"])
        outer, inner = divmod(assignment, 1 << 32)
        if outer != active_outer:
            _configure_outer(host, challenge, context, outer)
            active_outer = outer
        remaining_inner = (1 << 32) - inner
        count = min(stream, remaining_inner, logical - assignment)
        response = host.filter(inner, count)
        factual = [(outer << 32) | int(value) for value in response["factual"]]
        control = [(outer << 32) | int(value) for value in response["control"]]
        checkpoint["factual_filter_matches"].extend(factual)
        checkpoint["control_filter_matches"].extend(control)
        checkpoint["next_assignment"] = assignment + count
        checkpoint["completed_batches"] = int(checkpoint["completed_batches"]) + 1
        checkpoint["gpu_seconds"] = float(checkpoint["gpu_seconds"]) + float(
            response["gpu_seconds"]
        )
        _atomic_json(checkpoint_path, checkpoint)
    wall_seconds = time.monotonic() - started
    factual_expected = bytes.fromhex(challenge["target_block_hex"])
    control_expected = bytes.fromhex(challenge["control_block_hex"])
    factual_confirmations = [
        _confirm(challenge, context, factual_expected, value, "factual")
        for value in checkpoint["factual_filter_matches"]
    ]
    control_confirmations = [
        _confirm(challenge, context, control_expected, value, "one_bit_control")
        for value in checkpoint["control_filter_matches"]
    ]
    factual_full = [
        row["combined_assignment"]
        for row in factual_confirmations
        if row["complete_512_bit_block_match"]
    ]
    control_full = [
        row["combined_assignment"]
        for row in control_confirmations
        if row["complete_512_bit_block_match"]
    ]
    gpu_seconds = float(checkpoint["gpu_seconds"])
    return {
        "unknown_key_bits": context["width"],
        "known_key_bits": context["known_key_bits"],
        "logical_candidate_count": logical,
        "resumed_assignment_count": resumed_count,
        "newly_executed_assignment_count": logical - resumed_count,
        "total_executed_assignment_count": logical,
        "completed_batches": int(checkpoint["completed_batches"]),
        "complete_domain_executed": int(checkpoint["next_assignment"]) == logical,
        "early_stop_used": False,
        "factual_filter_matches": list(checkpoint["factual_filter_matches"]),
        "control_filter_matches": list(checkpoint["control_filter_matches"]),
        "factual_confirmations": factual_confirmations,
        "control_confirmations": control_confirmations,
        "factual_full_matches": factual_full,
        "control_full_matches": control_full,
        "unique_exact_assignment": len(factual_full) == 1,
        "control_target_rejected": len(control_full) == 0,
        "gpu_seconds": gpu_seconds,
        "volatile_wall_seconds": wall_seconds,
        "volatile_candidates_per_gpu_second": logical / gpu_seconds if gpu_seconds > 0 else None,
        "success_evaluated_only_after_complete_domain": True,
        "checkpoint_persisted_after_every_batch": True,
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        io_module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError(
                "dotcausal is required; install requirements or pass --dotcausal-src"
            ) from None
        sys.path.insert(0, str(dotcausal_src))
        io_module = importlib.import_module("dotcausal.io")
    writer = io_module.CausalWriter
    reader = io_module.CausalReader
    io_path = Path(inspect.getsourcefile(reader) or "")
    if not io_path.is_file():
        raise RuntimeError("A264 authoritative dotcausal.io source is unavailable")
    return (
        writer,
        reader,
        {
            "module": "dotcausal.io",
            "io_path": str(io_path),
            "io_sha256": _file_sha256(io_path),
        },
    )


def _build_authentic_causal(
    *, path: Path, payload: dict[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, reader_source = _load_dotcausal(dotcausal_src)
    execution = payload["execution"]
    width = int(execution["unknown_key_bits"])
    logical = int(execution["logical_candidate_count"])
    writer = CausalWriter(api_id="a264")
    writer._rules = []
    writer.add_rule(
        name="complete_domain_plus_independent_confirmation",
        description=(
            "Complete residual-key enumeration plus independent exact full-block "
            "confirmation establishes the recovered assignment."
        ),
        pattern=["complete_domain_enumeration", "independent_exact_confirmation"],
        conclusion="verified_residual_key_recovery",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="matched_control_separation",
        description=(
            "The same complete search returning zero exact models for the one-bit "
            "control establishes target-specific separation."
        ),
        pattern=["same_complete_search", "zero_exact_control_models"],
        conclusion="target_specific_recovery_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A263:pre_target_Salsa20_20_Metal_qualification",
        mechanism="specification_KAT_plus_scalar_cross_gate_plus_boundary_gate",
        outcome="A264:qualified_fullround_Salsa20_20_enumerator",
        confidence=1.0,
        source=payload["anchor_gates"]["qualification_sha256"],
        quantification="20 rounds; 512-bit block; exact little-endian identity",
        evidence=json.dumps(payload["mapping_gate"], sort_keys=True),
        domain="Salsa20/20 implementation equivalence",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"A264:frozen_public_W{width}_relation",
        mechanism="complete_domain_enumeration",
        outcome="A264:factual_filter_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{logical} assignments; no early stop",
        evidence=json.dumps(
            {
                "complete": execution["complete_domain_executed"],
                "matches": execution["factual_filter_matches"],
            },
            sort_keys=True,
        ),
        domain="full-round residual-key enumeration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A264:factual_filter_candidate_set",
        mechanism="independent_exact_confirmation",
        outcome=f"A264:unique_verified_{width}_bit_residual_key",
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="all 20 rounds; complete 512-bit output block",
        evidence=json.dumps(execution["factual_confirmations"], sort_keys=True),
        domain="independent key confirmation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A264:one_bit_flipped_control_relation",
        mechanism="same_complete_search",
        outcome="A264:control_filter_candidate_set",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=f"{logical} assignments; identical kernel and budget",
        evidence=json.dumps({"matches": execution["control_filter_matches"]}, sort_keys=True),
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A264:control_filter_candidate_set",
        mechanism="zero_exact_control_models",
        outcome="A264:control_relation_rejected",
        confidence=1.0,
        source=payload["confirmation_sha256"],
        quantification="zero independently confirmed assignments",
        evidence=json.dumps(execution["control_confirmations"], sort_keys=True),
        domain="matched negative control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"A264:frozen_public_W{width}_relation",
        mechanism="verified_complete_enumeration_and_confirmation_chain",
        outcome=f"A264:unique_verified_{width}_bit_residual_key",
        confidence=1.0,
        source="materialized:complete_domain_plus_independent_confirmation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after complete execution and exact confirmation.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_triplet(
        trigger="A264:one_bit_flipped_control_relation",
        mechanism="verified_matched_control_chain",
        outcome="A264:control_relation_rejected",
        confidence=1.0,
        source="materialized:matched_control_separation",
        quantification="exact two-edge closure retained in-file",
        evidence="Materialized after the identical complete control search.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A264 verified recovery chain",
        entities=[
            f"A264:frozen_public_W{width}_relation",
            "complete_domain_enumeration",
            "A264:factual_filter_candidate_set",
            "independent_exact_confirmation",
            f"A264:unique_verified_{width}_bit_residual_key",
        ],
    )
    writer.add_cluster(
        name="A264 matched control chain",
        entities=[
            "A264:one_bit_flipped_control_relation",
            "same_complete_search",
            "A264:control_filter_candidate_set",
            "zero_exact_control_models",
            "A264:control_relation_rejected",
        ],
    )
    writer.add_gap(
        subject=f"A264:unique_verified_{width}_bit_residual_key",
        predicate="next_required_gain",
        expected_object_type=(f"prospectively_selected_strict_subset_of_W{width}_domain"),
        confidence=1.0,
        suggested_queries=[
            f"Which frozen operator ranks the held-out W{width} region early?",
            f"Can a public reader reduce executed W{width} candidates?",
        ],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    writer_stats = writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    materialized = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a264"
        or len(explicit) != 5
        or len(all_rows) != 7
        or len(materialized) != 2
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
        or all_rows[-2]["outcome"] != f"A264:unique_verified_{width}_bit_residual_key"
        or all_rows[-1]["outcome"] != "A264:control_relation_rejected"
    ):
        raise RuntimeError("A264 authentic Causal Reader reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "file_sha256": _file_sha256(path),
        "file_bytes": path.stat().st_size,
        "magic": path.read_bytes()[:8].decode("ascii", errors="replace"),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(materialized),
        "total_triplets": len(all_rows),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "inference_recomputed_on_reader_open": False,
        "amplified_state_materialized_in_file": True,
        "integrity_verified_by_authoritative_reader": True,
        "reader_source": reader_source,
        "writer_stats": writer_stats,
        "personal_semantic_readback": {
            "recovery_chain": [
                row
                for row in all_rows
                if row["outcome"] == f"A264:unique_verified_{width}_bit_residual_key"
            ],
            "control_chain": [
                row for row in all_rows if row["outcome"] == "A264:control_relation_rejected"
            ],
            "next_gap": reader._gaps[0],
        },
    }


def _report(payload: dict[str, Any]) -> str:
    execution = payload["execution"]
    causal = payload["causal"]
    width = execution["unknown_key_bits"]
    recovered = execution["factual_full_matches"][0]
    return "\n".join(
        [
            f"# A264 — Full-round Salsa20/20 W{width} residual-key recovery",
            "",
            f"Every assignment in the frozen `2^{width}` residual domain was evaluated through all 20 standard Salsa20 rounds without early stopping.",
            "",
            "## Result",
            "",
            f"- Complete domain: **{execution['logical_candidate_count']:,} / {execution['logical_candidate_count']:,}**",
            f"- Recovered assignment: **`{recovered}`**",
            f"- Unknown / known master-key bits: **{width} / {execution['known_key_bits']}**",
            "- Independent confirmation: **complete 512-bit Salsa20/20 block**",
            f"- Exact factual models: **{len(execution['factual_full_matches'])}**",
            f"- Exact one-bit-control models: **{len(execution['control_full_matches'])}**",
            f"- GPU time: **{execution['gpu_seconds']:.3f} s**",
            "",
            "## AI-native Causal artifact",
            "",
            f"- Reader integrity gate: **{causal['integrity_verified_by_authoritative_reader']}**",
            f"- Explicit / retained inferred edges: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
            "- Amplified inference state is retained in-file and reopened by the authoritative Causal Reader.",
            "",
            "## Primary sources",
            "",
            "- Daniel J. Bernstein, *Salsa20 specification*, 2005.",
            "- Daniel J. Bernstein, public-domain Salsa20 reference implementation, version 20051118.",
            "",
        ]
    )


def _artifact_manifest(
    *,
    output: Path,
    causal_output: Path,
    report_output: Path,
    anchor_gates: dict[str, Any],
) -> dict[str, Any]:
    """Bind every retained A264 artifact to its frozen evidence chain."""

    return {
        "schema": "salsa20-20-a264-recovery-artifact-manifest-v1",
        "attempt_id": ATTEMPT_ID,
        "files": {
            "result": {"path": str(output), "sha256": _file_sha256(output)},
            "causal": {
                "path": str(causal_output),
                "sha256": _file_sha256(causal_output),
            },
            "report": {
                "path": str(report_output),
                "sha256": _file_sha256(report_output),
            },
        },
        "protocol_sha256": anchor_gates["protocol_sha256"],
        "qualification_sha256": anchor_gates["qualification_sha256"],
        "metal_evidence_ledger_sha256": anchor_gates["metal_evidence_ledger_sha256"],
        "complete_domain_executed": True,
        "authentic_dotcausal_v1_reader_verified": True,
        "causal_artifact_bound_to_result": True,
    }


def run(
    *,
    protocol_path: Path,
    expected_protocol_sha256: str,
    results_dir: Path,
    output: Path,
    causal_output: Path,
    report_output: Path,
    manifest_output: Path,
    checkpoint_path: Path,
    build_dir: Path,
    swiftc: str,
    dotcausal_src: Path,
    resume: bool,
    execute_full_domain: bool,
) -> dict[str, Any]:
    if execute_full_domain is not True:
        raise RuntimeError("A264 full-domain execution requires explicit execute_full_domain=True")
    analysis = analyze(
        protocol_path=protocol_path,
        expected_protocol_sha256=expected_protocol_sha256,
        results_dir=results_dir,
    )
    executable, native_build = _QUAL._compile_native(build_dir, swiftc)
    host = _QUAL.MetalSalsa2020Host(executable)
    try:
        mapping_gate = _mapping_gate(host, analysis["public_challenge"], analysis["context"])
        execution = _enumerate_domain(
            host=host,
            challenge=analysis["public_challenge"],
            context=analysis["context"],
            anchors=analysis["anchor_gates"],
            checkpoint_path=checkpoint_path,
            resume=resume,
        )
        host_identity = host.identity
    finally:
        host.close()
    if (
        execution["complete_domain_executed"] is not True
        or execution["unique_exact_assignment"] is not True
        or execution["control_target_rejected"] is not True
        or execution["early_stop_used"] is not False
    ):
        raise RuntimeError("A264 complete-domain recovery gate failed")
    width = analysis["context"]["width"]
    payload: dict[str, Any] = {
        "schema": f"salsa20-20-metal-width{width}-recovery-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (f"SALSA20_20_FULLROUND_{width}BIT_RESIDUAL_KEY_RECOVERY_RETAINED"),
        "result": (
            f"The Metal runner executed every assignment in the fresh {width}-bit "
            "residual domain through all 20 Salsa20 rounds and independently "
            "confirmed the unique result over the complete 512-bit block."
        ),
        "protocol_gate": {
            "artifact_sha256": analysis["anchor_gates"]["protocol_sha256"],
            "protocol_state": analysis["protocol"]["protocol_state"],
            "prospective_prediction": analysis["protocol"]["prospective_prediction"],
            "information_boundary": analysis["protocol"]["information_boundary"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": analysis["anchor_gates"]["public_challenge_sha256"],
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
        "native_build": native_build,
        "host_identity": host_identity,
        "mapping_gate": mapping_gate,
        "execution": execution,
        "execution_sha256": _canonical_sha256(
            {
                key: value
                for key, value in execution.items()
                if key
                not in {
                    "factual_confirmations",
                    "control_confirmations",
                    "volatile_wall_seconds",
                    "gpu_seconds",
                    "volatile_candidates_per_gpu_second",
                }
            }
        ),
        "confirmation_sha256": _canonical_sha256(
            {
                "factual": execution["factual_confirmations"],
                "control": execution["control_confirmations"],
            }
        ),
        "recovery": {
            "recovered_combined_assignments": execution["factual_full_matches"],
            "recovered_key_word0": [
                value & 0xFFFFFFFF for value in execution["factual_full_matches"]
            ],
            "recovered_key_word1_low_bits": [
                value >> 32 for value in execution["factual_full_matches"]
            ],
            "recovery_accepted_only_after_complete_domain_execution": True,
            "candidate_identities_persisted_in_checkpoint": True,
            "success_evaluated_only_after_complete_domain": True,
            "unknown_assignment_source_discarded_before_runner_process": True,
        },
    }
    payload["causal"] = _build_authentic_causal(
        path=causal_output, payload=payload, dotcausal_src=dotcausal_src
    )
    _atomic_json(output, payload)
    _atomic_text(report_output, _report(payload))
    manifest = _artifact_manifest(
        output=output,
        causal_output=causal_output,
        report_output=report_output,
        anchor_gates=analysis["anchor_gates"],
    )
    _atomic_json(manifest_output, manifest)
    checkpoint_path.unlink(missing_ok=True)
    _Writer, CausalReader, _source = _load_dotcausal(dotcausal_src)
    reader = CausalReader(str(causal_output), verify_integrity=True)
    if (
        json.loads(output.read_text()) != payload
        or json.loads(manifest_output.read_text()) != manifest
        or _file_sha256(causal_output) != payload["causal"]["file_sha256"]
        or len(reader.get_all_triplets(include_inferred=True)) != 7
        or not report_output.is_file()
    ):
        raise RuntimeError("A264 final artifact reopen gate failed")
    return {
        "output": str(output),
        "json_sha256": _file_sha256(output),
        "causal_output": str(causal_output),
        "causal_sha256": _file_sha256(causal_output),
        "report_output": str(report_output),
        "report_sha256": _file_sha256(report_output),
        "manifest_output": str(manifest_output),
        "manifest_sha256": _file_sha256(manifest_output),
        "complete_domain_executed": True,
        "logical_candidate_count": execution["logical_candidate_count"],
        "recovered_combined_assignments": execution["factual_full_matches"],
        "control_full_matches": execution["control_full_matches"],
        "gpu_seconds": execution["gpu_seconds"],
        "volatile_wall_seconds": execution["volatile_wall_seconds"],
        "authentic_causal_reader_verified": True,
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).parents[2]
    results = root / "research" / "results" / "v1"
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--expected-protocol-sha256", required=True)
    parser.add_argument("--results-dir", type=Path, default=results)
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--causal-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    parser.add_argument("--manifest-output", type=Path)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--execute-full-domain", action="store_true")
    args = parser.parse_args(argv)
    analysis = analyze(
        protocol_path=args.protocol,
        expected_protocol_sha256=args.expected_protocol_sha256,
        results_dir=args.results_dir,
    )
    if args.analyze_only:
        print(json.dumps(analysis, indent=2, sort_keys=True))
        return
    width = analysis["context"]["width"]
    stem = f"salsa20_20_metal_width{width}_recovery_v1"
    output = args.output or args.results_dir / f"{stem}.json"
    causal = args.causal_output or args.results_dir / f"{stem}.causal"
    report = args.report_output or (
        root / "research" / "reports" / f"FULLROUND_SALSA20_20_METAL_WIDTH{width}_RECOVERY_V1.md"
    )
    manifest = args.manifest_output or args.results_dir / f"{stem}.manifest.json"
    checkpoint = args.checkpoint or args.results_dir / f"{stem}.checkpoint.json"
    build_dir = args.build_dir or root / "build" / f"salsa20_20_metal_width{width}"
    print(
        json.dumps(
            run(
                protocol_path=args.protocol,
                expected_protocol_sha256=args.expected_protocol_sha256,
                results_dir=args.results_dir,
                output=output,
                causal_output=causal,
                report_output=report,
                manifest_output=manifest,
                checkpoint_path=checkpoint,
                build_dir=build_dir,
                swiftc=args.swiftc,
                dotcausal_src=args.dotcausal_src,
                resume=args.resume,
                execute_full_domain=args.execute_full_domain,
            ),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
