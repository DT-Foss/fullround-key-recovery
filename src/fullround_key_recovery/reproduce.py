"""Checkpointable Apple-Metal reproduction of the retained complete searches."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .artifacts import EXPECTED_SHA256, load_result, repository_root, sha256_file
from .ciphers import CHACHA_CONSTANTS, chacha20_block, speck32_64_encrypt, threefish256_encrypt
from .verify import verify_all

MASK32 = (1 << 32) - 1
INNER_CANDIDATES = 1 << 32
RESULT_CAPACITY = 64

SPECS: dict[str, dict[str, Any]] = {
    "chacha20": {
        "attempt_id": "A184",
        "native": "chacha20_metal_native.swift",
        "native_version": "chacha20-metal-native-v1",
        "unknown_bits": 40,
        "outer_slices": 1 << 8,
        "stream_candidates": 1 << 28,
        "output_words": 16,
        "word_bits": 32,
    },
    "speck32_64": {
        "attempt_id": "A237",
        "native": "speck32_64_metal_native.swift",
        "native_version": "speck32-64-metal-native-v1",
        "unknown_bits": 42,
        "outer_slices": 1 << 10,
        "stream_candidates": 1 << 30,
        "output_words": 6,
        "word_bits": 16,
    },
    "threefish256": {
        "attempt_id": "A240",
        "native": "threefish256_metal_native.swift",
        "native_version": "threefish256-metal-native-v1",
        "unknown_bits": 38,
        "outer_slices": 1 << 6,
        "stream_candidates": 1 << 28,
        "output_words": 8,
        "word_bits": 32,
    },
}


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _halves(words: Sequence[int]) -> list[int]:
    output: list[int] = []
    for word in words:
        output.extend((int(word) & MASK32, int(word) >> 32))
    return output


def _compile_native(root: Path, name: str, swiftc: str) -> tuple[Path, dict[str, Any]]:
    spec = SPECS[name]
    source = root / "experiments" / "native" / spec["native"]
    expected = EXPECTED_SHA256[f"experiments/native/{spec['native']}"]
    if sha256_file(source) != expected:
        raise RuntimeError(f"native source hash mismatch: {spec['native']}")
    compiler = shutil.which(swiftc)
    if compiler is None:
        raise FileNotFoundError(f"Swift compiler not found: {swiftc}")
    build_dir = root / "build" / "native"
    build_dir.mkdir(parents=True, exist_ok=True)
    output = build_dir / f"{name}-{expected[:16]}"
    flags = ["-O", "-whole-module-optimization", "-warnings-as-errors"]
    if not output.is_file():
        temporary = output.with_name(f".{output.name}.tmp")
        temporary.unlink(missing_ok=True)
        process = subprocess.run(
            [compiler, *flags, str(source), "-o", str(temporary)],
            check=False,
            capture_output=True,
            text=True,
        )
        if process.returncode:
            raise RuntimeError(f"native compilation failed: {process.stderr.strip()}")
        temporary.replace(output)
    version = subprocess.run(
        [compiler, "--version"], check=True, capture_output=True, text=True
    ).stdout.splitlines()[0]
    return output, {
        "source": str(source.relative_to(root)),
        "source_sha256": expected,
        "executable_sha256": sha256_file(output),
        "compiler_version": version,
        "flags": flags,
    }


class NativeHost:
    def __init__(self, executable: Path, expected_version: str):
        self.process = subprocess.Popen(
            [str(executable.resolve())],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        ready = self._read()
        metal = ready.get("metal", {})
        if (
            ready.get("op") != "ready"
            or ready.get("version") != expected_version
            or not str(metal.get("device", "")).startswith("Apple")
            or metal.get("shader_runtime_compiled") is not True
            or int(metal.get("filter_execution_width", 0)) <= 0
        ):
            self.close(force=True)
            raise RuntimeError("native Metal host identity gate failed")
        self.identity = ready

    def _read(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            assert self.process.stderr is not None
            raise RuntimeError(f"native host closed: {self.process.stderr.read().strip()}")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("native host returned a non-object")
        return value

    def request(self, value: dict[str, Any]) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError("native host is not running")
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        return self._read()

    def configure(self, value: dict[str, Any]) -> None:
        response = self.request({"op": "configure", **value})
        if response.get("op") != "configured":
            raise RuntimeError("native host configuration failed")

    def blocks(self, first: int, count: int) -> list[int]:
        response = self.request({"op": "blocks", "first": first, "count": count})
        if response.get("op") != "blocks" or response.get("count") != count:
            raise RuntimeError("native host block response failed")
        return [int(value) for value in response.get("words", [])]

    def filter(self, first: int, count: int) -> dict[str, Any]:
        response = self.request(
            {"op": "filter", "first": first, "count": count, "capacity": RESULT_CAPACITY}
        )
        if (
            response.get("op") != "filter"
            or response.get("first") != first
            or response.get("count") != count
            or not isinstance(response.get("factual"), list)
            or not isinstance(response.get("control"), list)
        ):
            raise RuntimeError("native host filter response failed")
        return response

    def close(self, *, force: bool = False) -> None:
        if self.process.poll() is not None:
            return
        if force:
            self.process.kill()
        else:
            try:
                response = self.request({"op": "quit"})
                if response.get("op") != "quit":
                    self.process.kill()
            except Exception:
                self.process.kill()
        self.process.wait(timeout=5)


def _candidate_output(name: str, challenge: dict[str, Any], assignment: int) -> list[int]:
    inner = assignment & MASK32
    outer = assignment >> 32
    if name == "chacha20":
        key = [
            inner,
            int(challenge["known_key_word1_upper24"]) | outer,
            *challenge["known_key_words_2_through_7"],
        ]
        return chacha20_block(key, challenge["counter"], challenge["nonce_words"])
    if name == "speck32_64":
        key = [
            inner & 0xFFFF,
            inner >> 16,
            int(challenge["known_key2_upper6"]) | outer,
            int(challenge["known_key3"]),
        ]
        output: list[int] = []
        plaintext = challenge["plaintext_words_xy_order"]
        for offset in range(0, 6, 2):
            output.extend(speck32_64_encrypt(plaintext[offset], plaintext[offset + 1], key))
        return output
    key = [
        int(challenge["known_key0_upper26"]) | assignment,
        *challenge["known_key_words_1_through_3"],
    ]
    return _halves(
        threefish256_encrypt(challenge["plaintext_words"], key, challenge["known_tweak_words"])
    )


def _retained_targets(name: str, challenge: dict[str, Any]) -> tuple[list[int], list[int]]:
    if name == "chacha20":
        return challenge["target_words"], challenge["control_target_words"]
    if name == "speck32_64":
        return (
            challenge["target_ciphertext_words_xy_order"],
            challenge["control_ciphertext_words_xy_order"],
        )
    return (
        _halves(challenge["target_ciphertext_words"]),
        _halves(challenge["control_ciphertext_words"]),
    )


def _configuration(
    name: str,
    challenge: dict[str, Any],
    outer: int,
    target: list[int],
    control: list[int],
) -> dict[str, Any]:
    if name == "chacha20":
        initial = [
            *CHACHA_CONSTANTS,
            0,
            int(challenge["known_key_word1_upper24"]) | outer,
            *challenge["known_key_words_2_through_7"],
            challenge["counter"],
            *challenge["nonce_words"],
        ]
        return {"initial": initial, "target": target[:2], "control": control[:2]}
    if name == "speck32_64":
        return {
            "plaintext": challenge["plaintext_words_xy_order"],
            "target": target,
            "control": control,
            "key2": int(challenge["known_key2_upper6"]) | outer,
            "key3": challenge["known_key3"],
        }
    key0 = int(challenge["known_key0_upper26"]) | (outer << 32)
    key_words = _halves([key0, *challenge["known_key_words_1_through_3"]])
    key_words[0] = 0
    return {
        "plaintext": _halves(challenge["plaintext_words"]),
        "target": target,
        "control": control,
        "key_words": key_words,
        "tweak_words": _halves(challenge["known_tweak_words"]),
    }


def mapping_gate(
    host: NativeHost, name: str, challenge: dict[str, Any], spec: dict[str, Any]
) -> dict[str, Any]:
    first = 184_032
    count = 256
    selected = first + 73
    rows = []
    for outer in (0, spec["outer_slices"] // 2, spec["outer_slices"] - 1):
        expected: list[int] = []
        for inner in range(first, first + count):
            expected.extend(_candidate_output(name, challenge, (outer << 32) | inner))
        target = _candidate_output(name, challenge, (outer << 32) | selected)
        control = list(target)
        control[0 if name == "chacha20" else -1] ^= 1
        host.configure(_configuration(name, challenge, outer, target, control))
        observed = host.blocks(first, count)
        filtered = host.filter(first, count)
        if observed != expected or filtered["factual"] != [selected] or filtered["control"] != []:
            raise RuntimeError(f"{name} three-slice scalar/Metal mapping gate failed")
        rows.append(
            {
                "outer": outer,
                "candidate_count": count,
                "factual_inner_candidate": selected,
                "output_sha256": hashlib.sha256(
                    b"".join(
                        int(word).to_bytes(spec["word_bits"] // 8, "little") for word in observed
                    )
                ).hexdigest(),
            }
        )
    return {
        "outer_values_checked": [row["outer"] for row in rows],
        "logical_candidates_checked": 3 * count,
        "complete_output_bits_checked": 3 * count * spec["output_words"] * spec["word_bits"],
        "exact_scalar_filter_and_mapping_identity": True,
        "rows": rows,
    }


def _checkpoint_fingerprint(
    name: str, spec: dict[str, Any], retained_sha: str, native_sha: str
) -> dict[str, Any]:
    return {
        "schema": "fullround-key-recovery-checkpoint-v1",
        "cipher": name,
        "attempt_id": spec["attempt_id"],
        "retained_result_sha256": retained_sha,
        "native_source_sha256": native_sha,
        "logical_candidates": 1 << spec["unknown_bits"],
        "stream_candidates": spec["stream_candidates"],
        "candidate_matches_persisted": False,
    }


def reproduce(
    name: str,
    *,
    root: Path,
    swiftc: str,
    resume: bool,
    mapping_only: bool,
) -> dict[str, Any]:
    if name not in SPECS:
        raise KeyError(f"unknown reproduction target: {name}")
    verify_all(root)
    spec = SPECS[name]
    payload = load_result(name, root)
    challenge = payload["public_challenge"]
    executable, build = _compile_native(root, name, swiftc)
    host = NativeHost(executable, spec["native_version"])
    try:
        gate = mapping_gate(host, name, challenge, spec)
        if mapping_only:
            return {
                "status": "mapping-gate-passed",
                "cipher": name,
                "native_build": build,
                "host_identity": host.identity,
                "mapping_gate": gate,
            }

        result_relative = next(
            relative
            for relative in EXPECTED_SHA256
            if relative.startswith("results/")
            and relative.endswith("recovery_v1.json")
            and json.loads((root / relative).read_text()).get("attempt_id") == spec["attempt_id"]
        )
        retained_sha = EXPECTED_SHA256[result_relative]
        native_sha = build["source_sha256"]
        fingerprint = _checkpoint_fingerprint(name, spec, retained_sha, native_sha)
        checkpoint_path = root / "build" / "checkpoints" / f"{name}.json"
        next_assignment = 0
        durable_next = 0
        gpu_seconds = 0.0
        durable_gpu_seconds = 0.0
        if resume and checkpoint_path.is_file():
            checkpoint = json.loads(checkpoint_path.read_text())
            if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
                raise RuntimeError("checkpoint fingerprint mismatch")
            next_assignment = int(checkpoint["next_assignment"])
            gpu_seconds = float(checkpoint.get("gpu_seconds", 0.0))
            if (
                next_assignment < 0
                or next_assignment > fingerprint["logical_candidates"]
                or next_assignment % spec["stream_candidates"]
                or checkpoint.get("factual", [])
                or checkpoint.get("control", [])
            ):
                raise RuntimeError("checkpoint progress is invalid")
            durable_next = next_assignment
            durable_gpu_seconds = gpu_seconds
        resumed = next_assignment
        factual: list[int] = []
        control: list[int] = []
        configured_outer: int | None = None
        retained_target, retained_control = _retained_targets(name, challenge)
        start = time.perf_counter()
        while next_assignment < fingerprint["logical_candidates"]:
            outer = next_assignment >> 32
            first = next_assignment & MASK32
            count = min(
                spec["stream_candidates"],
                INNER_CANDIDATES - first,
                fingerprint["logical_candidates"] - next_assignment,
            )
            if configured_outer != outer:
                host.configure(
                    _configuration(name, challenge, outer, retained_target, retained_control)
                )
                configured_outer = outer
            response = host.filter(first, count)
            gpu_seconds += float(response.get("gpu_seconds", 0.0))
            factual.extend((outer << 32) | int(value) for value in response["factual"])
            control.extend((outer << 32) | int(value) for value in response["control"])
            next_assignment += count
            if not factual and not control:
                durable_next = next_assignment
                durable_gpu_seconds = gpu_seconds
            _atomic_json(
                checkpoint_path,
                {
                    **fingerprint,
                    "next_assignment": durable_next,
                    "gpu_seconds": durable_gpu_seconds,
                    "factual": [],
                    "control": [],
                },
            )
            completed_slices = next_assignment // INNER_CANDIDATES
            if next_assignment % INNER_CANDIDATES == 0 and completed_slices and (
                completed_slices % max(1, spec["outer_slices"] // 16) == 0
                or next_assignment == fingerprint["logical_candidates"]
            ):
                print(
                    f"{spec['attempt_id']} {name}: {completed_slices}/{spec['outer_slices']} slices",
                    flush=True,
                )
        wall_seconds = time.perf_counter() - start
        factual_full = [
            value
            for value in factual
            if _candidate_output(name, challenge, value) == retained_target
        ]
        control_full = [
            value
            for value in control
            if _candidate_output(name, challenge, value) == retained_control
        ]
        if (
            factual_full != payload["execution"]["factual_full_matches"]
            or control_full != []
            or next_assignment != fingerprint["logical_candidates"]
        ):
            raise RuntimeError("complete reproduction differs from retained result")
        reproduction = {
            "schema": "fullround-key-recovery-reproduction-v1",
            "status": "complete-and-matched-retained-result",
            "author": "David Tom Foss",
            "cipher": name,
            "attempt_id": spec["attempt_id"],
            "retained_result_sha256": retained_sha,
            "native_build": build,
            "host_identity": host.identity,
            "mapping_gate": gate,
            "execution": {
                "logical_candidates": fingerprint["logical_candidates"],
                "resumed_candidates": resumed,
                "newly_executed_candidates": fingerprint["logical_candidates"] - resumed,
                "complete_domain_executed": True,
                "early_stop_used": False,
                "factual_full_matches": factual_full,
                "control_full_matches": control_full,
                "gpu_seconds": gpu_seconds,
                "wall_seconds": wall_seconds,
                "candidate_identities_persisted_in_checkpoint": False,
            },
        }
        output = root / "build" / "reproductions" / f"{name}.json"
        _atomic_json(output, reproduction)
        checkpoint_path.unlink(missing_ok=True)
        reproduction["output"] = str(output)
        reproduction["output_sha256"] = sha256_file(output)
        return reproduction
    finally:
        host.close()


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cipher", choices=tuple(SPECS))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--mapping-only", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)
    root = (args.root or repository_root()).resolve()
    value = reproduce(
        args.cipher,
        root=root,
        swiftc=args.swiftc,
        resume=not args.no_resume,
        mapping_only=args.mapping_only,
    )
    print(json.dumps(value, indent=2 if args.pretty else None, sort_keys=True))


if __name__ == "__main__":
    main()
