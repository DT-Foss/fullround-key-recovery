#!/usr/bin/env python3
"""Third-implementation root confirmation for one completed A285 target."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
MASK32 = (1 << 32) - 1


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_sha256(value: Any) -> str:
    return _sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    )


def _atomic_json(path: Path, value: Any) -> None:
    raw = (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _rol32(value: int, shift: int) -> int:
    return ((value << shift) & MASK32) | (value >> (32 - shift))


def _quarterround(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rol32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rol32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rol32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rol32(state[b] ^ state[c], 7)


def chacha20_block(
    key_words: Sequence[int], counter: int, nonce_words: Sequence[int]
) -> list[int]:
    if len(key_words) != 8 or len(nonce_words) != 3:
        raise ValueError("ChaCha20 requires eight key words and three nonce words")
    initial = [
        0x61707865,
        0x3320646E,
        0x79622D32,
        0x6B206574,
        *[int(word) & MASK32 for word in key_words],
        counter & MASK32,
        *[int(word) & MASK32 for word in nonce_words],
    ]
    state = initial.copy()
    for _ in range(10):
        _quarterround(state, 0, 4, 8, 12)
        _quarterround(state, 1, 5, 9, 13)
        _quarterround(state, 2, 6, 10, 14)
        _quarterround(state, 3, 7, 11, 15)
        _quarterround(state, 0, 5, 10, 15)
        _quarterround(state, 1, 6, 11, 12)
        _quarterround(state, 2, 7, 8, 13)
        _quarterround(state, 3, 4, 9, 14)
    return [(word + initial[index]) & MASK32 for index, word in enumerate(state)]


def _word_bytes(words: Sequence[int]) -> bytes:
    return b"".join(int(word).to_bytes(4, "little") for word in words)


def rfc8439_kat() -> dict[str, Any]:
    key = bytes(range(32))
    key_words = [
        int.from_bytes(key[offset : offset + 4], "little")
        for offset in range(0, 32, 4)
    ]
    nonce = bytes.fromhex("000000090000004a00000000")
    nonce_words = [
        int.from_bytes(nonce[offset : offset + 4], "little")
        for offset in range(0, 12, 4)
    ]
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    observed = _word_bytes(chacha20_block(key_words, 1, nonce_words))
    if observed != expected:
        raise RuntimeError("root standalone RFC 8439 ChaCha20 KAT failed")
    return {
        "vector": "RFC8439_section_2.3.2",
        "expected_sha256": _sha256(expected),
        "observed_sha256": _sha256(observed),
        "exact": True,
    }


def _load_reader(dotcausal_src: Path) -> tuple[Any, dict[str, Any]]:
    try:
        module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("authoritative dotcausal.io is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(module.CausalReader) or "")
    return module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": _file_sha256(source),
    }


def confirm(
    *,
    target_path: Path,
    expected_target_sha256: str,
    result_path: Path,
    expected_result_sha256: str,
    causal_path: Path,
    expected_causal_sha256: str,
    output: Path,
    dotcausal_src: Path,
) -> dict[str, Any]:
    target_path = target_path.resolve()
    result_path = result_path.resolve()
    causal_path = causal_path.resolve()
    output = output.resolve()
    fixed = {
        target_path: expected_target_sha256,
        result_path: expected_result_sha256,
        causal_path: expected_causal_sha256,
    }
    for path, digest in fixed.items():
        if _file_sha256(path) != digest:
            raise RuntimeError(f"root confirmation anchor differs: {path.name}")
    target_protocol = json.loads(target_path.read_bytes())
    challenge = target_protocol["public_challenge"]
    result = json.loads(result_path.read_bytes())
    confirmation = result.get("confirmation")
    if (
        challenge.get("rounds") != 20
        or challenge.get("block_count") != 8
        or challenge.get("unknown_assignment_included") is not False
        or result.get("evidence_stage")
        != "FULLROUND_R20_CROSS_MATERIAL_TARGET_BLIND_TOP128_RECOVERY_CONFIRMED"
        or not isinstance(confirmation, dict)
        or confirmation.get("output_bits_checked") != 4096
    ):
        raise RuntimeError("root confirmation input semantics differ")
    recovered = int(confirmation["recovered_unknown_low20"])
    if not 0 <= recovered < 1 << 20:
        raise RuntimeError("root confirmation recovered low20 differs")
    key_words = [
        int(challenge["known_key_word0_upper12"]) | recovered,
        *[int(word) for word in challenge["known_key_words_1_through_7"]],
    ]
    observed = [
        chacha20_block(
            key_words,
            int(challenge["counter_start"]) + block_index,
            challenge["nonce_words"],
        )
        for block_index in range(8)
    ]
    block_sha256 = [_sha256(_word_bytes(block)) for block in observed]
    if (
        observed != challenge["target_words"]
        or block_sha256 != challenge["target_block_sha256"]
        or observed[0] == challenge["control_target_words"]
    ):
        raise RuntimeError("root standalone ChaCha20 confirmation failed")
    top = result["top_execution"].get("sat_row")
    if not isinstance(top, dict):
        raise RuntimeError("root confirmation expected a top128 SAT row")
    CausalReader, reader_source = _load_reader(dotcausal_src)
    reader = CausalReader(str(causal_path), verify_integrity=True)
    all_rows = reader.get_all_triplets(include_inferred=True)
    gaps = list(reader._gaps)
    if (
        not str(reader.api_id).startswith("a285t")
        or len(all_rows) != 4
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(gaps) != 1
        or "confirmed_cross_material_R20_recovery" not in all_rows[-1]["outcome"]
    ):
        raise RuntimeError("root canonical Causal semantic gate failed")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-multitarget-root-confirmation-v1",
        "attempt_id": "A285-root-confirmation",
        "evidence_stage": "THIRD_IMPLEMENTATION_4096_BIT_CONFIRMATION",
        "anchors": {
            "target": {
                "path": str(target_path.relative_to(ROOT)),
                "sha256": expected_target_sha256,
            },
            "result": {
                "path": str(result_path.relative_to(ROOT)),
                "sha256": expected_result_sha256,
            },
            "canonical_causal": {
                "path": str(causal_path.relative_to(ROOT)),
                "sha256": expected_causal_sha256,
            },
            "standalone_source": {
                "path": str(Path(__file__).relative_to(ROOT)),
                "sha256": _file_sha256(Path(__file__)),
            },
        },
        "rfc8439_gate": rfc8439_kat(),
        "recovered_unknown_low20": recovered,
        "recovered_unknown_low20_hex": f"{recovered:05x}",
        "frozen_order_rank": int(top["cell_index"]) + 1,
        "standalone_direct_spec_all_8_blocks_match": True,
        "standalone_output_bits_checked": 4096,
        "standalone_block_sha256": block_sha256,
        "one_bit_control_rejected": True,
        "authentic_causal_readback": {
            "reader_source": reader_source,
            "api_id": reader.api_id,
            "triplets": len(all_rows),
            "rules": len(reader._rules),
            "clusters": len(reader._clusters),
            "terminal_chain": all_rows[-1],
            "next_gap": gaps[0],
        },
    }
    payload["confirmation_sha256"] = _canonical_sha256(
        {
            "recovered_unknown_low20": recovered,
            "frozen_order_rank": payload["frozen_order_rank"],
            "standalone_block_sha256": block_sha256,
            "one_bit_control_rejected": True,
            "terminal_chain": all_rows[-1],
            "next_gap": gaps[0],
        }
    )
    if output.exists():
        raise FileExistsError(f"root confirmation already exists: {output}")
    _atomic_json(output, payload)
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--expected-target-sha256", required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--expected-result-sha256", required=True)
    parser.add_argument("--causal", type=Path, required=True)
    parser.add_argument("--expected-causal-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    payload = confirm(
        target_path=args.target,
        expected_target_sha256=args.expected_target_sha256,
        result_path=args.result,
        expected_result_sha256=args.expected_result_sha256,
        causal_path=args.causal,
        expected_causal_sha256=args.expected_causal_sha256,
        output=args.output,
        dotcausal_src=args.dotcausal_src,
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "output_sha256": _file_sha256(args.output),
                "confirmation_sha256": payload["confirmation_sha256"],
                "rank": payload["frozen_order_rank"],
                "output_bits_checked": payload["standalone_output_bits_checked"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
