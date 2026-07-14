"""Exact scalar Salsa20/20 reference using Bernstein's byte conventions.

This module implements the 20-round, 256-bit-key construction used by the
record factory.  It also retains both 256-bit and 128-bit expansion examples
printed in the original Salsa20 specification as provenance KATs.
"""

from __future__ import annotations

from dataclasses import dataclass

WORD_MASK = 0xFFFFFFFF
KEY_BYTES = 32
NONCE_BYTES = 8
BLOCK_BYTES = 64
ROUNDS = 20
SIGMA = b"expand 32-byte k"
TAU = b"expand 16-byte k"

SPECIFICATION_URL = "https://cr.yp.to/snuffle/spec.pdf"
SPECIFICATION_PDF_SHA256 = "2d1680c468f3b8c8dd05141553170a37f7b35507ba854a879515793395702810"
BERNSTEIN_REFERENCE_URL = "https://cr.yp.to/snuffle/salsa20/ref/salsa20.c"
BERNSTEIN_REFERENCE_SHA256 = "1b240d8dc2530e8f5ee688d0347b30f3dbc760345a3794e24895efda3d9a893a"


@dataclass(frozen=True)
class ExpansionKat:
    """One literal expansion example from sections 8--9 of the specification."""

    key_hex: str
    input_hex: str
    output_hex: str


SPEC_256_EXPANSION_KAT = ExpansionKat(
    key_hex=("0102030405060708090a0b0c0d0e0f10c9cacbcccdcecfd0d1d2d3d4d5d6d7d8"),
    input_hex="65666768696a6b6c6d6e6f7071727374",
    output_hex=(
        "45254427290f6bc1ff8b7a06aae9d962"
        "5990b66a1533c841ef31de22d772287e"
        "68c507e1c5991f02664e4cb054f5f6b8"
        "b1a0858206489577c0c384ecea67f64a"
    ),
)

SPEC_128_EXPANSION_KAT = ExpansionKat(
    key_hex="0102030405060708090a0b0c0d0e0f10",
    input_hex="65666768696a6b6c6d6e6f7071727374",
    output_hex=(
        "27ad2ef81ec852113043feef25120df7"
        "f1c83d900a3732b9062ff6fd8f56bbe1"
        "86556ef6a1a32bebe75eab3391d6701d"
        "0ee80510978cb78dab097ab568b6b1c1"
    ),
)


def rol32(value: int, amount: int) -> int:
    """Rotate one unsigned 32-bit word left."""

    value &= WORD_MASK
    amount &= 31
    return ((value << amount) | (value >> ((32 - amount) & 31))) & WORD_MASK


def _words(raw: bytes) -> list[int]:
    if len(raw) % 4:
        raise ValueError("Salsa20 word input must be a multiple of four bytes")
    return [int.from_bytes(raw[offset : offset + 4], "little") for offset in range(0, len(raw), 4)]


def _quarterround(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[b] ^= rol32(state[a] + state[d], 7)
    state[c] ^= rol32(state[b] + state[a], 9)
    state[d] ^= rol32(state[c] + state[b], 13)
    state[a] ^= rol32(state[d] + state[c], 18)


def hash_words(input_words: list[int]) -> list[int]:
    """Return the Salsa20/20 hash of sixteen uint32 words."""

    if len(input_words) != 16:
        raise ValueError("Salsa20 hash input must contain sixteen words")
    initial = [int(word) & WORD_MASK for word in input_words]
    state = list(initial)
    for _ in range(ROUNDS // 2):
        # Column round.
        _quarterround(state, 0, 4, 8, 12)
        _quarterround(state, 5, 9, 13, 1)
        _quarterround(state, 10, 14, 2, 6)
        _quarterround(state, 15, 3, 7, 11)
        # Row round.
        _quarterround(state, 0, 1, 2, 3)
        _quarterround(state, 5, 6, 7, 4)
        _quarterround(state, 10, 11, 8, 9)
        _quarterround(state, 15, 12, 13, 14)
    return [(value + initial[index]) & WORD_MASK for index, value in enumerate(state)]


def expand(key: bytes, input16: bytes) -> bytes:
    """Apply the Salsa20 expansion function to a 16- or 32-byte key."""

    if len(input16) != 16:
        raise ValueError("Salsa20 expansion input must contain 16 bytes")
    if len(key) == 32:
        constants = _words(SIGMA)
        left = _words(key[:16])
        right = _words(key[16:])
    elif len(key) == 16:
        constants = _words(TAU)
        left = right = _words(key)
    else:
        raise ValueError("Salsa20 keys must contain 16 or 32 bytes")
    middle = _words(input16)
    state = [
        constants[0],
        *left,
        constants[1],
        *middle,
        constants[2],
        *right,
        constants[3],
    ]
    return b"".join(word.to_bytes(4, "little") for word in hash_words(state))


def block(key: bytes, nonce: bytes, counter: int) -> bytes:
    """Generate one full 64-byte Salsa20/20 keystream block."""

    if len(key) != KEY_BYTES:
        raise ValueError("Salsa20/20 record factory requires a 32-byte key")
    if len(nonce) != NONCE_BYTES:
        raise ValueError("Salsa20 nonces must contain 8 bytes")
    if counter < 0 or counter >= 1 << 64:
        raise ValueError("Salsa20 block counter must fit uint64")
    return expand(key, nonce + counter.to_bytes(8, "little"))


def keystream(key: bytes, nonce: bytes, length: int, *, counter: int = 0) -> bytes:
    """Generate ``length`` bytes, incrementing the 64-bit counter per block."""

    if length < 0:
        raise ValueError("Salsa20 keystream length must be nonnegative")
    blocks = (length + BLOCK_BYTES - 1) // BLOCK_BYTES
    if counter + blocks > 1 << 64:
        raise ValueError("Salsa20 counter range overflows uint64")
    return b"".join(block(key, nonce, counter + index) for index in range(blocks))[:length]


def crypt(message: bytes, key: bytes, nonce: bytes, *, counter: int = 0) -> bytes:
    """Encrypt or decrypt a byte string by XOR with the Salsa20 stream."""

    stream = keystream(key, nonce, len(message), counter=counter)
    return bytes(left ^ right for left, right in zip(message, stream, strict=True))


def verify_specification_kats() -> list[dict[str, object]]:
    """Recompute both literal KATs from the original Salsa20 specification."""

    rows: list[dict[str, object]] = []
    for name, vector in (
        ("specification_section_9_256_bit", SPEC_256_EXPANSION_KAT),
        ("specification_section_9_128_bit", SPEC_128_EXPANSION_KAT),
    ):
        actual = expand(bytes.fromhex(vector.key_hex), bytes.fromhex(vector.input_hex))
        rows.append(
            {
                "name": name,
                "key_hex": vector.key_hex,
                "input_hex": vector.input_hex,
                "expected_output_hex": vector.output_hex,
                "actual_output_hex": actual.hex(),
                "pass": actual.hex() == vector.output_hex,
            }
        )
    return rows
