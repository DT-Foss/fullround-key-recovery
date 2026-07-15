"""Minimal pure-Python RFC 8439 ChaCha20 block reference.

This module is deliberately independent of the symbolic/CNF pipeline and the
A219 target generator. It accepts only the public RFC byte representation and
always executes the standard 20 rounds followed by feed-forward.
"""

from __future__ import annotations

import struct

_MASK32 = 0xFFFFFFFF
_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

RFC8439_SECTION_2_3_2_KEY = bytes(range(32))
RFC8439_SECTION_2_3_2_COUNTER = 1
RFC8439_SECTION_2_3_2_NONCE = bytes.fromhex("000000090000004a00000000")
RFC8439_SECTION_2_3_2_BLOCK = bytes.fromhex(
    "10f1e7e4d13b5915500fdd1fa32071c4"
    "c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2"
    "b5129cd1de164eb9cbd083e8a2503c4e"
)


def _rotate_left32(value: int, distance: int) -> int:
    return ((value << distance) & _MASK32) | (value >> (32 - distance))


def _quarter_round(words: list[int], a: int, b: int, c: int, d: int) -> None:
    words[a] = (words[a] + words[b]) & _MASK32
    words[d] = _rotate_left32(words[d] ^ words[a], 16)
    words[c] = (words[c] + words[d]) & _MASK32
    words[b] = _rotate_left32(words[b] ^ words[c], 12)
    words[a] = (words[a] + words[b]) & _MASK32
    words[d] = _rotate_left32(words[d] ^ words[a], 8)
    words[c] = (words[c] + words[d]) & _MASK32
    words[b] = _rotate_left32(words[b] ^ words[c], 7)


def chacha20_block(*, key: bytes, counter: int, nonce: bytes) -> bytes:
    """Return one standard 64-byte ChaCha20 block as specified by RFC 8439."""
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not isinstance(nonce, bytes):
        raise TypeError("nonce must be bytes")
    if not isinstance(counter, int) or isinstance(counter, bool):
        raise TypeError("counter must be an integer")
    if len(key) != 32:
        raise ValueError("key must contain exactly 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must contain exactly 12 bytes")
    if counter < 0 or counter > _MASK32:
        raise ValueError("counter must fit an unsigned 32-bit word")

    initial = [
        *_CONSTANTS,
        *struct.unpack("<8I", key),
        counter,
        *struct.unpack("<3I", nonce),
    ]
    working = initial.copy()
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    block_words = [
        (word + initial_word) & _MASK32 for word, initial_word in zip(working, initial, strict=True)
    ]
    return struct.pack("<16I", *block_words)


def rfc8439_section_2_3_2_kat() -> bool:
    """Return whether the independent core passes RFC 8439 Section 2.3.2."""
    return (
        chacha20_block(
            key=RFC8439_SECTION_2_3_2_KEY,
            counter=RFC8439_SECTION_2_3_2_COUNTER,
            nonce=RFC8439_SECTION_2_3_2_NONCE,
        )
        == RFC8439_SECTION_2_3_2_BLOCK
    )


__all__ = ["chacha20_block", "rfc8439_section_2_3_2_kat"]
