"""Independent vectorized AES-256 confirmation oracle.

This implementation deliberately uses word-array key expansion and a row-major
NumPy state view instead of the scalar byte-list code in ``aes256_reference``.
It is an audit oracle, not a production cryptography API.
"""

from __future__ import annotations

import numpy as np

from .aes256_reference import BLOCK_BYTES, KEY_BYTES, RCON, ROUNDS, SBOX

_SBOX = np.asarray(SBOX, dtype=np.uint8)


def _fixed_key(key: bytes) -> np.ndarray:
    raw = bytes(key)
    if len(raw) != KEY_BYTES:
        raise ValueError("AES-256 key must contain exactly 32 bytes")
    return np.frombuffer(raw, dtype=np.uint8).copy()


def expand_key_words_independent(key: bytes) -> np.ndarray:
    """Return the 60 FIPS-order AES-256 schedule words."""

    key_bytes = _fixed_key(key)
    words = np.zeros((60, 4), dtype=np.uint8)
    words[:8] = key_bytes.reshape(8, 4)
    for index in range(8, 60):
        temporary = words[index - 1].copy()
        if index % 8 == 0:
            temporary = _SBOX[np.roll(temporary, -1)]
            temporary[0] ^= np.uint8(RCON[index // 8 - 1])
        elif index % 8 == 4:
            temporary = _SBOX[temporary]
        words[index] = words[index - 8] ^ temporary
    return words


def _xtime(values: np.ndarray) -> np.ndarray:
    wide = values.astype(np.uint16)
    return ((wide << 1) ^ (((wide >> 7) & 1) * 0x1B)).astype(np.uint8)


def encrypt_blocks_independent(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt one or more blocks through all 14 AES-256 rounds."""

    raw = bytes(plaintext)
    if not raw or len(raw) % BLOCK_BYTES:
        raise ValueError("AES plaintext must contain a non-empty whole number of blocks")
    count = len(raw) // BLOCK_BYTES
    round_keys = (
        expand_key_words_independent(key)
        .reshape(ROUNDS + 1, 4, 4)
        .transpose(0, 2, 1)
    )
    state = (
        np.frombuffer(raw, dtype=np.uint8)
        .reshape(count, 4, 4)
        .transpose(0, 2, 1)
        .copy()
    )
    state ^= round_keys[0][None, :, :]
    for round_index in range(1, ROUNDS + 1):
        state = _SBOX[state]
        for row in range(1, 4):
            state[:, row, :] = np.roll(state[:, row, :], -row, axis=1)
        if round_index != ROUNDS:
            s0 = state[:, 0, :].copy()
            s1 = state[:, 1, :].copy()
            s2 = state[:, 2, :].copy()
            s3 = state[:, 3, :].copy()
            x0, x1, x2, x3 = map(_xtime, (s0, s1, s2, s3))
            state[:, 0, :] = x0 ^ x1 ^ s1 ^ s2 ^ s3
            state[:, 1, :] = s0 ^ x1 ^ x2 ^ s2 ^ s3
            state[:, 2, :] = s0 ^ s1 ^ x2 ^ x3 ^ s3
            state[:, 3, :] = x0 ^ s0 ^ s1 ^ s2 ^ x3
        state ^= round_keys[round_index][None, :, :]
    return state.transpose(0, 2, 1).reshape(count, BLOCK_BYTES).tobytes()
