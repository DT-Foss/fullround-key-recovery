"""Exact NIST SP 800-232 Ascon-AEAD128 reference implementation.

The byte convention here is the standardized little-endian convention from
SP 800-232 Appendix A.  It is intentionally not compatible with the legacy
Ascon v1.2 big-endian interface.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

MASK64 = (1 << 64) - 1
RATE_BYTES = 16
KEY_BYTES = 16
NONCE_BYTES = 16
TAG_BYTES = 16
IV = 0x00001000808C0001
ROUND_CONSTANTS = (
    0xF0,
    0xE1,
    0xD2,
    0xC3,
    0xB4,
    0xA5,
    0x96,
    0x87,
    0x78,
    0x69,
    0x5A,
    0x4B,
)

SP800_232_URL = "https://doi.org/10.6028/NIST.SP.800-232"
SP800_232_PDF_SHA256 = (
    "1be9bb9a5fef3665ee8b258babe54b8e500d667fcfbbcc99710fe6077c6bad27"
)
OFFICIAL_KAT_COMMIT = "446347f21b209f3921c65ece70027c366cbe1693"
OFFICIAL_KAT_URL = (
    "https://raw.githubusercontent.com/ascon/ascon-c/"
    f"{OFFICIAL_KAT_COMMIT}/crypto_aead/asconaead128/"
    "LWC_AEAD_KAT_128_128.txt"
)
OFFICIAL_KAT_FILE_SHA256 = (
    "bbbc34692fe05e5fda0a3b025585622ab3e3747495e5e3655b29aae8c2a4bd33"
)


@dataclass(frozen=True)
class OfficialKat:
    """One pinned vector from the official standardized Ascon KAT file."""

    count: int
    key_hex: str
    nonce_hex: str
    plaintext_hex: str
    associated_data_hex: str
    combined_ciphertext_tag_hex: str

    @property
    def key(self) -> bytes:
        return bytes.fromhex(self.key_hex)

    @property
    def nonce(self) -> bytes:
        return bytes.fromhex(self.nonce_hex)

    @property
    def plaintext(self) -> bytes:
        return bytes.fromhex(self.plaintext_hex)

    @property
    def associated_data(self) -> bytes:
        return bytes.fromhex(self.associated_data_hex)

    @property
    def combined_ciphertext_tag(self) -> bytes:
        return bytes.fromhex(self.combined_ciphertext_tag_hex)


_KAT_KEY = "000102030405060708090A0B0C0D0E0F"
_KAT_NONCE = "101112131415161718191A1B1C1D1E1F"
OFFICIAL_KATS = (
    OfficialKat(
        count=1,
        key_hex=_KAT_KEY,
        nonce_hex=_KAT_NONCE,
        plaintext_hex="",
        associated_data_hex="",
        combined_ciphertext_tag_hex="4F9C278211BEC9316BF68F46EE8B2EC6",
    ),
    OfficialKat(
        count=35,
        key_hex=_KAT_KEY,
        nonce_hex=_KAT_NONCE,
        plaintext_hex="20",
        associated_data_hex="30",
        combined_ciphertext_tag_hex="962B8016836C75A7D86866588CA245D886",
    ),
    OfficialKat(
        count=563,
        key_hex=_KAT_KEY,
        nonce_hex=_KAT_NONCE,
        plaintext_hex="202122232425262728292A2B2C2D2E2F30",
        associated_data_hex="30",
        combined_ciphertext_tag_hex=(
            "96107D8A29A7529A7941BDC7DF1FE3C6C7"
            "EA70D7986E7B59CD0D357239F5D25BF5"
        ),
    ),
    OfficialKat(
        count=1074,
        key_hex=_KAT_KEY,
        nonce_hex=_KAT_NONCE,
        plaintext_hex=(
            "202122232425262728292A2B2C2D2E2F"
            "303132333435363738393A3B3C3D3E3F"
        ),
        associated_data_hex="303132333435363738393A3B3C3D3E3F40",
        combined_ciphertext_tag_hex=(
            "BF77C71B3DE9F1C5B372EF273A08E89B"
            "E9675ADC5777342F1D1EF3C5D4BFC7AA"
            "055DD1908BB4C524BC967452FFDAA943"
        ),
    ),
)
ORIENTATION_SENTINEL_COUNT = 1074


def _ror(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (64 - amount))) & MASK64


def _round(state: list[int], constant: int) -> None:
    """Apply one SP 800-232 Ascon permutation round in place."""

    x0, x1, x2, x3, x4 = state
    x2 ^= constant
    x0 ^= x4
    x4 ^= x3
    x2 ^= x1
    t0 = x0 ^ ((~x1 & MASK64) & x2)
    t1 = x1 ^ ((~x2 & MASK64) & x3)
    t2 = x2 ^ ((~x3 & MASK64) & x4)
    t3 = x3 ^ ((~x4 & MASK64) & x0)
    t4 = x4 ^ ((~x0 & MASK64) & x1)
    t1 ^= t0
    t0 ^= t4
    t3 ^= t2
    t2 = ~t2 & MASK64
    state[0] = t0 ^ _ror(t0, 19) ^ _ror(t0, 28)
    state[1] = t1 ^ _ror(t1, 61) ^ _ror(t1, 39)
    state[2] = t2 ^ _ror(t2, 1) ^ _ror(t2, 6)
    state[3] = t3 ^ _ror(t3, 10) ^ _ror(t3, 17)
    state[4] = t4 ^ _ror(t4, 7) ^ _ror(t4, 41)


def permutation(state: list[int], rounds: int) -> None:
    """Apply Ascon-p[rounds] to five 64-bit words in place."""

    if len(state) != 5:
        raise ValueError("Ascon state must contain five words")
    if rounds not in {8, 12}:
        raise ValueError("Ascon-AEAD128 uses only 8 or 12 permutation rounds")
    for constant in ROUND_CONSTANTS[12 - rounds :]:
        _round(state, constant)


def _load_le(data: bytes) -> int:
    return int.from_bytes(data, "little")


def _store_le(value: int, length: int = 8) -> bytes:
    return value.to_bytes(8, "little")[:length]


def _pad(length: int) -> int:
    if length < 0 or length >= 8:
        raise ValueError("padding offset must be in 0...7")
    return 1 << (8 * length)


def _absorb_associated_data(state: list[int], associated_data: bytes) -> None:
    if associated_data:
        offset = 0
        remaining = len(associated_data)
        while remaining >= RATE_BYTES:
            state[0] ^= _load_le(associated_data[offset : offset + 8])
            state[1] ^= _load_le(associated_data[offset + 8 : offset + 16])
            permutation(state, 8)
            offset += RATE_BYTES
            remaining -= RATE_BYTES
        if remaining >= 8:
            state[0] ^= _load_le(associated_data[offset : offset + 8])
            tail = associated_data[offset + 8 :]
            state[1] ^= _load_le(tail)
            state[1] ^= _pad(len(tail))
        else:
            tail = associated_data[offset:]
            state[0] ^= _load_le(tail)
            state[0] ^= _pad(len(tail))
        permutation(state, 8)
    state[4] ^= 0x8000000000000000


def encrypt(
    key: bytes,
    nonce: bytes,
    associated_data: bytes,
    plaintext: bytes,
) -> tuple[bytes, bytes]:
    """Encrypt and return ``(ciphertext, 16-byte tag)`` per SP 800-232."""

    if len(key) != KEY_BYTES:
        raise ValueError("Ascon-AEAD128 key must contain 16 bytes")
    if len(nonce) != NONCE_BYTES:
        raise ValueError("Ascon-AEAD128 nonce must contain 16 bytes")
    k0 = _load_le(key[:8])
    k1 = _load_le(key[8:])
    state = [IV, k0, k1, _load_le(nonce[:8]), _load_le(nonce[8:])]
    permutation(state, 12)
    state[3] ^= k0
    state[4] ^= k1
    _absorb_associated_data(state, associated_data)

    ciphertext = bytearray()
    offset = 0
    remaining = len(plaintext)
    while remaining >= RATE_BYTES:
        state[0] ^= _load_le(plaintext[offset : offset + 8])
        state[1] ^= _load_le(plaintext[offset + 8 : offset + 16])
        ciphertext.extend(_store_le(state[0]))
        ciphertext.extend(_store_le(state[1]))
        permutation(state, 8)
        offset += RATE_BYTES
        remaining -= RATE_BYTES
    if remaining >= 8:
        state[0] ^= _load_le(plaintext[offset : offset + 8])
        tail = plaintext[offset + 8 :]
        state[1] ^= _load_le(tail)
        ciphertext.extend(_store_le(state[0]))
        ciphertext.extend(_store_le(state[1], len(tail)))
        state[1] ^= _pad(len(tail))
    else:
        tail = plaintext[offset:]
        state[0] ^= _load_le(tail)
        ciphertext.extend(_store_le(state[0], len(tail)))
        state[0] ^= _pad(len(tail))

    state[2] ^= k0
    state[3] ^= k1
    permutation(state, 12)
    state[3] ^= k0
    state[4] ^= k1
    return bytes(ciphertext), _store_le(state[3]) + _store_le(state[4])


def encrypt_combined(
    key: bytes,
    nonce: bytes,
    associated_data: bytes,
    plaintext: bytes,
) -> bytes:
    """Return ciphertext followed by the full 128-bit tag."""

    ciphertext, tag = encrypt(key, nonce, associated_data, plaintext)
    return ciphertext + tag


def decrypt(
    key: bytes,
    nonce: bytes,
    associated_data: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    """Authenticate and decrypt, raising ``ValueError`` for an invalid tag."""

    if len(key) != KEY_BYTES:
        raise ValueError("Ascon-AEAD128 key must contain 16 bytes")
    if len(nonce) != NONCE_BYTES:
        raise ValueError("Ascon-AEAD128 nonce must contain 16 bytes")
    if len(tag) != TAG_BYTES:
        raise ValueError("Ascon-AEAD128 tag must contain 16 bytes")
    k0 = _load_le(key[:8])
    k1 = _load_le(key[8:])
    state = [IV, k0, k1, _load_le(nonce[:8]), _load_le(nonce[8:])]
    permutation(state, 12)
    state[3] ^= k0
    state[4] ^= k1
    _absorb_associated_data(state, associated_data)

    plaintext = bytearray()
    offset = 0
    remaining = len(ciphertext)
    while remaining >= RATE_BYTES:
        c0 = _load_le(ciphertext[offset : offset + 8])
        c1 = _load_le(ciphertext[offset + 8 : offset + 16])
        plaintext.extend(_store_le(state[0] ^ c0))
        plaintext.extend(_store_le(state[1] ^ c1))
        state[0] = c0
        state[1] = c1
        permutation(state, 8)
        offset += RATE_BYTES
        remaining -= RATE_BYTES
    if remaining >= 8:
        c0 = _load_le(ciphertext[offset : offset + 8])
        tail = ciphertext[offset + 8 :]
        c1 = _load_le(tail)
        plaintext.extend(_store_le(state[0] ^ c0))
        plaintext.extend(_store_le(state[1] ^ c1, len(tail)))
        keep_mask = MASK64 ^ ((1 << (8 * len(tail))) - 1)
        state[0] = c0
        state[1] = (state[1] & keep_mask) | c1
        state[1] ^= _pad(len(tail))
    else:
        tail = ciphertext[offset:]
        c0 = _load_le(tail)
        plaintext.extend(_store_le(state[0] ^ c0, len(tail)))
        keep_mask = MASK64 ^ ((1 << (8 * len(tail))) - 1)
        state[0] = (state[0] & keep_mask) | c0
        state[0] ^= _pad(len(tail))

    state[2] ^= k0
    state[3] ^= k1
    permutation(state, 12)
    state[3] ^= k0
    state[4] ^= k1
    expected_tag = _store_le(state[3]) + _store_le(state[4])
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("invalid Ascon-AEAD128 authentication tag")
    return bytes(plaintext)


def verify_official_kats() -> list[dict[str, object]]:
    """Verify all locally pinned official standardized KAT rows."""

    rows: list[dict[str, object]] = []
    for vector in OFFICIAL_KATS:
        actual = encrypt_combined(
            vector.key,
            vector.nonce,
            vector.associated_data,
            vector.plaintext,
        )
        rows.append(
            {
                "count": vector.count,
                "plaintext_bytes": len(vector.plaintext),
                "associated_data_bytes": len(vector.associated_data),
                "expected_combined_hex": vector.combined_ciphertext_tag.hex(),
                "actual_combined_hex": actual.hex(),
                "pass": actual == vector.combined_ciphertext_tag,
            }
        )
    return rows


def verify_orientation_sentinel() -> dict[str, object]:
    """Return an asymmetric word/byte sentinel for the standardized orientation."""

    vector = next(row for row in OFFICIAL_KATS if row.count == ORIENTATION_SENTINEL_COUNT)
    actual = encrypt_combined(
        vector.key,
        vector.nonce,
        vector.associated_data,
        vector.plaintext,
    )
    little_words = tuple(
        int.from_bytes(vector.key[offset : offset + 8], "little")
        for offset in (0, 8)
    )
    big_words = tuple(
        int.from_bytes(vector.key[offset : offset + 8], "big") for offset in (0, 8)
    )
    reversed_word_input = b"".join(
        vector.key[offset : offset + 8][::-1] for offset in (0, 8)
    )
    reversed_output = encrypt_combined(
        reversed_word_input,
        vector.nonce,
        vector.associated_data,
        vector.plaintext,
    )
    return {
        "official_kat_count": vector.count,
        "key_hex_nonpalindromic": vector.key.hex(),
        "little_endian_key_words_hex": [f"{word:016x}" for word in little_words],
        "legacy_big_endian_interpretation_hex": [f"{word:016x}" for word in big_words],
        "expected_combined_hex": vector.combined_ciphertext_tag.hex(),
        "word_reversed_key_combined_hex": reversed_output.hex(),
        "little_and_big_word_interpretations_differ": little_words != big_words,
        "word_reversed_key_rejected": reversed_output != vector.combined_ciphertext_tag,
        "pass": actual == vector.combined_ciphertext_tag
        and little_words != big_words
        and reversed_output != vector.combined_ciphertext_tag,
    }
