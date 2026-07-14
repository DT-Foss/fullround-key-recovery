"""Small, byte-exact FIPS 197 AES-256 reference implementation.

The implementation is intentionally scalar and table based.  It is the CPU
oracle for the prospective Metal record factory, not a constant-time API for
production secrets.  AES state and key bytes follow the FIPS 197 external byte
order.  Residual assignments are the contiguous low bits of the 256-bit
big-endian key integer: assignment bit 0 is bit 0 of key byte 31.
"""

from __future__ import annotations

from dataclasses import dataclass

BLOCK_BYTES = 16
KEY_BYTES = 32
ROUNDS = 14
FIPS197_URL = "https://doi.org/10.6028/NIST.FIPS.197-upd1"
NIST_AES_EXAMPLE_VALUES_URL = (
    "https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values"
)
LOCAL_INDEPENDENT_REFERENCE = "src/arx_carry_leak/aes256_independent.py"
LOCAL_C_REFERENCE = "provenance/dependencies/pqcrypto-upstream/pqclean/common/aes.c"

SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
INV_SBOX = tuple(SBOX.index(value) for value in range(256))


@dataclass(frozen=True)
class KnownAnswer:
    name: str
    key: bytes
    plaintext: bytes
    ciphertext: bytes


FIPS197_KATS = (
    KnownAnswer(
        name="FIPS197_Appendix_C3_AES256",
        key=bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        ),
        plaintext=bytes.fromhex("00112233445566778899aabbccddeeff"),
        ciphertext=bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"),
    ),
    KnownAnswer(
        name="NIST_SP800_38A_F5_AES256_ECB",
        key=bytes.fromhex(
            "603deb1015ca71be2b73aef0857d7781"
            "1f352c073b6108d72d9810a30914dff4"
        ),
        plaintext=bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        ciphertext=bytes.fromhex("f3eed1bdb5d2a03c064b5a7e3db181f8"),
    ),
)

LOCAL_ORIENTATION_KAT = KnownAnswer(
    name="LOCAL_AES256_NONPALINDROMIC_ORIENTATION_SENTINEL",
    key=bytes.fromhex(
        "00112233445566778899aabbccddeeff"
        "102132435465768798a9bacbdcedfe0f"
    ),
    plaintext=bytes.fromhex("ffeeddccbbaa99887766554433221100"),
    ciphertext=bytes.fromhex("2557998248d878d5049ebff99fd7d5bd"),
)

FIPS197_APPENDIX_A3_KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d7781"
    "1f352c073b6108d72d9810a30914dff4"
)
FIPS197_APPENDIX_A3_WORD_SENTINELS = {
    8: 0x9BA35411,
    12: 0xA8B09C1A,
    56: 0xFE4890D1,
    59: 0x706C631E,
}


def _fixed_bytes(value: bytes, *, size: int, name: str) -> bytes:
    raw = bytes(value)
    if len(raw) != size:
        raise ValueError(f"{name} must contain exactly {size} bytes")
    return raw


def expand_key(key: bytes) -> bytes:
    """Return the 15 concatenated AES-256 round keys in FIPS byte order."""

    expanded = bytearray(_fixed_bytes(key, size=KEY_BYTES, name="AES-256 key"))
    rcon_index = 0
    while len(expanded) < (ROUNDS + 1) * BLOCK_BYTES:
        word = list(expanded[-4:])
        word_index = len(expanded) // 4
        if word_index % 8 == 0:
            word = [SBOX[word[1]], SBOX[word[2]], SBOX[word[3]], SBOX[word[0]]]
            word[0] ^= RCON[rcon_index]
            rcon_index += 1
        elif word_index % 8 == 4:
            word = [SBOX[value] for value in word]
        for value in word:
            expanded.append(expanded[len(expanded) - KEY_BYTES] ^ value)
    return bytes(expanded)


def _xtime(value: int) -> int:
    return ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF


def _add_round_key(state: list[int], round_key: bytes) -> None:
    for index, value in enumerate(round_key):
        state[index] ^= value


def _shift_rows(state: list[int]) -> list[int]:
    shifted = [0] * BLOCK_BYTES
    for column in range(4):
        for row in range(4):
            shifted[4 * column + row] = state[4 * ((column + row) & 3) + row]
    return shifted


def _mix_columns(state: list[int]) -> None:
    for offset in range(0, BLOCK_BYTES, 4):
        a0, a1, a2, a3 = state[offset : offset + 4]
        total = a0 ^ a1 ^ a2 ^ a3
        state[offset] = a0 ^ total ^ _xtime(a0 ^ a1)
        state[offset + 1] = a1 ^ total ^ _xtime(a1 ^ a2)
        state[offset + 2] = a2 ^ total ^ _xtime(a2 ^ a3)
        state[offset + 3] = a3 ^ total ^ _xtime(a3 ^ a0)


def _gf_mul(left: int, right: int) -> int:
    product = 0
    a = left
    b = right
    for _ in range(8):
        if b & 1:
            product ^= a
        a = _xtime(a)
        b >>= 1
    return product


def _inv_shift_rows(state: list[int]) -> list[int]:
    shifted = [0] * BLOCK_BYTES
    for column in range(4):
        for row in range(4):
            shifted[4 * column + row] = state[4 * ((column - row) & 3) + row]
    return shifted


def _inv_mix_columns(state: list[int]) -> None:
    for offset in range(0, BLOCK_BYTES, 4):
        a0, a1, a2, a3 = state[offset : offset + 4]
        state[offset] = (
            _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
        )
        state[offset + 1] = (
            _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
        )
        state[offset + 2] = (
            _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
        )
        state[offset + 3] = (
            _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)
        )


def encrypt_block(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt one standard 128-bit block with all fourteen AES-256 rounds."""

    block = _fixed_bytes(plaintext, size=BLOCK_BYTES, name="AES plaintext")
    round_keys = expand_key(key)
    state = list(block)
    _add_round_key(state, round_keys[:BLOCK_BYTES])
    for round_index in range(1, ROUNDS + 1):
        state = [SBOX[value] for value in state]
        state = _shift_rows(state)
        if round_index != ROUNDS:
            _mix_columns(state)
        start = round_index * BLOCK_BYTES
        _add_round_key(state, round_keys[start : start + BLOCK_BYTES])
    return bytes(state)


def decrypt_block(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt one standard block with the inverse fourteen-round transform."""

    block = _fixed_bytes(ciphertext, size=BLOCK_BYTES, name="AES ciphertext")
    round_keys = expand_key(key)
    state = list(block)
    _add_round_key(state, round_keys[ROUNDS * BLOCK_BYTES :])
    for round_index in range(ROUNDS - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = [INV_SBOX[value] for value in state]
        start = round_index * BLOCK_BYTES
        _add_round_key(state, round_keys[start : start + BLOCK_BYTES])
        _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = [INV_SBOX[value] for value in state]
    _add_round_key(state, round_keys[:BLOCK_BYTES])
    return bytes(state)


def encrypt_blocks(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt a non-empty integral number of independent AES blocks."""

    raw = bytes(plaintext)
    if not raw or len(raw) % BLOCK_BYTES:
        raise ValueError("AES plaintext must contain a non-empty whole number of blocks")
    return b"".join(
        encrypt_block(key, raw[offset : offset + BLOCK_BYTES])
        for offset in range(0, len(raw), BLOCK_BYTES)
    )


def decrypt_blocks(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a non-empty integral number of independent AES blocks."""

    raw = bytes(ciphertext)
    if not raw or len(raw) % BLOCK_BYTES:
        raise ValueError("AES ciphertext must contain whole non-empty blocks")
    return b"".join(
        decrypt_block(key, raw[offset : offset + BLOCK_BYTES])
        for offset in range(0, len(raw), BLOCK_BYTES)
    )


def key_words_big_endian(key: bytes) -> tuple[int, ...]:
    """Split an external AES-256 key into eight FIPS-order 32-bit words."""

    raw = _fixed_bytes(key, size=KEY_BYTES, name="AES-256 key")
    return tuple(
        int.from_bytes(raw[index : index + 4], "big")
        for index in range(0, KEY_BYTES, 4)
    )


def residual_mask(width: int) -> int:
    if width < 0 or width > 256:
        raise ValueError("AES residual width must be in 0...256")
    return (1 << width) - 1 if width else 0


def zero_low_residual_bits(key: bytes, width: int) -> bytes:
    """Clear the contiguous low ``width`` bits of a FIPS-order AES key."""

    raw = _fixed_bytes(key, size=KEY_BYTES, name="AES-256 key")
    value = int.from_bytes(raw, "big") & ~residual_mask(width)
    return value.to_bytes(KEY_BYTES, "big")


def apply_low_residual_bits(known_key: bytes, assignment: int, width: int) -> bytes:
    """Materialize the key for one contiguous-low-bit residual assignment."""

    raw = _fixed_bytes(known_key, size=KEY_BYTES, name="known AES-256 key")
    mask = residual_mask(width)
    if assignment < 0 or assignment > mask:
        raise ValueError(f"assignment is outside the {width}-bit AES residual domain")
    known_integer = int.from_bytes(raw, "big")
    if known_integer & mask:
        raise ValueError("known AES key must have all residual bits cleared")
    return (known_integer | assignment).to_bytes(KEY_BYTES, "big")


def verify_fips197_kats() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for vector in FIPS197_KATS:
        observed = encrypt_block(vector.key, vector.plaintext)
        rows.append(
            {
                "name": vector.name,
                "key_hex": vector.key.hex(),
                "plaintext_hex": vector.plaintext.hex(),
                "expected_ciphertext_hex": vector.ciphertext.hex(),
                "observed_ciphertext_hex": observed.hex(),
                "pass": observed == vector.ciphertext,
            }
        )
    return rows


def verify_orientation_and_schedule_sentinels() -> dict[str, object]:
    expanded = expand_key(FIPS197_APPENDIX_A3_KEY)
    observed_words = {
        index: int.from_bytes(expanded[4 * index : 4 * index + 4], "big")
        for index in FIPS197_APPENDIX_A3_WORD_SENTINELS
    }
    observed_ciphertext = encrypt_block(
        LOCAL_ORIENTATION_KAT.key, LOCAL_ORIENTATION_KAT.plaintext
    )
    return {
        "round_key_word_sentinels": {
            str(index): {
                "expected": expected,
                "observed": observed_words[index],
                "pass": observed_words[index] == expected,
            }
            for index, expected in FIPS197_APPENDIX_A3_WORD_SENTINELS.items()
        },
        "orientation_ciphertext_expected_hex": LOCAL_ORIENTATION_KAT.ciphertext.hex(),
        "orientation_ciphertext_observed_hex": observed_ciphertext.hex(),
        "orientation_pass": observed_ciphertext == LOCAL_ORIENTATION_KAT.ciphertext,
        "decrypt_roundtrip_pass": (
            decrypt_block(LOCAL_ORIENTATION_KAT.key, observed_ciphertext)
            == LOCAL_ORIENTATION_KAT.plaintext
        ),
    }
