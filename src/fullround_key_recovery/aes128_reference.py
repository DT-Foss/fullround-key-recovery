"""Small, byte-exact FIPS 197 AES-128 reference implementation.

The implementation is intentionally scalar and table based.  It is the CPU
oracle for the prospective Metal record factory, not a constant-time API for
production secrets.  AES state and key bytes follow the FIPS 197 external byte
order.  Residual assignments are the contiguous low bits of the 128-bit
big-endian key integer: assignment bit 0 is bit 0 of key byte 15.
"""

from __future__ import annotations

from dataclasses import dataclass

BLOCK_BYTES = 16
KEY_BYTES = 16
ROUNDS = 10
FIPS197_URL = "https://doi.org/10.6028/NIST.FIPS.197-upd1"
NIST_AES_EXAMPLE_VALUES_URL = (
    "https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values"
)
LOCAL_INDEPENDENT_REFERENCE = "src/arx_carry_leak/live_casi_v091/ciphers.py"
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


@dataclass(frozen=True)
class KnownAnswer:
    name: str
    key: bytes
    plaintext: bytes
    ciphertext: bytes


FIPS197_KATS = (
    KnownAnswer(
        name="FIPS197_Appendix_B_Cipher_Example",
        key=bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        plaintext=bytes.fromhex("3243f6a8885a308d313198a2e0370734"),
        ciphertext=bytes.fromhex("3925841d02dc09fbdc118597196a0b32"),
    ),
    KnownAnswer(
        name="FIPS197_Appendix_C1_AES128",
        key=bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        plaintext=bytes.fromhex("00112233445566778899aabbccddeeff"),
        ciphertext=bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
    ),
)


def _fixed_bytes(value: bytes, *, size: int, name: str) -> bytes:
    raw = bytes(value)
    if len(raw) != size:
        raise ValueError(f"{name} must contain exactly {size} bytes")
    return raw


def expand_key(key: bytes) -> bytes:
    """Return the 11 concatenated AES-128 round keys in FIPS byte order."""

    expanded = bytearray(_fixed_bytes(key, size=KEY_BYTES, name="AES-128 key"))
    rcon_index = 0
    while len(expanded) < (ROUNDS + 1) * BLOCK_BYTES:
        word = list(expanded[-4:])
        if len(expanded) % KEY_BYTES == 0:
            word = [SBOX[word[1]], SBOX[word[2]], SBOX[word[3]], SBOX[word[0]]]
            word[0] ^= RCON[rcon_index]
            rcon_index += 1
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


def encrypt_block(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt one standard 128-bit block with all ten AES-128 rounds."""

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


def encrypt_blocks(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt a non-empty integral number of independent AES blocks."""

    raw = bytes(plaintext)
    if not raw or len(raw) % BLOCK_BYTES:
        raise ValueError("AES plaintext must contain a non-empty whole number of blocks")
    return b"".join(
        encrypt_block(key, raw[offset : offset + BLOCK_BYTES])
        for offset in range(0, len(raw), BLOCK_BYTES)
    )


def key_words_big_endian(key: bytes) -> tuple[int, int, int, int]:
    """Split an external AES key into its four FIPS-order 32-bit words."""

    raw = _fixed_bytes(key, size=KEY_BYTES, name="AES-128 key")
    return tuple(int.from_bytes(raw[index : index + 4], "big") for index in range(0, 16, 4))  # type: ignore[return-value]


def residual_mask(width: int) -> int:
    if width < 0 or width > 128:
        raise ValueError("AES residual width must be in 0...128")
    return (1 << width) - 1 if width else 0


def zero_low_residual_bits(key: bytes, width: int) -> bytes:
    """Clear the contiguous low ``width`` bits of a FIPS-order AES key."""

    raw = _fixed_bytes(key, size=KEY_BYTES, name="AES-128 key")
    value = int.from_bytes(raw, "big") & ~residual_mask(width)
    return value.to_bytes(KEY_BYTES, "big")


def apply_low_residual_bits(known_key: bytes, assignment: int, width: int) -> bytes:
    """Materialize the key for one contiguous-low-bit residual assignment."""

    raw = _fixed_bytes(known_key, size=KEY_BYTES, name="known AES-128 key")
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
