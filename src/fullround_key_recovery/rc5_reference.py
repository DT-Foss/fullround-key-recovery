"""Exact scalar reference for RC5-32/12/16 (RFC 2040 byte conventions)."""

from __future__ import annotations

from collections.abc import Sequence

WORD_BITS = 32
WORD_BYTES = 4
KEY_BYTES = 16
KEY_WORDS = KEY_BYTES // WORD_BYTES
ROUNDS = 12
SUBKEY_WORDS = 2 * (ROUNDS + 1)
MASK32 = 0xFFFFFFFF
P32 = 0xB7E15163
Q32 = 0x9E3779B9

RIVEST_RC5_32_12_16_KATS = (
    {
        "key_hex": "00000000000000000000000000000000",
        "plaintext_hex": "0000000000000000",
        "ciphertext_hex": "21a5dbee154b8f6d",
    },
    {
        "key_hex": "915f4619be41b2516355a50110a9ce91",
        "plaintext_hex": "21a5dbee154b8f6d",
        "ciphertext_hex": "f7c013ac5b2b8952",
    },
    {
        "key_hex": "783348e75aeb0f2fd7b169bb8dc16787",
        "plaintext_hex": "f7c013ac5b2b8952",
        "ciphertext_hex": "2f42b3b70369fc92",
    },
    {
        "key_hex": "dc49db1375a5584f6485b413b5f12baf",
        "plaintext_hex": "2f42b3b70369fc92",
        "ciphertext_hex": "65c178b284d197cc",
    },
    {
        "key_hex": "5269f149d41ba0152497574d7f153125",
        "plaintext_hex": "65c178b284d197cc",
        "ciphertext_hex": "eb44e415da319824",
    },
)

# RFC 2040 section 9 publishes this case as CBC.  For its first block,
# P xor IV = 1122334455667788, so the row below is the exact raw-block R12
# encryption relation under the RFC byte conventions.
RFC2040_DERIVED_R12_VECTOR = {
    "key_hex": "01020304050607081020304050607080",
    "plaintext_xor_iv_hex": "1122334455667788",
    "ciphertext_hex": "294ddb46b3278d60",
}


def rol32(value: int, rotation: int) -> int:
    rotation &= 31
    value &= MASK32
    if rotation == 0:
        return value
    return ((value << rotation) | (value >> (32 - rotation))) & MASK32


def ror32(value: int, rotation: int) -> int:
    rotation &= 31
    value &= MASK32
    if rotation == 0:
        return value
    return ((value >> rotation) | (value << (32 - rotation))) & MASK32


def key_bytes_to_words(key: bytes) -> list[int]:
    if len(key) != KEY_BYTES:
        raise ValueError("RC5-32/12/16 requires exactly 16 key bytes")
    return [
        int.from_bytes(key[offset : offset + WORD_BYTES], "little")
        for offset in range(0, KEY_BYTES, WORD_BYTES)
    ]


def expand_key_words(key_words: Sequence[int]) -> list[int]:
    if len(key_words) != KEY_WORDS:
        raise ValueError("RC5-32/12/16 requires exactly four key words")
    key_state = []
    for word in key_words:
        if int(word) < 0 or int(word) > MASK32:
            raise ValueError("RC5 key words must fit in uint32")
        key_state.append(int(word))

    subkeys = [P32]
    for _ in range(1, SUBKEY_WORDS):
        subkeys.append((subkeys[-1] + Q32) & MASK32)

    index_s = index_l = accumulator_a = accumulator_b = 0
    for _ in range(3 * max(SUBKEY_WORDS, KEY_WORDS)):
        accumulator_a = subkeys[index_s] = rol32(
            subkeys[index_s] + accumulator_a + accumulator_b, 3
        )
        accumulator_b = key_state[index_l] = rol32(
            key_state[index_l] + accumulator_a + accumulator_b,
            accumulator_a + accumulator_b,
        )
        index_s = (index_s + 1) % SUBKEY_WORDS
        index_l = (index_l + 1) % KEY_WORDS
    return subkeys


def expand_key(key: bytes) -> list[int]:
    return expand_key_words(key_bytes_to_words(key))


def encrypt_words(
    plaintext_a: int, plaintext_b: int, subkeys: Sequence[int]
) -> tuple[int, int]:
    if len(subkeys) != SUBKEY_WORDS:
        raise ValueError(f"RC5-32/12/16 requires {SUBKEY_WORDS} subkeys")
    value_a = (int(plaintext_a) + int(subkeys[0])) & MASK32
    value_b = (int(plaintext_b) + int(subkeys[1])) & MASK32
    for round_index in range(1, ROUNDS + 1):
        value_a = (
            rol32(value_a ^ value_b, value_b) + int(subkeys[2 * round_index])
        ) & MASK32
        value_b = (
            rol32(value_b ^ value_a, value_a)
            + int(subkeys[2 * round_index + 1])
        ) & MASK32
    return value_a, value_b


def decrypt_words(
    ciphertext_a: int, ciphertext_b: int, subkeys: Sequence[int]
) -> tuple[int, int]:
    if len(subkeys) != SUBKEY_WORDS:
        raise ValueError(f"RC5-32/12/16 requires {SUBKEY_WORDS} subkeys")
    value_a = int(ciphertext_a) & MASK32
    value_b = int(ciphertext_b) & MASK32
    for round_index in range(ROUNDS, 0, -1):
        value_b = ror32(
            value_b - int(subkeys[2 * round_index + 1]), value_a
        ) ^ value_a
        value_a = ror32(
            value_a - int(subkeys[2 * round_index]), value_b
        ) ^ value_b
    value_b = (value_b - int(subkeys[1])) & MASK32
    value_a = (value_a - int(subkeys[0])) & MASK32
    return value_a, value_b


def encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    if len(plaintext) != 8:
        raise ValueError("RC5-32/12/16 plaintext blocks contain exactly 8 bytes")
    word_a = int.from_bytes(plaintext[:4], "little")
    word_b = int.from_bytes(plaintext[4:], "little")
    encrypted_a, encrypted_b = encrypt_words(word_a, word_b, expand_key(key))
    return encrypted_a.to_bytes(4, "little") + encrypted_b.to_bytes(4, "little")


def verify_rivest_kats() -> list[dict[str, object]]:
    rows = []
    for vector in RIVEST_RC5_32_12_16_KATS:
        actual = encrypt_block(
            bytes.fromhex(vector["plaintext_hex"]),
            bytes.fromhex(vector["key_hex"]),
        ).hex()
        rows.append(
            {
                **vector,
                "actual_ciphertext_hex": actual,
                "pass": actual == vector["ciphertext_hex"],
            }
        )
    return rows


def verify_rfc2040_derived_r12() -> dict[str, object]:
    vector = RFC2040_DERIVED_R12_VECTOR
    actual = encrypt_block(
        bytes.fromhex(vector["plaintext_xor_iv_hex"]),
        bytes.fromhex(vector["key_hex"]),
    ).hex()
    return {
        **vector,
        "actual_ciphertext_hex": actual,
        "pass": actual == vector["ciphertext_hex"],
    }
