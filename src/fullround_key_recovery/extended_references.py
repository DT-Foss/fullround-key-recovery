"""Small independent references for the extended full-round recovery ledger."""

from __future__ import annotations

from collections.abc import Sequence

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


def apply_low_residual_words(
    known_words: Sequence[int], assignment: int, width: int
) -> list[int]:
    """Restore a contiguous little-endian residual interval into key words."""
    if not 0 <= assignment < 1 << width:
        raise ValueError("assignment is outside the residual domain")
    output = [int(word) for word in known_words]
    remaining = assignment
    bits = width
    index = 0
    while bits:
        take = min(32, bits)
        mask = (1 << take) - 1
        if output[index] & mask:
            raise ValueError("known key does not zero the residual interval")
        output[index] |= remaining & mask
        remaining >>= take
        bits -= take
        index += 1
    return output


_BLAKE3_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
_BLAKE3_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
_BLAKE3_KEYED_ROOT_FLAGS = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 4)


def _ror32(value: int, shift: int) -> int:
    return ((value >> shift) | (value << (32 - shift))) & MASK32


def _blake3_g(
    state: list[int], a: int, b: int, c: int, d: int, message_x: int, message_y: int
) -> None:
    state[a] = (state[a] + state[b] + message_x) & MASK32
    state[d] = _ror32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _ror32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + message_y) & MASK32
    state[d] = _ror32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _ror32(state[b] ^ state[c], 7)


def _blake3_round(state: list[int], message: Sequence[int]) -> None:
    _blake3_g(state, 0, 4, 8, 12, message[0], message[1])
    _blake3_g(state, 1, 5, 9, 13, message[2], message[3])
    _blake3_g(state, 2, 6, 10, 14, message[4], message[5])
    _blake3_g(state, 3, 7, 11, 15, message[6], message[7])
    _blake3_g(state, 0, 5, 10, 15, message[8], message[9])
    _blake3_g(state, 1, 6, 11, 12, message[10], message[11])
    _blake3_g(state, 2, 7, 8, 13, message[12], message[13])
    _blake3_g(state, 3, 4, 9, 14, message[14], message[15])


def blake3_keyed_root(key: bytes, message: bytes) -> bytes:
    """Return the first 256 keyed-root bits for one BLAKE3 message block."""
    if len(key) != 32 or len(message) > 64:
        raise ValueError("reference accepts a 32-byte key and one message block")
    cv = [int.from_bytes(key[offset : offset + 4], "little") for offset in range(0, 32, 4)]
    block = message + b"\0" * (64 - len(message))
    schedule = [
        int.from_bytes(block[offset : offset + 4], "little") for offset in range(0, 64, 4)
    ]
    state = cv + list(_BLAKE3_IV[:4]) + [0, 0, len(message), _BLAKE3_KEYED_ROOT_FLAGS]
    for round_index in range(7):
        _blake3_round(state, schedule)
        if round_index != 6:
            schedule = [schedule[index] for index in _BLAKE3_PERMUTATION]
    return b"".join(
        (state[index] ^ state[index + 8]).to_bytes(4, "little") for index in range(8)
    )


def _rotl64(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & MASK64


def _sipround(state: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    value0, value1, value2, value3 = state
    value0 = (value0 + value1) & MASK64
    value1 = _rotl64(value1, 13) ^ value0
    value0 = _rotl64(value0, 32)
    value2 = (value2 + value3) & MASK64
    value3 = _rotl64(value3, 16) ^ value2
    value0 = (value0 + value3) & MASK64
    value3 = _rotl64(value3, 21) ^ value0
    value2 = (value2 + value1) & MASK64
    value1 = _rotl64(value1, 17) ^ value2
    value2 = _rotl64(value2, 32)
    return value0, value1, value2, value3


def siphash24(key: bytes, data: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("SipHash-2-4 requires a 16-byte key")
    key0 = int.from_bytes(key[:8], "little")
    key1 = int.from_bytes(key[8:], "little")
    state = (
        key0 ^ 0x736F6D6570736575,
        key1 ^ 0x646F72616E646F6D,
        key0 ^ 0x6C7967656E657261,
        key1 ^ 0x7465646279746573,
    )
    end = len(data) - len(data) % 8
    for offset in range(0, end, 8):
        message = int.from_bytes(data[offset : offset + 8], "little")
        state = (*state[:3], state[3] ^ message)
        state = _sipround(_sipround(state))
        state = (state[0] ^ message, *state[1:])
    last = (len(data) & 0xFF) << 56
    for index, byte in enumerate(data[end:]):
        last |= byte << (8 * index)
    state = (*state[:3], state[3] ^ last)
    state = _sipround(_sipround(state))
    state = (state[0] ^ last, state[1], state[2] ^ 0xFF, state[3])
    for _ in range(4):
        state = _sipround(state)
    return (state[0] ^ state[1] ^ state[2] ^ state[3]).to_bytes(8, "little")


def tea_encrypt(plaintext: Sequence[int], key: Sequence[int]) -> tuple[int, int]:
    if len(plaintext) != 2 or len(key) != 4:
        raise ValueError("TEA requires two plaintext words and four key words")
    value0, value1 = (int(word) & MASK32 for word in plaintext)
    key0, key1, key2, key3 = (int(word) & MASK32 for word in key)
    running_sum = 0
    for _ in range(32):
        running_sum = (running_sum + 0x9E3779B9) & MASK32
        value0 = (
            value0
            + (((value1 << 4) + key0) ^ (value1 + running_sum) ^ ((value1 >> 5) + key1))
        ) & MASK32
        value1 = (
            value1
            + (((value0 << 4) + key2) ^ (value0 + running_sum) ^ ((value0 >> 5) + key3))
        ) & MASK32
    return value0, value1


def xtea_encrypt(plaintext: Sequence[int], key: Sequence[int]) -> tuple[int, int]:
    if len(plaintext) != 2 or len(key) != 4:
        raise ValueError("XTEA requires two plaintext words and four key words")
    value0, value1 = (int(word) & MASK32 for word in plaintext)
    keys = tuple(int(word) & MASK32 for word in key)
    running_sum = 0
    for _ in range(32):
        value0 = (
            value0
            + (
                (((value1 << 4) ^ (value1 >> 5)) + value1)
                ^ (running_sum + keys[running_sum & 3])
            )
        ) & MASK32
        running_sum = (running_sum + 0x9E3779B9) & MASK32
        value1 = (
            value1
            + (
                (((value0 << 4) ^ (value0 >> 5)) + value0)
                ^ (running_sum + keys[(running_sum >> 11) & 3])
            )
        ) & MASK32
    return value0, value1


_THREEFISH1024_C240 = 0x1BD11BDAA9FC1A22
_THREEFISH1024_ROTATIONS = (
    (24, 13, 8, 47, 8, 17, 22, 37),
    (38, 19, 10, 55, 49, 18, 23, 52),
    (33, 4, 51, 13, 34, 41, 59, 17),
    (5, 20, 48, 41, 47, 28, 16, 25),
    (41, 9, 37, 31, 12, 47, 44, 30),
    (16, 34, 56, 51, 4, 53, 42, 41),
    (31, 44, 47, 46, 19, 42, 44, 25),
    (9, 48, 35, 52, 23, 31, 37, 20),
)
_THREEFISH1024_PERMUTATION = (0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1)


def threefish1024_encrypt(
    plaintext: Sequence[int], key: Sequence[int], tweak: Sequence[int]
) -> list[int]:
    """Independent Skein 1.3 Threefish-1024 transcription, including final subkey."""
    if len(plaintext) != 16 or len(key) != 16 or len(tweak) != 2:
        raise ValueError("Threefish-1024 requires 16 words and a two-word tweak")
    schedule = [int(value) & MASK64 for value in key]
    parity = _THREEFISH1024_C240
    for value in schedule:
        parity ^= value
    schedule.append(parity)
    tweaks = [int(tweak[0]) & MASK64, int(tweak[1]) & MASK64]
    tweaks.append(tweaks[0] ^ tweaks[1])

    def subkey(index: int) -> list[int]:
        row = [schedule[(index + word) % 17] for word in range(16)]
        row[13] = (row[13] + tweaks[index % 3]) & MASK64
        row[14] = (row[14] + tweaks[(index + 1) % 3]) & MASK64
        row[15] = (row[15] + index) & MASK64
        return row

    state = [int(value) & MASK64 for value in plaintext]
    for round_index in range(80):
        if round_index % 4 == 0:
            row = subkey(round_index // 4)
            state = [(value + row[index]) & MASK64 for index, value in enumerate(state)]
        mixed = [0] * 16
        for pair, rotation in enumerate(_THREEFISH1024_ROTATIONS[round_index % 8]):
            left_index = 2 * pair
            right_index = left_index + 1
            left = (state[left_index] + state[right_index]) & MASK64
            right = _rotl64(state[right_index], rotation) ^ left
            mixed[left_index] = left
            mixed[right_index] = right
        state = [mixed[index] for index in _THREEFISH1024_PERMUTATION]
    final = subkey(20)
    return [(value + final[index]) & MASK64 for index, value in enumerate(state)]
