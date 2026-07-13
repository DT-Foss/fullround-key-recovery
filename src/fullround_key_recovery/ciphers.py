"""Small independent reference implementations for retained confirmations."""

from __future__ import annotations

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
CHACHA_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
THREEFISH_C240 = 0x1BD11BDAA9FC1A22
THREEFISH256_ROTATIONS = (
    (14, 16),
    (52, 57),
    (23, 40),
    (5, 37),
    (25, 33),
    (46, 12),
    (58, 22),
    (32, 32),
)


def _rol(value: int, amount: int, width: int) -> int:
    mask = (1 << width) - 1
    amount %= width
    return ((value << amount) | (value >> (width - amount))) & mask


def _ror(value: int, amount: int, width: int) -> int:
    mask = (1 << width) - 1
    amount %= width
    return ((value >> amount) | (value << (width - amount))) & mask


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rol(state[d] ^ state[a], 16, 32)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rol(state[b] ^ state[c], 12, 32)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rol(state[d] ^ state[a], 8, 32)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rol(state[b] ^ state[c], 7, 32)


def chacha20_block(key_words: list[int], counter: int, nonce_words: list[int]) -> list[int]:
    """Return the standard 20-round ChaCha20 block as sixteen uint32 words."""
    if len(key_words) != 8 or len(nonce_words) != 3:
        raise ValueError("ChaCha20 expects eight key words and three nonce words")
    initial = [*CHACHA_CONSTANTS, *key_words, counter, *nonce_words]
    if any(word < 0 or word > MASK32 for word in initial):
        raise ValueError("ChaCha20 words must fit in uint32")
    state = list(initial)
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    return [(word + initial[index]) & MASK32 for index, word in enumerate(state)]


def speck32_64_round_keys(master_key: list[int]) -> list[int]:
    """Expand a paper-order ``[K0, K1, K2, K3]`` Speck32/64 key."""
    if len(master_key) != 4 or any(word < 0 or word > 0xFFFF for word in master_key):
        raise ValueError("Speck32/64 expects four uint16 key words")
    keys = [master_key[0]]
    l_words = list(master_key[1:])
    for index in range(21):
        new_l = ((_ror(l_words[index], 7, 16) + keys[index]) & 0xFFFF) ^ index
        l_words.append(new_l)
        keys.append(_rol(keys[index], 2, 16) ^ new_l)
    return keys


def speck32_64_encrypt(x: int, y: int, master_key: list[int]) -> tuple[int, int]:
    """Encrypt one block with all 22 rounds of Speck32/64."""
    if x < 0 or x > 0xFFFF or y < 0 or y > 0xFFFF:
        raise ValueError("Speck32/64 block words must fit in uint16")
    for round_key in speck32_64_round_keys(master_key):
        x = ((_ror(x, 7, 16) + y) & 0xFFFF) ^ round_key
        y = _rol(y, 2, 16) ^ x
    return x, y


def threefish256_encrypt(
    plaintext: list[int], key: list[int], tweak: list[int], rounds: int = 72
) -> list[int]:
    """Encrypt one raw Threefish-256 block, including all subkey injections."""
    if len(plaintext) != 4 or len(key) != 4 or len(tweak) != 2:
        raise ValueError("Threefish-256 expects 4 plaintext/key and 2 tweak words")
    if rounds < 1:
        raise ValueError("rounds must be positive")
    if any(word < 0 or word > MASK64 for word in [*plaintext, *key, *tweak]):
        raise ValueError("Threefish-256 words must fit in uint64")

    key_schedule = list(key)
    parity = THREEFISH_C240
    for word in key:
        parity ^= word
    key_schedule.append(parity)
    tweak_schedule = [tweak[0], tweak[1], tweak[0] ^ tweak[1]]
    state = list(plaintext)
    state[0] = (state[0] + key_schedule[0]) & MASK64
    state[1] = (state[1] + key_schedule[1] + tweak_schedule[0]) & MASK64
    state[2] = (state[2] + key_schedule[2] + tweak_schedule[1]) & MASK64
    state[3] = (state[3] + key_schedule[3]) & MASK64

    for round_index in range(rounds):
        rotation_a, rotation_b = THREEFISH256_ROTATIONS[round_index % 8]
        state[0] = (state[0] + state[1]) & MASK64
        state[1] = _rol(state[1], rotation_a, 64) ^ state[0]
        state[2] = (state[2] + state[3]) & MASK64
        state[3] = _rol(state[3], rotation_b, 64) ^ state[2]
        state[1], state[3] = state[3], state[1]
        if (round_index + 1) % 4 == 0:
            subkey = (round_index + 1) // 4
            state[0] = (state[0] + key_schedule[subkey % 5]) & MASK64
            state[1] = (
                state[1]
                + key_schedule[(subkey + 1) % 5]
                + tweak_schedule[subkey % 3]
            ) & MASK64
            state[2] = (
                state[2]
                + key_schedule[(subkey + 2) % 5]
                + tweak_schedule[(subkey + 1) % 3]
            ) & MASK64
            state[3] = (
                state[3] + key_schedule[(subkey + 3) % 5] + subkey
            ) & MASK64
    return state
