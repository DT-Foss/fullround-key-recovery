from __future__ import annotations

from fullround_key_recovery.extended_references import (
    blake3_keyed_root,
    siphash24,
    tea_encrypt,
    threefish1024_encrypt,
    xtea_encrypt,
)


def test_blake3_official_keyed_64_byte_vector() -> None:
    key = b"whats the Elvish word for friend"
    message = bytes(index % 251 for index in range(64))
    assert blake3_keyed_root(key, message).hex() == (
        "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6"
    )


def test_siphash24_official_vectors() -> None:
    key = bytes(range(16))
    assert int.from_bytes(siphash24(key, b""), "little") == 0x726FDB47DD0E0E31
    assert int.from_bytes(siphash24(key, bytes(range(8))), "little") == 0x93F5F5799A932462


def test_tea_and_xtea_zero_vectors() -> None:
    assert tea_encrypt((0, 0), (0, 0, 0, 0)) == (0x41EA3A0A, 0x94BAA940)
    assert xtea_encrypt((0, 0), (0, 0, 0, 0)) == (0xDEE9D4D8, 0xF7131ED9)


def test_threefish1024_skein_13_zero_vector() -> None:
    assert threefish1024_encrypt([0] * 16, [0] * 16, [0, 0]) == [
        0x04B3053D0A3D5CF0,
        0x0136E0D1C7DD85F7,
        0x067B212F6EA78A5C,
        0x0DA9C10B4C54E1C6,
        0x0F4EC27394CBACF0,
        0x32437F0568EA4FD5,
        0xCFF56D1D7654B49C,
        0xA2D5FB14369B2E7B,
        0x540306B460472E0B,
        0x71C18254BCEA820D,
        0xC36B4068BEAF32C8,
        0xFA4329597A360095,
        0xC4A36C28434A5B9A,
        0xD54331444B1046CF,
        0xDF11834830B2A460,
        0x1E39E8DFE1F7EE4F,
    ]
