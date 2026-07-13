from __future__ import annotations

from fullround_key_recovery.ciphers import (
    chacha20_block,
    speck32_64_encrypt,
    threefish256_encrypt,
)


def test_chacha20_rfc_block_vector() -> None:
    key_bytes = bytes(range(32))
    key = [int.from_bytes(key_bytes[offset : offset + 4], "little") for offset in range(0, 32, 4)]
    nonce_bytes = bytes.fromhex("000000090000004a00000000")
    nonce = [
        int.from_bytes(nonce_bytes[offset : offset + 4], "little")
        for offset in range(0, 12, 4)
    ]
    output = b"".join(word.to_bytes(4, "little") for word in chacha20_block(key, 1, nonce))
    assert output.hex() == (
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )


def test_speck32_64_official_vector() -> None:
    assert speck32_64_encrypt(
        0x6574,
        0x694C,
        [0x0100, 0x0908, 0x1110, 0x1918],
    ) == (0xA868, 0x42F2)


def test_threefish256_zero_vector() -> None:
    assert threefish256_encrypt([0, 0, 0, 0], [0, 0, 0, 0], [0, 0]) == [
        0x94EEEA8B1F2ADA84,
        0xADF103313EAE6670,
        0x952419A1F4B16D53,
        0xD83F13E63C9F6B11,
    ]


def test_threefish256_nonzero_vector() -> None:
    assert threefish256_encrypt(
        [
            0xF8F9FAFBFCFDFEFF,
            0xF0F1F2F3F4F5F6F7,
            0xE8E9EAEBECEDEEEF,
            0xE0E1E2E3E4E5E6E7,
        ],
        [
            0x1716151413121110,
            0x1F1E1D1C1B1A1918,
            0x2726252423222120,
            0x2F2E2D2C2B2A2928,
        ],
        [0x0706050403020100, 0x0F0E0D0C0B0A0908],
    ) == [
        0xDF8FEA0EFF91D0E0,
        0xD50AD82EE69281C9,
        0x76F48D58085D869D,
        0xDF975E95B5567065,
    ]
