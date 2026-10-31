import pytest

from keepassxc_falkon.webauthn import attested_auth_data, b64url, cbor_loads, unb64url


def test_b64url_roundtrip_without_padding():
    for data in (b"", b"a", b"ab", b"abc", bytes(range(256))):
        text = b64url(data)
        assert "=" not in text
        assert "+" not in text
        assert "/" not in text
        assert unb64url(text) == data


def test_cbor_basic_items():
    assert cbor_loads(bytes([0x17])) == 23
    assert cbor_loads(bytes([0x18, 0xFF])) == 255
    assert cbor_loads(bytes([0x19, 0x01, 0x00])) == 256
    assert cbor_loads(bytes([0x26])) == -7  # COSE ES256
    assert cbor_loads(bytes([0x39, 0x01, 0x00])) == -257  # COSE RS256
    assert cbor_loads(bytes([0x43, 1, 2, 3])) == b"\x01\x02\x03"
    assert cbor_loads(bytes([0x64]) + b"none") == "none"
    assert cbor_loads(bytes([0x82, 0x01, 0xF5])) == [1, True]
    assert cbor_loads(bytes([0xA0])) == {}


def test_attestation_object_auth_data():
    auth_data = bytes(range(40))
    # {"fmt": "none", "attStmt": {}, "authData": h'00..27'}
    blob = (
        bytes([0xA3, 0x63])
        + b"fmt"
        + bytes([0x64])
        + b"none"
        + bytes([0x67])
        + b"attStmt"
        + bytes([0xA0])
        + bytes([0x68])
        + b"authData"
        + bytes([0x58, len(auth_data)])
        + auth_data
    )
    assert attested_auth_data(blob) == auth_data


@pytest.mark.parametrize("blob", [b"", bytes([0x58, 5, 1]), bytes([0xA1, 0x61]) + b"x", bytes([0x01, 0x02])])
def test_cbor_rejects_truncated_or_trailing(blob):
    with pytest.raises((ValueError, IndexError)):
        cbor_loads(blob)
