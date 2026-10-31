import os
import stat

import pytest

from keepassxc_falkon import sodium
from keepassxc_falkon.store import Store


def test_box_roundtrip_both_directions():
    a_pk, a_sk = sodium.keypair()
    b_pk, b_sk = sodium.keypair()
    nonce = os.urandom(sodium.NONCEBYTES)
    ct = sodium.Box(a_sk, b_pk).encrypt(b"hello", nonce)
    assert len(ct) == 5 + sodium.MACBYTES
    assert sodium.Box(b_sk, a_pk).decrypt(ct, nonce) == b"hello"


def test_box_rejects_tampering():
    a_pk, a_sk = sodium.keypair()
    b_pk, b_sk = sodium.keypair()
    nonce = os.urandom(sodium.NONCEBYTES)
    ct = bytearray(sodium.Box(a_sk, b_pk).encrypt(b"hello", nonce))
    ct[-1] ^= 1
    with pytest.raises(sodium.CryptoError):
        sodium.Box(b_sk, a_pk).decrypt(bytes(ct), nonce)


def test_increment_nonce_is_little_endian_and_wraps():
    assert sodium.increment_nonce(b"\x00" * 24) == b"\x01" + b"\x00" * 23
    assert sodium.increment_nonce(b"\xff" + b"\x00" * 23) == b"\x00\x01" + b"\x00" * 22
    assert sodium.increment_nonce(b"\xff" * 24) == b"\x00" * 24


def test_store_roundtrip_and_permissions(tmp_path):
    path = tmp_path / "sub" / "keepassxc.json"
    s = Store(str(path))
    s.set_association("hash1", "falkon", "KEY")
    s.set_option("unlock_on_login_form", False)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    again = Store(str(path))
    assert again.association("hash1") == {"id": "falkon", "key": "KEY"}
    assert again.option("unlock_on_login_form") is False
    assert again.option("fill_first_of_many") is False
    again.remove_association("hash1")
    assert Store(str(path)).associations() == {}


def test_store_ignores_garbage(tmp_path):
    path = tmp_path / "keepassxc.json"
    path.write_text("{not json")
    assert Store(str(path)).associations() == {}
