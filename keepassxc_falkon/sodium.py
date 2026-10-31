"""The slice of libsodium the KeePassXC browser protocol needs.

KeePassXC encrypts every browser message with NaCl's ``crypto_box``
(X25519 + XSalsa20-Poly1305). PyNaCl isn't a given on the system Python
Falkon embeds, but libsodium itself is (it's tiny and ubiquitous), so we
bind the four calls we need with ctypes rather than add a dependency.
"""

import ctypes
import ctypes.util

PUBLICKEYBYTES = 32
SECRETKEYBYTES = 32
NONCEBYTES = 24
MACBYTES = 16


class CryptoError(Exception):
    pass


def _load() -> ctypes.CDLL:
    name = ctypes.util.find_library("sodium")
    for candidate in filter(None, (name, "libsodium.so.26", "libsodium.so.23", "libsodium.so")):
        try:
            lib = ctypes.CDLL(candidate)
        except OSError:
            continue
        if lib.sodium_init() < 0:
            raise CryptoError("libsodium failed to initialise")
        return lib
    raise CryptoError("libsodium not found (install libsodium)")


_lib = _load()

_lib.crypto_box_keypair.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
_lib.crypto_box_easy.argtypes = (
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulonglong,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
)
_lib.crypto_box_open_easy.argtypes = _lib.crypto_box_easy.argtypes


def keypair() -> tuple[bytes, bytes]:
    """A fresh X25519 key pair as ``(public, secret)`` bytes."""
    pk = ctypes.create_string_buffer(PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(SECRETKEYBYTES)
    _lib.crypto_box_keypair(pk, sk)
    return pk.raw, sk.raw


def increment_nonce(nonce: bytes) -> bytes:
    """``sodium_increment``: the nonce as a little-endian counter, plus one.
    KeePassXC answers every request with the request's nonce incremented."""
    n = (int.from_bytes(nonce, "little") + 1) % (1 << (8 * len(nonce)))
    return n.to_bytes(len(nonce), "little")


class Box:
    """``crypto_box`` between our secret key and the peer's public key."""

    def __init__(self, secret_key: bytes, peer_public_key: bytes) -> None:
        if len(secret_key) != SECRETKEYBYTES or len(peer_public_key) != PUBLICKEYBYTES:
            raise CryptoError("bad key length")
        self._sk = secret_key
        self._pk = peer_public_key

    def encrypt(self, plaintext: bytes, nonce: bytes) -> bytes:
        if len(nonce) != NONCEBYTES:
            raise CryptoError("bad nonce length")
        out = ctypes.create_string_buffer(len(plaintext) + MACBYTES)
        if _lib.crypto_box_easy(out, plaintext, len(plaintext), nonce, self._pk, self._sk) != 0:
            raise CryptoError("encryption failed")
        return out.raw

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        if len(nonce) != NONCEBYTES or len(ciphertext) < MACBYTES:
            raise CryptoError("bad nonce or ciphertext length")
        out = ctypes.create_string_buffer(len(ciphertext) - MACBYTES)
        if _lib.crypto_box_open_easy(out, ciphertext, len(ciphertext), nonce, self._pk, self._sk) != 0:
            raise CryptoError("message authentication failed")
        return out.raw
