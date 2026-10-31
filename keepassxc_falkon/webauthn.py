"""Small WebAuthn helpers: base64url and just enough CBOR to read an
attestation object (definite-length items only, which is all they use)."""

import base64
from typing import Any


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _item(data: bytes, i: int) -> tuple[Any, int]:
    head = data[i]
    i += 1
    major, info = head >> 5, head & 0x1F
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if i + size > len(data):
            raise ValueError("truncated CBOR")
        arg = int.from_bytes(data[i:i + size], "big")
        i += size
    else:
        raise ValueError("unsupported CBOR item")
    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major in (2, 3):
        if i + arg > len(data):
            raise ValueError("truncated CBOR")
        chunk = bytes(data[i:i + arg])
        return (chunk if major == 2 else chunk.decode("utf-8")), i + arg
    if major == 4:
        items: list[Any] = []
        for _ in range(arg):
            value, i = _item(data, i)
            items.append(value)
        return items, i
    if major == 5:
        mapping: dict[Any, Any] = {}
        for _ in range(arg):
            key, i = _item(data, i)
            mapping[key], i = _item(data, i)
        return mapping, i
    if major == 6:
        return _item(data, i)           # a tag: the tagged value is what matters
    return {20: False, 21: True, 22: None}.get(arg, arg), i


def cbor_loads(data: bytes) -> Any:
    value, end = _item(data, 0)
    if end != len(data):
        raise ValueError("trailing bytes after CBOR item")
    return value


def attested_auth_data(attestation_object: bytes) -> bytes:
    """The authenticator data inside an attestation object."""
    decoded = cbor_loads(attestation_object)
    auth_data = decoded.get("authData") if isinstance(decoded, dict) else None
    if not isinstance(auth_data, bytes):
        raise TypeError("attestation object without authData")
    return auth_data
