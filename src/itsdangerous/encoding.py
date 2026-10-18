from __future__ import annotations

import base64
import binascii
import string
import struct
import typing as t

from .exc import BadData

try:
    from ._ablation import FAST_B64 as _FAST_B64
except ImportError:  # normal build: every optimisation is on
    _FAST_B64 = True


def want_bytes(
    s: str | bytes, encoding: str = "utf-8", errors: str = "strict"
) -> bytes:
    if isinstance(s, str):
        s = s.encode(encoding, errors)

    return s


# The alphabet used by base64.urlsafe_*
_base64_alphabet = f"{string.ascii_letters}{string.digits}-_=".encode("ascii")


def base64_encode(string: str | bytes) -> bytes:
    """Base64 encode a string of bytes or text. The resulting bytes are
    safe to use in URLs.
    """
    string = want_bytes(string)
    return base64.urlsafe_b64encode(string).rstrip(b"=")


#: Decoding table for :func:`base64_decode`: every byte that is not part of
#: the URL-safe alphabet is mapped to the padding byte, which is exactly what
#: ``base64.urlsafe_b64decode`` does after discarding non-alphabet characters.
#: ``_`` and ``-`` are translated to the standard alphabet bytes and ``=`` is
#: kept, so a single ``translate`` plus ``b64decode`` replaces the generic
#: ``urlsafe_b64decode`` (which re-validates and copies its input).
_DECODE_TABLE = bytes(
    (
        ord("+")
        if i == ord("-")
        else ord("/")
        if i == ord("_")
        else i
        if i in _base64_alphabet
        else ord("=")
    )
    for i in range(256)
)


def base64_decode(string: str | bytes) -> bytes:
    """Base64 decode a URL-safe string of bytes or text. The result is
    bytes.
    """
    string = want_bytes(string, encoding="ascii", errors="ignore")
    string += b"=" * (-len(string) % 4)

    try:
        if _FAST_B64:
            return base64.b64decode(string.translate(_DECODE_TABLE), validate=False)

        return base64.urlsafe_b64decode(string)
    except (TypeError, ValueError, binascii.Error) as e:
        raise BadData("Invalid base64-encoded data") from e


_int64_struct = struct.Struct(">Q")
_int_to_bytes = _int64_struct.pack
_bytes_to_int = t.cast("t.Callable[[bytes], tuple[int]]", _int64_struct.unpack)


def int_to_bytes(num: int) -> bytes:
    return _int_to_bytes(num).lstrip(b"\x00")


def bytes_to_int(bytestr: bytes) -> int:
    return _bytes_to_int(bytestr.rjust(8, b"\x00"))[0]
