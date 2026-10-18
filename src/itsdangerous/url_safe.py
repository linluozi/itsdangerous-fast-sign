from __future__ import annotations

import typing as t
import zlib

from ._json import _CompactJSON
from .encoding import base64_decode
from .encoding import base64_encode
from .exc import BadPayload
from .serializer import _PDataSerializer
from .serializer import Serializer
from .timed import TimedSerializer

try:
    from ._ablation import ZLIB_GATE as _ZLIB_GATE
except ImportError:  # normal build: every optimisation is on
    _ZLIB_GATE = True

# A zlib stream spends 2 header bytes, 4 bytes of Adler-32 and at least one
# final empty block on top of the deflate data, so for a short input the output
# is always longer than the input.  ``dump_payload`` additionally requires
# ``len(compressed) < len(json) - 1`` because of the ``.`` marker that flags a
# compressed payload.
#
# The smallest payload for which that test can ever succeed is 13 bytes: at 12
# bytes even the most compressible input (a run of identical bytes, which
# deflate encodes as a single length/distance pair) only breaks even.  That was
# measured over every byte string up to 3 bytes, every 1-byte mutation of every
# length up to 20, and millions of random and low-entropy samples
# (``bench/measure_gate.py``).  Below that length the compression attempt is
# skipped: it cannot change a single byte of the token, it can only waste a
# deflate initialisation.
_ZLIB_MIN_PROFITABLE = 13


class URLSafeSerializerMixin(Serializer[str]):
    """Mixed in with a regular serializer it will attempt to zlib
    compress the string to make it shorter if necessary. It will also
    base64 encode the string so that it can safely be placed in a URL.
    """

    default_serializer: _PDataSerializer[str] = _CompactJSON

    def load_payload(
        self,
        payload: bytes,
        *args: t.Any,
        serializer: t.Any | None = None,
        **kwargs: t.Any,
    ) -> t.Any:
        decompress = False

        if payload.startswith(b"."):
            payload = payload[1:]
            decompress = True

        try:
            json = base64_decode(payload)
        except Exception as e:
            raise BadPayload(
                "Could not base64 decode the payload because of an exception",
                original_error=e,
            ) from e

        if decompress:
            try:
                json = zlib.decompress(json)
            except Exception as e:
                raise BadPayload(
                    "Could not zlib decompress the payload before decoding the payload",
                    original_error=e,
                ) from e

        return super().load_payload(json, *args, **kwargs)

    def dump_payload(self, obj: t.Any) -> bytes:
        json = super().dump_payload(obj)
        is_compressed = False

        # Compressing a few dozen bytes spends ~half of the whole dump() call
        # on a deflate window that can never pay for itself, so the check for
        # "is there anything to gain" is done before compressing rather than
        # after.  ``len(zlib.compress(x)) >= len(x)`` holds for every input
        # below ``_ZLIB_MIN_PROFITABLE`` bytes, so the produced token is
        # identical to the unconditional implementation.
        if len(json) >= _ZLIB_MIN_PROFITABLE or not _ZLIB_GATE:
            compressed = zlib.compress(json)

            if len(compressed) < (len(json) - 1):
                json = compressed
                is_compressed = True

        base64d = base64_encode(json)

        if is_compressed:
            base64d = b"." + base64d

        return base64d


class URLSafeSerializer(URLSafeSerializerMixin, Serializer[str]):
    """Works like :class:`.Serializer` but dumps and loads into a URL
    safe string consisting of the upper and lowercase character of the
    alphabet as well as ``'_'``, ``'-'`` and ``'.'``.
    """


class URLSafeTimedSerializer(URLSafeSerializerMixin, TimedSerializer[str]):
    """Works like :class:`.TimedSerializer` but dumps and loads into a
    URL safe string consisting of the upper and lowercase character of
    the alphabet as well as ``'_'``, ``'-'`` and ``'.'``.
    """
