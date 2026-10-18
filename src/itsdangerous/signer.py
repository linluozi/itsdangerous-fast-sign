from __future__ import annotations

import collections.abc as cabc
import hashlib
import hmac
import typing as t

from .encoding import _base64_alphabet
from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadSignature

try:
    from ._ablation import CACHE_KEYS as _CACHE_KEYS
    from ._ablation import FAST_HMAC as _FAST_HMAC
except ImportError:  # normal build: every optimisation is on
    _CACHE_KEYS = True
    _FAST_HMAC = True

# ``hmac.new(key, msg, digestmod=<callable>)`` cannot use the C
# implementation shipped in ``_hashlib``: the fast path in :mod:`hmac` only
# accepts a digest *name*, and it still builds two hash objects plus an
# ``HMAC`` wrapper for every call.  HMAC's padded keys are therefore computed
# directly here (same algorithm as ``hmac.HMAC._init_old``, verified against it
# for every key length 0-299 and every supported digest) and the digest is
# taken with the plain ``hashlib`` constructor, which is the same OpenSSL call
# either way.  A digest that cannot be treated this way falls back to
# :func:`hmac.new`, so the result never changes.

#: ``bytes.translate`` tables that XOR a key with the ipad/opad byte.
_TRANS_36 = bytes(x ^ 0x36 for x in range(256))
_TRANS_5C = bytes(x ^ 0x5C for x in range(256))

#: Base class of every hash object returned by :mod:`hashlib`.
_HASH_BASE = type(hashlib.sha1())

#: Type of the :mod:`hashlib` constructors (``builtin_function_or_method``).
_HASH_CONSTRUCTOR = type(hashlib.sha1)


def _collect_digest_factories() -> list[tuple[t.Any, int]]:
    """List ``(constructor, digest_size)`` for every usable ``hashlib`` digest.

    ``shake_*`` are skipped because they have no fixed digest size.
    """
    found = []

    for name in sorted(dir(hashlib)):
        if name.startswith("_"):
            continue

        factory = getattr(hashlib, name, None)

        if not isinstance(factory, _HASH_CONSTRUCTOR):
            continue

        try:
            found.append((factory, factory().digest_size))
        except Exception:
            # shake_* have no fixed size, or the algorithm is unavailable.
            continue

    return found


#: Digest constructors, sorted by name for a deterministic probe order.
_DIGEST_FACTORIES = _collect_digest_factories()

#: Memoised result of :func:`_resolve_digest_method`, keyed by the object that
#: was passed as ``digest_method``.  ``None`` marks "not usable here".
_resolved_digests: dict[t.Any, t.Any] = {}

#: Cache of ``digest constructor -> block_size``.
_BLOCK_SIZES: dict[t.Any, int] = {}


class SigningAlgorithm:
    """Subclasses must implement :meth:`get_signature` to provide
    signature generation functionality.
    """

    def get_signature(self, key: bytes, value: bytes) -> bytes:
        """Returns the signature for the given key and value."""
        raise NotImplementedError()

    def verify_signature(self, key: bytes, value: bytes, sig: bytes) -> bool:
        """Verifies the given signature matches the expected
        signature.
        """
        return hmac.compare_digest(sig, self.get_signature(key, value))


class NoneAlgorithm(SigningAlgorithm):
    """Provides an algorithm that does not perform any signing and
    returns an empty signature.
    """

    def get_signature(self, key: bytes, value: bytes) -> bytes:
        return b""


def _lazy_sha1(string: bytes = b"") -> t.Any:
    """Don't access ``hashlib.sha1`` until runtime. FIPS builds may not include
    SHA-1, in which case the import and use as a default would fail before the
    developer can configure something else.
    """
    return hashlib.sha1(string)


def _hmac_digest(key: bytes, msg: bytes, digest_method: t.Any) -> bytes:
    """Return the raw HMAC of ``msg`` under ``key``.

    Identical to ``hmac.new(key, msg=msg, digestmod=digest_method).digest()``
    for every supported digest method, but without constructing an
    ``HMAC`` object per call.
    """
    if not _FAST_HMAC:
        return hmac.new(key, msg=msg, digestmod=digest_method).digest()

    # ``digest_method`` is usually a thin wrapper such as ``_lazy_sha1``;
    # resolve it to the digest constructor it actually returns.  Object
    # identity is stable, so the lookup is memoised.
    try:
        resolved = _resolved_digests[digest_method]
    except KeyError:
        resolved = _resolved_digests[digest_method] = _resolve_digest_method(
            digest_method
        )
    except TypeError:
        # Unhashable (e.g. a callable object with __hash__ = None).
        resolved = _resolve_digest_method(digest_method)

    inner_pad, outer_pad = _pad_key(key, resolved)

    if inner_pad is None:
        return hmac.new(key, msg=msg, digestmod=digest_method).digest()

    digest = resolved
    return digest(outer_pad + digest(inner_pad + msg).digest()).digest()


def _pad_key(key: bytes, digest: t.Any) -> tuple[bytes | None, bytes | None]:
    """Return the ipad/opad blocks for ``key``, or ``(None, None)``.

    ``None`` means the key or the digest cannot be handled here and the
    caller has to use :func:`hmac.new`.
    """
    if digest is None:
        return None, None

    if isinstance(key, bytearray):
        key = bytes(key)
    elif not isinstance(key, bytes):
        # Let ``hmac.new`` raise the error it normally raises.
        return None, None

    if not isinstance(digest, _HASH_CONSTRUCTOR):
        return None, None

    block_size = _BLOCK_SIZES.get(digest)

    if block_size is None:
        try:
            block_size = digest().block_size
        except Exception:
            return None, None

        _BLOCK_SIZES[digest] = block_size

    if not isinstance(block_size, int) or block_size < 16:
        # ``hmac`` warns and substitutes its own default in this case; do not
        # second-guess it.
        return None, None

    if len(key) > block_size:
        key = digest(key).digest()

    key = key.ljust(block_size, b"\0")
    return key.translate(_TRANS_36), key.translate(_TRANS_5C)


def _resolve_digest_method(digest_method: t.Any) -> t.Any:
    """Return the built-in digest constructor behind ``digest_method``.

    ``hashlib`` constructors are used as-is.  Anything else (like the
    ``_lazy_sha1`` wrapper used as the default) is probed with empty input and
    matched against every ``hashlib`` constructor by digest size and by the
    empty-input digest.  The result is only accepted when exactly one
    constructor produces that digest, so an ambiguous or exotic digest keeps
    using ``hmac.new``.  ``None`` means "not usable here".
    """
    if digest_method is None or isinstance(digest_method, _HASH_CONSTRUCTOR):
        return digest_method

    try:
        probe = digest_method()
    except Exception:
        return None

    if not isinstance(probe, _HASH_BASE):
        return None

    try:
        target_size = probe.digest_size
        target = probe.hexdigest()
    except Exception:
        return None

    matches = []

    for factory, size in _DIGEST_FACTORIES:
        if size != target_size:
            continue

        try:
            if factory(b"").hexdigest() == target:
                matches.append(factory)
        except Exception:
            continue

    if len(matches) != 1:
        # Ambiguous (two constructors with the same empty-input digest) or
        # unknown: keep the safe, generic path.
        return None

    return matches[0]


class HMACAlgorithm(SigningAlgorithm):
    """Provides signature generation using HMACs."""

    #: The digest method to use with the MAC algorithm. This defaults to
    #: SHA1, but can be changed to any other function in the hashlib
    #: module.
    default_digest_method: t.Any = staticmethod(_lazy_sha1)

    def __init__(self, digest_method: t.Any = None):
        if digest_method is None:
            digest_method = self.default_digest_method

        self.digest_method: t.Any = digest_method

    def get_signature(self, key: bytes, value: bytes) -> bytes:
        return _hmac_digest(key, value, self.digest_method)


def _make_keys_list(
    secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
) -> list[bytes]:
    if isinstance(secret_key, (str, bytes)):
        return [want_bytes(secret_key)]

    return [want_bytes(s) for s in secret_key]  # pyright: ignore


class Signer:
    """A signer securely signs bytes, then unsigns them to verify that
    the value hasn't been changed.

    The secret key should be a random string of ``bytes`` and should not
    be saved to code or version control. Different salts should be used
    to distinguish signing in different contexts. See :doc:`/concepts`
    for information about the security of the secret key and salt.

    :param secret_key: The secret key to sign and verify with. Can be a
        list of keys, oldest to newest, to support key rotation.
    :param salt: Extra key to combine with ``secret_key`` to distinguish
        signatures in different contexts.
    :param sep: Separator between the signature and value.
    :param key_derivation: How to derive the signing key from the secret
        key and salt. Possible values are ``concat``, ``django-concat``,
        or ``hmac``. Defaults to :attr:`default_key_derivation`, which
        defaults to ``django-concat``.
    :param digest_method: Hash function to use when generating the HMAC
        signature. Defaults to :attr:`default_digest_method`, which
        defaults to :func:`hashlib.sha1`. Note that the security of the
        hash alone doesn't apply when used intermediately in HMAC.
    :param algorithm: A :class:`SigningAlgorithm` instance to use
        instead of building a default :class:`HMACAlgorithm` with the
        ``digest_method``.

    .. versionchanged:: 2.0
        Added support for key rotation by passing a list to
        ``secret_key``.

    .. versionchanged:: 0.18
        ``algorithm`` was added as an argument to the class constructor.

    .. versionchanged:: 0.14
        ``key_derivation`` and ``digest_method`` were added as arguments
        to the class constructor.
    """

    #: The default digest method to use for the signer. The default is
    #: :func:`hashlib.sha1`, but can be changed to any :mod:`hashlib` or
    #: compatible object. Note that the security of the hash alone
    #: doesn't apply when used intermediately in HMAC.
    #:
    #: .. versionadded:: 0.14
    default_digest_method: t.Any = staticmethod(_lazy_sha1)

    #: The default scheme to use to derive the signing key from the
    #: secret key and salt. The default is ``django-concat``. Possible
    #: values are ``concat``, ``django-concat``, and ``hmac``.
    #:
    #: .. versionadded:: 0.14
    default_key_derivation: str = "django-concat"

    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        salt: str | bytes | None = b"itsdangerous.Signer",
        sep: str | bytes = b".",
        key_derivation: str | None = None,
        digest_method: t.Any | None = None,
        algorithm: SigningAlgorithm | None = None,
    ):
        #: The list of secret keys to try for verifying signatures, from
        #: oldest to newest. The newest (last) key is used for signing.
        #:
        #: This allows a key rotation system to keep a list of allowed
        #: keys and remove expired ones.
        self.secret_keys: list[bytes] = _make_keys_list(secret_key)
        self.sep: bytes = want_bytes(sep)

        if self.sep in _base64_alphabet:
            raise ValueError(
                "The given separator cannot be used because it may be"
                " contained in the signature itself. ASCII letters,"
                " digits, and '-_=' must not be used."
            )

        if salt is not None:
            salt = want_bytes(salt)
        else:
            salt = b"itsdangerous.Signer"

        self.salt = salt

        if key_derivation is None:
            key_derivation = self.default_key_derivation

        self.key_derivation: str = key_derivation

        if digest_method is None:
            digest_method = self.default_digest_method

        self.digest_method: t.Any = digest_method

        if algorithm is None:
            algorithm = HMACAlgorithm(self.digest_method)

        self.algorithm: SigningAlgorithm = algorithm

        # Cache of derived signing keys, keyed by the secret key they were
        # derived from. Key derivation is a pure function of
        # (salt, secret_key, key_derivation, digest_method); the inputs below
        # are snapshotted once so that a later in-place mutation of those
        # attributes is detected and the cache is discarded instead of
        # returning stale keys.
        self._key_cache: dict[bytes, bytes] = {}
        self._key_cache_signature: tuple[bytes | None, str, t.Any] = (
            self.salt,
            self.key_derivation,
            self.digest_method,
        )

    @property
    def secret_key(self) -> bytes:
        """The newest (last) entry in the :attr:`secret_keys` list. This
        is for compatibility from before key rotation support was added.
        """
        return self.secret_keys[-1]

    def derive_key(self, secret_key: str | bytes | None = None) -> bytes:
        """This method is called to derive the key. The default key
        derivation choices can be overridden here. Key derivation is not
        intended to be used as a security method to make a complex key
        out of a short password. Instead you should use large random
        secret keys.

        The derived key is memoised per signer instance. Derivation only
        depends on ``salt``, ``secret_key``, ``key_derivation`` and
        ``digest_method``, so repeated sign/verify calls with the same inputs
        reuse the previous result instead of hashing again.

        :param secret_key: A specific secret key to derive from.
            Defaults to the last item in :attr:`secret_keys`.

        .. versionchanged:: 2.0
            Added the ``secret_key`` parameter.
        """
        if secret_key is None:
            secret_key = self.secret_keys[-1]
        else:
            secret_key = want_bytes(secret_key)

        if not _CACHE_KEYS:
            return self._derive_key_uncached(secret_key)

        cache = self._key_cache

        if cache:
            signature = (self.salt, self.key_derivation, self.digest_method)

            if signature != self._key_cache_signature:
                # The instance was reconfigured in place; the memoised keys
                # no longer match the current parameters.
                cache.clear()
                self._key_cache_signature = signature
            else:
                key = cache.get(secret_key)

                if key is not None:
                    return key

        key = self._derive_key_uncached(secret_key)
        cache[secret_key] = key
        return key

    def _derive_key_uncached(self, secret_key: bytes) -> bytes:
        """Run the configured key derivation function once."""
        if self.key_derivation == "concat":
            return t.cast(bytes, self.digest_method(self.salt + secret_key).digest())
        elif self.key_derivation == "django-concat":
            return t.cast(
                bytes, self.digest_method(self.salt + b"signer" + secret_key).digest()
            )
        elif self.key_derivation == "hmac":
            mac = hmac.new(secret_key, digestmod=self.digest_method)
            mac.update(self.salt)
            return mac.digest()
        elif self.key_derivation == "none":
            return secret_key
        else:
            raise TypeError("Unknown key derivation method")

    def get_signature(self, value: str | bytes) -> bytes:
        """Returns the signature for the given value."""
        value = want_bytes(value)
        key = self.derive_key()
        sig = self.algorithm.get_signature(key, value)
        return base64_encode(sig)

    def sign(self, value: str | bytes) -> bytes:
        """Signs the given string."""
        value = want_bytes(value)
        return value + self.sep + self.get_signature(value)

    def verify_signature(self, value: str | bytes, sig: str | bytes) -> bool:
        """Verifies the signature for the given value."""
        try:
            sig = base64_decode(sig)
        except Exception:
            return False

        value = want_bytes(value)

        for secret_key in reversed(self.secret_keys):
            key = self.derive_key(secret_key)

            if self.algorithm.verify_signature(key, value, sig):
                return True

        return False

    def unsign(self, signed_value: str | bytes) -> bytes:
        """Unsigns the given string."""
        signed_value = want_bytes(signed_value)

        if self.sep not in signed_value:
            raise BadSignature(f"No {self.sep!r} found in value")

        value, sig = signed_value.rsplit(self.sep, 1)

        if self.verify_signature(value, sig):
            return value

        raise BadSignature(f"Signature {sig!r} does not match", payload=value)

    def validate(self, signed_value: str | bytes) -> bool:
        """Only validates the given signed value. Returns ``True`` if
        the signature exists and is valid.
        """
        try:
            self.unsign(signed_value)
            return True
        except BadSignature:
            return False
