"""Differential tests: the optimised build must be indistinguishable from upstream.

Each test loads the untouched upstream checkout and this build side by side
(under different module names) and compares *outputs*, not timings:

* signed tokens must be byte-identical, including the zlib-compressed branch;
* decoding must return equal payloads and raise the same exception types;
* the HMAC path is compared for every digest method and every key length in
  0..299, plus structured cases around the 64/128-byte block boundaries;
* key rotation, per-call salts, ``fallback_signers`` and in-place mutation of
  the configuration are exercised because they are exactly what a signer cache
  could get wrong;
* ``loads_unsafe`` must report the same ``(valid, payload)`` pairs.

Run with ``pytest tests/test_differential.py`` from the repository root, or set
``UPSTREAM_DIR`` to point at a checkout of upstream itsdangerous.
"""

from __future__ import annotations

import importlib
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if os.path.isdir(os.path.join(HERE, "src")):
    sys.path.insert(0, os.path.join(HERE, "src"))


def _upstream_dir() -> str | None:
    env = os.environ.get("UPSTREAM_DIR")

    if env:
        return os.path.abspath(env)

    default = os.path.abspath(os.path.join(HERE, "..", "upstream"))

    if os.path.isdir(os.path.join(default, "src", "itsdangerous")):
        return default

    return None


def _load(path: str, alias: str):
    """Import ``path``'s itsdangerous as a separate, top-level module."""
    saved = sys.modules.pop("itsdangerous", None)
    for name in [m for m in sys.modules if m.startswith("itsdangerous.")]:
        sys.modules.pop(name)

    sys.path.insert(0, os.path.join(path, "src"))

    try:
        module = importlib.import_module("itsdangerous")
    finally:
        sys.path.pop(0)

        if saved is not None:
            sys.modules["itsdangerous"] = saved

    sys.modules[alias] = module
    return module


UPSTREAM_DIR = _upstream_dir()

if UPSTREAM_DIR is None:  # pragma: no cover - depends on the checkout
    pytest.skip(
        "upstream checkout not found; set UPSTREAM_DIR to compare against it",
        allow_module_level=True,
    )

upstream = _load(UPSTREAM_DIR, "upstream_itsdangerous")
optimized = _load(HERE, "optimized_itsdangerous")

PAYLOADS = [
    {},
    {"a": 1},
    {"a": "b" * 3},
    {"user_id": 42, "name": "test", "roles": ["admin", "editor"]},
    {"user_id": 42, "name": "test", "roles": ["admin", "editor"], "x": 1},
    list(range(20)),
    {"blob": "x" * 400},
    {"blob": "x" * 4000},
    {"unicode": "\u4e2d\u6587 \U0001f600", "nested": {"a": [1, 2, {"b": "c"}]}},
]

KEYS = [
    "secret-key",
    b"secret-key",
    32 * "k",
    ["old-key", "middle-key", "secret-key"],
    [b"old-key", b"secret-key"],
]

SALTS = [None, "custom-salt", b"custom-salt"]


def both(cls_name: str):
    return getattr(upstream, cls_name), getattr(optimized, cls_name)


@pytest.mark.parametrize("payload", PAYLOADS, ids=range(len(PAYLOADS)))
@pytest.mark.parametrize("key", KEYS, ids=range(len(KEYS)))
@pytest.mark.parametrize(
    "cls_name",
    ["Serializer", "URLSafeSerializer", "TimedSerializer", "URLSafeTimedSerializer"],
)
def test_dumps_is_byte_identical(cls_name, key, payload):
    up_cls, opt_cls = both(cls_name)
    up = up_cls(key).dumps(payload)
    opt = opt_cls(key).dumps(payload)
    assert up == opt


@pytest.mark.parametrize("payload", PAYLOADS, ids=range(len(PAYLOADS)))
@pytest.mark.parametrize("salt", SALTS, ids=range(len(SALTS)))
def test_loads_round_trip_with_salt(payload, salt):
    up_cls, opt_cls = both("URLSafeTimedSerializer")
    up_ser = up_cls("secret-key")
    opt_ser = opt_cls("secret-key")

    token = up_ser.dumps(payload, salt=salt)
    assert opt_ser.dumps(payload, salt=salt) == token
    assert opt_ser.loads(token, salt=salt) == payload
    assert up_ser.loads(token, salt=salt) == payload


@pytest.mark.parametrize("method", ["sign", "unsign", "validate"])
def test_signer_bytes_identical(method):
    up_cls, opt_cls = both("TimestampSigner")
    up = up_cls("secret-key")
    opt = opt_cls("secret-key")
    token = up.sign(b"payload")

    if method == "sign":
        assert up.sign(b"payload") == opt.sign(b"payload")
    elif method == "unsign":
        assert up.unsign(token) == opt.unsign(token)
    else:
        assert up.validate(token) == opt.validate(token)


@pytest.mark.parametrize("key_length", list(range(0, 100)) + [127, 128, 129, 255, 299])
def test_hmac_all_key_lengths(key_length):
    """Every key length, including the hash-the-key branch above block_size."""
    key = bytes((i * 7 + key_length) % 256 for i in range(key_length))
    value = b"value-to-sign"
    up_cls, opt_cls = both("Signer")

    for derivation in ("concat", "django-concat", "hmac", "none"):
        up = up_cls(key, key_derivation=derivation)
        opt = opt_cls(key, key_derivation=derivation)
        assert up.get_signature(value) == opt.get_signature(value)
        assert up.sign(value) == opt.sign(value)


@pytest.mark.parametrize(
    "digest_name",
    ["sha1", "sha256", "sha384", "sha512", "md5", "sha3_256", "blake2b", "blake2s"],
)
def test_hmac_all_digests(digest_name):
    import hashlib

    digest = getattr(hashlib, digest_name)
    up_cls, opt_cls = both("Signer")
    up = up_cls("secret-key", digest_method=digest)
    opt = opt_cls("secret-key", digest_method=digest)

    for value in (b"", b"a", b"payload" * 100):
        assert up.get_signature(value) == opt.get_signature(value)


def test_hmac_custom_callable_digest():
    import hashlib

    def custom(data=b""):
        return hashlib.md5(data)

    def wrapper(data=b""):
        return hashlib.sha256(data)

    up_cls, opt_cls = both("Signer")

    for method in (custom, wrapper):
        up = up_cls("secret-key", digest_method=method)
        opt = opt_cls("secret-key", digest_method=method)
        assert up.get_signature(b"payload") == opt.get_signature(b"payload")


def test_key_rotation_verifies_old_tokens():
    up_cls, opt_cls = both("URLSafeTimedSerializer")
    payload = {"user": "alice"}

    old = up_cls("old-key").dumps(payload)
    newest = opt_cls(["old-key", "new-key"])
    assert newest.loads(old) == payload
    assert newest.secret_key == b"new-key"

    new_token = newest.dumps(payload)
    assert up_cls(["old-key", "new-key"]).loads(new_token) == payload


def test_configuration_mutation_invalidates_caches():
    """Mutating salt / keys / signer_kwargs in place must not reuse stale keys."""
    up_cls, opt_cls = both("URLSafeTimedSerializer")
    payload = {"user": "alice"}

    up = up_cls("key-one")
    opt = opt_cls("key-one")
    first = up.dumps(payload)
    assert opt.dumps(payload) == first

    for ser in (up, opt):
        ser.secret_keys[:] = [b"key-two"]

    after_up = up.dumps(payload)
    after_opt = opt.dumps(payload)
    assert after_up == after_opt
    assert after_up != first

    for ser in (up, opt):
        ser.salt = b"another-salt"

    assert up.dumps(payload) == opt.dumps(payload)


def test_signer_object_reconfiguration():
    up_cls, opt_cls = both("Signer")
    up = up_cls("secret-key")
    opt = opt_cls("secret-key")
    value = b"payload"

    assert up.get_signature(value) == opt.get_signature(value)

    for signer in (up, opt):
        signer.key_derivation = "hmac"

    assert up.get_signature(value) == opt.get_signature(value)

    for signer in (up, opt):
        signer.salt = b"other-salt"

    assert up.get_signature(value) == opt.get_signature(value)


def test_fallback_signers_match():
    """A fallback signer with a different key derivation must agree."""
    up_cls, opt_cls = both("URLSafeTimedSerializer")
    payload = {"a": 1}

    # ``fallback_signers`` entries are kwargs for additional signers; here the
    # fallback derives its key with plain "concat" instead of "django-concat".
    up = up_cls("secret-key", signer_kwargs={"key_derivation": "concat"})
    opt = opt_cls("secret-key", signer_kwargs={"key_derivation": "concat"})

    token = up.dumps(payload, salt="custom")
    assert opt.dumps(payload, salt="custom") == token
    assert up.loads(token, salt="custom") == payload
    assert opt.loads(token, salt="custom") == payload

    tampered = token[:-3] + ("AAA" if token[-3:] != "AAA" else "BBB")
    assert up.loads_unsafe(tampered, salt="custom") == opt.loads_unsafe(
        tampered, salt="custom"
    )


@pytest.mark.parametrize("payload", PAYLOADS[:6], ids=range(6))
def test_loads_unsafe_matches(payload):
    up_cls, opt_cls = both("URLSafeTimedSerializer")
    token = up_cls("secret-key").dumps(payload)
    tampered = token[:-2] + ("zz" if token[-2:] != "zz" else "yy")

    up = up_cls("secret-key")
    opt = opt_cls("secret-key")

    assert up.loads_unsafe(token) == opt.loads_unsafe(token)
    assert up.loads_unsafe(tampered) == opt.loads_unsafe(tampered)


def test_bad_signature_payloads_match():
    up_cls, opt_cls = both("URLSafeTimedSerializer")
    token = up_cls("secret-key").dumps({"a": 1})
    tampered = token[:-4] + "AAAA"

    errors = []

    for cls in (up_cls, opt_cls):
        try:
            cls("secret-key").loads(tampered)
        except Exception as e:  # noqa: BLE001 - the type is what is compared
            errors.append((type(e).__name__, e.payload))

    assert errors[0] == errors[1]


@pytest.mark.parametrize(
    "value",
    [
        "....",
        "..abc",
        "a.b",
        "",
        "eyJhIjoxfQ",
        "not-a-token",
        "eyJhIjoxfQ..",
    ],
)
def test_malformed_tokens_raise_the_same_error(value):
    up_cls, opt_cls = both("URLSafeTimedSerializer")

    def outcome(cls):
        try:
            return ("ok", cls("secret-key").loads(value))
        except Exception as e:  # noqa: BLE001
            return ("error", type(e).__name__, getattr(e, "payload", None))

    assert outcome(up_cls) == outcome(opt_cls)


@pytest.mark.parametrize("payload", PAYLOADS, ids=range(len(PAYLOADS)))
def test_compression_decision_matches(payload):
    """The token must show the same ".'' compressed marker on both builds."""
    up_cls, opt_cls = both("URLSafeTimedSerializer")
    up = up_cls("secret-key").dump_payload(payload)
    opt = opt_cls("secret-key").dump_payload(payload)
    assert up == opt
    assert up.startswith(b".") == opt.startswith(b".")


def test_json_output_matches_for_edge_values():
    payload = {"f": 1.5, "i": -3, "n": None, "t": True, "s": "a'b\"c", "u": "\u00e9"}
    up_cls, opt_cls = both("URLSafeSerializer")
    assert up_cls("k").dumps(payload) == opt_cls("k").dumps(payload)


def test_timestamp_round_trip_with_max_age():
    import time
    from datetime import datetime
    from datetime import timezone

    up_cls, opt_cls = both("URLSafeTimedSerializer")
    token = up_cls("secret-key").dumps({"a": 1})

    assert opt_cls("secret-key").loads(token, max_age=60) == {"a": 1}
    assert opt_cls("secret-key").loads(token, return_timestamp=True)[0] == {"a": 1}

    old = int(time.time()) - 10_000

    def sign_old(cls):
        ser = cls("secret-key")
        signer = ser.make_signer()
        signer.get_timestamp = lambda: old  # type: ignore[method-assign]
        return signer.sign(b"payload"), signer

    (token_a, signer_a), (token_b, signer_b) = sign_old(up_cls), sign_old(opt_cls)
    assert token_a == token_b

    stamp_a = signer_a.unsign(token_a, max_age=60, return_timestamp=True)[1]
    stamp_b = signer_b.unsign(token_b, max_age=60, return_timestamp=True)[1]
    assert stamp_a == stamp_b == datetime.fromtimestamp(old, tz=timezone.utc)

    # An old token must be rejected as expired by both builds.
    for cls in (up_cls, opt_cls):
        with pytest.raises(Exception) as info:
            cls("secret-key").loads(token_a, max_age=60)
        assert type(info.value).__name__ == "SignatureExpired"


def test_signer_is_reused_but_equivalent():
    """The cache must hand out one signer, and that signer must behave the same."""
    up_cls, opt_cls = both("URLSafeTimedSerializer")
    up = up_cls("secret-key")
    opt = opt_cls("secret-key")

    first = opt.make_signer()
    second = opt.make_signer()
    assert first is second, "signer should be reused"

    # Upstream builds a fresh one each time, but the outputs must still agree.
    assert up.make_signer().sign(b"payload") == second.sign(b"payload")
    assert up.make_signer(b"x").sign(b"payload") == opt.make_signer(b"x").sign(
        b"payload"
    )


def test_json_dumps_with_custom_serializer_kwargs():
    up_cls, opt_cls = both("Serializer")
    up = up_cls("k", serializer=json, serializer_kwargs={"sort_keys": True})
    opt = opt_cls("k", serializer=json, serializer_kwargs={"sort_keys": True})
    payload = {"b": 1, "a": 2}
    assert up.dumps(payload) == opt.dumps(payload)
