"""Proof that the ``_ZLIB_MIN_PROFITABLE`` shortcut cannot change a token.

``URLSafeSerializerMixin.dump_payload`` only calls ``zlib.compress`` when the
JSON payload can actually get smaller than ``len(json) - 1`` (the ``.``
compressed marker costs one byte).  The shortcut claims that for every payload
shorter than ``_ZLIB_MIN_PROFITABLE`` (13 bytes) compression can never win, so
skipping it cannot change a single byte of the output.

The claim is checked where a proof is cheap, and sampled where it is not:

1. exhaustively for every byte string of length 0-2 (65 793 inputs);
2. structured inputs (all zero, all 0xFF, JSON punctuation, counting bytes) and
   every single-byte value at every position of a 13-byte block;
3. random samples of every length 0-12 (2 000 each);
4. the boundary itself: the most compressible 12- and 13-byte inputs, to show
   that 12 breaks even and 13 is where a win first becomes possible;
5. end to end: 2 000 real payloads must produce identical tokens with and
   without the shortcut.

Run from the repository root: ``python bench/measure_gate.py``.
Exit code is 0 only when every check passes.
"""

from __future__ import annotations

import itertools
import os
import random
import sys
import zlib

THRESHOLD = 13

random.seed(20261018)
failures = 0


def margin(data: bytes) -> int:
    """Compressed length minus the length that would count as a win."""
    return len(zlib.compress(data)) - (len(data) - 1)


def check(data: bytes, label: str) -> None:
    global failures

    if margin(data) < 0:
        failures += 1
        print(f"  PROFITABLE below threshold ({label}): {data!r}")


print(f"zlib {zlib.ZLIB_RUNTIME_VERSION}; threshold {THRESHOLD} bytes")

# 1. exhaustive -----------------------------------------------------------------
for length in range(0, 3):
    for tup in itertools.product(range(256), repeat=length):
        check(bytes(tup), f"exhaustive {length}")
print(f"exhaustive 0-2 bytes ({sum(256**n for n in range(3)):,} inputs): done")

# 2. structured, and every byte value at every position --------------------------
for length in range(0, THRESHOLD):
    for value, name in ((0x00, "zero"), (0xFF, "0xff"), (0x61, "a")):
        check(bytes([value]) * length, f"{name}*{length}")

    check(bytes(range(length)), f"counting {length}")
    check(bytes(range(255, 255 - length, -1)), f"counting-down {length}")
    check(b'{}[]":,0123456789'[:length], f"json-punctuation {length}")

# Only lengths *below* the threshold are claimed to be safe, so the mutation
# sweep uses THRESHOLD - 1 bytes.
for pos in range(THRESHOLD - 1):
    for value in range(256):
        block = bytearray(b"q" * (THRESHOLD - 1))
        block[pos] = value
        check(bytes(block), f"mutate pos {pos} to {value}")
print(
    f"structured + 1-byte mutations at every position of a {THRESHOLD - 1}-byte "
    "block: done"
)

# 3. random samples --------------------------------------------------------------
for length in range(0, THRESHOLD):
    for _ in range(2000):
        check(random.randbytes(length), f"random {length}")
print("random samples below and at the threshold: done")

# 4. the boundary ----------------------------------------------------------------
# The most compressible input of a given length is a run of one byte; deflate
# encodes it as a single length/distance pair.  At ``THRESHOLD - 1`` this must
# still break even (margin >= 0), at ``THRESHOLD`` a win must be possible.
for fill in (0x00, 0x01, 0x61, 0xFF):
    data = bytes([fill]) * (THRESHOLD - 1)
    check(data, f"most compressible at {THRESHOLD - 1} (fill {fill:#04x})")
    if margin(data) < 0:  # pragma: no cover - reported by check() above
        failures += 1

best_at_threshold = min(margin(bytes([fill]) * THRESHOLD) for fill in range(256))
print(
    f"best margin at {THRESHOLD} bytes: {best_at_threshold} "
    "(must be < 0, i.e. compression can win exactly from this length)"
)

if best_at_threshold >= 0:
    failures += 1
    print(f"  threshold too high: no {THRESHOLD}-byte input benefits from compression")

# 5. end to end ------------------------------------------------------------------
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import itsdangerous  # noqa: E402
import itsdangerous.url_safe as url_safe  # noqa: E402

assert url_safe._ZLIB_MIN_PROFITABLE == THRESHOLD, "script and library disagree"


def token(obj, threshold):
    ser = itsdangerous.URLSafeSerializer("key")
    original = url_safe._ZLIB_MIN_PROFITABLE
    try:
        url_safe._ZLIB_MIN_PROFITABLE = threshold
        return ser.dumps(obj)
    finally:
        url_safe._ZLIB_MIN_PROFITABLE = original


payloads = [
    {},
    {"a": 1},
    {"a": "b"},
    {"user_id": 42, "name": "test", "roles": ["admin", "editor"]},
    {"sid": "9f8e7d6c5b4a39281706f5e4d3c2b1a0", "uid": 100238},
    {"blob": "x" * 4000},
    {"blob": "x" * 400},
    list(range(30)),
    "unicode \u4e2d\u6587 \U0001f600",
    {"nested": {"a": [1, 2, {"b": "c" * 50}]}},
]

for i in range(2000):
    rng = random.Random(i)
    size = rng.choice([1, 2, 3, 5, 10, 40, 120, 500, 2000])
    payloads.append({f"k{j}": rng.random() for j in range(size)})

mismatch = sum(1 for obj in payloads if token(obj, THRESHOLD) != token(obj, 0))
print(f"end-to-end tokens compared: {len(payloads)}, mismatches: {mismatch}")

total = failures + mismatch
print(
    "ALL CHECKS PASSED"
    if total == 0
    else (
        f"FAILED: {failures} profitable-below-threshold cases, "
        f"{mismatch} token mismatches"
    )
)
sys.exit(1 if total else 0)
