"""A/B harness: upstream itsdangerous vs the optimized build.

The machine this was developed on has bimodal timing noise: the very same
call can measure 11 us or 40 us depending on which second it lands in, so
"best of N in one process" produced ratios anywhere between 0.26x and 3.8x
for *identical* code.  The harness therefore:

* loads both trees into **one** process under distinct module names
  (``upstream`` / ``optimized``), so there is no import or interpreter
  difference between arms;
* alternates arms **per call block**, so both arms experience the same noise;
* reports the **median of per-round ratios** (never a ratio of medians) and
  the median of the per-round *differences* as a cross-check;
* verifies every result (dumps must be reproducible, loads must return the
  expected payload) so a fast-but-wrong arm cannot win;
* has an ``--a-a`` mode that loads the same tree twice — that is the noise
  floor the reported speedups have to clear.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import platform
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

SMALL = {"user_id": 42, "name": "test", "roles": ["admin", "editor"]}
MEDIUM = {
    "sid": "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
    "uid": 100238,
    "scopes": ["read:user", "write:repo", "read:org", "admin:hook"],
    "iat": 1729248100,
    "exp": 1729249900,
    "meta": {"ua": "Mozilla/5.0", "ip": "203.0.113.7"},
}
LARGE = {"blob": "+".join(f"chunk{i:05d}" for i in range(900))}
#: A payload that zlib actually compresses (~10x), i.e. the branch where the
#: compression cost is large enough to hide everything else.
HUGE = {"blob": "abcdefgh" * 50000}

KEY = "secret-key-for-benchmarks"
ROTATING = [f"old-key-{i}-padding" for i in range(3)] + ["current-key-padding"]

#: case -> (class name, payload, method name)
CASES = {
    "tds-dumps-small": ("URLSafeTimedSerializer", SMALL, "dumps"),
    "tds-loads-small": ("URLSafeTimedSerializer", SMALL, "loads"),
    "tds-dumps-medium": ("URLSafeTimedSerializer", MEDIUM, "dumps"),
    "tds-loads-medium": ("URLSafeTimedSerializer", MEDIUM, "loads"),
    "tds-dumps-large": ("URLSafeTimedSerializer", LARGE, "dumps"),
    "tds-loads-large": ("URLSafeTimedSerializer", LARGE, "loads"),
    "urlsafe-dumps-medium": ("URLSafeSerializer", MEDIUM, "dumps"),
    "urlsafe-loads-medium": ("URLSafeSerializer", MEDIUM, "loads"),
    "timed-dumps-medium": ("TimedSerializer", MEDIUM, "dumps"),
    "timed-loads-medium": ("TimedSerializer", MEDIUM, "loads"),
    "json-dumps-medium": ("Serializer", MEDIUM, "dumps"),
    "json-loads-medium": ("Serializer", MEDIUM, "loads"),
    "rotating-loads-medium": ("Rotating", MEDIUM, "loads"),
    "rotating-dumps-medium": ("Rotating", MEDIUM, "dumps"),
    "signer-sign-small": ("TimestampSigner", SMALL, "sign"),
    "signer-unsign-small": ("TimestampSigner", SMALL, "unsign"),
    "tds-dumps-huge": ("URLSafeTimedSerializer", HUGE, "dumps"),
    "tds-loads-huge": ("URLSafeTimedSerializer", HUGE, "loads"),
    "urlsafe-dumps-huge": ("URLSafeSerializer", HUGE, "dumps"),
    "urlsafe-loads-huge": ("URLSafeSerializer", HUGE, "loads"),
}


def load_tree(path: str, name: str):
    """Import ``<path>/itsdangerous`` and alias it as ``name`` in sys.modules.

    The first tree is imported normally.  Any later tree is imported through a
    private ``sys.path`` prefix with the real package name temporarily removed
    from ``sys.modules``, so both copies coexist without either one being
    found through the other's path entry.
    """
    src = os.path.abspath(path)
    if os.path.isdir(os.path.join(src, "src")):
        src = os.path.join(src, "src")

    already_loaded = "itsdangerous" in sys.modules

    if already_loaded:
        saved = sys.modules.pop("itsdangerous")
        saved_path = list(sys.path)
        for mod_name in [m for m in sys.modules if m.startswith("itsdangerous.")]:
            sys.modules.pop(mod_name)
    else:
        saved = None
        saved_path = None

    sys.path.insert(0, src)

    try:
        mod = importlib.import_module("itsdangerous")
    finally:
        sys.path.remove(src)

        if saved is not None:
            sys.path[:] = saved_path

    pkg_dir = os.path.dirname(os.path.abspath(mod.__file__))

    if not pkg_dir.startswith(os.path.abspath(path)):
        raise SystemExit(f"{path} resolved to {mod.__file__}")

    if saved is not None:
        sys.modules["itsdangerous"] = saved

    sys.modules[name] = mod
    return mod


def build(mod, case):
    cls_name, payload, op = CASES[case]
    key = ROTATING if cls_name == "Rotating" else KEY
    cls_name = "URLSafeTimedSerializer" if cls_name == "Rotating" else cls_name
    obj = getattr(mod, cls_name)(key)
    return obj, payload, op


def measure(obj, payload, op, iterations):
    if op == "sign":
        arg = b'{"user_id":42,"name":"test"}'
        fn = obj.sign
        reference = fn(arg)
        check = lambda out: isinstance(out, bytes) and len(out) == len(reference)  # noqa: E731
    elif op == "unsign":
        arg = obj.sign(b'{"user_id":42,"name":"test"}')
        fn = obj.unsign
        reference = b'{"user_id":42,"name":"test"}'
        check = lambda out: out == reference  # noqa: E731
    elif op == "loads":
        arg = obj.dumps(payload)
        fn = obj.loads
        reference = obj.loads(arg)
        check = lambda out: out == reference  # noqa: E731
    else:
        arg = payload
        fn = obj.dumps
        reference = len(obj.dumps(payload))
        check = lambda out: isinstance(out, (bytes, str)) and len(out) == reference  # noqa: E731

    for _ in range(min(500, iterations)):
        fn(arg)

    t = time.perf_counter()
    for _ in range(iterations):
        out = fn(arg)
    elapsed = time.perf_counter() - t

    assert check(out), "result check failed"
    return elapsed / iterations * 1e6


def calibrate(obj, payload, op, target_ms):
    n = 100
    while True:
        us = measure(obj, payload, op, n)
        if us * n / 1000 >= target_ms or n >= 200_000:
            return max(100, int(round(target_ms * 1000 / us)))
        n *= 4


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", default=os.path.join(HERE, "..", "upstream"))
    ap.add_argument("--optimized", default=os.path.join(HERE, ".."))
    ap.add_argument("--cases", default=",".join(CASES))
    ap.add_argument("--rounds", type=int, default=25)
    ap.add_argument("--target-ms", type=float, default=10.0)
    ap.add_argument("--a-a", action="store_true", help="noise floor: same tree twice")
    ap.add_argument("--out", default=os.path.join(HERE, "results", "ab.json"))
    ap.add_argument("--quick", action="store_true")
    ap.add_argument(
        "--ablate",
        action="store_true",
        help="measure every ablation/<variant> tree against baseline",
    )
    args = ap.parse_args()

    if args.quick:
        args.rounds = min(args.rounds, 5)
        args.out = args.out.replace(".json", "_quick.json")

    upstream = load_tree(args.upstream, "upstream_tree")
    if args.a_a:
        optimized = upstream
        args.optimized = args.upstream
    else:
        optimized = load_tree(args.optimized, "optimized_tree")

    cases = [c for c in args.cases.split(",") if c]
    out = {
        "python": platform.python_version(),
        "machine": platform.machine(),
        "rounds": args.rounds,
        "target_ms": args.target_ms,
        "upstream": os.path.abspath(args.upstream),
        "optimized": os.path.abspath(args.optimized),
        "mode": "A/A noise floor" if args.a_a else "A/B",
        "cases": [],
    }

    for case in cases:
        o_up, payload, op = build(upstream, case)
        o_opt, _, _ = build(optimized, case)

        n_up = calibrate(o_up, payload, op, args.target_ms)
        n_opt = calibrate(o_opt, payload, op, args.target_ms)
        iterations = max(n_up, n_opt)

        ratios_up = []
        ratios_opt = []

        for i in range(args.rounds):
            if i % 2 == 0:
                a = measure(o_up, payload, op, iterations)
                b = measure(o_opt, payload, op, iterations)
            else:
                b = measure(o_opt, payload, op, iterations)
                a = measure(o_up, payload, op, iterations)
            ratios_up.append(a)
            ratios_opt.append(b)

        pairs = list(zip(ratios_up, ratios_opt, strict=True))
        speedups = [a / b for a, b in pairs]
        savings = [a - b for a, b in pairs]

        row = {
            "case": case,
            "op": op,
            "iterations": iterations,
            "upstream_median_us": statistics.median(ratios_up),
            "optimized_median_us": statistics.median(ratios_opt),
            "speedup_median": statistics.median(speedups),
            "speedup_p25": statistics.quantiles(speedups, n=4)[0]
            if len(speedups) > 3
            else min(speedups),
            "speedup_p75": statistics.quantiles(speedups, n=4)[2]
            if len(speedups) > 3
            else max(speedups),
            "median_saving_us": statistics.median(savings),
            "speedups": [round(s, 4) for s in speedups],
            "upstream_us": [round(x, 3) for x in ratios_up],
            "optimized_us": [round(x, 3) for x in ratios_opt],
        }
        out["cases"].append(row)
        print(
            f"{case:24s} up={row['upstream_median_us']:8.2f}us "
            f"opt={row['optimized_median_us']:8.2f}us "
            f"speedup={row['speedup_median']:5.2f}x "
            f"p25={row['speedup_p25']:5.2f} p75={row['speedup_p75']:5.2f} "
            f"save={row['median_saving_us']:6.2f}us n={iterations}",
            flush=True,
        )

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print("written", args.out)
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
