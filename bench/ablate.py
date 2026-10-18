"""Ablation runner: which change is responsible for how much.

Every variant is compared against ``ablation/ablation_legacy_baseline`` (the
optimized tree with all five switches off, i.e. upstream behaviour) and
against ``ablation/ablation_full`` (all on).  Ratios are medians of paired
rounds, exactly like ``bench.py``.
"""

import glob
import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench

HERE = os.path.dirname(os.path.abspath(__file__))
VARIANTS = sorted(glob.glob(os.path.join(HERE, "ablation", "ablation_*")))
CASES = [
    "tds-dumps-medium",
    "tds-loads-medium",
    "json-dumps-medium",
    "signer-sign-small",
]
ROUNDS = 15
TARGET_MS = 8.0


def run(base_tree, target_tree, case):
    up = bench.load_tree(base_tree, "abl_base")
    opt = bench.load_tree(target_tree, "abl_target")
    o_up, payload, op = bench.build(up, case)
    o_opt, _, _ = bench.build(opt, case)
    n = max(
        bench.calibrate(o_up, payload, op, TARGET_MS),
        bench.calibrate(o_opt, payload, op, TARGET_MS),
    )
    a_list, b_list = [], []
    for i in range(ROUNDS):
        if i % 2 == 0:
            a = bench.measure(o_up, payload, op, n)
            b = bench.measure(o_opt, payload, op, n)
        else:
            b = bench.measure(o_opt, payload, op, n)
            a = bench.measure(o_up, payload, op, n)
        a_list.append(a)
        b_list.append(b)
    sp = sorted(x / y for x, y in zip(a_list, b_list, strict=True))
    return {
        "base_us": statistics.median(a_list),
        "target_us": statistics.median(b_list),
        "speedup": statistics.median(sp),
        "p25": sp[len(sp) // 4],
        "p75": sp[3 * len(sp) // 4],
        "iterations": n,
    }


if __name__ == "__main__":
    import random

    base = os.path.join(HERE, "ablation", "ablation_legacy_baseline")
    out = {}
    rng = random.Random(20261018)
    for case in CASES:
        out[case] = {}
        # Shuffle: the first variant measured always looks fastest because the
        # CPU is still in its best state, which made the ordering, not the code,
        # the dominant effect in the first run of this script.
        order = list(VARIANTS)
        rng.shuffle(order)
        for v in order:
            name = os.path.basename(v).replace("ablation_", "")
            out[case][name] = run(base, v, case)
            r = out[case][name]
            print(
                f"{case:20s} {name:22s} "
                f"{r['base_us']:8.2f} -> {r['target_us']:8.2f} us "
                f"{r['speedup']:5.2f}x [{r['p25']:.2f},{r['p75']:.2f}]",
                flush=True,
            )
    with open(
        os.path.join(HERE, "results", "ablation.json"),
        "w",
        encoding="utf-8",
        newline="\n",
    ) as f:
        json.dump(out, f, indent=2)
        f.write("\n")
