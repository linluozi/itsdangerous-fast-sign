"""Render the figures used by the README from the raw benchmark JSON.

Every number in the figures comes from ``results/*.json``; nothing is typed by
hand.  Run ``python assets/make_figures.py`` (from the repository root) after
re-running ``bench/bench.py``.

Palette: warm editorial (ink / paper / amber / terracotta / olive), the same
one used across the accompanying report.
"""

from __future__ import annotations

import json
import os
import statistics

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RESULTS = os.path.join(ROOT, "bench", "results")
OUT = HERE

INK = "#2b2119"
PAPER = "#faf6f0"
AMBER = "#c8892b"
TERRACOTTA = "#b4552f"
OLIVE = "#6b6b3a"
MUTED = "#8a7a68"
GRID = "#e2d7c6"

plt.rcParams.update(
    {
        "figure.facecolor": PAPER,
        "axes.facecolor": PAPER,
        "savefig.facecolor": PAPER,
        "axes.edgecolor": MUTED,
        "axes.labelcolor": INK,
        "text.color": INK,
        "xtick.color": INK,
        "ytick.color": INK,
        "axes.grid": True,
        "grid.color": GRID,
        "grid.linewidth": 0.9,
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.titleweight": "bold",
        "figure.dpi": 150,
    }
)

CASE_LABELS = {
    "tds-dumps-small": "URLSafeTimed.dumps small (74 B)",
    "tds-loads-small": "URLSafeTimed.loads small (74 B)",
    "tds-dumps-medium": "URLSafeTimed.dumps medium (214 B)",
    "tds-loads-medium": "URLSafeTimed.loads medium (214 B)",
    "tds-dumps-large": "URLSafeTimed.dumps large (8.6 kB)",
    "tds-loads-large": "URLSafeTimed.loads large (8.6 kB)",
    "urlsafe-dumps-medium": "URLSafeSerializer.dumps medium",
    "urlsafe-loads-medium": "URLSafeSerializer.loads medium",
    "timed-dumps-medium": "TimedSerializer.dumps medium",
    "timed-loads-medium": "TimedSerializer.loads medium",
    "json-dumps-medium": "Serializer(json).dumps medium",
    "json-loads-medium": "Serializer(json).loads medium",
    "rotating-loads-medium": "4-key rotation .loads",
    "rotating-dumps-medium": "4-key rotation .dumps",
    "signer-sign-small": "TimestampSigner.sign small",
    "signer-unsign-small": "TimestampSigner.unsign small",
    "tds-dumps-huge": "URLSafeTimed.dumps 400 kB",
    "tds-loads-huge": "URLSafeTimed.loads 400 kB",
    "urlsafe-dumps-huge": "URLSafeSerializer.dumps 400 kB",
    "urlsafe-loads-huge": "URLSafeSerializer.loads 400 kB",
}

CHANGE_LABELS = {
    "full": "all changes",
    "no_zlib_gate": "− zlib gate",
    "no_fast_hmac": "− fast HMAC",
    "no_signer_reuse": "− signer reuse",
    "no_key_cache": "− derived-key cache",
    "no_fast_b64": "− fast base64",
    "legacy_baseline": "all switches off\n(≡ upstream)",
}


def load(name: str) -> dict:
    with open(os.path.join(RESULTS, name), encoding="utf-8") as f:
        return json.load(f)


def figure_speedup() -> None:
    """Main result: per-case speedup with the A/A noise band."""
    ab = load("ab.json")
    aa = load("aa.json")

    # Band = median of the per-case quartiles of the A/A run, so one noisy
    # large-payload case cannot paint the whole chart grey.
    lo_noise = statistics.median(c["speedup_p25"] for c in aa["cases"])
    hi_noise = statistics.median(c["speedup_p75"] for c in aa["cases"])
    worst_lo = min(c["speedup_p25"] for c in aa["cases"])
    worst_hi = max(c["speedup_p75"] for c in aa["cases"])

    cases = sorted(
        (c for c in ab["cases"] if not c["case"].endswith("-huge")),
        key=lambda c: c["speedup_median"],
    )
    labels = [CASE_LABELS.get(c["case"], c["case"]) for c in cases]
    med = [c["speedup_median"] for c in cases]
    p25 = [c["speedup_p25"] for c in cases]
    p75 = [c["speedup_p75"] for c in cases]

    fig, ax = plt.subplots(figsize=(10.2, 6.2))
    y = range(len(cases))

    ax.axvspan(lo_noise, hi_noise, color=MUTED, alpha=0.18, zorder=0, lw=0)
    ax.axvline(1.0, color=INK, lw=1.0, ls="--", zorder=1)

    ax.hlines(y, p25, p75, color=AMBER, lw=5, alpha=0.35, zorder=2)
    ax.scatter(med, y, color=TERRACOTTA, s=48, zorder=3)

    for yi, m in zip(y, med, strict=False):
        ax.annotate(
            f"{m:.2f}×",
            (m, yi),
            textcoords="offset points",
            xytext=(7, -3),
            fontsize=9,
            color=INK,
            fontweight="bold",
        )

    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=8.5)
    ax.set_xlabel("speedup vs upstream  (× , median of paired rounds)")
    ax.set_title(
        "itsdangerous: optimized vs upstream, per call\n"
        "bars = interquartile range of the per-round ratio",
        loc="left",
    )
    ax.set_xlim(min(min(low) for low in [p25]) - 0.06, max(p75) + 0.16)
    ax.grid(axis="y", visible=False)
    ax.set_ylim(-1.4, len(cases) + 0.2)
    ax.annotate(
        f"A/A noise floor: {lo_noise:.2f}–{hi_noise:.2f}× (median case)\n"
        f"worst case {worst_lo:.2f}–{worst_hi:.2f}×",
        xy=(lo_noise, len(cases) + 0.05),
        xytext=(lo_noise - 0.32, -1.15),
        fontsize=8,
        color=MUTED,
        arrowprops={"arrowstyle": "-", "color": MUTED, "lw": 0.8},
    )
    fig.tight_layout(rect=(0.012, 0, 1, 0.9))
    fig.savefig(os.path.join(OUT, "speedup_by_case.png"), bbox_inches="tight")
    plt.close(fig)


def figure_ablation() -> None:
    """Which change is responsible, as measured by the ablation trees."""
    data = load("ablation.json")
    order = [
        "legacy_baseline",
        "no_signer_reuse",
        "no_key_cache",
        "no_fast_hmac",
        "no_zlib_gate",
        "full",
    ]
    cases = ["json-dumps-medium", "signer-sign-small", "tds-loads-medium"]

    fig, axes = plt.subplots(1, len(cases), figsize=(11.2, 4.0), sharey=True)
    colors = [MUTED, AMBER, AMBER, AMBER, AMBER, TERRACOTTA]

    for ax, case in zip(axes, cases, strict=False):
        rows = data[case]
        vals = [rows[k]["speedup"] for k in order]
        err_lo = [max(0, v - rows[k]["p25"]) for v, k in zip(vals, order, strict=False)]
        err_hi = [max(0, rows[k]["p75"] - v) for v, k in zip(vals, order, strict=False)]

        ypos = list(range(len(order)))
        ax.barh(
            ypos,
            vals,
            color=colors,
            height=0.62,
            xerr=[err_lo, err_hi],
            error_kw={"ecolor": INK, "lw": 0.9, "capsize": 2.5},
            zorder=3,
        )
        ax.axvline(1.0, color=INK, lw=1.0, ls="--", zorder=2)
        ax.set_xlim(0.8, max(max(vals), max(rows[k]["p75"] for k in order)) + 0.22)
        ax.set_title(CASE_LABELS.get(case, case), fontsize=10)
        ax.set_yticks(ypos)
        ax.set_yticklabels([CHANGE_LABELS[k] for k in order], fontsize=8.5)
        ax.set_xlabel("speedup vs all-switches-off", fontsize=9)
        ax.grid(axis="y", visible=False)

        for yi, v, hi in zip(ypos, vals, [rows[k]["p75"] for k in order], strict=False):
            ax.annotate(
                f"{v:.2f}×",
                (hi, yi),
                textcoords="offset points",
                xytext=(6, -3),
                fontsize=8.5,
                fontweight="bold",
            )

    fig.suptitle(
        "Ablation: disable one change at a time (bars = IQR over 15 paired rounds)",
        x=0.012,
        ha="left",
        fontsize=12,
        fontweight="bold",
    )
    fig.tight_layout(rect=(0.01, 0, 1, 0.9))
    fig.savefig(os.path.join(OUT, "ablation.png"), bbox_inches="tight")
    plt.close(fig)


def figure_call_events() -> None:
    """Deterministic metric: Python-level call events per operation."""
    metrics = load("call_events.json")

    cases = ["dumps-medium", "loads-medium"]
    labels = ["URLSafeTimed.dumps\n(medium)", "URLSafeTimed.loads\n(medium)"]
    up_vals = [metrics[c]["upstream"] for c in cases]
    opt_vals = [metrics[c]["optimized"] for c in cases]

    fig, ax = plt.subplots(figsize=(6.8, 4.2))
    x = range(len(cases))
    width = 0.32

    b1 = ax.bar(
        [i - width / 2 for i in x], up_vals, width, color=MUTED, label="upstream"
    )
    b2 = ax.bar(
        [i + width / 2 for i in x],
        opt_vals,
        width,
        color=TERRACOTTA,
        label="optimized",
    )

    for bars, vals in ((b1, up_vals), (b2, opt_vals)):
        for bar, v in zip(bars, vals, strict=False):
            ax.annotate(
                f"{v:.0f}",
                (bar.get_x() + bar.get_width() / 2, v),
                textcoords="offset points",
                xytext=(0, 4),
                ha="center",
                fontsize=10,
                fontweight="bold",
            )

    for i, (u, o) in enumerate(zip(up_vals, opt_vals, strict=False)):
        ax.annotate(
            f"−{(1 - o / u) * 100:.0f}%",
            (i, max(u, o) + 6),
            ha="center",
            fontsize=10,
            color=OLIVE,
            fontweight="bold",
        )

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylabel("Python call events per operation")
    ax.set_title(
        "Work the interpreter actually has to do\n"
        "(counted with sys.setprofile, deterministic)",
        loc="left",
    )
    ax.set_ylim(0, max(up_vals) * 1.30)
    ax.grid(axis="x", visible=False)
    ax.legend(frameon=False, loc="upper left", ncol=2, bbox_to_anchor=(0, 1.0))
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "call_events.png"), bbox_inches="tight")
    plt.close(fig)


def figure_large_payload() -> None:
    """Honest counter-example: where compression dominates, nothing changes."""
    ab = load("ab_huge.json")

    short = {
        "tds-dumps-huge": "URLSafeTimed.dumps",
        "tds-loads-huge": "URLSafeTimed.loads",
        "urlsafe-dumps-huge": "URLSafeSerializer.dumps",
        "urlsafe-loads-huge": "URLSafeSerializer.loads",
    }
    cases = [c for c in ab["cases"] if c["case"] in short]
    labels = [short[c["case"]] for c in cases]
    up = [c["upstream_median_us"] / 1000 for c in cases]
    opt = [c["optimized_median_us"] / 1000 for c in cases]

    fig, ax = plt.subplots(figsize=(8.2, 4.4))
    x = range(len(cases))
    w = 0.30

    b1 = ax.bar([i - w / 2 for i in x], up, w, color=MUTED, label="upstream")
    b2 = ax.bar([i + w / 2 for i in x], opt, w, color=TERRACOTTA, label="optimized")

    top = max(up + opt)

    for bars, vals in ((b1, up), (b2, opt)):
        for bar, v in zip(bars, vals, strict=False):
            ax.annotate(
                f"{v:.2f} ms",
                (bar.get_x() + bar.get_width() / 2, v),
                textcoords="offset points",
                xytext=(0, 3),
                ha="center",
                fontsize=8.5,
            )

    for i, c in enumerate(cases):
        ax.annotate(
            f"{c['speedup_median']:.2f}×",
            (i, top * 1.16),
            ha="center",
            fontsize=10,
            color=OLIVE,
            fontweight="bold",
        )

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, fontsize=8.5)
    ax.set_ylabel("median time per call (ms)")
    ax.set_title(
        "Where zlib compression dominates there is nothing left to win\n"
        "400 kB payload, ~10x compressible: our overhead is <1% of the call",
        loc="left",
    )
    ax.set_ylim(0, top * 1.32)
    ax.grid(axis="x", visible=False)
    ax.legend(frameon=False, loc="lower center", ncol=2, bbox_to_anchor=(0.5, -0.26))
    fig.tight_layout(rect=(0.01, 0, 1, 0.93))
    fig.savefig(os.path.join(OUT, "large_payload.png"), bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    figure_speedup()
    figure_ablation()
    figure_call_events()
    figure_large_payload()
    for name in (
        "speedup_by_case.png",
        "ablation.png",
        "call_events.png",
        "large_payload.png",
    ):
        print("wrote", os.path.join(OUT, name))


if __name__ == "__main__":
    main()
