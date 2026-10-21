# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

"""Compares vg_bench.py passes as a Markdown table:

    python vg_bench_compare.py other-1.json other-2.json -- vg-1.json vg-2.json

For each benchmark, each backend's time is the faster of its passes (the
least disturbed by other load); the spread is how far its passes differ.
"""

import json
import sys


def load(paths):
    runs = [json.load(open(p))["results"] for p in paths]
    out = {}
    for name in runs[0]:
        ts = [r.get(name) for r in runs]
        if any(t is None for t in ts):
            out[name] = None
        else:
            out[name] = (min(ts), max(ts) / min(ts) - 1)
    return out


def fmt_time(t):
    for unit, scale in (("s", 1), ("ms", 1e-3), ("us", 1e-6), ("ns", 1e-9)):
        if t >= scale:
            return f"{t / scale:.3g} {unit}"
    return f"{t / 1e-9:.3g} ns"


def throughput(name, t):
    sizes = {"64B": 64, "1KiB": 1024, "1MiB": 1024 * 1024}
    last = name.rsplit("/", 1)[-1]
    if last in sizes:
        return f" ({sizes[last] / t / 1e6:,.0f} MB/s)"
    return ""


sep = sys.argv.index("--")
a, b = load(sys.argv[1:sep]), load(sys.argv[sep + 1 :])
other = json.load(open(sys.argv[1]))["backend"]
print(f"| Benchmark | {other} | verified-garbage | VG vs {other} |")
print("|---|---|---|---|")
noisy = []
for name in a:
    ra, rb = a[name], b.get(name)
    ca = fmt_time(ra[0]) + throughput(name, ra[0]) if ra else "n/a"
    cb = fmt_time(rb[0]) + throughput(name, rb[0]) if rb else "n/a"
    if ra and rb:
        r = ra[0] / rb[0]
        rel = f"{r:.2f}x faster" if r >= 1 else f"{1 / r:.2f}x slower"
        if max(ra[1], rb[1]) > 0.10:
            noisy.append(name)
            rel += " †"
    else:
        rel = "—"
    print(f"| `{name}` | {ca} | {cb} | {rel} |")
print()
print(f"† passes differed by more than 10% ({len(noisy)} benchmarks)")
