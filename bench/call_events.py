"""Count CPython bytecode executions per operation (deterministic).

``sys.setprofile`` attaches a profiler that fires once per Python call, so the
lowest number of ``call`` events any implementation can produce is a good
proxy for how much interpreter work a path costs -- and unlike wall-clock time
it does not depend on CPU frequency or the OS scheduler.
"""

import os
import sys
from collections import Counter

pkg = os.path.abspath(sys.argv[1])
if os.path.isdir(os.path.join(pkg, "src", "itsdangerous")):
    pkg = os.path.join(pkg, "src")
case = sys.argv[2]
sys.path.insert(0, pkg)
import itsdangerous  # noqa: E402  (must come after sys.path is set up)

assert os.path.abspath(itsdangerous.__file__).startswith(pkg + os.sep), (
    f"imported {itsdangerous.__file__} instead of the tree in {pkg}"
)

P = {"user_id": 42, "name": "test", "roles": ["admin", "editor"]}
M = {
    "sid": "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
    "uid": 100238,
    "scopes": ["read:user", "write:repo"],
    "iat": 1729248100,
    "exp": 1729249900,
}
s = itsdangerous.URLSafeTimedSerializer("secret-key-for-benchmarks")
sm = s.dumps(M)
N = 500

ops = {
    "dumps-medium": lambda: [s.dumps(M) for _ in range(N)],
    "loads-medium": lambda: [s.loads(sm) for _ in range(N)],
}

c = Counter()
default = Counter()


def prof(frame, event, arg):
    if event == "call":
        mod = frame.f_globals.get("__name__", "?")
        c[mod] += 1
    return prof


fn = ops[case]
# warmup (imports, caches)
fn()

sys.setprofile(prof)
try:
    fn()
finally:
    sys.setprofile(None)

total = sum(c.values())
print(f"python_call_events_per_op={total / N:.1f}")
for mod, n in c.most_common(6):
    print(f"  {mod}: {n / N:.1f}")
