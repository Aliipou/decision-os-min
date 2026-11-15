"""Latency distribution (p50/p95/p99) for the allow path, single and concurrent.

Complements bench/benchmark.py (mean micro-timings). Measures wall-clock per
`DecisionOS.handle` call with a durable FileSpentStore (the realistic default),
so each call includes signing, the spend-record fsync, and the audit append.

    python bench/latency.py [--n 2000] [--threads 8]

Numbers are for the machine they ran on; quote them with the hardware, never
as production capacity.
"""

from __future__ import annotations

import argparse
import platform
import statistics
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from decision_os_min import DecisionOS, FileSpentStore

POLICY = {
    "grants": {"agent:bot": ["tool:send_email"]},
    "purpose_bindings": {"customer_support": ["support_reply"]},
    "default": "deny",
}
TOOLS = {"send_email": lambda p: "sent"}


def action(i: int) -> dict:
    return {
        "actor": "agent:bot", "tool": "send_email", "action_purpose": "support_reply",
        "data_labels": ["customer_support"], "payload": {"body": "hello"},
        "capability": "tool:send_email", "nonce": f"n{i}",
    }


def pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def summarize(label: str, ms: list[float]) -> None:
    print(f"{label:<26} n={len(ms):<6} p50={pct(ms, .50):7.3f}  p95={pct(ms, .95):7.3f}  "
          f"p99={pct(ms, .99):7.3f}  max={max(ms):7.3f}  mean={statistics.mean(ms):7.3f} ms")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--threads", type=int, default=8)
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as d:
        dos = DecisionOS(POLICY, audit_path=str(Path(d) / "audit.jsonl"),
                         spent_store=FileSpentStore(Path(d) / "spent"))

        def one(i: int) -> float:
            t = time.perf_counter()
            out = dos.handle(action(i), TOOLS)
            assert out.executed, out.refused_reason
            return (time.perf_counter() - t) * 1000

        print(f"python {platform.python_version()} on {platform.platform()}")
        for i in range(50):  # warm-up
            one(-i - 1)
        summarize("handle, 1 thread", [one(i) for i in range(a.n)])
        with ThreadPoolExecutor(a.threads) as ex:
            ms = list(ex.map(one, range(a.n, 2 * a.n)))
        summarize(f"handle, {a.threads} threads", ms)


if __name__ == "__main__":
    main()
