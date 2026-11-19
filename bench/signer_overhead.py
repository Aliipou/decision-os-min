"""Signing overhead: in-process key vs out-of-process signer (pipe round trip).

    python bench/signer_overhead.py [--n 2000]
"""
import argparse
import statistics
import tempfile
import time
from pathlib import Path

from decision_os_min.kernel import Kernel

POLICY = {"grants": {"agent:bot": ["tool:send_email"]}, "default": "deny"}
ACTION = {"actor": "agent:bot", "tool": "send_email", "capability": "tool:send_email",
          "action_purpose": "support_reply", "data_labels": [], "payload": {"to": "x"},
          "nonce": "n"}


def run(k, n):
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        k.decide(dict(ACTION), evaluators=[])
        ts.append((time.perf_counter() - t) * 1e6)
    ts.sort()
    return statistics.median(ts), ts[int(n * 0.95)]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    n = ap.parse_args().n
    d = Path(tempfile.mkdtemp())
    for label, iso in (("in-process key", False), ("signer process", True)):
        k = Kernel(POLICY, key_path=str(d / f"{iso}.pem"), isolate_key=iso)
        run(k, 50)
        p50, p95 = run(k, n)
        ts = []
        for _ in range(n):
            t = time.perf_counter()
            k._sign({"a": 1})
            ts.append((time.perf_counter() - t) * 1e6)
        ts.sort()
        print(f"{label:16s} _sign()   p50={statistics.median(ts):8.1f}us p95={ts[int(n*0.95)]:8.1f}us")
        print(f"{label:16s} decide() p50={p50:8.1f}us p95={p95:8.1f}us")
        if k._signer:
            k._signer.close()
