"""Micro-benchmarks for decision-os-min.

Honest, conservative, single-process/single-thread wall-clock timings for the
security-critical operations. NOT a throughput-at-scale or concurrency benchmark.

Run from the repo root:

    PYTHONIOENCODING=utf-8 python bench\\benchmark.py

Output is ASCII-only so it renders on a default Windows console.
"""

from __future__ import annotations

import gc
import platform
import sys
import tempfile
import time
from pathlib import Path

from decision_os_min import DecisionOS, Executor, Kernel, verify
from decision_os_min.audit import HashLog

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

POLICY = {
    "grants": {"agent:bot": ["tool:send_email"]},
    "purpose_bindings": {"customer_support": ["support_reply"]},
    "redactions": [{"action_purpose": "support_reply", "redact_fields": ["ssn"]}],
    "contain_threat_classes": ["malicious"],
    "default": "deny",
}

# An ALLOW-path action: bot has the capability, purpose binds, and the redaction
# rule does not fire (no 'ssn' field present) so the verdict is ALLOW, which mints
# a one-time token.
BASE_ACTION = {
    "actor": "agent:bot",
    "tool": "send_email",
    "action_purpose": "support_reply",
    "data_labels": ["customer_support"],
    "payload": {"body": "hello"},
    "capability": "tool:send_email",
    "nonce": "n",
}

TOOLS = {"send_email": lambda payload: "sent"}


def fresh_action(i: int) -> dict:
    """A distinct action per iteration (unique nonce) so tokens/bindings differ."""
    a = dict(BASE_ACTION)
    a["payload"] = {"body": "hello"}
    a["nonce"] = f"n-{i}"
    return a


# ---------------------------------------------------------------------------
# Timing harness
# ---------------------------------------------------------------------------

def _auto_iters(setup, per_iter, target_seconds: float = 2.0, cap: int = 200_000,
                floor: int = 20_000) -> int:
    """Pick an iteration count so the measured run lasts ~target_seconds, within
    [floor, cap]. Calibrates on a small sample."""
    ctx = setup(200)
    t0 = time.perf_counter()
    for i in range(200):
        per_iter(ctx, i)
    dt = time.perf_counter() - t0
    if dt <= 0:
        return floor
    per = dt / 200
    n = int(target_seconds / per)
    return max(floor, min(cap, n))


def bench(name: str, setup, per_iter, warmup: int = 2000):
    """setup(n) -> ctx built once for n iterations (fresh tokens/actions/etc).
    per_iter(ctx, i) -> runs exactly ONE operation for iteration i.
    Returns (name, us_per_op, ops_per_sec, iters)."""
    # Warm-up (JIT-less, but warms caches, imports, branch predictors, allocator).
    wctx = setup(warmup)
    for i in range(warmup):
        per_iter(wctx, i)

    iters = _auto_iters(setup, per_iter)
    ctx = setup(iters)

    gc_was = gc.isenabled()
    gc.disable()
    try:
        t0 = time.perf_counter()
        for i in range(iters):
            per_iter(ctx, i)
        elapsed = time.perf_counter() - t0
    finally:
        if gc_was:
            gc.enable()

    us = (elapsed / iters) * 1e6
    ops = iters / elapsed
    return name, us, ops, iters


# ---------------------------------------------------------------------------
# Operation definitions
# ---------------------------------------------------------------------------

def make_benches(tmpdir: Path):
    benches = []

    # 1) kernel.decide() on the ALLOW path (signs decision + mints token).
    def setup_decide(n):
        return {"kernel": Kernel(POLICY),
                "actions": [fresh_action(i) for i in range(n)]}

    def do_decide(ctx, i):
        ctx["kernel"].decide(ctx["actions"][i])

    benches.append(("kernel.decide (ALLOW)", setup_decide, do_decide))

    # 2) verify() on ONE pre-signed decision, repeated -> isolates Ed25519 verify.
    def setup_verify(n):
        k = Kernel(POLICY)
        res = k.decide(fresh_action(0))
        return {"decision": res["decision"],
                "sig": res["signature"],
                "pub": k.public_key_hex()}

    def do_verify(ctx, i):
        verify(ctx["decision"], ctx["sig"], ctx["pub"])

    benches.append(("verify (Ed25519 verify)", setup_verify, do_verify))

    # 3) token verification path: executor.execute happy path, fresh decide/iter.
    #    Tokens are one-time, so each iteration needs its own decision+token and a
    #    fresh (or non-colliding) executor. We pre-mint per-iteration results and
    #    use one Executor whose spent-set grows; token ids are unique per action.
    def setup_execute(n):
        k = Kernel(POLICY)
        actions = [fresh_action(i) for i in range(n)]
        results = [k.decide(actions[i]) for i in range(n)]
        ex = Executor(k.public_key_hex())
        return {"ex": ex, "actions": actions, "results": results}

    def do_execute(ctx, i):
        ctx["ex"].execute(ctx["actions"][i], ctx["results"][i], TOOLS)

    benches.append(("executor.execute (token path)", setup_execute, do_execute))

    # 4) audit append: HashLog.record on a temp file.
    def setup_audit(n):
        log = HashLog(tmpdir / "bench_audit.jsonl")
        return {"log": log}

    def do_audit(ctx, i):
        ctx["log"].record("agent:bot", "send_email", "ALLOW", "all checks passed")

    benches.append(("audit append (HashLog.record)", setup_audit, do_audit))

    # 5) full DecisionOS.handle() end-to-end (decide + audit + execute).
    def setup_handle(n):
        dos = DecisionOS(POLICY, audit_path=str(tmpdir / "bench_handle.jsonl"))
        return {"dos": dos, "actions": [fresh_action(i) for i in range(n)]}

    def do_handle(ctx, i):
        ctx["dos"].handle(ctx["actions"][i], TOOLS)

    benches.append(("DecisionOS.handle (end-to-end)", setup_handle, do_handle))

    return benches


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("decision-os-min micro-benchmarks")
    print("=" * 68)
    print(f"python     : {sys.version.split()[0]} ({platform.python_implementation()})")
    print(f"platform   : {platform.platform()}")
    print(f"processor  : {platform.processor()}")
    try:
        import cryptography
        print(f"cryptography: {cryptography.__version__}")
    except Exception:
        pass
    print("=" * 68)

    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)
        results = []
        for name, setup, per_iter in make_benches(tmpdir):
            results.append(bench(name, setup, per_iter))

    # Aligned ASCII table.
    hdr = f"{'operation':<32} {'us/op':>12} {'ops/sec':>14} {'iters':>10}"
    print()
    print(hdr)
    print("-" * len(hdr))
    for name, us, ops, iters in results:
        print(f"{name:<32} {us:>12.3f} {ops:>14,.0f} {iters:>10,d}")
    print("-" * len(hdr))
    print()
    print("Notes: single-process, single-thread wall-clock (time.perf_counter);")
    print("GC disabled during measurement; in-memory token store; local file audit.")
    print("These are micro-benchmarks, NOT throughput-at-scale or concurrent numbers.")


if __name__ == "__main__":
    main()
