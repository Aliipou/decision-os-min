# decision-os-min — Benchmarks

Honest, conservative micro-benchmarks for the security-critical operations of
`decision-os-min`. These are single-process, single-thread wall-clock timings.
They are **not** throughput-at-scale or concurrency numbers. Read the caveats
before quoting anything here.

## Results

| operation                       |   us/op |   ops/sec | iters   |
|---------------------------------|--------:|----------:|--------:|
| kernel.decide (ALLOW)           |  53.869 |    18,563 | 120,942 |
| verify (Ed25519 verify)         |  27.813 |    35,955 | 200,000 |
| executor.execute (token path)   |  78.407 |    12,754 | 102,032 |
| audit append (HashLog.record)   |  43.965 |    22,745 | 200,000 |
| DecisionOS.handle (end-to-end)  | 147.767 |     6,767 |  57,073 |

`us/op` = microseconds per single operation. `ops/sec` = 1 / (us/op), i.e. the
steady-state rate of that one operation on one core, doing nothing else.

A second independent run agreed within noise (decide 53.9us, verify 27.8us,
execute 77.8us, audit 46.8us, handle 149.3us), so these figures are stable, not
one-shot lucky draws.

## What each operation is

- **kernel.decide (ALLOW)** — full authorization decision on the ALLOW path:
  policy evaluation (capability + purpose binding + redaction check), computing
  the sha256 action fingerprint, **one Ed25519 sign of the decision**, and
  minting + **a second Ed25519 sign of the one-time token**. So `decide` on a
  permitting verdict pays for **two Ed25519 signatures**, which is why it is
  ~2x the cost of a single verify.
- **verify (Ed25519 verify)** — `verify()` on one pre-signed decision, repeated.
  This isolates the raw Ed25519 signature-verification cost (plus a sha256 of the
  canonical JSON and the identity check). This is the cheapest primitive here.
- **executor.execute (token path)** — the executor happy path: verify the
  decision signature, re-derive and compare the action binding, **verify the
  token signature**, check expiry, spend the one-time token, resolve the tool,
  and call it. Roughly **two Ed25519 verifies** plus binding/spend bookkeeping.
  A fresh `decide` is minted per iteration because tokens are single-use.
- **audit append (HashLog.record)** — one hash-chained append: build the entry,
  sha256 it against the previous hash, and `open(..., "a")` + `write` + close to
  a local file. Dominated by the per-call file open/write/flush, not crypto.
- **DecisionOS.handle (end-to-end)** — the whole pipeline in one call:
  `decide` (2 signs) -> `HashLog.record` (audit append) -> `executor.execute`
  (2 verifies + tool call). Its cost is approximately the sum of the three rows
  above (~54 + ~44 + ~78 us), which the ~148 us measured confirms.

## Machine / environment

| | |
|---|---|
| CPU          | Intel Core i5-7300U @ 2.60 GHz (2 cores / 4 threads, Kaby Lake, mobile) |
| OS           | Windows 10 Pro 10.0.19045 (x86-64) |
| Python       | 3.13.2, CPython, 64-bit (MSC v.1942) |
| cryptography | 46.0.5 (OpenSSL-backed Ed25519) |
| Install      | `pip install -e .` (editable) in the system Python |
| Dependencies | `cryptography` only |

This is a low-power laptop CPU. A modern server or desktop core will be
meaningfully faster; treat these as a conservative floor, not a ceiling.

## Methodology

- Timer: `time.perf_counter()` around a tight loop of N single operations;
  per-op time = elapsed / N.
- **Warm-up**: 2,000 untimed iterations of each operation before measuring
  (warms the allocator, branch predictors, file/OS caches, and the crypto
  backend) so start-up costs are excluded.
- **Auto-tuned iteration count**: each operation is calibrated on a 200-iteration
  sample and then run for ~2 seconds of wall time, clamped to
  `[20,000, 200,000]` iterations. This keeps every measurement well above timer
  resolution and averages out scheduler jitter. Actual counts are in the table.
- **GC disabled during the measured loop** (`gc.disable()` / restore after) so a
  stray collection cannot land inside a timing window.
- **Fresh state where correctness demands it**: tokens are one-time and the
  audit log appends to a file, so `decide`, `execute`, and `handle` mint a fresh
  action/decision/token per iteration (unique `nonce`), and all audit writes go
  to a `tempfile.TemporaryDirectory()` that is discarded afterward. The
  benchmark therefore measures real work, not a replayed cache hit.
- `verify` is the one deliberately-repeated case: it re-verifies a single
  pre-signed decision so the number reflects pure verification cost with no
  per-iteration signing mixed in.
- Output is ASCII-only so it renders on a default Windows console.

### Reproduce

From the repo root:

```
PYTHONIOENCODING=utf-8 python bench\benchmark.py
```

Benchmark source: `bench/benchmark.py`. Absolute-value noise of a few percent
between runs is expected on a loaded laptop; re-run a couple of times.

## Caveats — read before quoting these numbers

- **Micro-benchmarks, not throughput-at-scale.** Each number is the cost of
  *one* operation on *one* core with the machine otherwise idle. They do **not**
  describe sustained system throughput, tail latency, or behavior under load. Do
  **not** multiply `ops/sec` by a core count and call it production capacity.
- **Single-process, single-thread.** No concurrency was measured. Ed25519 in
  `cryptography` releases the GIL for the OpenSSL call, but shared state here —
  the executor's in-memory `_spent` set and the single append-only audit file —
  is **not** contention-tested. Concurrent numbers would require a separate
  benchmark and would likely be lower per-op under contention.
- **In-memory, unbounded token store.** The executor tracks spent tokens in a
  process-local `set` that grows without eviction and is lost on restart. The
  benchmark's `execute`/`handle` loops therefore also grow this set; a
  long-running real process needs an eviction/TTL policy, whose cost is not
  measured here.
- **Local single-file audit.** `HashLog.record` appends to one local file with an
  open/write/flush per call. The audit number reflects **this disk and this
  filesystem's** buffering; on a network filesystem, with `fsync`, or under
  concurrent writers it will differ substantially. There is also no rotation.
- **Ed25519 sign/verify dominates the crypto cost.** `decide` pays for two
  signs, `execute` for two verifies, `handle` for both. If you change the number
  of signatures per decision, these numbers move proportionally. The
  policy-evaluation logic itself (dict lookups, sha256 of a small JSON blob) is
  cheap by comparison.
- **Not production-throughput claims.** Nothing here has been validated for
  correctness under adversarial concurrency, persistence/durability guarantees,
  or horizontal scaling. These figures establish a per-operation cost floor on a
  modest laptop and nothing more.
