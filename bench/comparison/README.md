# Real-system comparison harness

This harness runs one six-scenario governance workload through real
implementations, then **separates** the comparable result from the
non-comparable measurements.

1. Decision OS built-in authority + legitimacy (policy decision only)
2. Official OPA Docker image (HTTP authorization query)
3. Official Cedar Policy CLI (`authorize` subprocess)
4. Decision OS `kernel.decide` (policy + sign + mint — extra work)
5. Decision OS full `handle` (sign + PEP + effect + audit — extra work)
6. Official MCP TypeScript SDK over stdio (transport only)

No look-alike policy engine or hand-written MCP wire mock is used.

## What is comparable

The comparable result is **policy conformance**: Decision OS, OPA, and Cedar
receive equivalent grants, consent, purpose, and data-label constraints in
each system's native schema and must agree with all expected ALLOW/DENY
outcomes.

Latency is **not** comparable across those three:

- Decision OS policy-only is an in-process Python evaluation.
- OPA is a warm HTTP query to a running server.
- Cedar is measured at the official CLI boundary, so each request pays for a
  new process. That is not the cost of the in-process `cedar-policy` library.

MCP is a tool transport. It has no legitimacy/authority verdict. Its handler
is reached even for cases that governance would deny.

## Pinned real implementations

- OPA `1.19.1`, official image pinned by digest in `run_comparison.py`
- Cedar Policy CLI `4.12.0`, official `cedar-policy-cli` crate
- `@modelcontextprotocol/server` and `@modelcontextprotocol/client` `2.0.0`,
  pinned transitively by `mcp/package-lock.json`

## Reproduce

Requirements: Python 3.11+, a running Docker engine, the pinned Cedar CLI, and
Node.js 20+.

```bash
pip install -e .
cargo install cedar-policy-cli --version 4.12.0 --locked
cd bench/comparison/mcp && npm ci && cd ../../..
python bench/comparison/run_comparison.py --iterations 50 --warmup 10
```

On this repository's Windows validation host, Cedar is installed outside the
global path, so reproduction can instead pass:

```powershell
python bench/comparison/run_comparison.py `
  --iterations 50 --warmup 10 `
  --cedar-bin "$env:LOCALAPPDATA\decision-os-comparison\cedar\cedar.exe"
```

The first `--warmup` iterations of each scenario are discarded. The
machine-readable result is written to `results/latest.json`. A nonzero exit
means a Decision OS/OPA/Cedar expected verdict disagreed or the real MCP
handler was not reached.

## What this establishes—and does not

It establishes shared-scenario agreement and records boundary-specific latency
on one machine after warmup. It does not establish production throughput,
equivalent feature scope, distributed correctness, or superiority over any
compared project. Cedar and OPA remain stronger policy languages. Decision OS
is being measured as an enforcement chain after a policy decision, not as a
replacement PDP.
