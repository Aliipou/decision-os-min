# Backlog — honest status (2026-08-23)

## Shipped with executable evidence

- [x] Signed, action-bound decisions and one-time capability tokens
- [x] Deny-dominant evaluator composition and adversarial regressions
- [x] Durable/atomic spent-store seam and audit-before-effect PEP
- [x] Sealed execution surface with mandatory legitimacy binding
- [x] Hosted Agent effect plane (TM-H)
- [x] Linux/Docker `agent-noambient-v1` slices: FS/network, exec/fork/thread,
  W^X, ptrace, credentials, and FD pressure
- [x] Real locked agent → JSONL Intent → outside `AgentHost` → governed effect
- [x] IPC identity binding, strict bounded frames, request replay refusal, and
  client response timeout
- [x] Persistent signing key option, readiness, metrics, Docker/Compose starter
- [x] Per-layer forbidden-actions table — `docs/FORBIDDEN_ACTIONS.md`

These checks do **not** make unqualified `DirectEffect(Agent)=∅` true. See
`docs/THREAT_MODELS.md`.

## Next validation work

- [ ] Recruit 3–5 independent users and record installation/use failures
- [x] Run a shared-workload empirical comparison with real OPA, Cedar, and MCP
  implementations — pinned harness, warmup discarded, policy conformance as
  the comparable result, latency labeled by boundary (not a ranking) in
  `bench/comparison/`
- [ ] Commission an independent skeptical/security review
- [ ] Publish a reproducible technical report from measured evidence

## Optional hardening — only when evidence demands it

- [ ] Evaluate gVisor/runsc against a concrete residual before adopting it
- [ ] Isolate Host signing keys (HSM/KMS) if Host compromise enters scope
- [ ] Add distributed request/token replay storage for independent machines
- [ ] Add an external/WORM audit anchor in production deployments
- [ ] Add deployment-level wall-clock supervision for CPU/DoS containment

## Parked research

- Normative ownership/consent/justice layers remain injected policy, not runtime
  mechanism. Do not encode unsettled philosophy into the trusted core.
- FDK's philosophical independence remains under re-evaluation; this runtime
  neither proves nor depends on it.
- Multi-agent scheduling/federation remains a separate R&D track. The
  evidence-grounded adversarial lab may test this system, but must not silently
  expand the kernel.

## Standing rules

- Never mix policy with mechanism.
- Every security claim needs an executable test or must be labeled unverified.
- Keep TM-H, named TM-A slices, and TM-A full separate.
- Never weaken a failing destructor to obtain green CI.
