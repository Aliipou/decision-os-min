# Forbidden actions by trust layer

This is the negative contract: what each layer must never permit. A checkmark
means executable in-repo evidence exists; it is not a universal proof outside
the named threat model.

| Layer | Forbidden action | Enforcement | Evidence |
|---|---|---|---|
| Admission | Unknown agent obtains a valid admission; ticket is reused | signed, expiring admission; atomic spend | `test_bypass_invariants.py`, `test_destructor_sealed.py` |
| Evaluator / context | Plugin grants authority, rewrites identity/tool/payload, or loosens DENY | deny-dominant canonical verdict meet; contributable-field allowlist; frozen action copy | `test_redteam_composition.py`, `test_redteam_round2.py` |
| Kernel / AuthGate | Ungranted or ambiguous capability produces an executable token; decision is rebound to another action | capability/purpose checks; canonical action binding; signed decision | `test_authority_convergence.py`, `test_adversarial_prompt_injection.py` |
| PEP / executor | Effect runs without valid signature, matching action, unspent token, or durable audit | signature/action verification; atomic `SpentStore`; audit-before-effect; arm-gated executor | `test_bypass_invariants.py`, `test_destructor_sealed.py`, `test_full_loop.py` |
| Hosted effect plane | Agent receives a live adapter; malformed/spoofed/replayed IPC reaches an effect | adapter ownership in `AgentHost`; channel-bound identity; exact 64 KiB schema; atomic request-ID spend; timeout | `test_hosted_agent_plane.py` |
| Agent sandbox | Durable write, arbitrary outbound network, exec/fork/thread creation, executable mappings, or ptrace succeeds under the declared profile | read-only root, no network/caps, post-bootstrap seccomp, PID/FD/memory/CPU bounds | `test_os_isolation.py` |
| Combined boundary | Sandboxed agent bypasses Intent mediation while a governed Host effect remains reachable | Docker attach stdin/stdout is the sole intentional channel; Host/adapters remain outside container | `test_e2e_agent_boundary.py` |
| Audit | Effect is reported without execution truth/payload digest; chain rewrite or anchored tail truncation goes undetected | execution fields + payload digest; hash chain; optional external head anchor | audit/red-team regressions |

## Explicit residuals

- A compromised Host/kernel process remains trusted and can access signing keys
  and adapters.
- Container/kernel escape and execution outside the declared Docker profile are
  outside demonstrated TM-A slices.
- Memory/CPU cgroups are configured bounds, not a proof against every denial of
  service or side channel.
- File/SQLite spent stores coordinate a single host/shared volume, not
  independent multi-machine disks without consensus.
- External audit anchoring is optional; an unanchored self-verifying chain alone
  cannot prove that its tail was not truncated.

The claim vocabulary and remaining residuals are authoritative in
[`THREAT_MODELS.md`](THREAT_MODELS.md).
