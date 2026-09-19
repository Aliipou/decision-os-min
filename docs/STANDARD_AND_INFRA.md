# Becoming a standard, and becoming infrastructure

**Status today:** this repository is a **reference runtime**, not a standard
and not infrastructure. The goal below is aspirational. Tests are evidence,
not proofs. TM-A full remains PARTIAL.

The reason to try anyway is [WHY.md](WHY.md): autonomous systems that act
still need a gate that preserves human ownership of effects. Permission
engines and prompt rules are not that gate. If anything in this space should
harden into a standard, it is the **mint/execute split**, not another policy
language.

## Two different destinations

| Word | What it would take | Not this |
|---|---|---|
| **Standard** | A small interop profile other implementations can meet; a conformance suite; at least two independent implementations; adoption by a host venue (MCP / A2A / AuthZEN / AGT) | A README claim, 35 GitHub comments, or “we were first” |
| **Infrastructure** | A named TCB, fail-closed ops defaults, isolation that matches the threat model, keys the agent cannot mint, multi-host spend, independent review | Calling a Python library an OS |

Cedar/OPA should remain the **policy** standard. This profile is the
**effect-mediation** standard they do not specify.

## Candidate interop profile (v0)

Normative language is for a *future* multi-impl spec. This repo is implementation
0. Field names may change; the axioms must not.

### MUST

1. **Single minter.** Only one component in the trust domain may produce an
   executable decision (signature + `token_id`). A PDP (Cedar, OPA, builtin
   grants, AGT dispatcher) may return grant/deny only. It MUST NOT mint,
   sign, or receive effect adapters.
2. **Action binding.** The signed object MUST commit to actor, capability,
   purpose, data labels, payload, and a caller nonce/action_ref. A decision
   MUST NOT authorize a different live action (`confused deputy`).
3. **Capability/tool agreement.** If both `tool` and `capability` are set,
   `capability` MUST equal `tool:<tool>`. This is a kernel well-formedness
   rule, not a policy preference.
4. **One-time spend.** A permitting decision MUST be consumable at most once
   on a shared spent-store. Replay MUST refuse. Store failure MUST refuse
   (fail closed), never “assume unspent.”
5. **Mandatory PEP.** An effect MUST run only after signature verify, binding
   match, permitting verdict, unexpired token, and successful spend.
6. **Legitimacy is DENY-only.** Injected ownership/consent evaluators MUST NOT
   author a permit or loosen a DENY. Advice (threat class) MUST only tighten.
7. **Independent signer.** The acting agent MUST NOT hold the signing key,
   the spent-store write path as a bypass, or live adapters. Hosted agents
   speak Intent only.
8. **Audit.** Every `execute` attempt MUST leave a record (ran or refused).
   The log MUST be hash-chained. Tail truncation without an out-of-band
   anchor remains a documented residual.

### MUST NOT claim (until evidenced)

- Process-wide `DirectEffect(Agent)=∅` (TM-A full)
- GDPR / HIPAA / EU AI Act / ISO 42001 attestation
- Formal verification, non-repudiation, or “no bypass anywhere”
- That Cedar/OPA/AGT are obsolete

### SHOULD

- Replaceable Authority PDP with canonicalized grant/deny only
- Durable spent-store on a shared volume; explicit opt-in for in-memory
- Hosted Intent JSONL with bound `agent_id` and request-id spend
- Named OS-isolation profile for TM-A slices (Docker + lock), labeled as a
  slice, never “TM-A PASS”

Evidence for this repo’s attempt: `contracts.py`, `kernel.py`, `execute.py`,
`authority_pdp.py`, `docs/AUTHORITY_MODEL.md`, `tests/`.

## Path to “standard”

1. Keep this profile stable. Grow adapters, not axioms.
2. Extract a language-agnostic schema (JSON) from `contracts.py` — the
   message, not the Python types.
3. Publish a **conformance pack**: the destructor cases as MUST-fail attacks
   any implementation has to survive (forge, replay, bind mismatch,
   capability≠tool, legitimacy-free mint, PDP field injection).
4. A second implementation (even a thin Rust/Go PEP that verifies the same
   objects) — one repo is a product, two is a standard candidate.
5. Offer the profile to a venue that already owns the front door:
   MCP work-contract / permission spec, AuthZEN PEP profile, A2A “who may
   commit,” AGT ADR for `proof_artefact`. We do not replace those venues.
6. Independent users and an outside review. Outreach is not adoption.

## Path to “infrastructure”

Infrastructure is earned by residuals, not by renaming Stage 1.

| Residual | Why it blocks “infra” |
|---|---|
| TM-A full PARTIAL | Agent with ambient OS rights is still a process, not a jail |
| Multi-machine spent-store | File/SQLite is one volume, not consensus |
| In-process `__wrapped__` / `object.__getattribute__` | Governor is friction; Hosted/OS is the boundary |
| Audit after effect / tail truncation | Crash and rewrite windows remain |
| Single-language TCB | Python reference is not a production kernel |

Do **not** enlarge the kernel to look like an OS. [ROADMAP.md](../ROADMAP.md)
already forbids that. Infra work is isolation, keys, spend, review — around
the same axioms.

## Honest current slice

| Layer | Today |
|---|---|
| Profile axioms in this Python reference | enforced; tests exist |
| Standard (multi-impl + venue) | **not started** |
| Infrastructure (unqualified) | **FAIL / PARTIAL** — do not say otherwise |

If this profile is wrong, the next implementation should break it in public,
not inherit the adjectives.
