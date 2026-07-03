# Decision OS vs. the alternatives — for governing AI-agent tool execution

This is an honest positioning of Decision OS (and its reference core
`decision-os-min`) against the real alternatives, for one specific use case. It is
written to be defensible, not flattering: where existing tools are more mature, it
says so; where Decision OS genuinely differs, it says why; and it names the prior
art that is converging on the same idea.

## The use case, precisely

> An autonomous AI agent proposes tool calls (send an email, issue a refund, query
> a record). Something must decide, per action, whether it may run — and if so
> under what constraints — then **mediate execution** and leave a **non-repudiable
> record**. The agent, its planner, and the transport are all **untrusted**.

That is narrower than "authorization" in general. It has four sub-problems:
**identity** (who is the agent), **decision** (may this action run), **enforcement**
(actually stop it, before side effects), and **audit** (prove what happened).

## The alternative landscape (as of mid-2026)

| Category | Representative tools | What layer it solves |
|---|---|---|
| Agent identity / token issuance | **MCP authorization** (OAuth 2.1 resource server, RFC 9728 metadata, RFC 8707 audience binding), Auth0 "Auth for MCP", SPIFFE/SPIRE | identity + scoped bearer tokens |
| Policy decision engines | **OPA/Rego**, **AWS Cedar** (formally analyzable), **OpenFGA/SpiceDB** (Zanzibar ReBAC), Oso, Casbin | the decision (allow/deny), rich policy languages |
| Capability tokens | **Macaroons** (HMAC caveats, attenuation), **Biscuit** (signed blocks + Datalog, offline verify) | attenuable, delegatable authority carried in a token |
| Enforcement points | Envoy `ext_authz`, service-mesh authz, API gateways, **MCP tool annotations** (`readOnly`/`destructive`), Anthropic Claude Managed Agents (hosted sandboxing) | stopping/ gating the call; sandboxed execution |
| Tamper-evident audit | Sigstore **Rekor** / Trillian (Merkle transparency logs) | non-repudiable, append-only records |
| Emerging agent-native research | **Agent Identity Protocol (AIP)** — verifiable delegation; **Agent Control Protocol** — "admission control for agent actions"; Vouchsafe | the whole agent-action-governance problem |

**Nobody ships all four sub-problems as one small coherent thing tuned for agent
tool-execution** — the mature options are each strong at one layer. That gap is the
only reason Decision OS is interesting; it is also why "just assemble the mature
pieces" is a serious alternative (see below).

## How Decision OS compares, dimension by dimension

| Dimension | Decision OS (`decision-os-min`) | Best-in-class alternative | Honest read |
|---|---|---|---|
| **Decision expressiveness** | Small deterministic engine (grants + purpose + redaction + containment) | OPA/Rego, Cedar (Cedar is *formally analyzable*) | **Alternatives win.** Our engine is deliberately tiny; it is not a policy language. |
| **Identity / token infra** | Minimal (capability grants; AuthGate in the full system) | MCP OAuth 2.1, Auth0, SPIFFE | **Alternatives win** on standards, refresh, discovery, ecosystem. |
| **Capability token** | One-time, **bound to the exact action content** (`action_fingerprint`), Ed25519 | Macaroons/Biscuit (attenuable, reusable within caveats) | **Different.** Macaroons/Biscuit are more flexible (delegation, offline attenuation); ours is stricter — single-use and content-bound, which kills token re-use across actions. |
| **Enforcement (PEP)** | **Mandatory** — the executor runs nothing without a signed decision + unspent bound token | OPA is a *decision point only* (you build the PEP); Envoy/gateways enforce at network layer | **Comparable/edge.** Coupling the PEP to a one-time content-bound token is stronger than a typical "ask the PDP, then trust yourself to obey." |
| **Verdict richness** | ALLOW / DENY / **LIMIT (redact payload)** / **CONTAIN (sandbox)** / DEFER | Binary allow/deny; Cedar/OPA emit *obligations* you enforce; MCP annotations gate `destructive` tools | **Edge.** Graduated, enforced verdicts (redaction + containment) are baked in, not left to the caller. |
| **AI/ML risk separation** | **Advisory ≠ authority**: an advisor may only *tighten*, never author a verdict | Rarely formalized; most guardrail tools blur "the model flagged it" with "the system decided" | **Distinctive framing.** Keeps ML out of the deterministic decision path by construction. |
| **Audit** | Integrated hash-chained, tamper-evident log (one truth) | Rekor/Trillian (distributed, witnessed, battle-tested) | **Alternatives win on maturity**; ours wins on being built-in and single-source. |
| **Maturity / scale / ecosystem** | Prototype, single-process, <2 months old | CNCF-graduated, standardized, enterprise-deployed | **Alternatives win decisively.** No contest today. |

## Where Decision OS is genuinely differentiated

Two things are not standard in the off-the-shelf stack:

1. **Action-content binding as a first-class confused-deputy defense.** MCP's RFC
   8707 binds a token to its *audience* (which server). Macaroons attenuate scope.
   Decision OS binds the signed decision **and** the one-time token to a hash of the
   *specific action's* actor+capability+purpose+labels+payload, and the executor
   recomputes and checks it. A valid authorization cannot be re-attached to a
   different (e.g. denied) action. This directly counters an agent/transport that
   swaps the action after approval — a threat our own red-team demonstrated and
   this closes.
2. **The advisory/authority split.** ML threat scoring is a *plugin that suggests*;
   the deterministic kernel decides. This is a clean answer to "how do I use a risk
   model without letting it become the security boundary."

Everything else — Ed25519 signing, capability tokens, policy evaluation, hash
chains — **exists elsewhere and is more mature.** We are not claiming to beat OPA
at policy or MCP at identity.

## Evidence for every claim (nothing here is asserted without a test)

Every ✅ below points to the enforcing code **and** a runnable test. Reproduce all
of it with `python -m pytest -v` in `decision-os-min`, or `python examples/demo.py`.
`~` = partial / depends on other layers; `❌` = **not in that tool's scope**.

> **Read `❌` as a scope boundary, not a defect.** OPA is a *policy decision point*
> by design — it deliberately does not mint tokens, enforce, or keep a
> tamper-evident log, and it is excellent at what it does. MCP OAuth is an
> *identity/authorization-token* layer, not an execution monitor. Comparing them on
> capabilities outside their remit would be unfair; the table maps *which layer
> owns what*, and where Decision OS spans several layers as one unit.

| Capability | Decision OS | OPA / Cedar | MCP OAuth (2026) | Macaroons / Biscuit | Evidence (file · test) |
|---|:--:|:--:|:--:|:--:|---|
| Signed decision from a single authority | ✅ | ~ (computes, doesn't sign a capability) | ✅ (identity token, not per-decision) | ✅ (token *is* authority) | `kernel.py:verify` · `test_forged_decision_refused` |
| **Action-content binding** (confused-deputy) | ✅ | ❌ | ~ binds token to *audience* (RFC 8707), not action content | ~ impl-dependent caveats | `kernel.action_fingerprint` + `execute.py` · `test_confused_deputy_refused` |
| **One-time token / replay protection** | ✅ | ❌ (no token) | ❌ (bearer, reusable within TTL) | ~ needs an added nonce layer | `execute.py:_spent` · `test_replayed_token_refused` |
| Capability forgery refused | ✅ | ~ | ✅ | ✅ | `execute.py:verify` · `test_forged_token_refused` |
| Graduated verdicts: LIMIT (redact) / CONTAIN (sandbox) | ✅ | ~ (obligations you enforce) | ~ (annotations gate `destructive`) | ❌ | `test_limit_redacts_before_the_tool`, `test_contain_refuses_sensitive_tool` |
| Advisory ≠ authority (ML can only tighten) | ✅ | n/a | n/a | n/a | `decide(advisor=)` · `test_advisory_never_loosens_a_deny`, `test_advisor_plugin_can_only_tighten` |
| **Tamper-evident audit, built in** | ✅ | ❌ (decision logs, not tamper-evident) | ❌ (external SIEM) | ❌ | `audit.py:verify` · `test_audit_tamper_detected` |
| Mandatory enforcement (PEP bound to token) | ✅ | ❌ (PDP only; you build the PEP) | ~ (gateway) | ❌ (token only) | `execute.py` · `test_deny_blocks`, `examples/demo.py` |
| Reference↔enterprise behavioral lock | ✅ | n/a | n/a | n/a | `decision-os-integration/tests/test_conformance_min_vs_core.py` |
| **Policy-language maturity** | ❌ (tiny engine) | ✅✅ (Cedar is *formally analyzable*) | n/a | n/a | — (we concede this) |
| **Identity / ecosystem / standardization** | ❌ (minimal) | ~ | ✅✅ (OAuth 2.1 standard) | ~ | — (we concede this) |
| **Production maturity / scale** | ❌ (prototype, <2 months) | ✅✅ | ✅✅ | ✅ | — (we concede this) |

The last three rows are losses, stated plainly. A comparison that only listed our
wins would not be credible.

## The strongest counter-argument: assemble, don't build

A principal engineer would rightly say: you could get ~80% of this by composing
**Cedar** (decisions, formally analyzable) + **Biscuit** (attenuable capability
tokens) + **MCP OAuth** (identity) + **Rekor** (transparency log) + an
**enforcement gateway**. That is true, and it would be more battle-tested. Decision
OS's honest value proposition is therefore *not* "better primitives" but:

- **one small, auditable, deterministic core** with agent-specific semantics
  (content-binding, graduated verdicts, advisory-split) already integrated, and
- a **reference/enterprise split** locked by a conformance test so the simple and
  scaled versions cannot diverge in behavior.

Whether that opinionated integration is worth owning versus assembling mature parts
is a real, open question — not one this project has yet earned the right to answer
with external evidence.

## Prior art and convergence (validation *and* competition)

The 2026 research direction is converging on exactly this problem: **"Agent Control
Protocol: Admission Control for Agent Actions"** and the **Agent Identity Protocol**
describe verifiable, per-action admission and delegation for agents. This is
**good** (the direction is real, not idiosyncratic) and **sobering** (well-resourced
groups are formalizing it). Decision OS's edge, if any, is being small and
runnable today — not being first or most rigorous.

## Claims we deliberately do NOT make

Until there is external review, real deployment, and independent attack, these
sentences are unearned and appear nowhere in this project's docs:

- ❌ "Decision OS is the first…" — the [Agent Control Protocol](https://arxiv.org/pdf/2603.18829) and [AIP](https://arxiv.org/pdf/2603.24775) are working the same problem.
- ❌ "Revolutionary / next-generation…" — the primitives are standard; only the composition is opinionated.
- ❌ "Solves AI safety…" — it governs *tool execution*, one narrow slice.
- ❌ Any performance claim without the numbers to back it (see `BENCHMARKS.md` once measured).

Conceding that OPA/Cedar lead on policy language and MCP leads on ecosystem
standardization is not a weakness of this document — it is what makes the rest of
it trustworthy.

## Bottom line

For the agent-tool-execution use case, Decision OS is best understood as an
**opinionated reference architecture** that integrates known-good primitives with
two arguably-distinctive ideas (action-content binding, advisory/authority split).
It is **not** a mature substitute for OPA/Cedar/MCP-OAuth/Rekor, and it should not
claim to be until it has external review, real deployment, and independent attack.
Its near-term value is as a **clear, minimal, auditable model** — for teaching, for
a starter, and for comparison against the assembled-from-parts approach.

---

### Sources

- [The biggest MCP spec update ships July 28: agent authentication (WorkOS)](https://workos.com/blog/mcp-2026-spec-agent-authentication)
- [Securing AI agents with MCP Authorization (Google Cloud)](https://medium.com/google-cloud/securing-ai-agents-with-mcp-authorization-5cd8a552c45b)
- [Best Authentication Platforms for AI Agents and MCP Servers in 2026 (MarkTechPost)](https://www.marktechpost.com/2026/05/25/best-authentication-platforms-for-ai-agents-and-mcp-servers-in-2026/)
- [MCP Access Control: OPA vs Cedar (Natoma)](https://natoma.ai/blog/mcp-access-control-opa-vs-cedar-the-definitive-guide)
- [Cedar vs Rego vs OpenFGA: Policy Language Comparison (sph.sh)](https://sph.sh/en/posts/policy-language-comparison-cedar-rego-openfga/)
- [Policy Engine Showdown — OPA vs OpenFGA vs Cedar (Permit.io)](https://www.permit.io/blog/policy-engine-showdown-opa-vs-openfga-vs-cedar)
- [AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A (arXiv)](https://arxiv.org/pdf/2603.24775)
- [Agent Control Protocol: Admission Control for Agent Actions (arXiv)](https://arxiv.org/pdf/2603.18829)
