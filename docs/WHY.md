# Why Decision OS exists

> Reference core: [`decision_os_min/`](../decision_os_min). See also
> [ARCHITECTURE.md](ARCHITECTURE.md) · [THREAT_MODEL.md](THREAT_MODEL.md) ·
> [TRUST_MODEL.md](TRUST_MODEL.md) · [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md) ·
> [COMPARISON.md](COMPARISON.md) · [README](../README.md)

## The reason: autonomous action needs governance

The age of capable, then AGI-class, then post-AGI systems is an age of
**machines that act** — they will send mail, move money, change production,
call other machines. Intelligence can propose. Something else must decide
whether an effect may happen, **stop it if not**, and leave a record a human
owner can trust.

Prompt instructions are not that something. A general permission engine is
not that something either: it answers *may this principal do this?* and then
the caller is trusted to obey. Autonomous systems are exactly the callers you
should not trust with ambient credentials.

This project exists to put a **property-rights-shaped checkpoint** between
an autonomous actor and the world:

- **Legitimacy** (ownership / consent): *should this happen at all?* DENY-only.
- **Authority** (delegated right): *does this actor hold the capability?*
  Grants only inside legitimacy.
- **Use**: the right is bound to *this* action and spent once.
- **Audit**: the record is not the actor's to edit.

Ethics and morals are **not** compiled into the kernel. They fill the
legitimacy slot as injected policy. The runtime's job is to make that slot
hard to skip. That is a candidate piece of machine–human infrastructure, not
a proof that civilization is saved, AGI is aligned, or a moral theory is true.

## The problem: agents act with ambient authority

An autonomous agent is a process that decides, on its own, to call tools —
send an email, wire money, read a file, hit an API. In the common design the
agent holds the credentials for those tools directly. Whatever the agent (or a
prompt injected into it, or a bug) decides to do, it can do, because the
authority to act is *ambient*: it sits in the calling process and applies to
every action that process takes.

That means:

- There is no mandatory checkpoint between "the agent wants to act" and "the
  effect happens." Policy, if any, is advisory and lives in the same process
  that it is supposed to constrain.
- Authority is coarse. A credential that can send one email can send any email;
  a token that reads one file reads all of them.
- There is no independent, tamper-evident record of *what was authorized and
  why* — logs are written by the same component that took the action and can be
  edited after the fact.

## What this gives you

`decision-os-min` inserts a governance layer between the agent and its tools so
that an effect can only happen through a checkpoint the agent does not control.
Concretely:

- **Mandatory mediation.** A tool runs only via
  [`Executor.execute`](../decision_os_min/execute.py), and only against a
  decision that carries the kernel's Ed25519 signature. No signed decision ⇒ no
  execution (`ExecutionRefused`). The agent cannot route around the checkpoint,
  because the tool functions are handed to the executor, not to the agent.

- **Least privilege via one-time capabilities.** A permitting decision mints a
  single [capability token](../decision_os_min/contracts.py) that is bound to
  one specific action and spent on first use
  ([`Kernel.decide`](../decision_os_min/kernel.py) →
  [`Executor.execute`](../decision_os_min/execute.py)). It is not a standing
  credential; it authorizes exactly one effect, once.

- **Non-repudiable audit.** Every decision is appended to a single
  hash-chained log ([`HashLog`](../decision_os_min/audit.py)) *before* the side
  effect runs. Any retroactive edit, insert, delete, or reorder is detectable by
  `HashLog.verify()`.

- **Graduated enforcement, not just yes/no.** The kernel can ALLOW, DENY, LIMIT
  (redact the payload before the tool sees it), CONTAIN (run only allowlisted
  tools in a sandbox posture), or DEFER (escalate). See
  [ARCHITECTURE.md](ARCHITECTURE.md).

## Who it's for

- Builders putting an autonomous or semi-autonomous agent in front of real
  tools who need a place to enforce **human ownership/consent** that the
  agent cannot bypass.
- Reviewers and auditors who need an independent, verifiable record of what
  was authorized and executed.
- Engineers evaluating the Decision OS approach who want a small, readable
  reference core (stdlib + `cryptography`, no cross-repo machinery) before
  adopting the full multi-repo system.

## What this is *not*

This is the **reference core** — the distilled subset that carries the
security invariants, deliberately small. It does not do distributed
deployment, cross-service orchestration, notary anchoring, or the full
advisory-research layer; those live in the larger multi-repo Decision OS,
which extends the *same* decision logic (see
[README](../README.md#relationship-to-the-full-decision-os)).

It is **not** a Cedar/OPA replacement, a complete ethics engine, or an AGI
safety proof. For an honest account of what it does and does not defend
against, read [THREAT_MODEL.md](THREAT_MODEL.md). For why a Cedar comparison
is still published, and what it is allowed to prove, read
[COMPARISON.md](COMPARISON.md).
