# Why Decision OS exists

> Reference core: [`decision_os_min/`](../decision_os_min). See also
> [ARCHITECTURE.md](ARCHITECTURE.md) · [THREAT_MODEL.md](THREAT_MODEL.md) ·
> [TRUST_MODEL.md](TRUST_MODEL.md) · [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md) ·
> [README](../README.md)

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
  tools who need a place to enforce policy that the agent cannot bypass.
- Reviewers and auditors who need an independent, verifiable record of what was
  authorized.
- Engineers evaluating the Decision OS approach who want a small, readable
  reference core (stdlib + `cryptography`, no cross-repo machinery) before
  adopting the full multi-repo system.

## What this is *not*

This is the **reference core** — the distilled subset that carries the security
invariants, deliberately small. It does not do distributed deployment,
cross-service orchestration, notary anchoring, or the full advisory-research
layer; those live in the larger multi-repo Decision OS, which extends the *same*
decision logic (see [README](../README.md#relationship-to-the-full-decision-os)).
For an honest account of what it does and does not defend against, read
[THREAT_MODEL.md](THREAT_MODEL.md).
