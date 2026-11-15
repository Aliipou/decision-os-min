# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities in **decision-os-min** privately. Do **not**
open a public issue for a suspected vulnerability.

- Preferred: open a private advisory via GitHub Security Advisories
  ("Security" tab → "Report a vulnerability") on this repository.
- Alternatively, email the maintainer at **nikzadpars@gmail.com** with the
  details and, where possible, a minimal reproduction.

Please include:

- a description of the issue and its impact,
- the affected version or commit,
- steps to reproduce (a runnable proof-of-concept is ideal),
- any known mitigations.

## What to expect

- We aim to acknowledge a report within **7 days**.
- We will keep you informed as we investigate and work on a fix.
- We ask that you give us a reasonable opportunity to release a fix before any
  public disclosure (coordinated disclosure).

There is **no bug-bounty program**; this project offers no monetary reward for
reports. We are grateful for responsible disclosure and will credit reporters
who wish to be acknowledged.

## Operational security model (what you must configure)

| Asset | Risk | Control |
|---|---|---|
| Signing key (`DECISION_OS_KEY_FILE` / `key_path`) | Anyone holding it can mint valid decisions | Created with mode 0600 via `O_EXCL` (race-safe, never world-readable); keep it on a volume only the kernel process can read; rotate by deploying a new key and treating older decisions as expired (they live 30s). Without `key_path` the identity is ephemeral and restarts invalidate every outstanding decision. |
| Spent-token store | In-memory store lets a captured decision be replayed after restart or on another replica | Use `FileSpentStore` / `SqliteSpentStore` on one shared volume (atomic, fsync'd, fails closed with `SpentStoreUnavailable`). It is not distributed consensus: replicas on separate disks would each accept a token once; implement `SpentStore` over a shared DB/Redis for that. Covered by the multi-process test in `tests/test_identity_and_concurrency.py`. |
| Audit log | Tampering or truncation | Hash-chained append-only log; ship copies off-host, since an attacker with disk write can truncate the tail. |
| Agent process | Bypassing the executor | The guarantee holds only if the agent cannot reach the tools except through the executor (see `docs/HOSTED_AGENT_PLANE.md`). |

Out of scope: a compromised kernel host, a malicious policy author, and side channels.

## Supported versions

This project is pre-1.0 and under active development. Only the latest released
version on the default branch receives security fixes.

## Scope

This repository is one component of the Decision OS. Its security properties are
verified in isolation and, where applicable, under the cross-repo composition
harness. See the repository `README.md` for the documented scope and honest
limitations of the threat model — in particular, guarantees that hold in
isolation may depend on assumptions about how the component is deployed and
composed.
