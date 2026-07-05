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
