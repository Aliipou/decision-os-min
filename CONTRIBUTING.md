# Contributing

This project runs on a specific discipline. Reading this first will save you time.

## The rule that matters most: try to break it, not to defend it

A change is reviewed by attacking it. If you add a security-relevant mechanism,
the expected companion is a test that tries to defeat it — not a test that
demonstrates it working. An argument that something is safe is worth less than a
runnable exploit that fails.

Corollary, learned the hard way: **fix the mechanism, never the demonstrated
variant.** A defect found in one construction is a defect in the class. Patching
the exact input that was shown to you produces a fix that the next construction
walks straight through.

## Claims

Conservative by default. Do not write "production-ready", "first", "solves X",
"formally verified", or an unmeasured percentage, unless the repo contains the
evidence for it. Where a claim is aspirational, label it aspirational. Where a
result is negative, keep it — negative results are not failures here, and several
of this project's most useful conclusions are negative.

Attribute prior art explicitly. If a mechanism already exists under another name,
say so and cite it; adopting an established primitive is preferred over inventing
a new one.

## Before you open a PR

- Tests pass, and new behaviour has a test that would fail without it.
- Lint and type checks pass (`ruff check .`, `mypy` where configured).
- Public-facing docs updated in the same change, not "later".
- Commit messages explain WHY, not what — the diff already says what.

## History

History is not rewritten. No force-push to shared branches. Commit SHAs are cited
from design documents and reviews, so rewriting them invalidates the record of how
a decision was reached — which in this project is often worth more than the code.

## Security

Do not open a public issue for a vulnerability. See `SECURITY.md`.
