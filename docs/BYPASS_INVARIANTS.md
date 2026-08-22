# Bypass / Sealed Invariants — Status (2026-08-22)

## Claim (precise)

**Sealed surface (`SealedRuntime`): PASS** for
`Executed ⇒ admitted ∧ legitimacy ∧ authority ∧ PEP` on tools that entered `seal()`.

**Process-wide / ambient Python: FAIL** — callables never passed to `seal()` retain
IO capability. Closing that requires OS redesign (seccomp, no ambient credentials,
mandatory interceptor), not more library axioms.

**Infrastructure-grade (unqualified): FAIL / PARTIAL** — do not claim globally.

## Evidence

| Suite | Path |
|---|---|
| Destructor (real execution attempts) | `tests/test_destructor_sealed.py` |
| NovaPulse multi-stakeholder | `tests/test_adversarial_novapulse.py`, `examples/adversarial_novapulse.py` |
| Implementation | `decision_os_min/sealed.py`, M5 fields in `kernel.py` / `compose.py` |

## Attack class table (sealed surface)

| Attack Class | Final Status |
|---|---|
| Raw reference (poisoned source) | PASS |
| Export / `__wrapped__` | PASS |
| Registry mutation | PASS |
| Actor spoofing (`set_actor`) | PASS (tickets required) |
| Ticket forgery / replay / substitution | PASS |
| Capability substitution | PASS |
| Decision token replay | PASS |
| Confused deputy | PASS |
| Stale FDK / strip binding | PASS |
| Shared spent-store replica | PASS |
| Ambient unsealed callable | FAIL (architectural) |

## One question

**Can an adversarial agent obtain real execution on the sealed tool plane without
legitimacy + authority + PEP + admission?** → **NO** (destructor + NovaPulse).

**Can it obtain execution via ambient Python outside seal()?** → **YES** →
unqualified infrastructure claim remains **FAIL/PARTIAL**.
