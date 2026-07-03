# Phased plan — honest status

The disciplined order: **freeze the value-neutral runtime first, then add normative
layers as policy.** No policy ever lives in the runtime. Below is every phase with
its real status.

## Phase 0 — Freeze the runtime ✅ DONE
Value-neutral, theory-independent. Public, released (v0.1.0), tested.
- [x] Kernel (single authority, signed decisions, action-binding)
- [x] PEP / executor (mandatory mediation, one-time tokens)
- [x] Audit (tamper-evident hash chain)
- [x] Capability model
- [x] Plugin SDK (RiskPlugin / ContextPlugin — advisory only)
- [x] **Rule: no policy inside the runtime** — held.

## Phase 1 — Formal specification ✅ MOSTLY DONE
- [x] **Authority Graph** — `docs/AUTHORITY_MODEL.md` (who may decide / execute / audit; the pipeline)
- [x] **Threat Model** — `docs/THREAT_MODEL.md` (attacker capabilities, defended vs residual)
- [x] Security invariants INV-1..6 (each with a test)
- [x] Trust model, design principles (10), comparison, constraint-vs-intelligence hypothesis
- [ ] Per-layer *forbidden-actions* table (Admission/Context/Kernel/PEP) — partial; could be sharpened

## Phase 2+ — Normative layers ⏸ PARKED (do NOT build yet)
Rights Ontology · Consent Logic · Ownership Calculus · Justice Optimizer · Rule
Evolution · Goal Layer (Mahdavi Objective). Seed only: `freedom-policy` (local,
unpushed, `ownership.py` + a "not ready" README).
- **Author's ruling: not yet** — the theory must first be stabilized philosophically,
  its axioms defined precisely, and its own threat model + invariants written.
  Encoding it now = rework in months. Each layer is a paper-sized project.

## FDK (freedom-decision-kernel) — the "other branch" ❌ CLOSED / DONE (negative result)
Checked branch `paradigm/stages-2-9`. Its own `STATUS.md` (2026-06-20, a deliberate
closure) records:
- **Theory of Freedom — CLOSED, negative result published.** It "did not survive its
  own attacks; reduces to Nozick / Pettit / Sen," and the surviving "reversibility"
  idea is "a reparameterization of the existing lock-in literature (≈ switching
  cost)." **Explicitly: do not reopen.**
- **Research layer — FINISHED** (frozen kernel, four-checker verification, 100%
  coverage) — kept as an engineering + honest-research showcase.
- **Lock-in Analytics tool — BUILT, frozen pending real data.**
- Open TODO items remain (real-world **ownership ontology** — "the hardest part"; the
  **attested→detected gap** for `coerced`/`deceived`), but flagged blocked / do-not-reopen.

**So: the FDK theory work is done — as a rigorously-closed negative result.** That is
itself the strongest evidence for the current strategy: the value is the
**theory-agnostic runtime**, not any one normative theory.

## Standing principles (apply to every phase)
- Never mix policy with mechanism (the most important rule).
- Every security claim → a test / PoC.
- No "first / revolutionary / alignment-solved" claims before evidence.
- Update the threat model *before* adding a capability.
- Build phases independently; each ships a testable artifact.
