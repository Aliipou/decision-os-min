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

## FDK (freedom-decision-kernel) — the "other branch" ⚠ REOPENED / UNDER RE-EVALUATION

**Status corrected 2026-08-10.** This section used to read "CLOSED — negative result,
do not reopen," quoting `STATUS.md` (2026-06-20). That framing was OVERSTATED and was
retracted in the 2026-07-05 correction sweep (READMEs + RFC-100 were fixed then; this
file was missed). The accurate status:

- **Independence from Nozick / Pettit / Sen is NOT demonstrated — and NOT refuted.**
  The honest claim was always "independence not established under the then-available
  evidence," which is undetermined, not false. New evidence was subsequently entered
  (the green-team defense, `paper/SYMPOSIUM.md`, and the killer-test / predictive-test
  program), and a symposium found the earlier red-teams had OVERCLOSED in two places,
  both empirical. So: **OPEN / under active re-evaluation.** Assert neither "closed"
  nor "proven."
- **Research layer — FINISHED as engineering** (frozen kernel, four-checker
  verification, 100% coverage); kept as an engineering + honest-research showcase.
  "Finished building" is not "settled question."
- **Lock-in Analytics tool — BUILT, frozen pending real data.** The reversibility
  construct is **undecided, not killed**: the r² = 0.97 result was traced to a seed
  artifact, and a cheap outcome-free discriminant test was identified but never run.
- Open items remain: the real-world **ownership ontology** ("the hardest part") and the
  **attested→detected gap** for `coerced` / `deceived` — the gate trusts flags it
  cannot itself verify.

**What this does NOT change:** the strategy here is unaffected either way. This runtime
is deliberately **theory-agnostic** — the legitimacy rule is injected policy, never
baked into the kernel — so it neither depends on FDK being right nor benefits from its
being wrong. That independence is the point of the seam, and it is why the runtime was
frozen before any normative layer was built.

## Standing principles (apply to every phase)
- Never mix policy with mechanism (the most important rule).
- Every security claim → a test / PoC.
- No "first / revolutionary / alignment-solved" claims before evidence.
- Update the threat model *before* adding a capability.
- Build phases independently; each ships a testable artifact.
