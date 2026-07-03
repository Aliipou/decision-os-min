# Roadmap — and the discipline that governs it

`decision-os-min` is **Stage 1** of a much longer, deliberately unhurried path. The
single rule that governs everything below:

> **The core stays small, stable, and validatable. OS-scale capabilities are a
> separate, future R&D track — added only when a real problem demands them, never
> by growing the kernel.** The name "Decision OS" is *earned* at the later stages,
> not claimed now.

The trap to avoid (where projects like this usually die): asking *"what does an OS
have?"* and bolting on a scheduler, memory manager, and IPC for resemblance. The
only valid question is *"what does the problem actually require next?"*

## Stages

| Stage | Scope | Status |
|---|---|---|
| **1 — Decision Authority Kernel** | single-authority signed decisions, action-binding, one-time capability tokens, PEP, tamper-evident audit | ✅ **done** (this repo, v0.1.0) |
| **2 — Agent Runtime** | agent sessions, lifecycle, resource limits | 🔬 future R&D (separate track) |
| **3 — Multi-Agent Coordination** | scheduling, isolation, message passing | 🔬 future R&D |
| **4 — Distributed Runtime** | cluster, remote execution, federation | 🔬 future R&D |
| **5 — "Decision OS"** | the point where the name is technically defensible: managing agents like an OS (scheduling, isolation, comms, lifecycle, policy enforcement) | 🎯 aspirational |

Stages 2–5 are **years** of work, not months. They belong in a **separate
experimental repo** (e.g. `decision-os-lab` / `decision-runtime`), created only
when Stage 2 has a concrete requirement — so the kernel is never destabilized by
research.

## What comes before *any* of Stage 2

None of the above matters until the Stage-1 core proves its worth. The next
milestones are **validation, not construction**:

1. Independent users (3–5) actually installing and using it.
2. An empirical comparison vs OPA / Cedar / MCP on a shared workload.
3. Fixing what real users find.
4. Independent review / a technical write-up with evidence.

Only if the core earns its place does the OS track become worth starting. Until
then this file is a *direction*, not a backlog.
