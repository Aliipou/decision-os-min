"""decision-os-min — the distilled core of the Decision OS in one small package.

A single authority (the kernel) signs a decision bound to an action's content and
mints a one-time capability token; the executor runs an effect ONLY against that
signed, bound decision + unspent token; every decision is appended to one
tamper-evident log. That is the whole security model — no control-plane repo, no
advisory layer, no notary, no contracts package.

    from decision_os_min import DecisionOS
    dos = DecisionOS(policy, audit_path="audit.jsonl")
    outcome = dos.handle(action, tools)              # decide -> audit -> execute

`threat_class` is an OPTIONAL advisory hook (a caller may pass one); the kernel —
not the caller — maps it to CONTAIN. Advice is not authority.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .advisors import simple_threat_advisor
from .attenuation import AttenuationError, AuthorityGraph, Macaroon
from .audit import HashLog
from .compose import Evaluator, compose, meet
from .contracts import Action, AuditEntry, CapabilityToken, Decision, Verdict
from .evaluators import LegitimacyPolicy, legitimacy
from .execute import AuditSink, ExecutionRefused, Executor
from .kernel import Kernel, UnfingerprintablePayload, action_fingerprint, verify
from .paradigm import LegitimacyAuthorityPipeline
from .plugins import (
    ContextPlugin,
    Enrichment,
    HeuristicRiskPlugin,
    PIIContextPlugin,
    RiskAssessment,
    RiskPlugin,
    apply_context,
    risk_advisor,
)
from .spentstore import (
    FileSpentStore,
    InMemorySpentStore,
    SpentStore,
    SpentStoreUnavailable,
    SqliteSpentStore,
)

__all__ = [
    "DecisionOS",
    "Outcome",
    "Kernel",
    "Executor",
    "ExecutionRefused",
    "AuditSink",
    "HashLog",
    "SpentStore",
    "FileSpentStore",
    "SqliteSpentStore",
    "InMemorySpentStore",
    "SpentStoreUnavailable",
    "UnfingerprintablePayload",
    "action_fingerprint",
    "verify",
    "simple_threat_advisor",
    "Action",
    "Decision",
    "CapabilityToken",
    "AuditEntry",
    "Verdict",
    "Governor",
    "GovernanceRefused",
    "set_actor",
    "current_actor",
    # plugin SDK (one stable contract; no plugin holds authority)
    "RiskPlugin",
    "ContextPlugin",
    "RiskAssessment",
    "Enrichment",
    "risk_advisor",
    "apply_context",
    "HeuristicRiskPlugin",
    "PIIContextPlugin",
    "LegitimacyAuthorityPipeline",
    # composition primitives (co-equal evaluators -> one verdict, deny-dominant)
    "Evaluator",
    "compose",
    "meet",
    "legitimacy",
    "LegitimacyPolicy",
    # macaroon-inspired attenuation (AE-4 / AE-5)
    "AttenuationError",
    "AuthorityGraph",
    "Macaroon",
]


# The forced-path adoption surface (governed tools). Imported last: govern.py
# consumes DecisionOS (defined above) lazily, so there is no import cycle.
from .govern import GovernanceRefused, Governor, current_actor, set_actor  # noqa: E402
from .host import AgentClient, AgentHost, Intent, locked_agent_docker_cmd, spawn_host  # noqa: E402
from .sealed import (  # noqa: E402
    AdmissionError,
    AdmissionOffice,
    AdmissionTicket,
    EvidenceRecord,
    SealedBreach,
    SealedRefused,
    SealedRuntime,
    poison,
    tri_state_legitimacy,
)

__all__ += [
    "AgentClient",
    "AgentHost",
    "Intent",
    "locked_agent_docker_cmd",
    "spawn_host",
    "AdmissionError",
    "AdmissionOffice",
    "AdmissionTicket",
    "EvidenceRecord",
    "SealedBreach",
    "SealedRefused",
    "SealedRuntime",
    "poison",
    "tri_state_legitimacy",
]


@dataclass
class Outcome:
    verdict: str
    executed: bool
    output: Any = None
    refused_reason: str | None = None


class DecisionOS:
    """The whole system, composed. A single decision does not require standing up
    an OS — it is one method call."""

    def __init__(self, policy: dict[str, Any], *, audit_path: str) -> None:
        self.kernel = Kernel(policy)
        self.log = HashLog(audit_path)
        # The executor OWNS the audit write now (HB-3): it records exactly one
        # entry per execute() — executed or refused — so no effect runs unlogged.
        self.executor = Executor(self.kernel.public_key_hex(), self.log)

    def grant(self, actor: str, capability: str) -> None:
        self.kernel.grant(actor, capability)

    def revoke(self, actor: str, capability: str) -> None:
        self.kernel.revoke(actor, capability)

    def delegate(
        self,
        parent: str,
        child: str,
        tools: list[str],
        *,
        expires_at: datetime | None = None,
    ) -> Macaroon:
        return self.kernel.delegate(parent, child, tools, expires_at=expires_at)

    def handle(
        self,
        action: dict[str, Any],
        tools: dict[str, Callable[[dict[str, Any]], Any]],
        threat_class: str | None = None,
        *,
        advisor: Callable[[dict[str, Any]], str | None] | None = None,
        evaluators: list[Callable[[dict[str, Any]], dict[str, Any] | str]] | None = None,
    ) -> Outcome:
        # One action passes THREE gates against ONE central policy — the gate
        # philosophy of the full system, collapsed into one call (not one gate
        # per repo). Simplify the layers, keep the gate-passes.

        # Gate 1 — pre-decision (inside the kernel): identity/capability + purpose.
        # Gate 2 — pre-execution (inside the executor): signature + action binding
        #          + one-time token. Both are enforced by the calls below.
        result = self.kernel.decide(
            action, threat_class, advisor=advisor, evaluators=evaluators
        )
        decision = result["decision"]

        # Gate 3 — audit/commit is now enforced INSIDE the executor (HB-3): a
        # single audit entry is written per execute() with the executed/refused
        # outcome and a payload digest (W-3), so the record reflects what actually
        # happened, not just the pre-execution verdict. The executor writes even on
        # refusal, so both branches below are already audited.
        try:
            output = self.executor.execute(action, result, tools)   # Gate 2 + audit + effect
            return Outcome(decision["verdict"], True, output)
        except ExecutionRefused as e:
            # Surface the decision's reason (veto text) alongside the mechanical
            # PEP refusal — same discipline as AE-10 audit fidelity.
            why = decision.get("reason") or ""
            refused = f"{why} [refused: {e}]" if why else str(e)
            return Outcome(decision["verdict"], False, refused_reason=refused)
