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
from typing import Any

from .advisors import simple_threat_advisor
from .audit import HashLog
from .contracts import Action, AuditEntry, CapabilityToken, Decision, Verdict
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
]


# The forced-path adoption surface (governed tools). Imported last: govern.py
# consumes DecisionOS (defined above) lazily, so there is no import cycle.
from .govern import GovernanceRefused, Governor, current_actor, set_actor  # noqa: E402


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

    def handle(
        self,
        action: dict[str, Any],
        tools: dict[str, Callable[[dict[str, Any]], Any]],
        threat_class: str | None = None,
        *,
        advisor: Callable[[dict[str, Any]], str | None] | None = None,
    ) -> Outcome:
        # One action passes THREE gates against ONE central policy — the gate
        # philosophy of the full system, collapsed into one call (not one gate
        # per repo). Simplify the layers, keep the gate-passes.

        # Gate 1 — pre-decision (inside the kernel): identity/capability + purpose.
        # Gate 2 — pre-execution (inside the executor): signature + action binding
        #          + one-time token. Both are enforced by the calls below.
        result = self.kernel.decide(action, threat_class, advisor=advisor)
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
            return Outcome(decision["verdict"], False, refused_reason=str(e))
