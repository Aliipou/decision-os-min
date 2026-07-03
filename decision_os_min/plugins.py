"""Plugin SDK — ONE stable contract for extensions. No plugin holds authority.

Two plugin kinds, one contract each. By construction a plugin can only return
*advice* or *context* — never a decision, a token, or a policy change:

    RiskPlugin.analyze(action)  -> RiskAssessment   (a score + evidence)
    ContextPlugin.enrich(action) -> Enrichment      (adds labels/metadata only)

The two enforced invariants (see DESIGN_PRINCIPLES §4, §10):
- **Risk can only tighten.** Risk plugins are composed into the kernel's advisor
  seam; a high score maps to CONTAIN, never to a permit. A plugin cannot loosen a
  DENY.
- **Context can only add.** Enrichment unions `data_labels` and adds metadata; it
  can never change actor / capability / tool / purpose, so it cannot spoof
  identity or widen authority — only give the kernel *more* to gate on.

Plugins never execute tools (that is the PEP) and never see the signing key.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class RiskAssessment:
    """A risk plugin's output. Advice, not a decision."""

    score: float                                  # 0.0 (safe) .. 1.0 (dangerous)
    evidence: list[str] = field(default_factory=list)
    recommended: str | None = None                # a HINT only (e.g. "LIMIT"/"CONTAIN")


@dataclass
class Enrichment:
    """A context plugin's output. Additive only."""

    data_labels: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class RiskPlugin(Protocol):
    name: str

    def analyze(self, action: dict[str, Any]) -> RiskAssessment: ...


@runtime_checkable
class ContextPlugin(Protocol):
    name: str

    def enrich(self, action: dict[str, Any]) -> Enrichment: ...


# --- composition into the core (the ONLY way a plugin reaches a decision) ----
def risk_advisor(*plugins: RiskPlugin, contain_at: float = 0.8, suspect_at: float = 0.4):
    """Compose risk plugins into ONE kernel advisor `(action) -> threat_class`.
    Takes the MAX score across plugins; maps it to a threat class the kernel MAY
    act on. Tighten-only: it can never return a permit."""

    def advise(action: dict[str, Any]) -> str | None:
        worst = 0.0
        for p in plugins:
            try:
                worst = max(worst, p.analyze(action).score)
            except Exception:  # a broken risk plugin cannot break the decision
                continue
        if worst >= contain_at:
            return "malicious"      # kernel maps -> CONTAIN
        if worst >= suspect_at:
            return "suspicious"
        return None

    return advise


def apply_context(action: dict[str, Any], *plugins: ContextPlugin) -> dict[str, Any]:
    """Return a copy of `action` enriched by context plugins. Additive only:
    unions data_labels and adds metadata; NEVER touches actor/capability/tool/
    action_purpose — so context cannot spoof identity or widen authority."""
    enriched = dict(action)
    labels = set(enriched.get("data_labels") or [])
    meta = dict(enriched.get("context") or {})
    for p in plugins:
        try:
            e = p.enrich(action)
        except Exception:
            continue
        labels |= set(e.data_labels)           # union: only ever ADD labels
        meta.update(e.metadata)                # additive metadata
    enriched["data_labels"] = sorted(labels)
    enriched["context"] = meta
    return enriched


# --- reference implementations (so the contract is concrete + tested) --------
class HeuristicRiskPlugin:
    """A deterministic reference risk scorer. Real model? Same contract."""

    name = "heuristic-risk"
    _WEIGHTS = {"known_bad_actor": 0.9, "capability_probing": 0.4, "irreversible": 0.6}

    def analyze(self, action: dict[str, Any]) -> RiskAssessment:
        signals = list(action.get("signals") or action.get("_signals") or [])
        score = min(1.0, sum(self._WEIGHTS.get(s, 0.05) for s in signals))
        rec = "CONTAIN" if score >= 0.8 else ("LIMIT" if score >= 0.4 else None)
        return RiskAssessment(score=round(score, 3), evidence=signals, recommended=rec)


class PIIContextPlugin:
    """A reference context plugin: flags PII in the payload by adding a label."""

    name = "pii-context"
    _PII = {"ssn", "card", "passport", "dob"}

    def enrich(self, action: dict[str, Any]) -> Enrichment:
        payload = action.get("payload") or {}
        hits = sorted(self._PII & set(payload))
        if hits:
            return Enrichment(data_labels=["pii"], metadata={"pii_fields": hits})
        return Enrichment()
