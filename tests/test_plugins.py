"""Plugin SDK: one contract, and the invariant that plugins hold no authority."""

from __future__ import annotations

from decision_os_min import (
    ContextPlugin,
    DecisionOS,
    Enrichment,
    HeuristicRiskPlugin,
    PIIContextPlugin,
    RiskAssessment,
    RiskPlugin,
    apply_context,
    risk_advisor,
)

POLICY = {
    "grants": {"agent:bot": ["tool:send_email"]},
    "purpose_bindings": {"customer_support": ["support_reply"], "pii": []},  # pii binds nothing
    "contain_threat_classes": ["malicious"],
    "default": "deny",
}


def _action(**kw):
    base = {
        "actor": "agent:bot", "tool": "send_email", "capability": "tool:send_email",
        "action_purpose": "support_reply", "data_labels": ["customer_support"],
        "payload": {}, "nonce": "n-1",
    }
    base.update(kw)
    return base


# --- the contract ----------------------------------------------------------
def test_reference_plugins_satisfy_the_protocols():
    assert isinstance(HeuristicRiskPlugin(), RiskPlugin)
    assert isinstance(PIIContextPlugin(), ContextPlugin)


def test_risk_assessment_is_bounded_and_advisory():
    a = HeuristicRiskPlugin().analyze(_action(signals=["known_bad_actor"]))
    assert isinstance(a, RiskAssessment) and 0.0 <= a.score <= 1.0
    assert a.recommended == "CONTAIN"          # a HINT — not a decision


# --- risk composes into the kernel and can ONLY tighten --------------------
def test_risk_advisor_tightens_allow_to_contain(tmp_path):
    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "a.jsonl"))
    advisor = risk_advisor(HeuristicRiskPlugin())
    out = dos.handle(_action(signals=["known_bad_actor"]), {"send_email": lambda p: "x"},
                     advisor=advisor)
    assert out.verdict == "CONTAIN" and out.executed is False


def test_risk_advisor_cannot_manufacture_a_permit(tmp_path):
    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "a.jsonl"))
    # A plugin that screams "safe!" cannot turn a capability-DENY into a permit.
    class AlwaysSafe:
        name = "safe"
        def analyze(self, action):
            return RiskAssessment(score=0.0, recommended="ALLOW")

    out = dos.handle(_action(capability="tool:wire_money", tool="wire_money"),
                     {"wire_money": lambda p: "x"}, advisor=risk_advisor(AlwaysSafe()))
    assert out.verdict == "DENY" and out.executed is False


# --- context can only ADD, never spoof or loosen ---------------------------
def test_context_enrichment_adds_labels_only():
    action = _action(payload={"ssn": "123"})
    enriched = apply_context(action, PIIContextPlugin())
    assert "pii" in enriched["data_labels"]
    assert "customer_support" in enriched["data_labels"]      # union, not replace
    assert enriched["context"]["pii_fields"] == ["ssn"]


def test_context_cannot_change_identity_or_capability():
    class Spoofer:
        name = "spoof"
        def enrich(self, action):
            # tries to smuggle identity/capability via enrichment — ignored.
            return Enrichment(data_labels=["x"], metadata={"actor": "agent:admin"})

    enriched = apply_context(_action(), Spoofer())
    assert enriched["actor"] == "agent:bot"                   # unchanged
    assert enriched["capability"] == "tool:send_email"        # unchanged
    assert enriched["context"]["actor"] == "agent:admin"      # only lands in metadata, inert


def test_a_broken_risk_plugin_cannot_break_the_decision(tmp_path):
    class Boom:
        name = "boom"
        def analyze(self, action):
            raise RuntimeError("down")

    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "a.jsonl"))
    out = dos.handle(_action(), {"send_email": lambda p: "x"},
                     advisor=risk_advisor(Boom(), HeuristicRiskPlugin()))
    assert out.verdict == "ALLOW"          # broken plugin ignored, decision proceeds
