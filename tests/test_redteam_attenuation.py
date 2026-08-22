"""RED TEAM — AE-4 / AE-5 macaroon-lite attenuation + AE-10 audit fidelity.

Threat model for attenuation: the attacker can read a minted macaroon (caveats +
signature tip) and can write back a modified macaroon into the authority graph
(the same surface as the existing drop-caveat integrity test). They do NOT have
the root HMAC key.

HEADLINE BREAK (now closed) — HMAC-append allowlist amplification
-----------------------------------------------------------------
Macaroon HMAC chains are *designed* so anyone who knows the tip can append a
caveat without the root key. That is safe only when every append **narrows**.
The first vocabulary used one ``tool:<name>`` caveat per permitted tool and
interpreted the set as a **union** allowlist. Appending ``tool:wire_money`` to a
``tool:send_email``-only macaroon therefore:

  * produced a signature that still verified (chain extension);
  * made ``holds(..., tool:wire_money)`` true;
  * let the holder ``delegate`` wire_money to a grandchild.

That is AE-4 inverted: a caveat widened authority.

Closed by minting a single ``tools:a,b`` caveat and taking the **intersection**
of all allowlist caveats — append can only shrink (or empty) the set.

Also closed here: rebinding a valid macaroon under a different holder key in
``_macaroons`` (identifier is now bound to the holder); expired parents cannot
delegate; parent credentials are OR'd (union) to match ``holds``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from decision_os_min import AttenuationError, DecisionOS
from decision_os_min.attenuation import AuthorityGraph, Macaroon, _h
from decision_os_min.compose import DENY


def _dos(tmp_path, name="a.jsonl"):
    return DecisionOS({"grants": {}, "default": "allow"}, audit_path=str(tmp_path / name))


def _tools(sink):
    return {
        "send_email": lambda p: sink.append(("send_email", p)) or "ok",
        "wire_money": lambda p: sink.append(("wire_money", p)) or "ok",
    }


def test_fixed_hmac_append_cannot_amplify_tools(tmp_path):
    """CLOSED. ATTACK: extend the HMAC tip with ``tools:send_email,wire_money``
    without the root key. Under union-allowlist semantics this USED to verify and
    grant wire_money — AE-4 break.

    Now allowlists intersect, so the append either leaves authority unchanged
    (superset append) or empties it (disjoint append) — never widens.
    """
    g = AuthorityGraph()
    g.grant("root", "tool:send_email")
    g.grant("root", "tool:wire_money")
    m = g.delegate("root", "agent:sub", ["send_email"])
    assert m.tool_set() == frozenset({"send_email"})
    assert g.holds("agent:sub", "tool:send_email")
    assert not g.holds("agent:sub", "tool:wire_money")

    wider = "tools:send_email,wire_money"
    forged = Macaroon(
        location=m.location,
        identifier=m.identifier,
        caveats=m.caveats + (wider,),
        signature=_h(m.signature, f"caveat|{wider}"),
    )
    assert g._verify_sig(forged), "append remains cryptographically valid"
    g._macaroons["agent:sub"] = [forged]

    assert forged.tool_set() == frozenset({"send_email"})
    assert g.holds("agent:sub", "tool:send_email")
    assert not g.holds("agent:sub", "tool:wire_money")

    disjoint = "tools:wire_money"
    emptied = Macaroon(
        location=m.location,
        identifier=m.identifier,
        caveats=m.caveats + (disjoint,),
        signature=_h(m.signature, f"caveat|{disjoint}"),
    )
    g._macaroons["agent:sub"] = [emptied]
    assert emptied.tool_set() == frozenset()
    assert not g.holds("agent:sub", "tool:send_email")
    assert not g.holds("agent:sub", "tool:wire_money")

    dos = _dos(tmp_path)
    dos.grant("root", "tool:send_email")
    dos.grant("root", "tool:wire_money")
    live = dos.delegate("root", "agent:sub", ["send_email"])
    amp = Macaroon(
        location=live.location,
        identifier=live.identifier,
        caveats=live.caveats + (wider,),
        signature=_h(live.signature, f"caveat|{wider}"),
    )
    dos.kernel.authority._macaroons["agent:sub"] = [amp]
    sink: list = []
    out = dos.handle(
        {
            "actor": "agent:sub",
            "tool": "wire_money",
            "capability": "tool:wire_money",
            "action_purpose": "t",
            "payload": {"amount": 1},
            "nonce": "amp-1",
        },
        _tools(sink),
    )
    assert not out.executed and sink == []


def test_fixed_hmac_append_cannot_delegate_amplified_tool(tmp_path):
    """CLOSED. ATTACK: after append-amplifying wire_money onto a send_email-only
    macaroon, ``delegate`` to a grandchild USED to mint a live wire_money
    capability (transitive AE-4 failure)."""
    g = AuthorityGraph()
    g.grant("root", "tool:send_email")
    g.grant("root", "tool:wire_money")
    m = g.delegate("root", "agent:sub", ["send_email"])
    wider = "tools:send_email,wire_money"
    g._macaroons["agent:sub"] = [
        Macaroon(
            location=m.location,
            identifier=m.identifier,
            caveats=m.caveats + (wider,),
            signature=_h(m.signature, f"caveat|{wider}"),
        )
    ]
    with pytest.raises(AttenuationError):
        g.delegate("agent:sub", "agent:child", ["wire_money"])
    assert not g.holds("agent:child", "tool:wire_money")


def test_fixed_macaroon_cannot_be_rebound_to_another_holder(tmp_path):
    """CLOSED. ATTACK: copy a valid macaroon from agent:good into
    ``_macaroons['agent:evil']``. Signature still verified, so evil USED to
    ``holds`` the capability. Identifier is now bound to the minted holder."""
    g = AuthorityGraph()
    g.grant("root", "tool:send_email")
    m = g.delegate("root", "agent:good", ["send_email"])
    g._macaroons["agent:evil"] = [m]
    assert g.holds("agent:good", "tool:send_email")
    assert not g.holds("agent:evil", "tool:send_email")


def test_fixed_ae10_composed_deny_keeps_veto_reason_in_audit(tmp_path):
    """CLOSED (AE-10). Composed DENY must audit the vetoing reason and the tool."""
    dos = DecisionOS(
        {"grants": {"agent:a": ["tool:send_email"]}, "default": "deny"},
        audit_path=str(tmp_path / "ae10.jsonl"),
    )
    out = dos.handle(
        {
            "actor": "agent:a",
            "tool": "send_email",
            "capability": "tool:send_email",
            "payload": {"to": "a@b.test"},
            "nonce": "ae10",
        },
        _tools([]),
        evaluators=[lambda a: {"verdict": DENY, "reason": "CONSTRAINT-REASON-XYZ"}],
    )
    assert not out.executed
    entry = dos.log.entries()[-1]
    assert entry["verdict"] == DENY
    assert "CONSTRAINT-REASON-XYZ" in entry["reason"]
    assert entry["tool"] == "send_email"
    assert entry["executed"] is False


def test_fixed_ae5_expired_parent_cannot_delegate():
    """CLOSED. ATTACK: parent whose only credential is an expired macaroon could
    still call ``delegate``. AE-5: dead authority must not derive further authority."""
    g = AuthorityGraph()
    g.grant("root", "tool:send_email")
    past = datetime.now(UTC) - timedelta(seconds=5)
    parent_m = g._mint(
        "agent:parent",
        ("tools:send_email", f"time < {past.astimezone(UTC).isoformat()}"),
    )
    g._macaroons.setdefault("agent:parent", []).append(parent_m)
    assert not g.holds("agent:parent", "tool:send_email")
    with pytest.raises(AttenuationError):
        g.delegate(
            "agent:parent",
            "agent:child",
            ["send_email"],
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    assert not g.holds("agent:child", "tool:send_email")


def test_fixed_ae4_parent_union_of_credentials_not_intersection():
    """CLOSED. Intersecting a parent's root grant with a sibling macaroon emptied
    authority so ``holds`` said yes for each tool but ``delegate`` of both failed.
    Parent credentials are OR'd (union)."""
    g = AuthorityGraph()
    g.grant("agent:p", "tool:send_email")
    g.grant("root", "tool:wire_money")
    future = datetime.now(UTC) + timedelta(hours=1)
    g.delegate("root", "agent:p", ["wire_money"], expires_at=future)
    assert g.holds("agent:p", "tool:send_email")
    assert g.holds("agent:p", "tool:wire_money")
    child = g.delegate("agent:p", "agent:c", ["send_email", "wire_money"])
    assert child.tool_set() == frozenset({"send_email", "wire_money"})
    assert child.expires_at() is not None
    assert child.expires_at() <= future


def test_fixed_ae5_root_tools_not_clamped_by_unrelated_macaroon_expiry():
    """CLOSED. A time-limited macaroon for tool A must not force a time ceiling
    onto a root-granted tool B when only B is delegated."""
    g = AuthorityGraph()
    g.grant("agent:p", "tool:send_email")
    g.grant("root", "tool:wire_money")
    soon = datetime.now(UTC) + timedelta(minutes=5)
    g.delegate("root", "agent:p", ["wire_money"], expires_at=soon)
    far = datetime.now(UTC) + timedelta(days=30)
    child = g.delegate("agent:p", "agent:c", ["send_email"], expires_at=far)
    assert child.expires_at() == far
    assert "wire_money" not in (child.tool_set() or frozenset())


def test_holds_drop_and_reorder_still_break_hmac():
    """Integrity: drop/reorder remain detectable after the vocabulary change."""
    g = AuthorityGraph()
    g.grant("root", "tool:send_email")
    g.grant("root", "tool:wire_money")
    m = g.delegate("root", "agent:sub", ["send_email", "wire_money"])
    forged = Macaroon(
        location=m.location,
        identifier=m.identifier,
        caveats=("tools:send_email",),
        signature=m.signature,
    )
    g._macaroons["agent:sub"] = [forged]
    assert not g.holds("agent:sub", "tool:send_email")
    assert not g.holds("agent:sub", "tool:wire_money")
