"""A 5-minute end-to-end demo: an AI agent under Decision OS governance.

    AI Agent  ->  Decision OS  ->  Tool Execution  ->  Audit  ->  Replay

Run:  python examples/demo.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from decision_os_min import DecisionOS

# ---------------------------------------------------------------- the tools
def lookup_order(p):
    return f"order {p.get('order_id', '?')}: shipped"


def send_email(p):
    card = f" card={p['card']}" if p.get("card") else ""
    return f"email -> {p.get('to', '?')}: {p.get('body', '')!r}{card}"


def issue_refund(p):
    return f"REFUNDED ${p.get('amount', 0)}"


TOOLS = {"lookup_order": lookup_order, "send_email": send_email, "issue_refund": issue_refund}

# ---------------------------------------------------------------- the policy
POLICY = {
    "grants": {"agent:support-ai": ["tool:lookup_order", "tool:send_email"]},
    "purpose_bindings": {"customer_data": ["support_reply"]},
    "redactions": [{"action_purpose": "support_reply", "redact_fields": ["card", "ssn"]}],
    "contain_threat_classes": ["malicious"],
    "default": "deny",
}


def _act(tool, purpose="support_reply", labels=("customer_data",), **payload):
    return {
        "actor": "agent:support-ai",
        "tool": tool,
        "capability": f"tool:{tool}",
        "action_purpose": purpose,
        "data_labels": list(labels),
        "payload": payload,
        "nonce": f"{tool}-{payload.get('nonce', '')}",
    }


# What the AI agent decides (on its own) to try. Decision OS governs it.
AGENT_PLAN = [
    ("look up the customer's order", _act("lookup_order", order_id="A-1001", nonce="1"), None),
    ("reply to the customer", _act("send_email", to="cust@x.com", body="Your order shipped.", nonce="2"), None),
    ("reply, but the draft leaks a card number", _act("send_email", to="cust@x.com", body="refund to", card="4111-1111", nonce="3"), None),
    ("try to issue a refund (NOT granted)", _act("issue_refund", purpose="support_reply", amount=500, nonce="4"), None),
    ("an action flagged malicious by the advisor", _act("send_email", to="x@x.com", body="?", nonce="5"), "malicious"),
]


def main() -> int:
    audit = Path(tempfile.gettempdir()) / "decision_os_demo.jsonl"
    if audit.exists():
        audit.unlink()

    print("=" * 70)
    print("  DECISION OS  —  an AI support agent under governance")
    print("=" * 70)
    dos = DecisionOS(POLICY, audit_path=str(audit))
    print(f"  policy: agent:support-ai may  lookup_order, send_email")
    print(f"  kernel key: {dos.kernel.public_key_hex()[:16]}...\n")

    for title, action, threat in AGENT_PLAN:
        out = dos.handle(action, TOOLS, threat_class=threat)
        flag = f" [advisor: {threat}]" if threat else ""
        status = f"EXECUTED -> {out.output}" if out.executed else f"BLOCKED  ({out.refused_reason})"
        print(f"  * agent wants to: {title}{flag}")
        print(f"    verdict={out.verdict:<8} {status}\n")

    # --------------------------------------------------- REPLAY (the audit)
    print("-" * 70)
    print("  REPLAY  —  independent auditor reads the tamper-evident log")
    print("-" * 70)
    for e in dos.log.entries():
        print(f"    seq={e['seq']}  {e['verdict']:<8} {e['tool']:<13} {e['reason'][:38]}")
    print(f"\n  chain verifies: {dos.log.verify()}")

    # --------------------------------------------------- tamper demonstration
    lines = audit.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"ALLOW"', '"DENY"')  # someone edits history
    audit.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  after an insider edits seq=0 in the file: chain verifies: {dos.log.verify()}")
    print("=" * 70)
    print("  Every agent action was gated, executed-or-refused, and recorded.")
    print("  The record is tamper-evident. That is the whole product.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
