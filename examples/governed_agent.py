"""The 5-minute "aha": drop Decision OS into an agent's tools in 3 lines.

Simulates a tool-calling agent (the shape of OpenAI function-calling / LangGraph /
MCP: the model emits (tool_name, args); your code runs the tool). The ONLY change
to govern it is wrapping the tool registry once. After that, every tool call is
authorized + audited, and an over-privileged call is refused — with zero changes
to the agent loop.

Run:  python examples/governed_agent.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from decision_os_min import GovernanceRefused, Governor, set_actor


# ---- your existing tools (unchanged) --------------------------------------
def send_email(to, body):
    return f"email -> {to}: {body}"


def read_order(order_id):
    return f"order {order_id}: shipped"


def wire_money(amount, dest):
    return f"WIRED ${amount} -> {dest}"


TOOLS = {"send_email": send_email, "read_order": read_order, "wire_money": wire_money}

# ---- your existing agent loop (unchanged) ---------------------------------
def run_agent(name, tools, tool_calls):
    print(f"\n=== agent run: {name} ===")
    for tool_name, args in tool_calls:
        try:
            result = tools[tool_name](**args)
            print(f"  {tool_name}({args}) -> {result}")
        except GovernanceRefused as e:
            print(f"  {tool_name}({args}) -> BLOCKED: {e.verdict}")


# What the "LLM" decided to do — including one over-privileged call.
PLAN = [
    ("read_order", {"order_id": "A-1001"}),
    ("send_email", {"to": "cust@x.com", "body": "your order shipped"}),
    ("wire_money", {"amount": 9999, "dest": "attacker@evil.com"}),   # the agent goes rogue
]

POLICY = {
    "grants": {"agent:support": ["tool:read_order", "tool:send_email"]},  # NOT wire_money
    "default": "deny",
}


def main():
    print("BEFORE — ungoverned: the agent can do anything its code allows.")
    run_agent("ungoverned", TOOLS, PLAN)   # wires money to the attacker

    print("\n" + "=" * 60)
    print("The 3 lines you add:")
    print("    gov = Governor(policy, audit_path='audit.jsonl')")
    print("    tools = gov.wrap(YOUR_TOOLS, specs=...)")
    print("    set_actor('agent:support')")
    print("=" * 60)

    audit = Path(tempfile.gettempdir()) / "governed_agent_audit.jsonl"
    audit.unlink(missing_ok=True)
    gov = Governor(POLICY, audit_path=str(audit))
    governed = gov.wrap(TOOLS, specs={
        "read_order": {"capability": "tool:read_order"},
        "send_email": {"capability": "tool:send_email"},
        "wire_money": {"capability": "tool:wire_money"},
    })
    set_actor("agent:support")

    print("\nAFTER — governed: SAME agent loop, SAME plan.")
    run_agent("governed", governed, PLAN)   # the rogue wire_money is refused

    print("\n--- tamper-evident audit trail ---")
    for e in gov._dos.log.entries():
        print(f"  {e['verdict']:<6} {e['tool']:<12} {e['reason'][:40]}")
    print(f"  chain verified: {gov._dos.log.verify()}")
    print("\nThe attack was stopped and recorded — without touching the agent loop.")


if __name__ == "__main__":
    main()
