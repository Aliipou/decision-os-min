"""Integrity checks for the measured real-system comparison artifact."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPARISON = ROOT / "bench" / "comparison"
POLICY_COMPARABLE = ("decision-os-min-policy", "opa", "cedar")
DECISION_OS_SCOPES = (
    "decision-os-min-policy",
    "decision-os-min-signed",
    "decision-os-min",
)


def test_shared_workload_and_measured_result_are_complete():
    scenarios = json.loads((COMPARISON / "scenarios.json").read_text(encoding="utf-8"))
    result = json.loads(
        (COMPARISON / "results" / "latest.json").read_text(encoding="utf-8")
    )

    ids = [scenario["id"] for scenario in scenarios]
    assert len(ids) == len(set(ids)) == 6
    assert {scenario["expected"] for scenario in scenarios} == {"ALLOW", "DENY"}
    methodology = result["methodology"]
    assert methodology["iterations_per_scenario"] >= 50
    assert methodology["warmup_per_scenario"] >= 0
    assert methodology["latency_not_a_ranking"] is True

    systems = {system["implementation"]: system for system in result["systems"]}
    for name in (*POLICY_COMPARABLE, *DECISION_OS_SCOPES):
        rows = systems[name]["conformance"]
        assert [row["id"] for row in rows] == ids
        assert all(row["match"] for row in rows)
        assert systems[name]["timing"]["n"] == 6 * methodology["iterations_per_scenario"]

    assert systems["decision-os-min-policy"]["comparable_policy_decision"] is True
    assert systems["opa"]["comparable_policy_decision"] is True
    assert systems["cedar"]["comparable_policy_decision"] is True
    assert systems["decision-os-min-signed"]["comparable_policy_decision"] is False
    assert systems["decision-os-min"]["comparable_policy_decision"] is False
    assert systems["official-mcp-typescript-sdk"]["comparable_policy_decision"] is False

    mcp_rows = systems["official-mcp-typescript-sdk"]["conformance"]
    assert [row["id"] for row in mcp_rows] == ids
    assert all(row["transported"] and row["handler_executed"] for row in mcp_rows)
