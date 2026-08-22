"""Executable NovaPulse adversarial scenario — evidence, not narrative."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from adversarial_novapulse import run_scenario


def test_novapulse_adversarial_matrix(tmp_path):
    report = run_scenario(str(tmp_path / "novapulse_audit.jsonl"))
    m = report["matrix"]
    assert report["cases"]["1_legitimate_deploy"]["ok"] is True
    assert report["cases"]["2_auth_ok_legit_deny"]["ok"] is False
    assert report["cases"]["3_unresolved_defer"]["ok"] is False
    assert report["cases"]["6_direct_bypass"]["ok"] is False
    assert report["cases"]["8_ticket_replay"]["ok"] is False
    assert m["Non-bypassability (sealed surface)"]["status"] == "PASS"
    assert m["Non-bypassability (process-wide ambient Python)"]["status"] == "FAIL"
    assert m["End-to-end invariant (sealed)"]["status"] == "PASS"
    assert m["FDK/AuthGate binding (M5)"]["status"] == "PASS"
    assert report["question"]["infrastructure_grade_claim"].startswith("PARTIAL")
    assert (tmp_path / "novapulse_audit.report.json").is_file()
