"""Regression tests adapted from the red-team PoCs (poc1/3/5/6/7 + W-1/2/3).

Each test encodes a break the red-team demonstrated and asserts it is now
CONTAINED. If any of these flips back to the broken behaviour, the fix regressed.
"""

from __future__ import annotations

import pytest

from decision_os_min import (
    DecisionOS,
    ExecutionRefused,
    Executor,
    FileSpentStore,
    HashLog,
    InMemorySpentStore,
    Kernel,
    SpentStore,
    SpentStoreUnavailable,
    UnfingerprintablePayload,
    action_fingerprint,
)

POLICY = {"grants": {"agent:a": ["tool:pay"]}, "default": "deny"}


def _action(**kw):
    base = {
        "actor": "agent:a", "tool": "pay", "capability": "tool:pay",
        "payload": {"amount": 100}, "nonce": "n1",
    }
    base.update(kw)
    return base


# --- HB-1: cross-instance token double-spend --------------------------------
def test_hb1_cross_instance_replay_rejected(tmp_path):
    """poc1: a second Executor instance backed by the SAME durable store must
    reject a token already spent by the first — one decision, ONE effect."""
    store = FileSpentStore(tmp_path / "spent")
    k = Kernel(POLICY)
    pub = k.public_key_hex()
    action = _action()
    result = k.decide(action)

    calls = []
    tools = {"pay": lambda p: calls.append(p) or "PAID"}

    ex1 = Executor(pub, HashLog(tmp_path / "a1.jsonl"), spent_store=store)
    ex2 = Executor(pub, HashLog(tmp_path / "a2.jsonl"), spent_store=store)

    assert ex1.execute(action, result, tools) == "PAID"
    with pytest.raises(ExecutionRefused, match="already spent"):
        ex2.execute(action, result, tools)  # replay against a SECOND instance
    assert len(calls) == 1, "durable store must make the token one-time across instances"


def test_hb1_fails_closed_when_store_unreachable(tmp_path):
    """If the spent-store cannot be reached, the executor refuses (fail closed) —
    it never falls back to 'assume unspent'."""

    class BrokenStore:
        def try_spend(self, token_id: str) -> bool:
            raise SpentStoreUnavailable("simulated outage")

    k = Kernel(POLICY)
    action = _action()
    result = k.decide(action)
    ex = Executor(k.public_key_hex(), HashLog(tmp_path / "a.jsonl"),
                  spent_store=BrokenStore())
    with pytest.raises(ExecutionRefused, match="fail-closed"):
        ex.execute(action, result, {"pay": lambda p: "PAID"})


def test_hb1_inmemory_is_explicit_optin(tmp_path):
    """The old in-process store is still available but ONLY by explicit opt-in;
    it is (correctly) not durable across separate store objects."""
    k = Kernel(POLICY)
    pub = k.public_key_hex()
    action = _action()
    result = k.decide(action)
    ex1 = Executor(pub, HashLog(tmp_path / "a1.jsonl"), spent_store=InMemorySpentStore())
    ex2 = Executor(pub, HashLog(tmp_path / "a2.jsonl"), spent_store=InMemorySpentStore())
    assert ex1.execute(action, result, {"pay": lambda p: "PAID"}) == "PAID"
    # Two SEPARATE in-memory stores do not share state — this is the documented
    # single-process-only limitation, which is why it is opt-in, not the default.
    assert ex2.execute(action, result, {"pay": lambda p: "PAID"}) == "PAID"
    assert isinstance(InMemorySpentStore(), SpentStore)


# --- HB-2: audit tail-truncation now detectable via anchor ------------------
def test_hb2_tail_truncation_detected_by_anchor(tmp_path):
    """poc3: plain verify() still passes after truncation (internal consistency),
    but verify_against_anchor() with a retained head detects it."""
    p = tmp_path / "audit.jsonl"
    log = HashLog(p)
    log.record("agent:a", "pay", "ALLOW", "ok #1")
    log.record("agent:a", "pay", "ALLOW", "ok #2")
    log.record("agent:evil", "wire", "ALLOW", "MALICIOUS #3")
    log.record("agent:evil", "wire", "ALLOW", "MALICIOUS #4")

    anchored_seq, anchored_hash = log.head()  # operator retains this out of band
    assert log.verify()

    # Attacker truncates the tail to erase the malicious entries.
    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")

    reloaded = HashLog(p)
    assert reloaded.verify() is True  # plain verify STILL passes (the old blind spot)
    ok, reason = reloaded.verify_against_anchor(anchored_hash, anchored_seq)
    assert ok is False and "truncation" in reason.lower()


def test_hb2_untampered_chain_matches_anchor(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = HashLog(p)
    log.record("agent:a", "pay", "ALLOW", "ok")
    seq, h = log.head()
    reloaded = HashLog(p)
    ok, reason = reloaded.verify_against_anchor(h, seq)
    assert ok is True and reason == "ok"


# --- HB-3: no effect without an audit record --------------------------------
def test_hb3_executor_requires_audit_sink():
    """poc5: constructing an Executor without an audit sink is a TypeError — you
    cannot build a PEP that runs effects unlogged."""
    k = Kernel(POLICY)
    with pytest.raises(TypeError):
        Executor(k.public_key_hex())  # type: ignore[call-arg]


def test_hb3_effect_writes_exactly_one_audit_entry(tmp_path):
    k = Kernel(POLICY)
    log = HashLog(tmp_path / "audit.jsonl")
    ex = Executor(k.public_key_hex(), log, spent_store=InMemorySpentStore())
    action = _action()
    result = k.decide(action)
    calls = []
    ex.execute(action, result, {"pay": lambda p: calls.append(p) or "PAID"})
    entries = log.entries()
    assert len(calls) == 1
    assert len(entries) == 1 and entries[0]["executed"] is True


def test_hb3_refused_effect_still_audited(tmp_path):
    k = Kernel(POLICY)
    log = HashLog(tmp_path / "audit.jsonl")
    ex = Executor(k.public_key_hex(), log, spent_store=InMemorySpentStore())
    action = _action()
    result = k.decide(action)
    with pytest.raises(ExecutionRefused):
        ex.execute(action, result, {})  # no tool registered -> refused
    entries = log.entries()
    assert len(entries) == 1 and entries[0]["executed"] is False
    assert "refused" in entries[0]["reason"]


# --- W-1: nonce/action_ref bound --------------------------------------------
def test_w1_nonce_folded_into_fingerprint():
    """poc2/poc9(B): two actions differing ONLY by nonce must NOT share a
    fingerprint anymore."""
    authorized = _action(nonce="n1", action_ref="REQ-1")
    attacker = _action(nonce="TOTALLY-DIFFERENT", action_ref="REQ-9999")
    assert action_fingerprint(authorized) != action_fingerprint(attacker)


def test_w1_different_action_rejected_by_executor(tmp_path):
    k = Kernel(POLICY)
    log = HashLog(tmp_path / "audit.jsonl")
    ex = Executor(k.public_key_hex(), log, spent_store=InMemorySpentStore())
    authorized = _action(nonce="n1")
    attacker = _action(nonce="DIFFERENT")
    result = k.decide(authorized)
    with pytest.raises(ExecutionRefused, match="binding mismatch|action_ref|nonce"):
        ex.execute(attacker, result, {"pay": lambda p: "PAID"})


# --- W-2: default=str collision closed --------------------------------------
def test_w2_object_string_collision_rejected():
    """poc6/poc7: an object whose __str__ returns '100' must NOT be silently
    coerced; fingerprinting it now RAISES instead of colliding with the string
    '100'."""

    class Weird:
        def __str__(self) -> str:
            return "100"

    base = {"actor": "agent:a", "capability": "tool:pay"}
    with pytest.raises(UnfingerprintablePayload):
        action_fingerprint({**base, "payload": {"x": Weird()}})
    # the plain string still fingerprints fine
    ok = action_fingerprint({**base, "payload": {"x": "100"}})
    assert isinstance(ok, str)


def test_w2_mutate_after_auth_impossible(tmp_path):
    """poc7: a mutable object payload can no longer be authorized at all, so there
    is no str-snapshot to diverge from the live value."""

    class Amount:
        def __init__(self) -> None:
            self.live = 100

        def __str__(self) -> str:
            return "100"

    k = Kernel(POLICY)
    with pytest.raises(UnfingerprintablePayload):
        k.decide(_action(payload={"amount": Amount()}))


# --- W-3: audit reflects outcome + payload ----------------------------------
def test_w3_audit_records_outcome_and_payload_digest(tmp_path):
    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "audit.jsonl"))
    out1 = dos.handle(_action(nonce="x1", payload={"amount": 1}),
                      {"pay": lambda p: "PAID"})
    out2 = dos.handle(_action(nonce="x2", payload={"amount": 1_000_000}),
                      {"pay": lambda p: "PAID"})
    assert out1.executed and out2.executed
    entries = dos.log.entries()
    assert all(e["executed"] is True for e in entries)
    # $1 and $1M produce DIFFERENT digests (poc4's complaint).
    digests = [e["payload_digest"] for e in entries]
    assert digests[0] != digests[1] and all(d for d in digests)


def test_w3_refused_distinguishable_from_ran(tmp_path):
    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "audit.jsonl"))
    dos.handle(_action(nonce="ran"), {"pay": lambda p: "PAID"})
    dos.handle(_action(nonce="refused"), {})  # no tool -> refused
    entries = dos.log.entries()
    assert entries[0]["executed"] is True
    assert entries[1]["executed"] is False
