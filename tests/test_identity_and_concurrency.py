"""C1/C2: persistent signing identity and cross-process one-time-token spend."""

from __future__ import annotations

import multiprocessing as mp
import os
import stat
import sys

import pytest

from decision_os_min import DecisionOS, FileSpentStore, SqliteSpentStore
from decision_os_min.kernel import load_or_create_signing_key

POLICY = {
    "grants": {"agent:bot": ["tool:send_email"]},
    "purpose_bindings": {"customer_support": ["support_reply"]},
    "default": "deny",
}
ACTION = {
    "actor": "agent:bot", "tool": "send_email", "action_purpose": "support_reply",
    "data_labels": ["customer_support"], "payload": {"body": "hi"},
    "capability": "tool:send_email", "nonce": "n1",
}


def test_key_persists_across_restart(tmp_path):
    kp = str(tmp_path / "k.pem")
    a = DecisionOS(POLICY, audit_path=str(tmp_path / "a.jsonl"), key_path=kp)
    b = DecisionOS(POLICY, audit_path=str(tmp_path / "b.jsonl"), key_path=kp)
    assert a.kernel.public_key_hex() == b.kernel.public_key_hex()


def test_decision_signed_before_restart_executes_after_restart(tmp_path):
    kp = str(tmp_path / "k.pem")
    store = FileSpentStore(tmp_path / "spent")
    first = DecisionOS(POLICY, audit_path=str(tmp_path / "a.jsonl"), key_path=kp, spent_store=store)
    result = first.kernel.decide(ACTION)
    second = DecisionOS(POLICY, audit_path=str(tmp_path / "b.jsonl"), key_path=kp, spent_store=store)
    out = second.executor.execute(ACTION, result, {"send_email": lambda p: "sent"})
    assert out == "sent"


def test_without_key_path_identity_is_ephemeral(tmp_path):
    a = DecisionOS(POLICY, audit_path=str(tmp_path / "a.jsonl"))
    b = DecisionOS(POLICY, audit_path=str(tmp_path / "b.jsonl"))
    assert a.kernel.public_key_hex() != b.kernel.public_key_hex()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_key_file_is_private(tmp_path):
    kp = tmp_path / "k.pem"
    load_or_create_signing_key(str(kp))
    assert stat.S_IMODE(os.stat(kp).st_mode) == 0o600


def test_rejects_non_ed25519_key(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )
    kp = tmp_path / "rsa.pem"
    kp.write_bytes(rsa.generate_private_key(65537, 2048).private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    with pytest.raises(TypeError):
        load_or_create_signing_key(str(kp))


def _create_key(path, q):
    q.put(load_or_create_signing_key(path).public_key().public_bytes_raw().hex())


def test_concurrent_key_creation_yields_one_identity(tmp_path):
    kp = str(tmp_path / "race.pem")
    q = mp.Queue()
    procs = [mp.Process(target=_create_key, args=(kp, q)) for _ in range(6)]
    [p.start() for p in procs]
    keys = {q.get(timeout=60) for _ in procs}
    [p.join(30) for p in procs]
    assert len(keys) == 1


def _spend(kind, location, token_id, q):
    store = FileSpentStore(location) if kind == "file" else SqliteSpentStore(location)
    q.put(store.try_spend(token_id))


@pytest.mark.parametrize("kind", ["file", "sqlite"])
def test_double_spend_across_processes_exactly_one_wins(tmp_path, kind):
    loc = str(tmp_path / ("spent" if kind == "file" else "spent.db"))
    q = mp.Queue()
    n = 12
    procs = [mp.Process(target=_spend, args=(kind, loc, "tok-1", q)) for _ in range(n)]
    [p.start() for p in procs]
    results = [q.get(timeout=120) for _ in procs]
    [p.join(30) for p in procs]
    assert results.count(True) == 1
    assert results.count(False) == n - 1


def test_replay_after_restart_refused(tmp_path):
    from decision_os_min import ExecutionRefused
    kp = str(tmp_path / "k.pem")
    store = FileSpentStore(tmp_path / "spent")
    tools = {"send_email": lambda p: "sent"}
    a = DecisionOS(POLICY, audit_path=str(tmp_path / "a.jsonl"), key_path=kp, spent_store=store)
    result = a.kernel.decide(ACTION)
    a.executor.execute(ACTION, result, tools)
    b = DecisionOS(POLICY, audit_path=str(tmp_path / "b.jsonl"), key_path=kp, spent_store=store)
    with pytest.raises(ExecutionRefused):
        b.executor.execute(ACTION, result, tools)
