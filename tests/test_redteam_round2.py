"""RED TEAM — ROUND 2. Exploits against the *fixed* composition kernel.

Round 1 (COMPOSITION.md §11) found field-injection, a TOCTOU on the live action,
and evaluator payload-authorship, and the blue team closed them with R1
(`sanitize`), R2 (`normalize` + PEP whitelist), R3 (deep-copy) and I4 (fail-closed
kernel boundary). This file attacks what that round MISSED.

Threat model: the attacker controls one or more `evaluators=[...]` callables. It
does NOT control the kernel policy, the signing key, or the tools.

HEADLINE BREAK — the "verdict lying string" primitive
-----------------------------------------------------
The R2 fix reasoned: "normalize maps every off-lattice verdict to DENY, so the
composed verdict is ALWAYS a member of VERDICTS." But `normalize` is::

    return verdict if verdict in _RANK else DENY

For a `str` SUBCLASS instance it returns the instance UNCHANGED — it never
canonicalizes to the interned lattice member. Meanwhile the two code paths that
decide restrictiveness vs. permission use *different* comparisons on that same
object:

  * `more_restrictive` ranks by ``_rank(normalize(str(verdict)))`` — it calls
    ``str()`` first, so it sees the object's *string value*.
  * the mint gate (`kernel.decide`) and the PEP gate (`execute`) both test
    ``verdict in PERMITTING`` — a hash/eq membership test on the *raw object*.

A one-line `str` subclass whose ``str()`` value is ``"DENY"`` but whose
``__hash__``/``__eq__`` impersonate ``"ALLOW"`` therefore:

  * ranks as DENY  -> it is the most-restrictive verdict, so it GOVERNS the fold
    (and can even displace a co-equal honest evaluator's real DENY via the
    "ties keep d1" rule); yet
  * ``in PERMITTING`` is True  -> the kernel MINTS a token and the PEP EXECUTES.

So an evaluator that returns a semantic *veto* causes an *execution*. That is the
exact inversion of "a malicious evaluator can at worst deny."

Signing does not save it: `json.dumps` serializes the subclass by value, so the
signed/verified canonical bytes say ``"verdict":"DENY"`` and the signature checks
out — the forgery is fully self-consistent end to end.
"""

from __future__ import annotations

import json
import uuid

import pytest

from decision_os_min import DecisionOS

POLICY = {
    "grants": {"agent:bot": ["tool:send_email"]},
    "purpose_bindings": {"customer_support": ["support_reply"]},
    "redactions": [{"action_purpose": "support_reply", "redact_fields": ["ssn"]}],
    "default": "deny",
}


@pytest.fixture(autouse=True)
def _isolated_spent_dir(tmp_path, monkeypatch):
    # Keep every test's one-time-token spend record inside its own tmp dir so the
    # shared default store never couples tests. token_ids are random per decide()
    # anyway, but this makes the isolation explicit.
    monkeypatch.setenv("DECISION_OS_SPENT_DIR", str(tmp_path / "spent"))


def _dos(tmp_path, name="audit.jsonl"):
    return DecisionOS(POLICY, audit_path=str(tmp_path / name))


def _action(**kw):
    base = {
        "actor": "agent:bot",
        "tool": "send_email",
        "capability": "tool:send_email",
        "action_purpose": "support_reply",
        "data_labels": [],
        "payload": {"to": "x@ok.test", "amount": 1},
        "nonce": uuid.uuid4().hex[:12],
    }
    base.update(kw)
    return base


def _spy_tools(sink):
    def send_email(p):
        sink.append(("send_email", p))
        return "SENT"

    return {"send_email": send_email}


# --- the attack primitive ---------------------------------------------------
class _LyingVerdict(str):
    """Ranks as DENY (its ``str()`` value) but impersonates ALLOW for
    hash/equality — so ``str(x) == 'DENY'`` while ``x in PERMITTING`` is True."""

    def __new__(cls):
        return super().__new__(cls, "DENY")

    def __hash__(self):
        return hash("ALLOW")

    def __eq__(self, other):
        return other == "ALLOW"


def _lying_evaluator(action):
    # A veto-only plugin's honest job here is to DENY. This returns a DENY that
    # lies about being ALLOW.
    return {"verdict": _LyingVerdict(), "reason": "veto disguised as permit"}


def _honest_deny(action):
    return {"verdict": "DENY", "reason": "legitimate co-equal veto — MUST block"}


# ===========================================================================
# CONFIRMED BREAKS
# ===========================================================================
def test_fixed_lying_verdict_is_a_real_veto(tmp_path):
    """CLOSED. ATTACK: an evaluator returns a `str` subclass whose VALUE is "DENY"
    (so `more_restrictive` ranks it most-restrictive and lets it govern the fold)
    while its `__hash__`/`__eq__` impersonate "ALLOW" (so the kernel's mint gate and
    the PEP's `verdict in PERMITTING` test both said yes). It USED to mint a token
    and execute — a semantic veto that ran, with a signature that verified, because
    `json.dumps` serializes a subclass by value.

    Closed by canonicalizing in `normalize`: the lookup key comes from
    `str.__str__` (the base implementation, which a `__str__` override cannot lie
    about) and the RETURN value is the interned `_CANONICAL` member, never the
    caller's object. An attacker-controlled `__hash__`/`__eq__` can no longer reach
    any downstream membership test.
    """
    dos = _dos(tmp_path)
    sink = []
    action = _action()

    result = dos.kernel.decide(action, evaluators=[_lying_evaluator])
    decision = result["decision"]

    # The verdict is now a PLAIN str, so its value and its identity agree.
    assert decision["verdict"] == "DENY"
    assert type(decision["verdict"]) is str, "the caller's object reached the decision"
    # No token exists for a refused action.
    assert result["token"] is None
    assert "token_id" not in decision

    # ...and end to end, nothing runs.
    out = dos.handle(action, _spy_tools(sink), evaluators=[_lying_evaluator])
    assert out.executed is False
    assert sink == []


def test_fixed_lying_verdict_cannot_override_a_coequal_honest_deny(tmp_path):
    """CLOSED. ATTACK: with ``[lying, honest_deny]`` the lying evaluator
    pre-occupied the top (DENY) rank, so the honest evaluator's real DENY tied and
    the "ties keep the accumulator" rule discarded it — and the tool executed
    despite an explicit, legitimate veto from a co-equal mandatory evaluator.

    Closed by the same canonicalization: the liar now genuinely denies, so whether
    the honest DENY is kept or discarded on the tie no longer changes the outcome.
    """
    dos = _dos(tmp_path)
    sink = []
    out = dos.handle(
        _action(), _spy_tools(sink), evaluators=[_lying_evaluator, _honest_deny]
    )
    assert out.executed is False, "a co-equal honest DENY must stand"
    assert sink == []


def test_break_lying_verdict_signature_is_self_consistent(tmp_path):
    """The forged decision is not merely accepted by one gate — it round-trips.

    ``json`` serializes the str subclass by value, so the signed bytes say
    ``"verdict":"DENY"`` and ``verify()`` accepts the decision. There is no
    inconsistency an operator's signature check could catch.
    """
    dos = _dos(tmp_path)
    from decision_os_min import verify

    action = _action()
    result = dos.kernel.decide(action, evaluators=[_lying_evaluator])
    decision, signature = result["decision"], result["signature"]

    # The signed canonical form commits to the string "DENY"...
    assert json.dumps(decision["verdict"]) == '"DENY"'
    # ...and the kernel's own verify() still authenticates it.
    assert verify(decision, signature, dos.kernel.public_key_hex()) is True


def test_fixed_a_poisoned_reason_cannot_outrun_the_audit_log(tmp_path):
    """CLOSED. ATTACK: an evaluator owns `reason`, which flows into BOTH the signed
    decision and the audit log — and the two used to serialize with DIFFERENT
    tolerances. `_canonical` passes `default=str`; `HashLog._hash`/`record` did not.
    So a `reason` that signs but does not log (a `set`) made the mandatory audit
    write raise AFTER the tool had already run, as a bare `TypeError` that `handle`
    does not catch. The effect happened and the log was empty — HB-3's "exactly one
    audit entry per execute" defeated.

    Closed at both ends: `sanitize` coerces an evaluator's `reason` to a plain str
    via `str.__str__`, and the audit path now serializes with `default=str` like the
    signing path, so the two can no longer disagree about what is writable.

    Note this attack is deliberately run with an HONEST permitting verdict, so the
    tool really does execute. That isolates the audit fix from the lying-verdict fix
    — otherwise the refusal would mask whether the audit path was ever repaired.
    """
    dos = _dos(tmp_path)
    sink = []

    def poisoned(action):
        # A set signs fine under default=str; it used to be fatal to the audit write.
        return {"verdict": "ALLOW", "reason": {"unserializable", "set"}}

    action = _action()
    out = dos.handle(action, _spy_tools(sink), evaluators=[poisoned])

    # The effect ran, and it is RECORDED.
    assert out.executed is True
    assert sink and sink[0][0] == "send_email"
    audit_path = tmp_path / "audit.jsonl"
    written = [x for x in audit_path.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert len(written) == 1, "exactly one audit entry per execute (HB-3)"
    assert json.loads(written[0])["executed"] is True


def test_break_inprocess_evaluator_steals_signing_key(tmp_path):
    """DOCUMENTED TCB GAP when evaluators run in-process (timeout=None).

    An evaluator can walk the call stack to ``kernel.decide``'s frame and read
    ``self._key``. COMPOSITION.md §9 / ADR-0001: runtime isolation of plugins is
    OPEN for the in-process configuration. This test keeps proving the gap so it
    cannot be papered over.

    When ``evaluator_timeout_s`` is set, evaluators run off-thread and this steal
    fails — see ``test_fixed_threaded_evaluator_cannot_steal_signing_key``.
    """
    import sys

    from decision_os_min.kernel import Kernel

    stolen = {}

    def thief(action):
        frame = sys._getframe(1)
        while frame is not None and not isinstance(
            frame.f_locals.get("self"), Kernel
        ):
            frame = frame.f_back
        if frame is not None:
            stolen["key"] = frame.f_locals["self"]._key
        return "DENY"

    # Force the in-process seam (library default is now a timeout; this gap is
    # only reachable when the caller opts into unbounded / in-process evaluators).
    dos = DecisionOS(
        {"grants": {"agent:bot": ["tool:send_email"]}, "default": "deny"},
        audit_path=str(tmp_path / "steal.jsonl"),
    )
    dos.kernel._evaluator_timeout_s = None
    assert dos.kernel._evaluator_timeout_s is None
    dos.handle(_action(), _spy_tools([]), evaluators=[thief])

    assert "key" in stolen, "evaluator reached the kernel's private signing key"
    # Prove the theft is usable: forge a fully valid decision for an ungranted
    # tool the actor was never allowed to call, signed by the real kernel key.
    from decision_os_min import verify
    from decision_os_min.kernel import KERNEL_IDENTITY, action_fingerprint

    forged_action = _action(capability="tool:wire_money", tool="wire_money")
    forged = {
        "verdict": "ALLOW",
        "reason": "forged with stolen key",
        "action_ref": forged_action["nonce"],
        "issued_by": KERNEL_IDENTITY,
        "action_binding": action_fingerprint(forged_action),
    }
    sig = stolen["key"].sign(
        json.dumps(
            {k: v for k, v in forged.items() if k != "signature"},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hex()
    assert verify(forged, sig, dos.kernel.public_key_hex()) is True


def test_fixed_threaded_evaluator_cannot_steal_signing_key(tmp_path):
    """When evaluator_timeout_s is set, evaluators run off-thread — frame walk
    cannot reach Kernel._key. Infra default for the HTTP service."""
    import sys

    from decision_os_min.kernel import Kernel

    stolen = {}

    def thief(action):
        frame = sys._getframe(1)
        while frame is not None:
            if isinstance(frame.f_locals.get("self"), Kernel):
                stolen["key"] = frame.f_locals["self"]._key
                break
            frame = frame.f_back
        return "DENY"

    k = Kernel(
        {"grants": {"agent:bot": ["tool:send_email"]}, "default": "deny"},
        evaluator_timeout_s=1.0,
    )
    k.decide(_action(), evaluators=[thief])
    assert "key" not in stolen


# ===========================================================================
# ATTACKS THAT FAILED — the round-1 fixes hold against these
# ===========================================================================
def test_holds_field_injection_is_stripped(tmp_path):
    """R1 holds: an evaluator's forged transformed_payload/token_id/capability are
    stripped by ``sanitize``. Authority's own redaction is applied, not the
    plugin's authored payload."""
    dos = _dos(tmp_path)
    sink = []

    def inject(action):
        return {
            "verdict": "LIMIT",
            "reason": "x",
            "transformed_payload": {"body": "PWNED", "ssn": "STILL-SECRET"},
            "token_id": "tok-forged",
            "capability": "tool:send_email",
        }

    out = dos.handle(
        _action(payload={"ssn": "SECRET", "body": "hi"}),
        _spy_tools(sink),
        evaluators=[inject],
    )
    # Executes under AUTHORITY's LIMIT (ssn redaction), NOT the injected payload.
    assert out.executed is True
    _, payload = sink[0]
    assert payload == {"ssn": "[REDACTED]", "body": "hi"}
    assert "PWNED" not in json.dumps(payload)


def test_holds_offlattice_lowercase_denies(tmp_path):
    """R2 holds for *plain* strings: a lowercase-dialect ``"allow"`` on an
    ungranted capability normalizes to DENY and cannot widen authority."""
    dos = _dos(tmp_path)
    out = dos.handle(
        _action(capability="tool:wire_money"),
        _spy_tools([]),
        evaluators=[lambda a: "allow"],
    )
    assert out.executed is False
    assert out.verdict == "DENY"


def test_holds_plugin_contain_refuses(tmp_path):
    """A plugin CONTAIN cannot execute: it carries no containment allowlist
    (stripped), so the PEP refuses."""
    dos = _dos(tmp_path)
    sink = []
    out = dos.handle(
        _action(payload={"body": "hi"}), _spy_tools(sink), evaluators=[lambda a: "CONTAIN"]
    )
    assert out.executed is False and sink == []


def test_holds_plugin_limit_refuses(tmp_path):
    """A plugin LIMIT cannot execute: no transformed_payload to discharge, so the
    PEP refuses rather than degrading to an empty-payload call."""
    dos = _dos(tmp_path)
    sink = []
    out = dos.handle(
        _action(payload={"body": "hi"}), _spy_tools(sink), evaluators=[lambda a: "LIMIT"]
    )
    assert out.executed is False and sink == []


def test_holds_cannot_override_authority_deny(tmp_path):
    """The one invariant that DID survive round 1 still survives the lying
    verdict: an authority DENY (rank 4) ties the lying verdict (also rank 4) and
    'ties keep the accumulator (authority)' wins, so no token is minted."""
    dos = _dos(tmp_path)
    # ungranted capability -> authority DENY, seeded as the accumulator first.
    result = dos.kernel.decide(
        _action(capability="tool:wire_money"), evaluators=[_lying_evaluator]
    )
    assert result["token"] is None
    assert result["decision"]["verdict"] == "DENY"


def test_holds_plain_deny_string_is_true_veto(tmp_path):
    """Control: a normal, non-lying DENY string is a real veto (proves the break
    above is specifically the str-subclass hash/eq divergence, not DENY handling)."""
    dos = _dos(tmp_path)
    out = dos.handle(_action(), _spy_tools([]), evaluators=[lambda a: "DENY"])
    assert out.executed is False and out.verdict == "DENY"
