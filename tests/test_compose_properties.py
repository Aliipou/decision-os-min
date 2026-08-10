"""Property-based proof that the verdict lattice really is an algebra.

`test_compose.py` pins the composition contract with hand-picked examples; those
examples show the laws hold *at the points we thought to check*. The security
argument in `COMPOSITION.md` is stronger than that: it says composition is a meet
on a bounded lattice, therefore evaluator ORDER carries no semantic content and
adding an evaluator can only ever restrict. Those are universally-quantified
claims, so they deserve universally-quantified tests. Hypothesis searches for the
counterexample instead of trusting the enumeration.

The ordering below (`_ORDER`) is re-stated FROM THE SPEC (COMPOSITION.md §3)
rather than imported from `compose._RANK`, so these tests compare the
implementation against the contract, not against itself.

EVERY PROPERTY IN THE BRIEF HOLDS — but three of them hold only in a weaker form
than the prose claims, and the gap is where the findings are. Four are pinned
here, not papered over; see the tests named `test_FINDING_*`:

  F1. `meet` is commutative/associative/permutation-invariant **up to rank**, not
      up to string identity. Off-lattice strings all rank as DENY but are returned
      verbatim, so `meet(DENY, "WAT") == "DENY"` while `meet("WAT", DENY) == "WAT"`,
      and `compose` can return a string that is not a member of `VERDICTS`. It is
      fail-closed (nothing off-lattice is in `PERMITTING`, so no token is minted),
      but a downstream consumer testing `verdict == DENY` instead of
      `verdict not in PERMITTING` would misread it.

  F2. Invariant 4 (fail-closed composition) is NOT enforced at the kernel
      boundary — only inside the `evaluators.py` wrappers. A raw evaluator whose
      return value is neither a str nor a mapping, or whose "verdict" is
      unhashable, makes `Kernel.decide` raise rather than compose as DENY. No
      token is minted, so it is a DoS and not an escalation, but the exception
      escapes the kernel.

  F3. "Evaluator order carries no semantic meaning" is proved here for the
      VERDICT and is false for the OBLIGATION. Two evaluators tying at LIMIT with
      different `transformed_payload`s agree on the verdict and disagree on what
      actually executes; `more_restrictive` breaks the tie by registration order.
      COMPOSITION.md §7 flags that obligations do not compose — this is the
      operational consequence.

  F4. A governing evaluator can overwrite the signed `action_ref`, because
      `as_decision` uses `setdefault` for it. Fail-closed (the PEP then refuses
      the decision), so it is a plugin-triggerable DoS inside the antitone
      guarantee — but an untrusted veto-only plugin should not be able to write
      an identity field of a signed decision at all.

None of the four is an escalation: no combination of evaluator inputs found by
Hypothesis ever produced a token for a non-permitting composed verdict, or made
the kernel less restrictive than its own authority ruling.
"""

from __future__ import annotations

from functools import reduce
from typing import Any

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from decision_os_min import Kernel
from decision_os_min.compose import (
    ALLOW,
    CONTAIN,
    DEFER,
    DENY,
    LIMIT,
    PERMITTING,
    VERDICTS,
    as_decision,
    compose,
    meet,
)
from decision_os_min.kernel import action_fingerprint

# The restrictiveness order, transcribed from COMPOSITION.md §3 (least → most).
# An unknown verdict ranks as DENY: this is the fail-closed rule of the contract.
_ORDER = [ALLOW, LIMIT, CONTAIN, DEFER, DENY]


def rank(verdict: object) -> int:
    """Spec-side rank. Independent of `compose._RANK` on purpose."""
    return _ORDER.index(verdict) if verdict in _ORDER else _ORDER.index(DENY)


def same(a: object, b: object) -> bool:
    """Semantic equality in the lattice: two verdicts of equal rank are the same
    element. `"WAT"` and `DENY` are the same lattice element, different strings."""
    return rank(a) == rank(b)


# --- strategies -------------------------------------------------------------
# Off-lattice strings are the interesting half of the input space: they are what a
# neighbouring engine with a different vocabulary ("allow", "permit", "") sends.
_PRINTABLE = st.characters(min_codepoint=32, max_codepoint=126)
lattice_verdicts = st.sampled_from(sorted(VERDICTS))
off_lattice = st.text(alphabet=_PRINTABLE, max_size=6).filter(lambda s: s not in VERDICTS)
any_verdict = st.one_of(lattice_verdicts, off_lattice)

verdict_lists = st.lists(any_verdict, max_size=6)
lattice_lists = st.lists(lattice_verdicts, max_size=6)


# --- 1. meet is a semilattice operation -------------------------------------
@given(a=any_verdict, b=any_verdict)
def test_meet_is_commutative(a: str, b: str) -> None:
    """Order of two verdicts carries no meaning. Stated over ARBITRARY strings, so
    this is the version that covers foreign vocabularies too."""
    assert same(meet(a, b), meet(b, a))


@given(a=lattice_verdicts, b=lattice_verdicts)
def test_meet_is_commutative_verbatim_on_the_lattice(a: str, b: str) -> None:
    """Inside the declared vocabulary the law holds on the nose, not just up to
    rank — rank is injective on VERDICTS, so equal rank means equal string."""
    assert meet(a, b) == meet(b, a)


@given(a=any_verdict, b=any_verdict, c=any_verdict)
def test_meet_is_associative(a: str, b: str, c: str) -> None:
    assert same(meet(meet(a, b), c), meet(a, meet(b, c)))


@given(a=lattice_verdicts, b=lattice_verdicts, c=lattice_verdicts)
def test_meet_is_associative_verbatim_on_the_lattice(a: str, b: str, c: str) -> None:
    assert meet(meet(a, b), c) == meet(a, meet(b, c))


@given(a=any_verdict)
def test_meet_is_idempotent(a: str) -> None:
    """Consulting the same evaluator twice must change nothing — this is what makes
    retries and duplicated plugin registrations safe."""
    assert meet(a, a) == a


@given(a=any_verdict, b=any_verdict)
def test_meet_returns_the_more_restrictive_operand(a: str, b: str) -> None:
    """The defining property: meet is a greatest-lower-bound in restrictiveness."""
    assert rank(meet(a, b)) == max(rank(a), rank(b))
    assert meet(a, b) in (a, b)  # it selects an operand; it never invents a verdict


# --- 2. identity and absorbing element --------------------------------------
@given(x=any_verdict)
def test_allow_is_the_identity(x: str) -> None:
    """An evaluator that ALLOWs contributes nothing — the formal content of
    "a non-authority evaluator's ALLOW grants no permission"."""
    assert meet(ALLOW, x) == x
    assert meet(x, ALLOW) == x


@given(x=any_verdict)
def test_deny_is_absorbing(x: str) -> None:
    """Any DENY sinks the composition: Invariant 2, as an algebraic law."""
    assert same(meet(DENY, x), DENY)
    assert same(meet(x, DENY), DENY)
    assert meet(DENY, x) not in PERMITTING
    assert meet(x, DENY) not in PERMITTING


@given(x=off_lattice)
def test_FINDING_absorption_is_only_up_to_rank_for_off_lattice_verdicts(x: str) -> None:
    """FINDING F1. `meet(x, DENY)` returns `x`, not the string "DENY", whenever `x`
    is off-lattice — the two are rank-equal so the *decision* is right, but the
    returned token is a string no consumer's vocabulary contains. Pinned rather
    than smoothed over: the safe read of a verdict is `not in PERMITTING`, never
    `== DENY`. Fixing it would mean normalizing unknown verdicts to DENY in
    `_rank`'s caller — a one-line change to `meet`, deliberately not made here."""
    assert meet(x, DENY) == x
    assert meet(DENY, x) == DENY
    assert meet(x, DENY) != meet(DENY, x)  # commutativity fails at string level
    assert meet(x, DENY) not in VERDICTS  # ...and the result escapes the vocabulary


# --- 3. compose is the fold, and is permutation-invariant -------------------
@given(verdicts=verdict_lists)
def test_compose_is_the_fold_of_meet_from_allow(verdicts: list[str]) -> None:
    """n-ary composition is exactly the binary meet folded from the identity —
    there is no extra n-ary rule that could smuggle in different behaviour."""
    assert compose(verdicts) == reduce(meet, verdicts, ALLOW)


@given(verdicts=verdict_lists, data=st.data())
def test_compose_is_invariant_under_any_permutation(verdicts: list[str], data: Any) -> None:
    """THE order claim, formally. If this holds for every permutation then
    "Authority first" vs "Legitimacy first" is a latency choice with no semantic
    content, exactly as COMPOSITION.md §3 asserts."""
    shuffled = data.draw(st.permutations(verdicts))
    assert same(compose(verdicts), compose(shuffled))
    # And the security-relevant projection is identical, not merely rank-equal:
    assert (compose(verdicts) in PERMITTING) == (compose(shuffled) in PERMITTING)


@given(verdicts=lattice_lists, data=st.data())
def test_compose_permutation_invariance_is_verbatim_on_the_lattice(
    verdicts: list[str], data: Any
) -> None:
    assert compose(verdicts) == compose(data.draw(st.permutations(verdicts)))


@given(x=off_lattice)
def test_FINDING_compose_can_return_a_string_outside_the_vocabulary(x: str) -> None:
    """FINDING F1, continued. Permutation invariance is rank-level only: the two
    orderings below agree on the DECISION and disagree on the STRING. `VERDICTS`
    exists so adapters can reject foreign verdicts, yet `compose` itself can hand
    one back."""
    assume(x != DENY)
    assert compose([x, DENY]) == x
    assert compose([DENY, x]) == DENY
    assert compose([x, DENY]) not in VERDICTS
    assert compose([x, DENY]) not in PERMITTING  # still fail-closed, which is the point


# --- 4. antitone: adding evaluators can only restrict -----------------------
@given(xs=verdict_lists, ys=verdict_lists)
def test_compose_is_antitone_under_extension(xs: list[str], ys: list[str]) -> None:
    """Monotonicity of restriction. Registering another plugin can never loosen an
    existing decision, which is what makes untrusted veto-only plugins safe to add
    (COMPOSITION.md §9)."""
    assert rank(compose(xs + ys)) >= rank(compose(xs))
    assert rank(compose(xs + ys)) >= rank(compose(ys))


@given(xs=verdict_lists, ys=verdict_lists)
def test_permitting_is_downward_closed_under_extension(xs: list[str], ys: list[str]) -> None:
    """The consequence that matters operationally: if the extended composition
    permits, every sub-composition already permitted."""
    if compose(xs + ys) in PERMITTING:
        assert compose(xs) in PERMITTING
        assert compose(ys) in PERMITTING


# --- 5-6. the same laws through the real kernel -----------------------------
POLICY = {"grants": {"agent:bot": ["tool:send_email"]}, "default": "deny"}
ACTION = {
    "actor": "agent:bot",
    "tool": "send_email",
    "capability": "tool:send_email",
    "payload": {"to": "x@ok.test"},
    "nonce": "n-prop",
}
# One kernel for the whole module: `decide` is a pure function of (action,
# evaluators) apart from the token id/expiry, and key generation per example would
# dominate the runtime.
KERNEL = Kernel(POLICY)


def _evaluator(verdict: str):
    """A minimal co-equal evaluator returning a fixed verdict, dict-shaped like a
    real one so `as_decision` takes the dict path."""
    return lambda action: {"verdict": verdict, "reason": f"prop:{verdict}"}


def _obligation_evaluator(marker: str):
    """A LIMIT evaluator carrying an OBLIGATION (the redacted payload). Two of these
    tie in the lattice yet disagree about what should actually be executed."""
    return lambda action: {
        "verdict": LIMIT,
        "reason": f"redacted by {marker}",
        "transformed_payload": {"to": marker},
    }


# Ed25519 signing time varies enough on a loaded machine to trip Hypothesis'
# per-example deadline; the properties are about verdicts, not latency.
@settings(deadline=None)
@given(verdicts=verdict_lists)
def test_kernel_is_antitone_in_its_evaluators(verdicts: list[str]) -> None:
    """5. End-to-end: no set of evaluators can make the kernel LESS restrictive
    than its own authority ruling. This is the untrusted-plugin trust argument
    measured on the real `decide` path, not on `compose` in isolation."""
    baseline = KERNEL.decide(ACTION)["decision"]["verdict"]
    with_evaluators = KERNEL.decide(
        ACTION, evaluators=[_evaluator(v) for v in verdicts]
    )["decision"]["verdict"]
    assert rank(with_evaluators) >= rank(baseline)


@settings(deadline=None)
@given(verdicts=verdict_lists)
def test_kernel_composition_agrees_with_the_algebra(verdicts: list[str]) -> None:
    """The kernel's fold (`more_restrictive` over decision dicts) must compute the
    same lattice element as `compose` over the bare verdicts — otherwise the
    algebra proved above says nothing about the product."""
    baseline = KERNEL.decide(ACTION)["decision"]["verdict"]
    out = KERNEL.decide(ACTION, evaluators=[_evaluator(v) for v in verdicts])
    assert same(out["decision"]["verdict"], compose([baseline, *verdicts]))


@settings(deadline=None)
@given(verdicts=verdict_lists, data=st.data())
def test_kernel_verdict_is_independent_of_evaluator_order(
    verdicts: list[str], data: Any
) -> None:
    """Order-independence where it is actually claimed: on the kernel path."""
    shuffled = data.draw(st.permutations(verdicts))
    a = KERNEL.decide(ACTION, evaluators=[_evaluator(v) for v in verdicts])["decision"]
    b = KERNEL.decide(ACTION, evaluators=[_evaluator(v) for v in shuffled])["decision"]
    assert same(a["verdict"], b["verdict"])


@settings(deadline=None)
@given(payload_a=st.text(max_size=4), payload_b=st.text(max_size=4))
def test_FINDING_order_independence_covers_the_verdict_but_not_the_obligation(
    payload_a: str, payload_b: str
) -> None:
    """FINDING F3 — the sharpest one. "Evaluator order carries no semantic meaning"
    is proved above FOR THE VERDICT. It is FALSE for the obligation attached to the
    verdict, which is the field that actually shapes execution. `more_restrictive`
    keeps `d1` on a tie, so two evaluators tying at LIMIT with different
    `transformed_payload`s produce the same verdict and DIFFERENT executed payloads
    depending purely on registration order. COMPOSITION.md §7 records that
    obligations do not compose; this shows the consequence is not merely "we lose
    an obligation" but "the surviving obligation is order-selected".

    Asserted as the CURRENT behaviour so a future obligation-union implementation
    breaks this test loudly."""
    assume(payload_a != payload_b)
    first = _obligation_evaluator(payload_a)
    second = _obligation_evaluator(payload_b)

    ab = KERNEL.decide(ACTION, evaluators=[first, second])["decision"]
    ba = KERNEL.decide(ACTION, evaluators=[second, first])["decision"]

    assert ab["verdict"] == ba["verdict"] == LIMIT  # verdict: order-free, as claimed
    assert ab["transformed_payload"] != ba["transformed_payload"]  # obligation: NOT
    assert ab["reason"] != ba["reason"]  # nor the reason that lands in the audit log


@settings(deadline=None)
@given(forged=st.text(alphabet=_PRINTABLE, min_size=1, max_size=8))
def test_FINDING_a_governing_evaluator_can_overwrite_the_signed_action_ref(
    forged: str,
) -> None:
    """FINDING F4. `as_decision` sets `action_ref` with `setdefault`, so an
    evaluator that WINS the fold (any verdict strictly more restrictive than
    authority's) carries its own `action_ref` into the signed decision — a field an
    untrusted, veto-only plugin should have no say over.

    It is fail-closed, not an escalation: `action_binding` is recomputed by the
    kernel from the real action, and the PEP's W-1 check then compares the live
    nonce against the corrupted `action_ref` and refuses. So the reachable effect
    is that a plugin can silently render a PERMITTING decision unexecutable (DoS),
    which is inside the antitone guarantee. Still a defect: the fix is for
    `as_decision` to ASSIGN `action_ref` from the action rather than defer to the
    evaluator. Not fixed here — this file's job is falsification, not repair."""
    assume(forged != ACTION["nonce"])
    out = KERNEL.decide(
        ACTION, evaluators=[lambda action: {"verdict": LIMIT, "action_ref": forged}]
    )
    assert out["decision"]["action_ref"] == forged  # plugin-controlled, and signed
    assert out["token"]["action_ref"] == forged
    # ...but the binding still commits to the REAL action, which is why it is safe.
    assert out["token"]["action_binding"] == out["decision"]["action_binding"]
    assert out["decision"]["action_binding"] == action_fingerprint(ACTION)


@settings(deadline=None)
@given(verdicts=verdict_lists)
def test_token_is_minted_iff_the_composed_verdict_permits(verdicts: list[str]) -> None:
    """6. Invariant 3, generatively: the token exists exactly when the COMPOSED
    verdict permits — never one-sided, never before composition — and when it
    exists it is bound to the same action fingerprint the decision commits to."""
    out = KERNEL.decide(ACTION, evaluators=[_evaluator(v) for v in verdicts])
    decision, token = out["decision"], out["token"]
    permits = decision["verdict"] in PERMITTING

    assert (token is not None) is permits  # IFF, both directions
    assert ("token_id" in decision) is permits  # no half-minted decision either
    if token is not None:
        assert token["action_binding"] == decision["action_binding"]
        assert token["token_id"] == decision["token_id"]
        assert token["action_ref"] == decision["action_ref"]


@settings(deadline=None)
@given(verdicts=st.lists(any_verdict, min_size=1, max_size=6))
def test_a_single_non_permitting_evaluator_blocks_the_mint(verdicts: list[str]) -> None:
    """Invariant 2 through the kernel: one veto is enough, wherever it sits."""
    assume(any(v not in PERMITTING for v in verdicts))
    out = KERNEL.decide(ACTION, evaluators=[_evaluator(v) for v in verdicts])
    assert out["token"] is None
    assert "token_id" not in out["decision"]


# --- 7. as_decision normalization never loosens -----------------------------
# An evaluator return value: a bare string, a well-formed dict, or a dict missing
# the verdict key (the malformed case that must fail closed).
evaluator_outputs = st.one_of(
    any_verdict,
    st.builds(lambda v, r: {"verdict": v, "reason": r}, any_verdict, st.text(max_size=4)),
    st.fixed_dictionaries({"reason": st.text(max_size=4)}),
)


def _raw_verdict(out: dict[str, Any] | str) -> str:
    """What the evaluator actually said, per the contract: a bare string IS the
    verdict; a dict with no verdict key said nothing, which the contract reads as
    DENY (Invariant 4)."""
    return out if isinstance(out, str) else out.get("verdict", DENY)


@given(out=evaluator_outputs)
def test_as_decision_never_loosens_what_the_evaluator_said(out: dict[str, Any] | str) -> None:
    """7. Normalization is not allowed to be a widening step. A malformed return
    value may become MORE restrictive (DENY) but never less."""
    normalized = as_decision(out, ACTION)
    assert rank(normalized["verdict"]) >= rank(_raw_verdict(out))


@given(out=evaluator_outputs)
def test_as_decision_output_is_well_formed_and_bound(out: dict[str, Any] | str) -> None:
    """The normalized decision always carries the three fields the kernel folds on,
    and is tied to this action's reference."""
    normalized = as_decision(out, ACTION)
    assert set(normalized) >= {"verdict", "reason", "action_ref"}
    assert normalized["action_ref"] == ACTION["nonce"]


@given(reason=st.text(max_size=4))
def test_as_decision_fails_closed_on_a_verdictless_dict(reason: str) -> None:
    assert as_decision({"reason": reason}, ACTION)["verdict"] == DENY


# --- FINDING F2: fail-closed stops at the evaluators.py wrappers -------------
def test_FINDING_kernel_raises_instead_of_denying_on_a_non_mapping_evaluator() -> None:
    """FINDING F2. COMPOSITION.md Invariant 4 says an evaluator that "errors, times
    out, or returns an unknown verdict is composed as DENY". That holds for the
    wrappers in `evaluators.py`, which catch — but `Kernel.decide` calls a raw
    evaluator unguarded, so a plugin returning a non-str, non-mapping value makes
    the kernel raise. No token is minted (the exception escapes before the mint),
    so this is a DoS, not an escalation — but the kernel does not itself satisfy
    Invariant 4, and a caller that treats an exception as "no decision" rather than
    "deny" would be wrong. Pinned as the current behaviour, not asserted as
    correct. Note the exception TYPE is not even stable (TypeError for a scalar,
    ValueError for a list), so a caller cannot reliably catch-and-deny either."""
    for bad in (42, None, ["ALLOW"]):
        try:
            KERNEL.decide(ACTION, evaluators=[lambda action, b=bad: b])
        except (TypeError, ValueError):
            continue
        raise AssertionError(f"expected the kernel to raise on evaluator output {bad!r}")


def test_FINDING_kernel_raises_on_an_unhashable_verdict() -> None:
    """FINDING F2, continued. `_rank` looks the verdict up in a dict, so a verdict
    that is unhashable raises TypeError inside the composer itself rather than
    ranking as DENY. The fail-closed rule is written as "unknown → DENY"; unknown
    here means "not a key", and an unhashable value is not even askable."""
    try:
        KERNEL.decide(ACTION, evaluators=[lambda action: {"verdict": ["ALLOW"]}])
    except TypeError:
        return
    raise AssertionError("expected TypeError from an unhashable verdict")


# --- sanity: the generated space really does exercise the whole lattice -----
def test_every_lattice_element_is_reachable_by_composition() -> None:
    """Guards the properties above from vacuity: if the strategies could only ever
    produce DENY, every antitone assertion would pass for the wrong reason."""
    assert {compose([v]) for v in (ALLOW, LIMIT, CONTAIN, DEFER, DENY)} == set(VERDICTS)
