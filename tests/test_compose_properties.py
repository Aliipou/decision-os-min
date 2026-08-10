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

EVERY PROPERTY IN THE BRIEF HELD — but four of them once held only in a weaker
form than the prose claimed, and those gaps were pinned here as `test_FINDING_*`
tests asserting the honest weakness rather than the property we wanted. The
blue-team fix (COMPOSITION.md §11, root causes R1/R2/R3) has removed all four, so
each is now restated as the STRENGTHENED property it has become. They remain
Hypothesis property tests over the same strategies — including the off-lattice
strings that produced the original counterexamples — so a regression is found by
search, not by our imagination:

  F1 -> CLOSED by R2 (`normalize`). `meet` was commutative/associative/
      permutation-invariant only **up to rank**: off-lattice strings ranked as DENY
      but were returned verbatim, so `meet(DENY, "WAT") == "DENY"` while
      `meet("WAT", DENY) == "WAT"`, and `compose` could return a string that was not
      a member of `VERDICTS`. `meet` now normalizes both operands, so the laws hold
      VERBATIM over arbitrary strings and `compose` always returns a member of
      `VERDICTS`. See `test_meet_is_commutative_verbatim_for_arbitrary_strings` and
      `test_compose_always_returns_a_member_of_the_vocabulary`.

  F2 -> CLOSED by the `as_decision` hardening. Invariant 4 (fail-closed
      composition) was enforced only inside the `evaluators.py` wrappers, so a raw
      evaluator returning a non-str non-mapping, or an unhashable "verdict", made
      `Kernel.decide` raise instead of composing as DENY. Both now compose as DENY.
      See `test_a_non_mapping_evaluator_return_denies_instead_of_raising`.

  F3 -> CLOSED by R1 (`sanitize`), in the only way it honestly could be. "Order
      carries no semantic meaning" was true of the VERDICT and false of the
      OBLIGATION: two evaluators tying at LIMIT with different
      `transformed_payload`s agreed on the verdict and disagreed on what executed.
      An evaluator can no longer carry an obligation at all, so there is nothing
      left for registration order to select — and a LIMIT with no obligation is
      refused by the PEP rather than degraded. Obligations still do not COMPOSE
      (COMPOSITION.md §7); they are now refused instead of silently order-selected.
      One residual is pinned inside that test: the `reason` string is still chosen
      by registration order, and it is what lands in the audit log.

  F4 -> CLOSED by R1. `as_decision` used `setdefault` for `action_ref`, letting a
      governing evaluator write an identity field of a signed decision (a
      plugin-triggerable DoS, since the PEP then refused the decision). It now
      ASSIGNS `action_ref` from the action, unconditionally.

None of the four was ever an escalation on its own: no combination of evaluator
VERDICTS found by Hypothesis ever produced a token for a non-permitting composed
verdict, or made the kernel less restrictive than its own authority ruling. The
escalations lived in the fields around the verdict, and are covered by
`test_redteam_composition.py`.
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
    retries and duplicated plugin registrations safe.

    Stated on the NORMALIZED value: `meet(a, a)` is idempotent as a lattice
    operation, and for an off-lattice `a` the single lattice element it denotes is
    DENY. Before R2 this was `meet(a, a) == a` verbatim — which passed only because
    the unknown string was handed back unchanged, i.e. it passed for the reason that
    was the bug."""
    assert meet(a, a) == meet(meet(a, a), a)
    assert meet(a, a) == (a if a in VERDICTS else DENY)


@given(a=any_verdict, b=any_verdict)
def test_meet_returns_the_more_restrictive_operand(a: str, b: str) -> None:
    """The defining property: meet is a greatest-lower-bound in restrictiveness.

    R2 strengthens the second half. `meet` still never invents a verdict — it
    selects an operand — but it selects the operand's LATTICE ELEMENT, so the
    returned value is always a member of `VERDICTS` even when the operands are not.
    An evaluator speaking a foreign dialect can therefore never put a string into a
    signed decision that no consumer's vocabulary contains."""
    assert rank(meet(a, b)) == max(rank(a), rank(b))
    normalized = (a if a in VERDICTS else DENY, b if b in VERDICTS else DENY)
    assert meet(a, b) in normalized  # selects an operand; never invents a verdict
    assert meet(a, b) in VERDICTS  # ...and always lands inside the vocabulary


# --- 2. identity and absorbing element --------------------------------------
@given(x=lattice_verdicts)
def test_allow_is_the_identity_for_lattice_members(x: str) -> None:
    """An evaluator that ALLOWs contributes nothing — the formal content of
    "a non-authority evaluator's ALLOW grants no permission". This is the identity
    law proper, and it is stated where an identity law belongs: over the lattice's
    own elements."""
    assert meet(ALLOW, x) == x
    assert meet(x, ALLOW) == x


@given(x=off_lattice)
def test_allow_composed_with_an_off_lattice_verdict_is_deny(x: str) -> None:
    """The other half of the old `test_allow_is_the_identity`, which used to quantify
    over ANY string and passed only because an unknown verdict was returned verbatim
    — so `meet(ALLOW, "WAT") == "WAT"` looked like the identity law when it was
    really the R2 bug wearing the law's clothes.

    Off-lattice input is not an element of the lattice, so ALLOW cannot be its
    identity; it is normalized to DENY first. Composing an unknown verdict with
    ALLOW therefore DENIES — fail-closed, and in the lattice's own vocabulary."""
    assert meet(ALLOW, x) == DENY
    assert meet(x, ALLOW) == DENY
    assert meet(ALLOW, x) not in PERMITTING


@given(x=any_verdict)
def test_deny_is_absorbing(x: str) -> None:
    """Any DENY sinks the composition: Invariant 2, as an algebraic law."""
    assert same(meet(DENY, x), DENY)
    assert same(meet(x, DENY), DENY)
    assert meet(DENY, x) not in PERMITTING
    assert meet(x, DENY) not in PERMITTING


@given(x=off_lattice)
def test_meet_is_commutative_verbatim_for_arbitrary_strings(x: str) -> None:
    """WAS FINDING F1 — now the strengthened property.

    `meet(x, DENY)` used to return `x`, not the string "DENY", whenever `x` was
    off-lattice. The two were rank-equal so the *decision* was right, but the
    returned value was a string no consumer's vocabulary contained, and
    commutativity failed at the string level: `meet(DENY, "WAT") != meet("WAT",
    DENY)`. A consumer testing `verdict == DENY` — a natural, wrong-but-plausible
    read — saw a refusal as "not a denial".

    R2's `normalize` makes absorption hold verbatim over arbitrary `str` VALUES,
    not merely up to rank. This is the one-line change the old docstring described
    as "deliberately not made here"; it has now been made.

    SCOPE LIMIT, stated so this is not read as more than it is: `normalize` tests
    `verdict in _RANK`, a hash lookup. A `str` SUBCLASS with a lying `__eq__`/
    `__hash__` can collide with a lattice member and be returned verbatim, so the
    law is over plain strings, not over every object that is `isinstance(x, str)`.
    That residual is fail-closed and pinned in
    `test_redteam_composition.test_finding_R2_normalize_is_bypassable_by_a_lying_str_subclass`."""
    assert meet(x, DENY) == DENY
    assert meet(DENY, x) == DENY
    assert meet(x, DENY) == meet(DENY, x)  # commutativity now holds string-level
    assert meet(x, DENY) in VERDICTS  # ...and the result stays in the vocabulary


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


@given(verdicts=verdict_lists)
def test_compose_always_returns_a_member_of_the_vocabulary(verdicts: list[str]) -> None:
    """WAS FINDING F1, continued — now the strengthened property, and quantified
    over whole LISTS rather than the single off-lattice string of the finding.

    Permutation invariance used to be rank-level only: `compose([x, DENY])` returned
    `x` while `compose([DENY, x])` returned "DENY" — the same decision, different
    strings. `VERDICTS` exists so adapters can reject foreign verdicts, yet `compose`
    itself could hand one back.

    Post-R2 the composed verdict is ALWAYS a member of `VERDICTS`, whatever dialects
    the evaluators spoke, and permutation invariance is verbatim rather than up to
    rank. (Same scope limit as above: plain `str` values, not lying `str`
    subclasses.)"""
    assert compose(verdicts) in VERDICTS
    assert compose(list(reversed(verdicts))) == compose(verdicts)


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
def test_an_evaluator_obligation_cannot_be_order_selected(
    payload_a: str, payload_b: str
) -> None:
    """WAS FINDING F3, the sharpest one — now the strengthened property.

    "Evaluator order carries no semantic meaning" was proved above FOR THE VERDICT,
    and was FALSE for the obligation attached to it — the field that actually shapes
    execution. `more_restrictive` keeps `d1` on a tie, so two evaluators tying at
    LIMIT with different `transformed_payload`s produced the same verdict and
    DIFFERENT executed payloads depending purely on registration order.

    R1 closes it at the root: `transformed_payload` is not evaluator-contributable,
    so neither evaluator carries an obligation and there is nothing for registration
    order to select. Both orders yield the identical decision content. Note this is
    a refusal to honour an unverified obligation, not an obligation-union
    implementation — COMPOSITION.md §7 still stands, and the PEP now REFUSES a LIMIT
    that arrives with no payload rather than executing something else.

    RESIDUAL, pinned deliberately rather than smoothed over: `reason` IS still
    evaluator-contributable, and `more_restrictive`'s tie-break still selects it by
    registration order — so the SIGNED decision's reason string, which every
    downstream verifier reads, depends on which plugin was registered first. It
    cannot shape an effect, so it is a provenance defect and not an authorization
    one, but it is the last place where evaluator order is not semantically
    empty."""
    assume(payload_a != payload_b)
    first = _obligation_evaluator(payload_a)
    second = _obligation_evaluator(payload_b)

    ab = KERNEL.decide(ACTION, evaluators=[first, second])["decision"]
    ba = KERNEL.decide(ACTION, evaluators=[second, first])["decision"]

    assert ab["verdict"] == ba["verdict"] == LIMIT  # verdict: order-free, as claimed
    # R1: the obligation never made it into either decision, so it cannot differ.
    assert "transformed_payload" not in ab
    assert "transformed_payload" not in ba
    # RESIDUAL: the reason is still tie-broken by registration order.
    assert ab["reason"] != ba["reason"]


@settings(deadline=None)
@given(forged=st.text(alphabet=_PRINTABLE, min_size=1, max_size=8))
def test_a_governing_evaluator_cannot_overwrite_the_signed_action_ref(
    forged: str,
) -> None:
    """WAS FINDING F4 — now the strengthened property.

    `as_decision` used to set `action_ref` with `setdefault`, so an evaluator that
    WON the fold (any verdict strictly more restrictive than authority's) carried
    its own `action_ref` into the signed decision — an identity field an untrusted,
    veto-only plugin should have no say over. It was fail-closed rather than an
    escalation (the PEP's W-1 check then refused the decision), so the reachable
    effect was a plugin silently rendering a PERMITTING decision unexecutable.

    R1 assigns `action_ref` from the action unconditionally: `action_ref` is one of
    the three keys an evaluator may nominally contribute, but `as_decision`
    immediately overwrites it with the kernel's value. The forged reference is
    discarded for every string Hypothesis can produce, and the decision stays
    executable."""
    assume(forged != ACTION["nonce"])
    out = KERNEL.decide(
        ACTION, evaluators=[lambda action: {"verdict": LIMIT, "action_ref": forged}]
    )
    assert out["decision"]["action_ref"] == ACTION["nonce"]  # kernel-controlled
    assert out["decision"]["action_ref"] != forged
    assert out["token"]["action_ref"] == ACTION["nonce"]
    # ...and the binding still commits to the REAL action, as it always did.
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


# --- WAS FINDING F2: fail-closed now holds AT the kernel boundary ------------
# Both of these were example tests pinning a crash. They are now property tests:
# Hypothesis searches the malformed-return space instead of the three values we
# happened to think of.
malformed_returns = st.one_of(
    st.integers(),
    st.none(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.booleans(),
    st.lists(st.text(max_size=4), max_size=3),
    st.tuples(st.text(max_size=4)),
    st.sets(st.text(max_size=4), max_size=3),
)


@settings(deadline=None)
@given(bad=malformed_returns)
def test_a_non_mapping_evaluator_return_denies_instead_of_raising(bad: Any) -> None:
    """WAS FINDING F2 — now the strengthened property.

    COMPOSITION.md Invariant 4 says an evaluator that "errors, times out, or returns
    an unknown verdict is composed as DENY". That held for the wrappers in
    `evaluators.py`, which catch — but `Kernel.decide` called a raw evaluator
    unguarded, so a plugin returning a non-str, non-mapping value made the kernel
    RAISE. No token was minted (the exception escaped before the mint), so it was a
    DoS rather than an escalation — but the kernel did not itself satisfy Invariant
    4, and the exception TYPE was not even stable (TypeError for a scalar,
    ValueError for a list), so a caller could not reliably catch-and-deny.

    `as_decision` now recognises a non-dict non-str return and composes it as DENY
    with an explanatory reason. The kernel boundary itself is fail-closed, for every
    malformed shape Hypothesis can build — no exception, no token."""
    out = KERNEL.decide(ACTION, evaluators=[lambda action, b=bad: b])
    assert out["decision"]["verdict"] == DENY
    assert out["token"] is None
    assert "token_id" not in out["decision"]
    assert "malformed evaluator output" in out["decision"]["reason"]


@settings(deadline=None)
@given(verdict=st.one_of(st.lists(st.text(max_size=4), max_size=3), st.dictionaries(
    st.text(max_size=2), st.text(max_size=2), max_size=2)))
def test_an_unhashable_verdict_denies_instead_of_raising(verdict: Any) -> None:
    """WAS FINDING F2, continued — now the strengthened property.

    `_rank` looks the verdict up in a dict, so an UNHASHABLE verdict used to raise
    TypeError inside the composer itself rather than ranking as DENY. The
    fail-closed rule reads "unknown -> DENY"; unknown meant "not a key", and an
    unhashable value is not even askable.

    `as_decision` now type-checks before ranking (`normalize(v) if isinstance(v,
    str) else DENY`), so a non-string verdict of any kind — hashable or not —
    composes as DENY without touching the rank table."""
    out = KERNEL.decide(ACTION, evaluators=[lambda action, v=verdict: {"verdict": v}])
    assert out["decision"]["verdict"] == DENY
    assert out["token"] is None
    assert "token_id" not in out["decision"]


# --- sanity: the generated space really does exercise the whole lattice -----
def test_every_lattice_element_is_reachable_by_composition() -> None:
    """Guards the properties above from vacuity: if the strategies could only ever
    produce DENY, every antitone assertion would pass for the wrong reason."""
    assert {compose([v]) for v in (ALLOW, LIMIT, CONTAIN, DEFER, DENY)} == set(VERDICTS)
