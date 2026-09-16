# Semantic veto

## Problem

The kernel decides whether an actor holds a capability and whether the declared
purpose is bound to the action's data labels. It never reads what the payload
means. An agent with `tool:send_email` and purpose `support_reply` can therefore
send a message whose body is a full customer export, and every structural check
passes. Legitimacy evaluators can catch some of this, but only for properties
someone wrote down in advance.

A semantic judge (a language model, a trained classifier, a rules table) can
compare the concrete content of an action with its declared purpose. Its
judgement is useful and cannot be verified. The design question is where such a
component may sit without weakening anything the kernel already guarantees.

## Placement

`semantic_veto` is an ordinary co-equal evaluator under ADR-0001. It is composed
with the authority verdict and the other evaluators by the deny-dominant meet in
`compose.py`, before any token is minted. It is not part of the kernel, the PEP,
or the audit log's trust base, and it is off unless the host passes it in.

On the hosted plane it enters through `extra_evaluators` on `AgentHost` or
`SealedRuntime`, after the mandatory legitimacy evaluator.

## Guarantee

For every action and every judge behaviour, the composed verdict with the
semantic veto is either the verdict without it or `DENY`. In particular, an
action that authority or legitimacy refused cannot execute because of anything
the judge returns, raises, or fails to return in time.

This follows from three facts already enforced in the kernel (evaluators receive
a deep copy, run under `evaluator_timeout_s`, and are sanitised to
`{verdict, reason}`) plus the evaluator itself only ever emitting `ALLOW` or
`DENY`. `tests/test_semantic.py::test_semantic_veto_never_widens_authority`
checks it as a property over arbitrary judge outputs.

## Defences specific to a free-text judge

| Risk | Defence |
|---|---|
| Judge mutates the action or reaches kernel objects | The judge receives a canonical JSON string, not the action. |
| Harmful content hidden past a truncation point | A view longer than `max_view_chars` is denied without calling the judge. |
| Attacker-controlled `repr` shown to the judge | Non-JSON payloads (objects, NaN) are denied without calling the judge. |
| Judge output impersonating a judgment | Only `consistent`, `inconsistent`, `uncertain` are accepted, compared by base `str` value. Everything else is denied. |
| Judge errors used to switch the check off | Exceptions, `SystemExit`, `KeyboardInterrupt`, timeouts and malformed output are denied regardless of `on_uncertain`. |
| Judge text forging or disguising audit records | Reasons are flattened to one line, control, line-separator, zero-width and bidi characters are removed, length is capped at 280 characters. |
| Extra evaluator replacing M5 legitimacy evidence | On the hosted plane, `evidence_free` strips `legitimacy_digest` and `axiom_ids` from extra evaluators. `semantic_veto` never emits them. |

Every denial reason starts with `semantic-veto[<judge name>]`, so the audit log
shows which evaluator refused and why (AE-10).

## Prompt injection

The payload is controlled by the agent, and the agent may be controlled by an
attacker. A model-backed judge should be expected to be talked into answering
`consistent` some of the time. That outcome is acceptable by construction: it
grants nothing. The judge is a filter that raises the cost of misuse inside
already-granted authority; it is not a boundary.

The opposite attack, making the judge answer `inconsistent` for legitimate
traffic, is a denial of service against the agent. Operators who cannot accept
that should not deploy a semantic veto on that path.

## Configuration

`on_uncertain="deny"` is the default. `"abstain"` lets an explicit `uncertain`
answer pass to the other evaluators; errors still deny.

`evaluator_timeout_s` defaults to one second, which will time out most network
calls to a model. Set it on `DecisionOS`, `Governor`, `SealedRuntime` or
`AgentHost` to a budget that fits the judge. A timeout is a denial.

`fields` selects what the judge sees. The default omits `actor`, since identity
is authority's question.

## Non-claims

The semantic veto is outside everything covered by the Kani harnesses, the Lean
theorems and the TLA+ model. A semantic `ALLOW` is not evidence that an action is
safe, only that this judge did not object. The veto does not detect harm spread
across several individually consistent actions, and it does not inspect tool
output. It adds latency and, for a model-backed judge, sends action content to
that model's provider, which may itself be a data-handling concern.
