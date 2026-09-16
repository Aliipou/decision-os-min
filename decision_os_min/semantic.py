"""Semantic veto: an OPTIONAL, untrusted evaluator that asks whether an action
means what it claims to mean.

Authority answers "may this actor call this tool?". Legitimacy answers "should
this happen at all?". Neither reads the *meaning* of the payload. A semantic
judge (an LLM, a classifier, a rules engine) can notice that an action declared
as ``action_purpose="support_reply"`` is in fact exporting a customer table, or
that a ``cleanup`` intent carries ``rm -rf /``. That judgement is useful and
unverifiable, so it lives here, outside the kernel, under the same ADR-0001
plugin rules as every other evaluator.

Why this cannot weaken the kernel
---------------------------------
``semantic_veto`` returns ``ALLOW`` or ``DENY`` and nothing else. Composition is
the deny-dominant meet (``compose.py``), so:

* a judge that says "consistent" grants nothing authority did not already grant;
* a judge that is wrong, slow, crashed, or prompt-injected by the payload can at
  worst DENY an action authority would have allowed. Its failure is an
  availability problem, never an authorization problem.

The kernel already enforces the rest of the plugin contract on this evaluator:
it receives a deep copy of the action, runs under ``evaluator_timeout_s``, and
``sanitize`` strips its output to ``{verdict, reason}``. This module adds the
defences specific to a free-text judge:

1. **The judge sees a string, not the action.** A canonical JSON view of the
   selected fields is built here. The judge cannot mutate the action or reach
   kernel objects through it.
2. **No truncation.** A view longer than ``max_view_chars`` is DENIED without
   calling the judge. Truncating would let an attacker place the harmful part
   beyond the cut.
3. **No lossy serialisation.** A payload that is not plain JSON is DENIED. A
   ``default=str`` fallback would show the judge a ``repr`` the attacker controls.
4. **Strict output parsing.** Only the three canonical judgments are accepted,
   compared by base-``str`` value so a ``str`` subclass cannot impersonate one.
   Anything else is DENY.
5. **Audit-safe reasons.** The judge's reason flows into the signed decision and
   the hash-chained log (AE-10). Control characters, line separators and bidi
   overrides are removed and the length is bounded, so judge text cannot forge
   log lines or visually disguise a record.

Non-claims
----------
Nothing here is covered by the Kani/Lean/TLA+ results. A semantic ALLOW is not
evidence that an action is safe; it only means this judge did not object. The
evaluator contributes no ``legitimacy_digest`` and no ``axiom_ids``, so it never
displaces the legitimacy evidence bound into the decision (M5).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

from .compose import ALLOW, DENY, Evaluator

CONSISTENT = "consistent"
INCONSISTENT = "inconsistent"
UNCERTAIN = "uncertain"
JUDGMENTS = frozenset({CONSISTENT, INCONSISTENT, UNCERTAIN})
_CANONICAL_JUDGMENT = {j: j for j in JUDGMENTS}

# Fields shown to the judge by default. `actor` is left out on purpose: identity
# is authority's question, and showing it invites a judge to reason about who is
# asking instead of what is being asked.
DEFAULT_FIELDS: tuple[str, ...] = (
    "tool",
    "capability",
    "action_purpose",
    "intent",
    "resource",
    "data_labels",
    "payload",
)
DEFAULT_MAX_VIEW_CHARS = 8000
MAX_REASON_CHARS = 280
MAX_NAME_CHARS = 48

OnUncertain = Literal["deny", "abstain"]

# C0/C1 controls, DEL, Unicode line/paragraph separators, bidi embeddings,
# overrides and isolates, zero-width characters and the BOM.
_UNSAFE_CHARS = re.compile(
    "[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]"
)
_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class SemanticJudgment:
    """A judge's answer. ``judgment`` must be one of ``JUDGMENTS``."""

    judgment: str
    reason: str = ""


@runtime_checkable
class SemanticJudge(Protocol):
    """Anything with a ``name`` and a ``judge(view) -> judgment`` method.

    ``view`` is the canonical JSON string built by ``build_view``. The return
    value is a ``SemanticJudgment`` or a dict with ``judgment`` and ``reason``.
    Implementations are untrusted: they may raise, hang, or return garbage, and
    every one of those outcomes is a DENY.
    """

    name: str

    def judge(self, view: str) -> SemanticJudgment | dict[str, Any]: ...


def clean_text(text: object, limit: int = MAX_REASON_CHARS) -> str:
    """Make judge-supplied text safe to sign and log: one line, no control or
    direction-changing characters, bounded length."""
    raw = str.__str__(text) if isinstance(text, str) else ""
    flat = _WHITESPACE.sub(" ", _UNSAFE_CHARS.sub(" ", raw)).strip()
    if len(flat) > limit:
        flat = flat[: max(limit - 1, 0)].rstrip() + "…"
    return flat


def build_view(action: dict[str, Any], fields: Iterable[str] = DEFAULT_FIELDS) -> str:
    """Canonical JSON of the selected action fields. Raises ``TypeError`` or
    ``ValueError`` if the content is not plain JSON (no silent ``repr``)."""
    selected = {f: action[f] for f in fields if f in action}
    return json.dumps(
        selected, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    )


def _parse(raw: object) -> tuple[str | None, str]:
    judgment: object
    reason: object
    if isinstance(raw, SemanticJudgment):
        judgment, reason = raw.judgment, raw.reason
    elif isinstance(raw, dict):
        judgment, reason = raw.get("judgment"), raw.get("reason", "")
    else:
        return None, f"malformed judge output of type {type(raw).__name__}"
    if not isinstance(judgment, str):
        return None, "judge output has no string judgment"
    canonical = _CANONICAL_JUDGMENT.get(str.__str__(judgment))
    if canonical is None:
        return None, f"unknown judgment {clean_text(judgment, 40)!r}"
    return canonical, clean_text(reason)


def semantic_veto(
    judge: SemanticJudge,
    *,
    fields: Iterable[str] = DEFAULT_FIELDS,
    max_view_chars: int = DEFAULT_MAX_VIEW_CHARS,
    on_uncertain: OnUncertain = "deny",
) -> Evaluator:
    """Adapt a semantic judge into a **veto-only, fail-closed** ``Evaluator``.

    ``on_uncertain`` decides what an explicit "uncertain" answer means. The
    default ``"deny"`` is the safe choice. ``"abstain"`` lets the action through
    to the other evaluators, and should only be used when a DENY on every hard
    case is operationally unacceptable. Errors, timeouts and malformed output
    are DENY regardless of this setting, since an attacker who can induce them
    must not be able to switch the check off.

    Pass the returned callable in ``evaluators=[...]``. When the judge calls a
    remote model, raise the kernel's ``evaluator_timeout_s`` accordingly; the 1s
    default will turn most network calls into timeouts, which are DENY.
    """
    fields = tuple(fields)
    if not fields:
        raise ValueError("semantic_veto needs at least one field to show the judge")
    if not isinstance(max_view_chars, int) or max_view_chars < 1:
        raise ValueError("max_view_chars must be a positive int")
    if on_uncertain not in ("deny", "abstain"):
        raise ValueError("on_uncertain must be 'deny' or 'abstain'")
    name = clean_text(getattr(judge, "name", ""), MAX_NAME_CHARS) or type(judge).__name__
    label = f"semantic-veto[{name}]"

    def deny(why: str) -> dict[str, Any]:
        return {"verdict": DENY, "reason": f"{label}: {why}"}

    def evaluate(action: dict[str, Any]) -> dict[str, Any]:
        try:
            view = build_view(action, fields)
        except (TypeError, ValueError) as exc:
            return deny(f"action is not plain JSON, refusing to judge (fail-closed): "
                        f"{type(exc).__name__}")
        if len(view) > max_view_chars:
            return deny(f"view is {len(view)} chars, limit {max_view_chars}; "
                        f"a truncated action is not judged (fail-closed)")
        try:
            raw = judge.judge(view)
        except Exception as exc:
            return deny(f"judge error (fail-closed): {type(exc).__name__}: {clean_text(exc, 120)}")
        except BaseException as exc:
            if isinstance(exc, GeneratorExit):
                raise
            return deny(f"judge BaseException (fail-closed): {type(exc).__name__}")

        judgment, reason = _parse(raw)
        if judgment is None:
            return deny(f"{reason} (fail-closed)")
        if judgment == INCONSISTENT:
            return deny(f"inconsistent: {reason}" if reason else "inconsistent")
        if judgment == UNCERTAIN:
            if on_uncertain == "abstain":
                return {"verdict": ALLOW, "reason": f"{label}: abstained (uncertain)"}
            return deny(f"uncertain: {reason}" if reason else "uncertain")
        return {"verdict": ALLOW, "reason": f"{label}: consistent"}

    return evaluate


class PurposeTableJudge:
    """Deterministic reference judge, so the contract is concrete and tested.

    ``table`` maps a tool name to the purposes it is meant to serve. An action
    whose declared purpose is not listed for its tool is judged inconsistent; an
    unknown tool is uncertain. A model-backed judge is a drop-in replacement
    (see ``examples/semantic_llm_judge.py``).
    """

    name = "purpose-table"

    def __init__(self, table: dict[str, Iterable[str]]) -> None:
        self._table = {tool: frozenset(purposes) for tool, purposes in table.items()}

    def judge(self, view: str) -> SemanticJudgment:
        action = json.loads(view)
        tool = action.get("tool", "")
        purpose = action.get("action_purpose") or action.get("intent") or ""
        allowed = self._table.get(tool)
        if allowed is None:
            return SemanticJudgment(UNCERTAIN, f"no purpose table entry for tool {tool!r}")
        if purpose in allowed:
            return SemanticJudgment(CONSISTENT, "")
        return SemanticJudgment(
            INCONSISTENT, f"purpose {purpose!r} is not one tool {tool!r} serves"
        )
