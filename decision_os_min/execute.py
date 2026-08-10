"""The Policy Enforcement Point: run an effect ONLY against a signed, action-bound
decision AND a valid, one-time token. No token -> no execution.

HB-3: the PEP now REQUIRES an audit sink and writes EXACTLY ONE audit entry per
execute() call — on the way out, whether the effect ran or was refused. It is
structurally impossible to construct an Executor (and therefore to run an effect)
without an audit record: the constructor has no audit-less form.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .compose import CONTAIN, LIMIT, PERMITTING
from .kernel import action_fingerprint, verify
from .spentstore import FileSpentStore, SpentStore, SpentStoreUnavailable


class ExecutionRefused(RuntimeError):
    pass


@runtime_checkable
class AuditSink(Protocol):
    """What the executor needs to write its mandatory audit entry. ``HashLog``
    satisfies this; any object with a matching ``record`` does too."""

    def record(
        self,
        actor: str,
        tool: str,
        verdict: str,
        reason: str,
        *,
        executed: bool | None = ...,
        payload_digest: str | None = ...,
    ) -> dict[str, Any]: ...


def _default_spent_store() -> SpentStore:
    """The durable default: a file-backed store on a stable, shared path so a
    second executor process/replica on the same volume sees an already-spent
    token. Overridable via ``$DECISION_OS_SPENT_DIR``; otherwise a fixed dir under
    the system temp root (shared by every process on the host)."""
    directory = os.environ.get("DECISION_OS_SPENT_DIR") or str(
        Path(tempfile.gettempdir()) / "decision_os_min_spent"
    )
    return FileSpentStore(directory)


def _payload_digest(payload: Any) -> str:
    """A stable sha256 over the executed payload (W-3), so $1 and $1M produce
    different audit lines. Best-effort canonical JSON; falls back to repr for
    anything non-serializable so this never raises inside audit."""
    try:
        canonical = json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        canonical = repr(payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class Executor:
    """The PEP. Two mandatory dependencies:

    * an **audit sink** — required, so an effect can never run without a record
      (HB-3). There is no audit-less constructor.
    * a **spent-store** — durable and cross-process by default, so a one-time
      token is one-time across replicas/restarts (HB-1). Pass
      ``spent_store=InMemorySpentStore()`` to explicitly opt in to the old
      single-process behaviour. If the store is unreachable the executor FAILS
      CLOSED (refuses), never assuming a token is unspent.
    """

    def __init__(
        self,
        kernel_public_key: str,
        audit: AuditSink,
        *,
        spent_store: SpentStore | None = None,
    ) -> None:
        if audit is None:
            raise ValueError("Executor requires an audit sink (no unaudited execution)")
        self._pub = kernel_public_key
        self._audit = audit
        self._spent: SpentStore = spent_store if spent_store is not None else _default_spent_store()

    def execute(
        self,
        action: dict[str, Any],
        result: dict[str, Any],
        tools: dict[str, Callable[[dict[str, Any]], Any]],
    ) -> Any:
        decision = result["decision"]
        # Values used by the mandatory audit entry, resolved defensively so the
        # audit is written even when the decision is malformed.
        actor = action.get("actor", "") if isinstance(action, dict) else ""
        cap = decision.get("capability") if isinstance(decision, dict) else None
        # AE-10: the kernel sets `capability` only on PERMITTING verdicts, so a
        # refused action used to be logged with tool="" — the record could not say
        # WHAT was refused. Fall back to the action's own tool/capability.
        if not cap and isinstance(action, dict):
            cap = action.get("capability") or (
                f"tool:{action['tool']}" if action.get("tool") else None
            )
        tool_for_audit = (cap or "").split("tool:")[-1] if cap else ""
        verdict_for_audit = decision.get("verdict", "") if isinstance(decision, dict) else ""
        reason_for_audit = decision.get("reason", "") if isinstance(decision, dict) else ""

        try:
            output = self._execute_inner(action, result, tools)
        except ExecutionRefused as e:
            # HB-3 + W-3: one audit entry even on refusal — executed=False, with
            # the reason the effect did not run.
            # AE-10 (audit fidelity): the RECORDED reason must be the reason the
            # decision was made, not merely the mechanical consequence. This used
            # to log only `refused: verdict DENY: no execution`, discarding the
            # vetoing evaluator's reason entirely — so an audit could never answer
            # "who vetoed this, and why". That is the one channel a veto-only
            # evaluator still owns (COMPOSITION.md §11 strips it of every other),
            # which made discarding it precisely the wrong field to drop.
            self._audit.record(
                actor,
                tool_for_audit,
                verdict_for_audit,
                f"{reason_for_audit} [refused: {e}]" if reason_for_audit else f"refused: {e}",
                executed=False,
                payload_digest=None,
            )
            raise
        # W-3: record the executed outcome AND a digest of the executed payload,
        # so allow-and-ran is distinguishable from allow-but-refused, and the
        # amount/target of the effect is committed to the log.
        self._audit.record(
            actor,
            tool_for_audit,
            verdict_for_audit,
            reason_for_audit,
            executed=True,
            payload_digest=self._last_payload_digest,
        )
        return output

    def _execute_inner(
        self,
        action: dict[str, Any],
        result: dict[str, Any],
        tools: dict[str, Callable[[dict[str, Any]], Any]],
    ) -> Any:
        self._last_payload_digest: str | None = None
        decision = result["decision"]

        # ONE verification authenticates BOTH the ruling and the folded-in token
        # (token_id / capability / expiry live inside the signed decision now).
        if not verify(decision, result.get("signature", ""), self._pub):
            raise ExecutionRefused("decision not authenticated by the kernel")

        # Mandatory mediation: the action handed to us must be the one authorized.
        if decision.get("action_binding") != action_fingerprint(action):
            raise ExecutionRefused(
                "action does not match the authorized decision (binding mismatch)"
            )

        # W-1: the LIVE action's reference must equal the one the kernel signed.
        # action_binding already folds action_ref in, but check it explicitly so
        # the refusal reason is precise and the invariant is enforced at the PEP.
        live_ref = action.get("nonce") or action.get("action_ref") or ""
        if live_ref != decision.get("action_ref", ""):
            raise ExecutionRefused(
                "action nonce/action_ref does not match the authorized decision"
            )

        verdict = decision["verdict"]
        # R2: gate on the PERMITTING WHITELIST, not on a blacklist of two verdicts.
        # The old test was `verdict in (DENY, DEFER) or not token_id`, which let any
        # verdict outside that pair through as long as a `token_id` was present —
        # and a plugin could inject one. Lowercase `"deny"` (a neighbouring engine's
        # dialect) was neither DENY nor DEFER, so a refusal executed.
        if verdict not in PERMITTING or not decision.get("token_id"):
            raise ExecutionRefused(f"verdict {verdict}: no execution")

        # Token semantics enforced from the SIGNED decision fields: expiry + a
        # one-time spend of the signed token_id (which an attacker cannot re-mint
        # without breaking the decision signature).
        try:
            if datetime.now(UTC) >= datetime.fromisoformat(decision["token_expires_at"]):
                raise ExecutionRefused("token expired")
        except (KeyError, ValueError):
            raise ExecutionRefused("token missing/invalid expiry") from None
        tid = decision["token_id"]
        # HB-1: atomic, durable, cross-instance spend. Fail CLOSED if the store is
        # unreachable — never fall back to "assume unspent".
        try:
            first_spender = self._spent.try_spend(tid)
        except SpentStoreUnavailable as e:
            raise ExecutionRefused(f"spent-store unavailable, refusing (fail-closed): {e}") from e
        if not first_spender:
            raise ExecutionRefused("token already spent (replay)")

        tool_name = decision["capability"].split("tool:")[-1]
        if verdict == CONTAIN:
            allowed = (decision.get("containment") or {}).get("allowed_tools", [])
            if tool_name not in allowed:
                raise ExecutionRefused(f"contained: '{tool_name}' not in allowlist {allowed}")

        fn = tools.get(tool_name)
        if fn is None:
            raise ExecutionRefused(f"no executor registered for tool '{tool_name}'")
        if verdict == LIMIT and "transformed_payload" not in decision:
            # An obligation the PEP cannot discharge must REFUSE, not degrade. A
            # LIMIT means "run, but minimized"; with no minimized payload attached
            # the old code fell back to `{}` and called the tool with no arguments
            # — a DIFFERENT effect, not a more restrictive one. This is reachable
            # now that evaluator obligations are stripped (COMPOSITION.md §11), so
            # an evaluator's LIMIT collapses to a clean veto, which is exactly what
            # a veto-only plugin is allowed to be.
            raise ExecutionRefused("LIMIT without a transformed_payload: refusing")
        # Apply the minimized payload whenever the signed decision carries one — not
        # only when the verdict happens to be LIMIT. Gating on the verdict meant a
        # CONTAIN decision discarded a redaction the kernel had already computed.
        payload = (
            decision["transformed_payload"]
            if "transformed_payload" in decision
            else action.get("payload")
        )
        payload = payload or {}
        self._last_payload_digest = _payload_digest(payload)
        return fn(payload)
