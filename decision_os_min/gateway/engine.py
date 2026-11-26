"""The gateway engine: one governed tool call, end to end.

    tool call (from an MCP client or a model response)
        -> Action {actor, tool, capability, purpose, labels, payload, nonce}
        -> Kernel.decide(action, evaluators=[guardrails])     # PDP + veto, signed
        -> Executor.execute(action, decision, {tool: release}) # PEP + audit + effect
        -> DEFER?  approval bound to the action fingerprint, then decide again

``release`` is the effect: for MCP it forwards the call to the real server, for
the model gateway it lets the tool call through to the agent. It only ever runs
inside ``Executor.execute``, after signature, binding and one-time-token checks,
and after the audit entry is written.
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..authority_pdp import CanonicalAuthorityResult
from ..compose import ALLOW, DEFER, DENY
from ..execute import ExecutionRefused, Executor
from ..kernel import Kernel, UnfingerprintablePayload, action_fingerprint
from ..spentstore import SqliteSpentStore
from .approvals import APPROVED, ApprovalStore, LearnedStore, ensure_dashboard, notify
from .audit import LockedHashLog
from .guardrails import Guardrails, redact_secrets
from .locking import file_lock
from .paths import Home, write_private
from .policy import GatewayPolicy, PolicyError, evaluate, load_policy

AGENT_PREFIX = "agent:"


def slug(name: str) -> str:
    """Server/client names become part of the capability string."""
    return re.sub(r"[\s/:\\]+", "-", name.strip()) or "unnamed"


@dataclass
class GovernResult:
    executed: bool
    output: Any = None
    verdict: str = ""
    reason: str = ""
    approval: str | None = None
    decision: dict[str, Any] | None = None

    @property
    def message(self) -> str:
        return self.reason or self.verdict


class GatewayAuthorityPDP:
    """The policy file as a trusted, replaceable ``AuthorityPDP``. It rules; it
    cannot sign, mint, spend or reach the effect."""

    name = "decision-os-gateway-policy"
    mutable = False

    def __init__(self, gateway: Gateway) -> None:
        self._gw = gateway

    @property
    def policy_revision(self) -> str:
        p = self._gw.policy
        return f"{p.revision if p else 'invalid'}+{self._gw.learned.revision()}"

    def healthcheck(self) -> tuple[bool, str]:
        if self._gw.policy is None:
            return False, f"policy error: {self._gw.policy_error}"
        return True, "ok"

    def evaluate(self, action: dict[str, Any]) -> CanonicalAuthorityResult | dict[str, Any]:
        policy = self._gw.policy
        if policy is None:
            return {
                "verdict": DENY,
                "reason": f"policy error (fail-closed): {self._gw.policy_error}",
            }
        client, server, tool, model, hints = parse_action(action)
        m = evaluate(
            policy,
            client=client,
            server=server,
            tool=tool,
            model=model,
            args=action.get("payload") or {},
            hints=hints,
            learned=self._gw.learned.load(),
        )
        if action.get("action_purpose") != m.purpose:
            return {
                "verdict": DENY,
                "reason": "policy changed while this call was being decided; retry",
            }
        if policy.mode == "observe":
            if m.decision == "allow":
                return {"verdict": ALLOW, "reason": m.reason}
            return {"verdict": ALLOW, "reason": f"observe: would {m.decision}: {m.reason}"}
        if m.decision == "allow":
            return {"verdict": ALLOW, "reason": m.reason}
        if m.decision == "deny":
            return {"verdict": DENY, "reason": m.reason}
        if self._gw.approvals.is_approved(action_fingerprint(action)):
            return {"verdict": ALLOW, "reason": f"approved by you ({m.reason})"}
        return {"verdict": DEFER, "reason": m.reason}


def parse_action(action: dict[str, Any]) -> tuple[str, str, str, str | None, tuple[str, ...]]:
    actor = str(action.get("actor", ""))
    client = actor[len(AGENT_PREFIX) :] if actor.startswith(AGENT_PREFIX) else actor
    server, _, tool = str(action.get("tool", "")).partition("/")
    labels = [str(x) for x in action.get("data_labels") or []]
    model = next((x[len("model:") :] for x in labels if x.startswith("model:")), None)
    hints = tuple(x for x in labels if x.startswith("hint:"))
    return client, server, tool, model, hints


class Gateway:
    def __init__(
        self,
        *,
        client: str,
        home: Home | None = None,
        interactive: bool = True,
        dashboard_spawn: Callable[[list[str]], Any] | None = None,
    ) -> None:
        self.home = (home or Home.resolve()).ensure()
        self.client = slug(client)
        self.interactive = interactive
        self._dashboard_spawn = dashboard_spawn
        self.approvals = ApprovalStore(self.home)
        self.learned = LearnedStore(self.home)
        self.log = LockedHashLog(self.home.audit, self.home.locks / "audit.lock")
        # Every app starts several proxies at once; SQLite can fail the WAL switch
        # on a brand-new database with "database is locked" instead of waiting.
        with file_lock(self.home.locks / "spent.lock"):
            self._spent = SqliteSpentStore(self.home.spent)
        self._lock = threading.RLock()
        self.policy: GatewayPolicy | None = None
        self.policy_error: str | None = None
        self._policy_stamp: tuple[int, int] | None = None
        self._pdp = GatewayAuthorityPDP(self)
        self.kernel: Kernel
        self.executor: Executor
        self._load(force=True)

    # ------------------------------------------------------------- policy
    def _stamp(self) -> tuple[int, int] | None:
        try:
            st = self.home.policy.stat()
            return (st.st_mtime_ns, st.st_size)
        except FileNotFoundError:
            return None

    def _load(self, *, force: bool = False) -> None:
        with self._lock:
            stamp = self._stamp()
            if not force and stamp == self._policy_stamp:
                return
            self._policy_stamp = stamp
            try:
                self.policy = load_policy(self.home.policy)
                self.policy_error = None
            except PolicyError as exc:
                self.policy, self.policy_error = None, str(exc)
            rules = self.policy.rules if self.policy else ()
            kernel_policy = {
                "redactions": [
                    {"action_purpose": r.purpose, "redact_fields": list(r.redact)}
                    for r in rules
                    if r.redact
                ],
                "contain_threat_classes": [],
                "default": "deny",
            }
            self.kernel = Kernel(
                kernel_policy, key_path=str(self.home.key), authority_pdp=self._pdp
            )
            self.executor = Executor(
                self.kernel.public_key_hex(), self.log, spent_store=self._spent
            )
            self.guardrails = Guardrails(
                self.policy.guardrails if self.policy else _fallback_guardrails(),
                self_paths=self_protected_paths(self.home),
            )
            self._guard_eval = self.guardrails.evaluator(
                observe=lambda: bool(self.policy and self.policy.mode == "observe"),
                approved=self.approvals.is_approved,
            )

    def reload_if_changed(self) -> None:
        self._load()

    # ------------------------------------------------------------- helpers
    def capability_tool(self, server: str, tool: str) -> str:
        return f"{slug(server)}/{tool}"

    def static_decision(self, server: str, tool: str, hints: tuple[str, ...] = ()) -> str:
        """Decision without arguments (used to hide hard-denied tools in tools/list)."""
        self.reload_if_changed()
        if self.policy is None:
            return "deny"
        m = evaluate(
            self.policy,
            client=self.client,
            server=slug(server),
            tool=tool,
            args=None,
            hints=hints,
            learned=self.learned.load(),
        )
        return m.decision

    def build_action(
        self,
        *,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        model: str | None,
        hints: tuple[str, ...],
        purpose: str,
    ) -> dict[str, Any]:
        labels = sorted({*(h.lower() for h in hints), *([f"model:{model}"] if model else [])})
        cap_tool = self.capability_tool(server, tool)
        return {
            "actor": f"{AGENT_PREFIX}{self.client}",
            "tool": cap_tool,
            "capability": f"tool:{cap_tool}",
            "action_purpose": purpose,
            "data_labels": labels,
            "payload": arguments,
            "nonce": uuid.uuid4().hex,
        }

    def _handle(
        self,
        action: dict[str, Any],
        release: Callable[[dict[str, Any]], Any],
        approval: str | None = None,
    ) -> GovernResult:
        result = self.kernel.decide(action, evaluators=[self._guard_eval])
        decision = result["decision"]
        try:
            output = self.executor.execute(action, result, {action["tool"]: release})
            return GovernResult(
                True, output, decision["verdict"], decision.get("reason", ""), approval, decision
            )
        except ExecutionRefused as exc:
            return GovernResult(
                False,
                None,
                decision["verdict"],
                decision.get("reason") or str(exc),
                approval,
                decision,
            )

    def _refuse(self, server: str, tool: str, reason: str) -> GovernResult:
        self.log.record(
            f"{AGENT_PREFIX}{self.client}",
            self.capability_tool(server, tool),
            DENY,
            reason,
            executed=False,
            payload_digest=None,
        )
        return GovernResult(False, None, DENY, reason)

    # ------------------------------------------------------------- govern
    def govern(
        self,
        *,
        server: str,
        tool: str,
        arguments: Any,
        release: Callable[[dict[str, Any]], Any],
        model: str | None = None,
        hints: tuple[str, ...] = (),
        cancelled: threading.Event | None = None,
    ) -> GovernResult:
        self.reload_if_changed()
        if self.policy is None:
            return self._refuse(
                server, tool, f"Decision OS policy error (fail-closed): {self.policy_error}"
            )
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return self._refuse(server, tool, "tool arguments must be a JSON object")
        m = evaluate(
            self.policy,
            client=self.client,
            server=slug(server),
            tool=tool,
            model=model,
            args=arguments,
            hints=hints,
            learned=self.learned.load(),
        )
        action = self.build_action(
            server=server,
            tool=tool,
            arguments=arguments,
            model=model,
            hints=hints,
            purpose=m.purpose,
        )
        try:
            fp = action_fingerprint(action)
        except UnfingerprintablePayload as exc:
            return self._refuse(server, tool, f"arguments cannot be bound: {exc}")
        self._touch_session(server)

        first = self._handle(action, release)
        if first.executed or first.verdict != DEFER or self.policy.mode == "observe":
            return first
        if not self.interactive:
            return first

        # ---- ask: wait for a human decision bound to this exact action
        # "Always allow" is offered only when the policy (not a guardrail) asked:
        # remembering a tool must never pre-approve a future force push.
        from_policy = (first.decision or {}).get("authority_verdict") == DEFER
        preview = redact_secrets(json.dumps(arguments, ensure_ascii=False, sort_keys=True))
        info = {
            "client": self.client,
            "server": slug(server),
            "tool": tool,
            "model": model,
            "reason": first.reason,
            "arguments_preview": preview[:4000],
            "rememberable": from_policy,
            "expires_in_s": self.policy.ask_timeout_seconds,
        }
        self.approvals.request(fp, info)
        if self.policy.notify:
            notify("Decision OS: approval needed", f"{self.client} wants {slug(server)}/{tool}")
        if self.policy.open_dashboard or self._dashboard_spawn is not None:
            ensure_dashboard(
                self.home,
                self.policy.dashboard_port,
                open_browser=self.policy.open_dashboard,
                spawn=self._dashboard_spawn,
            )
        status = self.approvals.wait(fp, self.policy.ask_timeout_seconds, cancelled=cancelled)
        if status == APPROVED:
            return self._handle(action, release, approval=fp)
        why = {
            "denied": "denied by you",
            "expired": "no answer before the approval timeout",
            "cancelled": "the client cancelled the request",
        }.get(status, status)
        res = self._refuse(server, tool, f"{why} ({first.reason})")
        res.approval = fp
        return res

    def _touch_session(self, server: str) -> None:
        try:
            path = self.home.sessions / f"{self.client}__{slug(server)}.json"
            write_private(
                path,
                json.dumps(
                    {"client": self.client, "server": slug(server), "last_call": time.time()}
                ),
            )
        except OSError:
            pass


def _fallback_guardrails():
    from .policy import GuardrailConfig

    return GuardrailConfig()


def self_protected_paths(home: Home) -> list[Path]:
    """The gateway's own state, every global MCP client config, and every
    project config the installer wrapped: rewriting any of them through a tool
    would unwrap or reconfigure the gateway."""
    from .clients import all_config_paths

    wrapped: list[Path] = []
    try:
        data = json.loads(home.state.read_text(encoding="utf-8"))
        wrapped = sorted({Path(json.loads(k)[0]) for k in data.get("entries", {})})
    except (OSError, ValueError, TypeError, IndexError):
        pass
    return [home.root, *all_config_paths(), *wrapped]
