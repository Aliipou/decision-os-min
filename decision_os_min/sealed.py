"""Sealed deployment surface — production enforcement for the mediated tool plane.

Claim (precise):
  For every effect executed via SealedRuntime.invoke / sealed tool table:
    Executed(e) ⇒ PEP(e) ∧ legitimacy_pass(e) ∧ authority_pass(e) ∧ admitted(e)
  For every poisoned/sealed handle:
    ¬PEP_mediated(e) ⇒ ¬Executed(e)

Non-claim:
  Code that never entered seal() retains ambient process capability. That is an
  OS/sandbox redesign (seccomp, no credentials, network policy), not a library fix.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .audit import HashLog
from .compose import ALLOW, DEFER, DENY, PERMITTING, Evaluator
from .execute import ExecutionRefused, Executor
from .kernel import Kernel, verify
from .spentstore import SpentStore, SpentStoreUnavailable


class SealedBreach(RuntimeError):
    """Direct invocation of a sealed/poisoned tool — execution impossible."""


class AdmissionError(RuntimeError):
    """Missing, forged, expired, replayed, or substituted admission ticket."""


class SealedRefused(RuntimeError):
    def __init__(
        self,
        verdict: str,
        reason: str | None,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(f"sealed refused: {verdict} ({reason})")
        self.verdict = verdict
        self.reason = reason
        self.evidence = evidence or {}


class _SealedExecutor(Executor):
    """Executor that refuses execute() unless armed once by SealedRuntime.invoke."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._arm: tuple[str, dict[str, Callable[[dict[str, Any]], Any]]] | None = None

    def arm(self, action_binding: str, tools: dict[str, Callable[[dict[str, Any]], Any]]) -> None:
        self._arm = (action_binding, dict(tools))

    def execute(
        self,
        action: dict[str, Any],
        result: dict[str, Any],
        tools: dict[str, Callable[[dict[str, Any]], Any]],
    ) -> Any:
        arm = self._arm
        self._arm = None
        if arm is None:
            raise ExecutionRefused("sealed executor: not armed by invoke (fail-closed)")
        binding, expected = arm
        decision = result.get("decision") if isinstance(result, dict) else None
        if not isinstance(decision, dict) or decision.get("action_binding") != binding:
            raise ExecutionRefused("sealed executor: arm binding mismatch")
        if list(tools.keys()) != list(expected.keys()):
            raise ExecutionRefused("sealed executor: tool map not armed")
        for name, fn in expected.items():
            if tools.get(name) is not fn:
                raise ExecutionRefused("sealed executor: tool callable substitution")
        return super().execute(action, result, tools)


class _KernelFacade:
    """Public kernel handle: identity only. decide() is closed on the sealed surface."""

    def __init__(self, kernel: Kernel) -> None:
        self._kernel = kernel

    def public_key_hex(self) -> str:
        return self._kernel.public_key_hex()

    def decide(self, *args: Any, **kwargs: Any) -> Any:
        raise SealedBreach("SealedRuntime.kernel.decide is closed; use invoke()")

    def __getattr__(self, name: str) -> Any:
        raise SealedBreach(f"SealedRuntime.kernel.{name} is closed; use invoke()")


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def poison(name: str) -> Callable[..., Any]:
    def _dead(*_a: Any, **_k: Any) -> Any:
        raise SealedBreach(
            f"tool {name!r} sealed: direct call is non-executable (PEP required)"
        )

    _dead.__name__ = f"poisoned_{name}"
    return _dead


class _BodyCell:
    """Non-callable holder for a sealed tool body.

    Closes ``rt._bodies[name](**kwargs)``. Residual: in-process
    ``object.__getattribute__(cell, '_fn')`` still reaches the callable — that is
    ambient Python introspection, not the sealed public surface.
    """

    __slots__ = ("_fn", "_fn_id", "_name")

    def __init__(self, fn: Callable[..., Any], name: str) -> None:
        object.__setattr__(self, "_fn", fn)
        object.__setattr__(self, "_fn_id", id(fn))
        object.__setattr__(self, "_name", name)

    def __call__(self, *_a: Any, **_k: Any) -> Any:
        raise SealedBreach(
            f"body cell {self._name!r} is not callable; use SealedRuntime.invoke()"
        )

    def __setattr__(self, key: str, value: Any) -> None:
        raise SealedBreach("body cell is immutable")


@dataclass(frozen=True)
class AdmissionTicket:
    actor: str
    stakeholder: str
    expires_at: str
    nonce: str
    signature: str

    def as_dict(self) -> dict[str, str]:
        return {
            "actor": self.actor,
            "stakeholder": self.stakeholder,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "signature": self.signature,
        }


class AdmissionOffice:
    """Signed, single-use admission tickets backed by the shared SpentStore.

    Replay is enforced by the same durable store as decision tokens (prefix
    ``adm:``), so two SealedRuntime replicas sharing a store cannot both consume
    one ticket. Fail-closed if the store is unreachable.
    """

    def __init__(
        self,
        *,
        seed_material: str,
        spent_store: SpentStore,
        ttl_seconds: int = 300,
    ) -> None:
        seed = hashlib.sha256(seed_material.encode()).digest()
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self._pub: Ed25519PublicKey = self._key.public_key()
        self._ttl = ttl_seconds
        self._spent = spent_store

    def issue(self, actor: str, stakeholder: str) -> AdmissionTicket:
        body = {
            "actor": actor,
            "stakeholder": stakeholder,
            "expires_at": (datetime.now(UTC) + timedelta(seconds=self._ttl)).isoformat(),
            "nonce": uuid.uuid4().hex,
        }
        sig = self._key.sign(_canon(body)).hex()
        return AdmissionTicket(
            actor=body["actor"],
            stakeholder=body["stakeholder"],
            expires_at=body["expires_at"],
            nonce=body["nonce"],
            signature=sig,
        )

    def consume(self, ticket: AdmissionTicket | dict[str, str]) -> tuple[str, str]:
        """Verify + single-spend via SpentStore. Returns (actor, stakeholder)."""
        d = ticket.as_dict() if isinstance(ticket, AdmissionTicket) else dict(ticket)
        sig_hex = d.get("signature", "")
        body = {k: d[k] for k in ("actor", "stakeholder", "expires_at", "nonce")}
        try:
            if datetime.now(UTC) >= datetime.fromisoformat(body["expires_at"]):
                raise AdmissionError("admission ticket expired")
            self._pub.verify(bytes.fromhex(sig_hex), _canon(body))
        except AdmissionError:
            raise
        except Exception as exc:
            raise AdmissionError(f"admission ticket invalid: {exc}") from exc
        key = f"adm:{body['nonce']}"
        try:
            first = self._spent.try_spend(key)
        except SpentStoreUnavailable as exc:
            raise AdmissionError(
                f"admission spent-store unavailable (fail-closed): {exc}"
            ) from exc
        if not first:
            raise AdmissionError("admission ticket already spent (replay)")
        return body["actor"], body["stakeholder"]


def tri_state_legitimacy(
    policy: Callable[[dict[str, Any]], tuple[bool | None, str, tuple[str, ...]]],
) -> Evaluator:
    def evaluate(action: dict[str, Any]) -> dict[str, Any]:
        try:
            ok, reason, axioms = policy(action)
        except Exception as exc:
            return {
                "verdict": DENY,
                "reason": f"legitimacy error (fail-closed): {exc}",
                "axiom_ids": [],
                "legitimacy_digest": hashlib.sha256(str(exc).encode()).hexdigest(),
            }
        if ok is None:
            verdict = DEFER
        elif ok:
            verdict = ALLOW
        else:
            verdict = DENY
        digest = hashlib.sha256(
            _canon({"ok": ok, "reason": reason, "axioms": list(axioms), "verdict": verdict})
        ).hexdigest()
        return {
            "verdict": verdict,
            "reason": reason,
            "axiom_ids": list(axioms),
            "legitimacy_digest": digest,
        }

    return evaluate


@dataclass
class EvidenceRecord:
    timestamp: str
    actor: str
    agent_id: str
    stakeholder: str
    intent: str
    tool: str
    resource: str
    payload: dict[str, Any]
    capabilities: list[str]
    legitimacy_verdict: str
    legitimacy_reason: str
    axiom_ids: list[str]
    legitimacy_binding: str | None
    authority_verdict: str
    pep_verdict: str
    executed: bool
    output: Any
    decision_ref: str | None
    signature_ref: str | None

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class SealedRuntime:
    policy: dict[str, Any]
    audit_path: str
    legitimacy: Callable[[dict[str, Any]], tuple[bool | None, str, tuple[str, ...]]]
    spent_store: SpentStore
    kernel: _KernelFacade = field(init=False)
    log: HashLog = field(init=False)
    executor: _SealedExecutor = field(init=False)
    admission: AdmissionOffice = field(init=False)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    # Public-facing table: always poisoned / inert callables (never live effects).
    _tools: dict[str, Callable[..., Any]] = field(default_factory=dict)
    # Private bodies — only wrapped as a fresh closure inside invoke() for PEP.
    _bodies: dict[str, Callable[..., Any]] = field(default_factory=dict)
    _tool_ids: dict[str, int] = field(default_factory=dict)
    _agent_meta: dict[str, dict[str, str]] = field(default_factory=dict)
    _frozen: bool = False
    _source_registry: dict[str, Callable[..., Any]] | None = None
    _kernel: Kernel = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._kernel = Kernel(self.policy)
        self.kernel = _KernelFacade(self._kernel)
        self.log = HashLog(self.audit_path)
        self.executor = _SealedExecutor(
            self._kernel.public_key_hex(),
            self.log,
            spent_store=self.spent_store,
        )
        self.admission = AdmissionOffice(
            seed_material=self._kernel.public_key_hex(),
            spent_store=self.spent_store,
        )
        self._leg_eval = tri_state_legitimacy(self.legitimacy)

    def register_agent(self, agent_id: str, *, actor: str, stakeholder: str) -> None:
        self._agent_meta[agent_id] = {"actor": actor, "stakeholder": stakeholder}

    def admit(self, agent_id: str) -> AdmissionTicket:
        meta = self._agent_meta[agent_id]
        return self.admission.issue(meta["actor"], meta["stakeholder"])

    def seal(self, tools: dict[str, Callable[..., Any]]) -> dict[str, Callable[..., Any]]:
        if self._frozen:
            raise SealedBreach("tool registry frozen; seal() refused")
        self._source_registry = tools
        exports: dict[str, Callable[..., Any]] = {}
        for name, fn in list(tools.items()):
            self._bodies[name] = _BodyCell(fn, name)
            self._tool_ids[name] = id(fn)
            # _tools never holds a live effect — closes rt._tools[name](...) bypass.
            self._tools[name] = poison(name)
            tools[name] = poison(name)

            def _make_export(n: str) -> Callable[..., Any]:
                def _export(**_payload: Any) -> Any:
                    raise SealedBreach(
                        f"{n!r} export is inert; use SealedRuntime.invoke()"
                    )

                return _export

            exports[name] = _make_export(name)
        self._frozen = True
        return exports

    def _assert_registry_integrity(self, tool: str) -> Callable[..., Any]:
        if tool not in self._bodies:
            raise SealedBreach(f"tool {tool!r} not in sealed registry")
        cell = self._bodies[tool]
        if not isinstance(cell, _BodyCell):
            raise SealedBreach("registry mutation detected; body cell replaced")
        body = object.__getattribute__(cell, "_fn")
        body_id = object.__getattribute__(cell, "_fn_id")
        if id(body) != self._tool_ids.get(tool) or id(body) != body_id:
            raise SealedBreach("registry mutation detected; execution refused")
        if self._source_registry is not None:
            src = self._source_registry.get(tool)
            if src is not None and not getattr(src, "__name__", "").startswith("poisoned_"):
                raise SealedBreach("source registry un-poisoned; execution refused")
        slot = self._tools.get(tool)
        if slot is None or not getattr(slot, "__name__", "").startswith("poisoned_"):
            raise SealedBreach("_tools slot is not poisoned; execution refused")
        return body

    def _pep_closure(self, body: Callable[..., Any]) -> Callable[[dict[str, Any]], Any]:
        """Fresh PEP-only wrapper; not stored on the runtime."""

        def effect(payload: dict[str, Any], _body: Callable[..., Any] = body) -> Any:
            return _body(**payload)

        return effect

    def invoke(
        self,
        *,
        ticket: AdmissionTicket | dict[str, str],
        agent_id: str,
        tool: str,
        payload: dict[str, Any],
        intent: str,
        resource: str = "",
        capability: str | None = None,
    ) -> Any:
        actor, stakeholder = self.admission.consume(ticket)
        meta = self._agent_meta.get(agent_id, {})
        if meta.get("actor") and meta["actor"] != actor:
            raise AdmissionError(
                f"ticket actor {actor!r} does not match agent {agent_id} ({meta['actor']})"
            )
        if meta.get("stakeholder") and meta["stakeholder"] != stakeholder:
            raise AdmissionError("ticket stakeholder substitution refused")

        effect_body = self._assert_registry_integrity(tool)
        pep_tool = self._pep_closure(effect_body)
        cap = capability or f"tool:{tool}"
        purpose = intent
        if purpose in ("deploy", "price", "regulate"):
            labels = ["ops"]
        elif purpose == "audit":
            labels = ["ops", "public"]
        else:
            labels = ["ops"]
        action = {
            "actor": actor,
            "tool": tool,
            "capability": cap,
            "action_purpose": purpose,
            "data_labels": labels,
            "payload": dict(payload),
            "nonce": uuid.uuid4().hex[:12],
            "agent_id": agent_id,
            "stakeholder": stakeholder,
            "intent": intent,
            "resource": resource,
        }

        auth_preview = self._kernel.decide(dict(action), evaluators=None)
        result = self._kernel.decide(action, evaluators=[self._leg_eval])
        decision = result["decision"]

        # M5 is mandatory on the sealed surface — no opt-out.
        if decision.get("verdict") in PERMITTING and not decision.get("legitimacy_binding"):
            raise SealedRefused(
                DENY,
                "M5: permitting decision missing legitimacy_binding",
                {"decision": decision},
            )
        if decision.get("legitimacy_binding"):
            expected = hashlib.sha256(
                _canon(
                    {
                        "action_binding": decision.get("action_binding"),
                        "legitimacy_digest": decision.get("legitimacy_digest", ""),
                        "axiom_ids": decision.get("axiom_ids", []),
                        "verdict": decision.get("verdict"),
                    }
                )
            ).hexdigest()
            if expected != decision["legitimacy_binding"]:
                raise SealedRefused(DENY, "M5: legitimacy_binding mismatch", {})

        # Stale/substituting legitimacy: PEP already binds action_fingerprint.
        # Extra: refuse if signature does not verify (forged decision inject).
        if not verify(decision, result.get("signature", ""), self._kernel.public_key_hex()):
            raise SealedRefused(DENY, "decision signature invalid", {})

        tools_map = {tool: pep_tool}
        self.executor.arm(str(decision.get("action_binding") or ""), tools_map)
        try:
            output = self.executor.execute(action, result, tools_map)
        except ExecutionRefused as exc:
            rec = self._emit(
                action,
                agent_id,
                intent,
                resource,
                auth_preview,
                decision,
                result,
                False,
                None,
                f"PEP:{exc}",
            )
            raise SealedRefused(
                decision.get("verdict", DENY),
                f"{decision.get('reason')} [{exc}]",
                rec.as_dict(),
            ) from exc

        self._emit(
            action,
            agent_id,
            intent,
            resource,
            auth_preview,
            decision,
            result,
            True,
            output,
            "PERMIT+execute",
        )
        return output

    def _emit(
        self,
        action: dict[str, Any],
        agent_id: str,
        intent: str,
        resource: str,
        auth_preview: dict[str, Any],
        decision: dict[str, Any],
        result: dict[str, Any],
        executed: bool,
        output: Any,
        pep_note: str,
    ) -> EvidenceRecord:
        sig = result.get("signature") or ""
        rec = EvidenceRecord(
            timestamp=datetime.now(UTC).isoformat(),
            actor=action["actor"],
            agent_id=agent_id,
            stakeholder=str(action.get("stakeholder", "")),
            intent=intent,
            tool=action["tool"],
            resource=resource,
            payload=dict(action.get("payload") or {}),
            capabilities=list(self.policy.get("grants", {}).get(action["actor"], [])),
            legitimacy_verdict=str(decision.get("verdict")),
            legitimacy_reason=str(decision.get("reason", "")),
            axiom_ids=list(decision.get("axiom_ids") or []),
            legitimacy_binding=decision.get("legitimacy_binding"),
            authority_verdict=str(auth_preview["decision"].get("verdict")),
            pep_verdict=pep_note,
            executed=executed,
            output=output,
            decision_ref=decision.get("token_id") or decision.get("action_ref"),
            signature_ref=(sig[:16] + "…") if sig else None,
        )
        self.evidence.append(rec)
        self.log.record(
            action["actor"],
            action["tool"],
            str(decision.get("verdict")),
            f"{decision.get('reason')}|{pep_note}|axioms={rec.axiom_ids}|bind={rec.legitimacy_binding}",
            executed=executed,
            payload_digest=hashlib.sha256(_canon(action.get("payload") or {})).hexdigest(),
        )
        return rec
