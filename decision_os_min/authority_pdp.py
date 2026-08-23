"""Trusted, replaceable policy-decision providers.

An AuthorityPDP may grant policy authority, so it belongs to the policy trust
base.  It is deliberately *not* an execution authority: providers never receive
the kernel signing key, token store, effect adapters, or PEP handles.  Their
bounded output is canonicalized before the kernel signs or mints anything.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .attenuation import AuthorityGraph, Macaroon
from .compose import ALLOW, DENY, normalize

MAX_REASON_CHARS = 1024
MAX_HTTP_RESPONSE_BYTES = 64 * 1024


class AuthorityPDPError(RuntimeError):
    """The trusted PDP could not produce a valid bounded result."""


class AuthorityMutationUnsupported(RuntimeError):
    """The selected PDP is externally managed and cannot be mutated in-process."""


@dataclass(frozen=True, slots=True)
class CanonicalAuthorityResult:
    verdict: str
    reason: str
    provider: str
    policy_revision: str


@runtime_checkable
class AuthorityPDP(Protocol):
    """Policy trust-base contract; never a signer, minter, PEP, or adapter."""

    name: str
    mutable: bool

    @property
    def policy_revision(self) -> str: ...

    def evaluate(
        self, action: dict[str, Any]
    ) -> CanonicalAuthorityResult | dict[str, Any] | str: ...

    def healthcheck(self) -> tuple[bool, str]: ...


def _plain_bounded(value: Any, *, fallback: str, limit: int) -> str:
    if isinstance(value, str):
        text = str.__str__(value)
    else:
        try:
            text = str(value)
        except BaseException:
            text = fallback
    return text[:limit] or fallback


def _identity(provider: AuthorityPDP) -> tuple[str, str]:
    try:
        name = _plain_bounded(provider.name, fallback="authority-pdp", limit=128)
    except BaseException:
        name = "authority-pdp"
    try:
        revision = _plain_bounded(
            provider.policy_revision, fallback="unknown", limit=256
        )
    except BaseException:
        revision = "unknown"
    return name, revision


def canonicalize_authority_output(
    provider: AuthorityPDP,
    output: CanonicalAuthorityResult | dict[str, Any] | str | Any,
) -> CanonicalAuthorityResult:
    """Strip every provider-owned field except verdict/reason.

    Provider/revision identity always comes from the selected host object, never
    from its returned dictionary. Unknown or malformed verdicts normalize to
    DENY, using the same canonical lattice objects as the mint gate.
    """

    name, revision = _identity(provider)
    if isinstance(output, CanonicalAuthorityResult):
        raw_verdict: Any = output.verdict
        raw_reason: Any = output.reason
    elif isinstance(output, dict):
        raw_verdict = output.get("verdict", DENY)
        raw_reason = output.get("reason", "")
    elif isinstance(output, str):
        raw_verdict = output
        raw_reason = ""
    else:
        raw_verdict = DENY
        raw_reason = f"malformed authority output: {type(output).__name__}"

    verdict = normalize(raw_verdict) if isinstance(raw_verdict, str) else DENY
    reason = _plain_bounded(
        raw_reason,
        fallback=f"{name}: {verdict.lower()}",
        limit=MAX_REASON_CHARS,
    )
    if verdict == DENY and raw_verdict != DENY:
        reason = f"unknown/malformed authority verdict (fail-closed): {reason}"[
            :MAX_REASON_CHARS
        ]
    return CanonicalAuthorityResult(verdict, reason, name, revision)


def evaluate_authority(
    provider: AuthorityPDP,
    action: dict[str, Any],
    *,
    timeout_s: float | None,
) -> CanonicalAuthorityResult:
    """Evaluate on a deep copy with a wall bound and fail closed."""

    name, revision = _identity(provider)
    try:
        if timeout_s is None:
            output = provider.evaluate(copy.deepcopy(action))
        else:
            pool = ThreadPoolExecutor(max_workers=1)
            try:
                future = pool.submit(provider.evaluate, copy.deepcopy(action))
                try:
                    output = future.result(timeout=timeout_s)
                except FuturesTimeoutError:
                    return CanonicalAuthorityResult(
                        DENY,
                        f"authority PDP timeout (fail-closed): {timeout_s}s",
                        name,
                        revision,
                    )
            finally:
                pool.shutdown(wait=False, cancel_futures=True)
        return canonicalize_authority_output(provider, output)
    except Exception as exc:
        return CanonicalAuthorityResult(
            DENY,
            f"authority PDP error (fail-closed): {type(exc).__name__}: {exc}"[
                :MAX_REASON_CHARS
            ],
            name,
            revision,
        )
    except BaseException as exc:
        if isinstance(exc, GeneratorExit):
            raise
        return CanonicalAuthorityResult(
            DENY,
            (
                f"authority PDP BaseException (fail-closed): "
                f"{type(exc).__name__}: {exc}"
            )[:MAX_REASON_CHARS],
            name,
            revision,
        )


class BuiltinAuthorityPDP:
    """The existing grants + purpose policy behind the new stable seam."""

    name = "builtin"
    mutable = True

    def __init__(
        self,
        grants: dict[str, list[str]],
        purpose_bindings: dict[str, list[str]],
        authority_graph: AuthorityGraph,
        *,
        default_deny: bool,
    ) -> None:
        self._grants = grants
        self._bindings = purpose_bindings
        self._authority = authority_graph
        self._default_deny = default_deny
        self._revision_counter = 0

    @property
    def policy_revision(self) -> str:
        payload = json.dumps(
            {
                "grants": self._grants,
                "purpose_bindings": self._bindings,
                "default_deny": self._default_deny,
                "revision": self._revision_counter,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return f"builtin:{hashlib.sha256(payload).hexdigest()[:16]}"

    def evaluate(self, action: dict[str, Any]) -> CanonicalAuthorityResult:
        actor = action.get("actor", "")
        cap = action.get("capability") or f"tool:{action.get('tool', '')}"
        tool = action.get("tool")
        if action.get("capability") and tool and action["capability"] != f"tool:{tool}":
            return CanonicalAuthorityResult(
                DENY,
                f"ambiguous: capability '{action['capability']}' != tool '{tool}'",
                self.name,
                self.policy_revision,
            )
        if not self._authority.holds(actor, cap):
            return CanonicalAuthorityResult(
                DENY,
                f"actor '{actor}' lacks capability '{cap}'",
                self.name,
                self.policy_revision,
            )
        for label in action.get("data_labels", []):
            allowed = self._bindings.get(label)
            if allowed is None:
                if self._default_deny:
                    return CanonicalAuthorityResult(
                        DENY,
                        f"unknown data purpose '{label}' -> default-deny",
                        self.name,
                        self.policy_revision,
                    )
                continue
            if action.get("action_purpose") not in allowed:
                return CanonicalAuthorityResult(
                    DENY,
                    f"purpose mismatch: '{label}' != '{action.get('action_purpose')}'",
                    self.name,
                    self.policy_revision,
                )
        return CanonicalAuthorityResult(
            ALLOW, "all checks passed", self.name, self.policy_revision
        )

    def grant(self, actor: str, capability: str) -> None:
        self._grants.setdefault(actor, [])
        if capability not in self._grants[actor]:
            self._grants[actor].append(capability)
        self._authority.grant(actor, capability)
        self._revision_counter += 1

    def revoke(self, actor: str, capability: str) -> None:
        self._grants[actor] = [
            current for current in self._grants.get(actor, []) if current != capability
        ]
        self._authority.revoke(actor, capability)
        self._revision_counter += 1

    def delegate(
        self,
        parent: str,
        child: str,
        tools: list[str],
        *,
        expires_at: datetime | None = None,
    ) -> Macaroon:
        macaroon = self._authority.delegate(
            parent, child, tools, expires_at=expires_at
        )
        self._revision_counter += 1
        return macaroon

    def healthcheck(self) -> tuple[bool, str]:
        return (True, self.policy_revision)


class OPAHTTPAuthorityPDP:
    """Bounded adapter for an official OPA data API decision endpoint."""

    name = "opa"
    mutable = False

    def __init__(
        self,
        decision_url: str,
        *,
        policy_revision: str,
        timeout_s: float = 1.0,
        health_url: str | None = None,
        max_response_bytes: int = MAX_HTTP_RESPONSE_BYTES,
    ) -> None:
        parsed = urllib.parse.urlsplit(decision_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("OPA decision URL must be absolute http(s)")
        if timeout_s <= 0 or max_response_bytes < 1:
            raise ValueError("OPA timeout/response bound must be positive")
        self.decision_url = decision_url
        self._policy_revision = _plain_bounded(
            policy_revision, fallback="unknown", limit=256
        )
        self.timeout_s = timeout_s
        self.max_response_bytes = max_response_bytes
        self.health_url = health_url or urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, "/health", "", "")
        )

    @property
    def policy_revision(self) -> str:
        return self._policy_revision

    def _read(self, response: Any) -> bytes:
        body = response.read(self.max_response_bytes + 1)
        if len(body) > self.max_response_bytes:
            raise AuthorityPDPError("OPA response exceeds configured limit")
        return body

    def evaluate(self, action: dict[str, Any]) -> CanonicalAuthorityResult:
        payload = json.dumps(
            {"input": action}, sort_keys=True, separators=(",", ":")
        ).encode()
        request = urllib.request.Request(
            self.decision_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
            decoded = json.loads(self._read(response))
        if not isinstance(decoded, dict) or "result" not in decoded:
            raise AuthorityPDPError("OPA response missing result")
        result = decoded["result"]
        if isinstance(result, bool):
            verdict = ALLOW if result else DENY
            reason = f"OPA boolean result: {result}"
        elif isinstance(result, (str, dict)):
            canonical = canonicalize_authority_output(self, result)
            verdict, reason = canonical.verdict, canonical.reason
        else:
            raise AuthorityPDPError("OPA result must be bool, verdict string, or object")
        return CanonicalAuthorityResult(
            verdict, reason, self.name, self.policy_revision
        )

    def healthcheck(self) -> tuple[bool, str]:
        try:
            with urllib.request.urlopen(self.health_url, timeout=self.timeout_s) as response:
                self._read(response)
            return (True, self.policy_revision)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            return (False, f"OPA unavailable: {exc}"[:MAX_REASON_CHARS])


class CedarCLIAuthorityPDP:
    """Reference adapter for the official Cedar Policy CLI."""

    name = "cedar"
    mutable = False

    def __init__(
        self,
        cedar_bin: str | Path,
        *,
        policies: str | Path,
        entities: str | Path,
        schema: str | Path | None = None,
        policy_revision: str,
        timeout_s: float = 1.0,
        principal_type: str = "Agent",
        resource_type: str = "Effect",
        default_resource: str = "governed",
        context_map: dict[str, str] | None = None,
        max_output_chars: int = 16 * 1024,
    ) -> None:
        if timeout_s <= 0 or max_output_chars < 1:
            raise ValueError("Cedar timeout/output bound must be positive")
        self.cedar_bin = str(cedar_bin)
        self.policies = Path(policies)
        self.entities = Path(entities)
        self.schema = Path(schema) if schema is not None else None
        self._policy_revision = _plain_bounded(
            policy_revision, fallback="unknown", limit=256
        )
        self.timeout_s = timeout_s
        self.principal_type = principal_type
        self.resource_type = resource_type
        self.default_resource = default_resource
        self.context_map = context_map or {"purpose": "action_purpose"}
        self.max_output_chars = max_output_chars
        for path in (self.policies, self.entities, self.schema):
            if path is not None and not path.is_file():
                raise FileNotFoundError(path)

    @property
    def policy_revision(self) -> str:
        return self._policy_revision

    @staticmethod
    def _uid(entity_type: str, entity_id: str) -> str:
        return f"{entity_type}::{json.dumps(entity_id)}"

    @staticmethod
    def _lookup(action: dict[str, Any], dotted: str) -> Any:
        current: Any = action
        for part in dotted.split("."):
            if not isinstance(current, dict) or part not in current:
                raise AuthorityPDPError(f"Cedar context source missing: {dotted}")
            current = current[part]
        return current

    def evaluate(self, action: dict[str, Any]) -> CanonicalAuthorityResult:
        context = {
            target: self._lookup(action, source)
            for target, source in self.context_map.items()
        }
        resource = str(action.get("resource") or self.default_resource)
        request = {
            "principal": self._uid(self.principal_type, str(action.get("actor", ""))),
            "action": self._uid("Action", str(action.get("tool", ""))),
            "resource": self._uid(self.resource_type, resource),
            "context": context,
        }
        with tempfile.TemporaryDirectory() as tmp:
            request_path = Path(tmp) / "request.json"
            request_path.write_text(json.dumps(request), encoding="utf-8")
            command = [
                self.cedar_bin,
                "authorize",
                "--policies",
                str(self.policies),
                "--entities",
                str(self.entities),
                "--request-json",
                str(request_path),
            ]
            if self.schema is not None:
                command.extend(["--schema", str(self.schema)])
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.timeout_s,
                )
            except subprocess.TimeoutExpired as exc:
                raise AuthorityPDPError("Cedar CLI timed out") from exc
        output = f"{completed.stdout}\n{completed.stderr}"[: self.max_output_chars]
        if completed.returncode == 0:
            return CanonicalAuthorityResult(
                ALLOW, "Cedar permit", self.name, self.policy_revision
            )
        if completed.returncode == 2:
            return CanonicalAuthorityResult(
                DENY, "Cedar deny", self.name, self.policy_revision
            )
        raise AuthorityPDPError(
            f"Cedar CLI failure ({completed.returncode}): {output}"
        )

    def healthcheck(self) -> tuple[bool, str]:
        try:
            completed = subprocess.run(
                [self.cedar_bin, "--version"],
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                encoding="utf-8",
                errors="replace",
            )
            if completed.returncode == 0:
                return (True, completed.stdout.strip()[:256])
            return (False, f"Cedar version check failed: {completed.returncode}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            return (False, f"Cedar unavailable: {exc}"[:MAX_REASON_CHARS])
