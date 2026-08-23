"""The kernel: sole executable-decision signer and one-time token minter.

This is the distilled core of the multi-repo Decision OS — the ~30% that carries
the real security value, in one file with no cross-repo machinery. Deterministic;
stdlib + cryptography only.
"""

from __future__ import annotations

import copy
import hashlib
import json
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .attenuation import AuthorityGraph, Macaroon
from .authority_pdp import (
    AuthorityMutationUnsupported,
    AuthorityPDP,
    BuiltinAuthorityPDP,
    CanonicalAuthorityResult,
    evaluate_authority,
)

# Verdicts + the meet/compose primitives live in compose.py (the base module with
# no internal deps). Imported here and re-exported, so existing callers that do
# `from .kernel import DENY, PERMITTING, ...` keep working unchanged.
from .compose import (
    ALLOW,
    CONTAIN,
    DEFER,
    DENY,
    LIMIT,
    PERMITTING,
    Evaluator,
    as_decision,
    more_restrictive,
    sanitize,
)

# An advisor is an OPTIONAL plugin: given an action, it may suggest a threat
# class (e.g. "malicious"). It is advice, never authority — the kernel decides.
Advisor = Callable[[dict[str, Any]], "str | None"]

KERNEL_IDENTITY = "decision-os-min-kernel"

_CONTAINMENT = {"sandbox": True, "network": "none", "allowed_tools": [], "time_limit_seconds": 5}


def _canonical(obj: dict[str, Any]) -> bytes:
    payload = {k: v for k, v in obj.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class UnfingerprintablePayload(TypeError):
    """A payload value is not a JSON primitive, so it cannot be safely committed
    to by the action fingerprint (W-2). Raised instead of silently coercing it
    with ``str()`` — the coercion is what let an object stringifying to "100"
    collide with the string "100", and let a mutable object be swapped after the
    hash was taken."""


# The only value types the fingerprint will commit to. Anything else (custom
# objects, callables, sets, bytes, …) is REJECTED rather than str()-coerced.
_JSON_PRIMITIVES = (str, int, float, bool, type(None))


def _strict_encode(value: Any, _path: str = "payload") -> Any:
    """Return ``value`` unchanged if it is built only from JSON primitives, else
    raise :class:`UnfingerprintablePayload`.

    This closes W-2: the fingerprint used ``json.dumps(..., default=str)``, which
    (a) coerced any non-serializable object via ``str()`` — so an object whose
    ``__str__`` returns "100" fingerprinted identically to the string "100"
    (type-confusion collision), and (b) committed to a STRING SNAPSHOT of a
    mutable object, letting the object be mutated after authorization while the
    binding still matched (TOCTOU / mutate-after-auth). Rejecting non-primitives
    up front makes both unrepresentable: the payload must be plain JSON data whose
    value at hash-time IS its value at execute-time."""
    if isinstance(value, bool) or value is None or isinstance(value, (int, float, str)):
        return value
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise UnfingerprintablePayload(
                    f"{_path}: non-string dict key {k!r} of type {type(k).__name__}"
                )
            out[k] = _strict_encode(v, f"{_path}.{k}")
        return out
    if isinstance(value, (list, tuple)):
        return [_strict_encode(v, f"{_path}[{i}]") for i, v in enumerate(value)]
    raise UnfingerprintablePayload(
        f"{_path}: value of type {type(value).__name__} is not a JSON primitive; "
        f"payloads bound by a decision must be plain JSON data "
        f"(str/int/float/bool/None/list/dict) — refusing to str()-coerce it"
    )


def action_fingerprint(action: dict[str, Any]) -> str:
    """sha256 committing a decision/token to the security-relevant action content
    (actor, capability, purpose, labels, payload, and the nonce/action_ref) — so a
    signed authorization cannot be re-attached to a different action. Closes the
    confused-deputy gap.

    W-1: ``action_ref`` (falling back to ``nonce``) is folded into the binding so
    two actions that differ ONLY by nonce no longer share a fingerprint.

    W-2: the payload is passed through a strict encoder that REJECTS any value
    that is not a JSON primitive (raising :class:`UnfingerprintablePayload`),
    instead of ``str()``-coercing it — closing the object/string collision and the
    mutate-after-auth window."""
    normalized = {
        "actor": action.get("actor", ""),
        "capability": action.get("capability") or f"tool:{action.get('tool', '')}",
        "action_purpose": action.get("action_purpose", ""),
        "data_labels": sorted(action.get("data_labels") or []),
        # W-1: bind the caller-supplied action reference. The kernel derives
        # `action_ref` the same way (`nonce` else `action_ref`), and the executor
        # checks action.nonce/action_ref == decision.action_ref, so a decision
        # minted for one reference cannot authorize a different action object.
        "action_ref": action.get("nonce") or action.get("action_ref") or "",
        "payload": _strict_encode(action.get("payload") or {}),
    }
    # default=str is no longer needed: _strict_encode guarantees JSON primitives.
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def verify(obj: dict[str, Any], signature_hex: str, public_key_hex: str) -> bool:
    """True iff `obj` carries the kernel identity AND a valid kernel signature."""
    if obj.get("issued_by") != KERNEL_IDENTITY:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(signature_hex), _canonical(obj))
        return True
    except (InvalidSignature, ValueError):
        return False


def load_or_create_signing_key(path: str | None) -> Ed25519PrivateKey:
    """Infra: persist the kernel signing key across restarts.

    Without persistence every container restart mints a new key and every prior
    decision signature becomes unverifiable. If ``path`` is set, load PEM from
    that file or create+write one (mode 0600 when the OS supports it).
    """
    if not path:
        return Ed25519PrivateKey.generate()
    from pathlib import Path

    p = Path(path)
    if p.is_file():
        data = p.read_bytes()
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError(f"{path}: expected an Ed25519 private key PEM")
        return key
    key = Ed25519PrivateKey.generate()
    p.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    p.write_bytes(pem)
    try:
        p.chmod(0o600)
    except OSError:
        pass
    return key


class Kernel:
    """Sole execution authority: canonicalizes PDP output, signs, and mints."""

    def __init__(
        self,
        policy: dict[str, Any],
        _key: Ed25519PrivateKey | None = None,
        *,
        key_path: str | None = None,
        evaluator_timeout_s: float | None = 1.0,
        authority_pdp: AuthorityPDP | None = None,
        authority_timeout_s: float | None = 1.0,
    ) -> None:
        self._key = _key or load_or_create_signing_key(key_path)
        self._pub = self._key.public_key().public_bytes_raw().hex()
        self._grants: dict[str, list[str]] = policy.get("grants", {})
        self._bindings: dict[str, list[str]] = policy.get("purpose_bindings", {})
        self._redactions: list[dict[str, Any]] = policy.get("redactions", [])
        self._contain: set[str] = set(policy.get("contain_threat_classes", ["malicious"]))
        self._default_deny: bool = policy.get("default", "deny") == "deny"
        # I4: bound untrusted evaluator runtime (default 1s). ``None`` = in-process
        # and unbounded (legacy / deliberate). Overridable per ``decide(...)``.
        self._evaluator_timeout_s = evaluator_timeout_s
        # AE-4 / AE-5: macaroon-inspired attenuation graph. Root grants mirror the
        # flat policy map so existing callers keep working; `delegate()` adds
        # attenuated children that cannot amplify tools or outlive their parent.
        self.authority = AuthorityGraph()
        self.authority.set_root_grants(self._grants)
        self._builtin_authority: BuiltinAuthorityPDP | None = None
        if authority_pdp is None:
            self._builtin_authority = BuiltinAuthorityPDP(
                self._grants,
                self._bindings,
                self.authority,
                default_deny=self._default_deny,
            )
            authority_pdp = self._builtin_authority
        self._authority_pdp = authority_pdp
        self._authority_timeout_s = authority_timeout_s

    def public_key_pem(self) -> str:
        return self._key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    def public_key_hex(self) -> str:
        return self._pub

    def authority_provider(self) -> tuple[str, str]:
        """Return the selected PDP identity and policy revision (never secrets)."""
        return (
            self._authority_pdp.name,
            self._authority_pdp.policy_revision,
        )

    def authority_healthcheck(self) -> tuple[bool, str]:
        return self._authority_pdp.healthcheck()

    def grant(self, actor: str, capability: str) -> None:
        """Explicit root issuance — the only operation that raises authority."""
        if self._builtin_authority is None:
            raise AuthorityMutationUnsupported(
                f"{self._authority_pdp.name} policy is externally managed"
            )
        self._builtin_authority.grant(actor, capability)

    def revoke(self, actor: str, capability: str) -> None:
        if self._builtin_authority is None:
            raise AuthorityMutationUnsupported(
                f"{self._authority_pdp.name} policy is externally managed"
            )
        self._builtin_authority.revoke(actor, capability)

    def delegate(
        self,
        parent: str,
        child: str,
        tools: list[str],
        *,
        expires_at: datetime | None = None,
    ) -> Macaroon:
        """Attenuating delegation (AE-4 / AE-5). See ``attenuation.AuthorityGraph``."""
        if self._builtin_authority is None:
            raise AuthorityMutationUnsupported(
                f"{self._authority_pdp.name} policy is externally managed"
            )
        return self._builtin_authority.delegate(
            parent, child, tools, expires_at=expires_at
        )

    def _sign(self, obj: dict[str, Any]) -> str:
        return self._key.sign(_canonical(obj)).hex()

    def _evaluate(
        self,
        action: dict[str, Any],
        threat_class: str | None,
        *,
        authority_timeout_s: float | None,
    ) -> tuple[dict[str, Any], CanonicalAuthorityResult]:
        ref = action.get("nonce") or action.get("action_ref") or ""

        def d(verdict: str, reason: str, **extra: Any) -> dict[str, Any]:
            return {"verdict": verdict, "reason": reason, "action_ref": ref, **extra}

        authority_result = evaluate_authority(
            self._authority_pdp,
            action,
            timeout_s=authority_timeout_s,
        )
        authority_decision = d(
            authority_result.verdict,
            authority_result.reason,
            authority_provider=authority_result.provider,
            authority_policy_revision=authority_result.policy_revision,
        )
        if authority_result.verdict in {DENY, DEFER}:
            return authority_decision, authority_result
        # Data minimization is an OBLIGATION, not a verdict. Compute it FIRST so it
        # survives whatever verdict this action ends up with. It used to be computed
        # AFTER the containment return, so a CONTAIN decision carried no
        # transformed_payload and the redaction was silently dropped. That was latent
        # rather than harmless: the default containment allowlist is empty, so CONTAIN
        # executes nothing and nothing leaks — but an empty allowlist also makes
        # CONTAIN operationally equivalent to DENY. The first operator to allowlist
        # the tool (i.e. to make CONTAIN do its actual job) would have had the raw
        # payload delivered into the sandbox. Verdict and obligation are orthogonal.
        payload = dict(action.get("payload") or {})
        redacted: list[str] = []
        for rule in self._redactions:
            if rule.get("action_purpose") != action.get("action_purpose"):
                continue
            hit = [f for f in rule.get("redact_fields", []) if payload.get(f) not in (None, "")]
            if hit:
                for f in hit:
                    payload[f] = "[REDACTED]"
                redacted = sorted(hit)
                break
        obligations: dict[str, Any] = {"transformed_payload": payload} if redacted else {}

        local_decision = d(ALLOW, "host obligations satisfied")
        if threat_class in self._contain:
            local_decision = d(
                CONTAIN,
                f"threat '{threat_class}' -> sandbox"
                + (f"; redacted {redacted}" if redacted else ""),
            )
        elif redacted:
            local_decision = d(LIMIT, f"redacted {redacted}")

        decision = more_restrictive(authority_decision, local_decision)
        if decision["verdict"] == LIMIT:
            if not redacted:
                return (
                    d(
                        DENY,
                        "authority LIMIT has no host-owned transformation -> fail-closed",
                        authority_provider=authority_result.provider,
                        authority_policy_revision=authority_result.policy_revision,
                    ),
                    authority_result,
                )
            decision.update(obligations)
        elif decision["verdict"] == CONTAIN:
            decision["containment"] = dict(_CONTAINMENT)
            decision.update(obligations)
        decision["authority_provider"] = authority_result.provider
        decision["authority_policy_revision"] = authority_result.policy_revision
        return decision, authority_result

    def decide(
        self,
        action: dict[str, Any],
        threat_class: str | None = None,
        *,
        advisor: Advisor | None = None,
        evaluators: list[Evaluator] | None = None,
        evaluator_timeout: float | None | object = ...,
        authority_timeout: float | None | object = ...,
    ) -> dict[str, Any]:
        """Return {decision, signature, token}. The decision and token both bind
        the action fingerprint; token is None for non-permitting verdicts.

        `advisor` is an OPTIONAL plugin (e.g. an FDK threat classifier). Without
        it the kernel works fully; with it the kernel CONSULTS its suggestion but
        still makes the call. `advisor` takes precedence over an explicit
        `threat_class` when both are given.

        The selected trusted ``AuthorityPDP`` supplies the policy ruling. It may
        grant or deny, but receives no signing/minting/execution capability.
        This kernel canonicalizes that ruling and remains the only component
        capable of producing a signed executable decision.

        `evaluators` are OPTIONAL **co-equal** governance evaluators (e.g. an FDK
        legitimacy evaluator, and later safety/privacy/cost/...). Unlike an
        advisor — which can only *suggest* a threat class the kernel may map to
        CONTAIN — an evaluator returns a full verdict, and its DENY is
        AUTHORITATIVE: we compose this kernel's own authority verdict with every
        evaluator's verdict by the lattice meet (most-restrictive-wins, DENY
        absorbing) BEFORE minting any token. So authority ∧ legitimacy ∧ … must
        all permit, no side can override another's DENY, and (Invariant: token
        mint only after the composed verdict) no capability is minted for an
        action a later evaluator vetoes. Composition is commutative/associative,
        so evaluator order carries no meaning — only latency.

        `evaluator_timeout` bounds each evaluator call in seconds (default:
        ``self._evaluator_timeout_s``, typically 1.0). Pass ``None`` for
        unbounded in-process evaluation."""
        if advisor is not None:
            threat_class = advisor(action)
        authority_timeout_value: float | None = (
            self._authority_timeout_s
            if authority_timeout is ...
            else authority_timeout  # type: ignore[assignment]
        )
        # TRUSTED POLICY AUTHORITY: the selected PDP may grant/deny, but only this
        # kernel can canonicalize obligations, sign, and mint.
        decision, authority_result = self._evaluate(
            action,
            threat_class,
            authority_timeout_s=authority_timeout_value,
        )
        # CO-EQUAL EVALUATORS: fold each verdict in by meet, deny-dominant. This
        # happens before issued_by/binding/mint below, so the token (minted only
        # on a PERMITTING composed verdict) can never precede the composition.
        #
        # Three defences make the antitone/veto-only claim true rather than merely
        # argued (see COMPOSITION.md §11 for the exploits that motivated each):
        #   R3 — each evaluator sees a DEEP COPY, so it cannot mutate the action
        #        that authority already ruled on (a plugin used to be able to
        #        rewrite `capability` and have an ungranted tool execute under a
        #        perfectly valid signature, because the fingerprint is taken from
        #        the action AFTER this loop). A private copy each also stops one
        #        evaluator from hiding an attribute from the next.
        #   R1 — `sanitize` strips the evaluator's dict to {verdict, reason},
        #        so it cannot inject token/capability/payload/containment fields.
        #   I4 — a raising or timing-out evaluator DENIES rather than propagating
        #        out of `decide()`. Plugin-raised SystemExit/KeyboardInterrupt is
        #        also DENY (fail-closed against plugin abuse). True process shutdown
        #        still works when those exceptions are raised outside this seam.
        #        GeneratorExit still propagates. Optional evaluator_timeout bounds hangs.
        timeout: float | None = (
            self._evaluator_timeout_s if evaluator_timeout is ... else evaluator_timeout  # type: ignore[assignment]
        )
        leg_digests: list[str] = []
        axiom_acc: list[str] = []
        for evaluate in evaluators or ():
            try:
                if timeout is None:
                    out = evaluate(copy.deepcopy(action))
                else:
                    # Run off-thread so (a) we can bound wall time and (b) an
                    # in-process evaluator cannot frame-walk to self._key.
                    # shutdown(wait=False): do not block on a timed-out sleeper.
                    pool = ThreadPoolExecutor(max_workers=1)
                    try:
                        fut = pool.submit(evaluate, copy.deepcopy(action))
                        try:
                            out = fut.result(timeout=timeout)
                        except FuturesTimeoutError:
                            out = {
                                "verdict": DENY,
                                "reason": f"evaluator timeout (fail-closed): {timeout}s",
                            }
                    finally:
                        pool.shutdown(wait=False, cancel_futures=True)
            except Exception as exc:
                out = {"verdict": DENY, "reason": f"evaluator error (fail-closed): {exc}"}
            except BaseException as exc:
                # Plugin-raised SystemExit/KeyboardInterrupt -> DENY. Re-raise
                # GeneratorExit so generator cleanup is not swallowed.
                if isinstance(exc, GeneratorExit):
                    raise
                out = {
                    "verdict": DENY,
                    "reason": (
                        f"evaluator BaseException (fail-closed): "
                        f"{type(exc).__name__}: {exc}"
                    ),
                }
            decision = more_restrictive(decision, sanitize(as_decision(out, action)))
            # M5 accumulation: digests/axioms from evaluator output BEFORE sanitize
            # (sanitize still admits them; we also record for binding even if meet
            # later drops a non-governing evaluator's reason).
            if isinstance(out, dict):
                dig = out.get("legitimacy_digest")
                if isinstance(dig, str) and dig:
                    leg_digests.append(dig)
                ax = out.get("axiom_ids")
                if isinstance(ax, (list, tuple)):
                    axiom_acc.extend(str(a) for a in ax)
        # Provider identity/revision are kernel-owned fields. Preserve them even
        # when a legitimacy evaluator's stricter verdict governs the meet.
        decision["authority_provider"] = authority_result.provider
        decision["authority_policy_revision"] = authority_result.policy_revision
        decision["issued_by"] = KERNEL_IDENTITY
        decision["action_binding"] = action_fingerprint(action)
        # M5: cryptographic binding of legitimacy evidence into the signed decision.
        if leg_digests or axiom_acc:
            decision["legitimacy_digest"] = leg_digests[-1] if leg_digests else ""
            decision["axiom_ids"] = sorted(set(axiom_acc))
            decision["legitimacy_binding"] = hashlib.sha256(
                _canonical(
                    {
                        "action_binding": decision["action_binding"],
                        "legitimacy_digest": decision["legitimacy_digest"],
                        "axiom_ids": decision["axiom_ids"],
                        "verdict": decision["verdict"],
                    }
                )
            ).hexdigest()
        token = None
        if decision["verdict"] in PERMITTING:
            # Fold the one-time capability grant INTO the decision so a SINGLE
            # signature authenticates both the ruling and the token. Previously the
            # token was signed separately -> two Ed25519 signs per decide() and two
            # verifies per execute(); the benchmark showed crypto dominates, so this
            # halves it with no loss of guarantees (token_id/capability/expiry are
            # all still signed).
            decision["capability"] = action.get("capability") or f"tool:{action.get('tool', '')}"
            decision["token_id"] = f"tok-{uuid.uuid4().hex[:12]}"
            decision["token_expires_at"] = (datetime.now(UTC) + timedelta(seconds=30)).isoformat()
        signature = self._sign(decision)  # ONE signature covers ruling + token
        if decision["verdict"] in PERMITTING:
            token = {  # convenience view only; its authority IS the signed decision
                "token_id": decision["token_id"],
                "actor": action.get("actor", ""),
                "capability": decision["capability"],
                "action_ref": decision["action_ref"],
                "action_binding": decision["action_binding"],
                "issued_by": KERNEL_IDENTITY,
                "expires_at": decision["token_expires_at"],
                "legitimacy_binding": decision.get("legitimacy_binding"),
            }
        return {"decision": decision, "signature": signature, "token": token}
