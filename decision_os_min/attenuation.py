"""Macaroon-inspired attenuation for AE-4 / AE-5.

Adopts the governing property of Macaroons (Birgisson et al., NDSS 2014) and
Biscuit: a caveat can only **narrow** authority; it can never widen it. This is
deliberately a *lite* subset — first-party caveats only, HMAC-chained, no
third-party discharge, no Datalog — because inventing a new delegation format
would cost the conformance profile its credibility (PROFILE.md §2a).

Caveat vocabulary (first-party):
  - ``tools:<a,b,…>`` — holder may use only the listed tools. Multiple ``tools:``
                        caveats **intersect** (HMAC append can only shrink the
                        allowlist; a disjoint append yields empty authority).
  - ``tool:<name>``   — legacy singleton allowlist (treated as ``tools:<name>``);
                        also intersected when several appear.
  - ``time < <iso8601>`` — absolute expiry; child expiry MUST be ≤ parent expiry

The HMAC chain tip is the integrity seal: dropping or reordering caveats
invalidates the signature. Verification recomputes the chain from the root key.
Appending is cryptographically possible without the root key (as in Macaroons);
the allowlist vocabulary is therefore intersection-based so append cannot amplify.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

_MacList = list[tuple[frozenset[str] | None, datetime | None]]
_ParentAuthority = tuple[frozenset[str] | None, frozenset[str], _MacList]


def _h(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _parse_expiry(caveat: str) -> datetime | None:
    if not caveat.startswith("time < "):
        return None
    raw = caveat[len("time < ") :].strip()
    # Accept trailing Z as UTC.
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    return datetime.fromisoformat(raw)


def _parse_tools_caveat(caveat: str) -> frozenset[str] | None:
    """Parse one allowlist caveat into a frozenset, or None if not a tools caveat."""
    if caveat.startswith("tools:"):
        parts = [p.strip() for p in caveat[len("tools:") :].split(",") if p.strip()]
        return frozenset(parts)
    if caveat.startswith("tool:"):
        # Legacy singleton form — same as tools:<name>.
        return frozenset([caveat[len("tool:") :]])
    return None


def _tools_from(caveats: tuple[str, ...]) -> frozenset[str] | None:
    """Effective tool allowlist = intersection of all tool allowlist caveats.

    None means 'no tool caveats yet' (unrestricted within parent — only at root).
    An empty frozenset means 'explicitly nothing' (unsatisfiable / fully attenuated).

    Intersection is load-bearing for AE-4: the HMAC chain permits anyone who knows
    the tip to *append* a caveat without the root key. If tool caveats were a union
    allowlist, appending ``tool:wire_money`` would amplify. Intersecting makes
    append-only-narrow, matching Macaroon semantics.
    """
    sets: list[frozenset[str]] = []
    for c in caveats:
        parsed = _parse_tools_caveat(c)
        if parsed is not None:
            sets.append(parsed)
    if not sets:
        return None
    out = sets[0]
    for s in sets[1:]:
        out &= s
    return out


def _expiry_from(caveats: tuple[str, ...]) -> datetime | None:
    times = [t for c in caveats if (t := _parse_expiry(c)) is not None]
    return min(times) if times else None


def _holder_from_identifier(identifier: str) -> str:
    """Macaroon identifiers are ``{holder}|{nonce}`` — bind verification to holder."""
    return identifier.split("|", 1)[0]


@dataclass(frozen=True)
class Macaroon:
    """A bearer authority token whose caveats can only attenuate."""

    location: str
    identifier: str
    caveats: tuple[str, ...]
    signature: bytes

    def tool_set(self) -> frozenset[str] | None:
        return _tools_from(self.caveats)

    def expires_at(self) -> datetime | None:
        return _expiry_from(self.caveats)


class AttenuationError(ValueError):
    """Raised when a proposed caveat would amplify authority."""


class AuthorityGraph:
    """Root grants + macaroon-style attenuated delegations.

    Root grants are issued by the kernel (they *are* ``grant()``). Delegations
    are minted as macaroons whose caveats are a subset of the parent's effective
    authority. Holders without a macaroon fall back to the flat grant map for
    backward compatibility with existing policies.
    """

    def __init__(self, root_key: bytes | None = None) -> None:
        self._root_key = root_key or secrets.token_bytes(32)
        # holder -> list of live macaroons (a holder may hold several)
        self._macaroons: dict[str, list[Macaroon]] = {}
        # flat root grants: holder -> set of "tool:<name>" (or "*")
        self._root_grants: dict[str, set[str]] = {}

    # --- root grants (explicit issuance = grant()) --------------------------
    def grant(self, holder: str, capability: str) -> None:
        self._root_grants.setdefault(holder, set()).add(capability)

    def revoke(self, holder: str, capability: str) -> None:
        caps = self._root_grants.get(holder)
        if caps is not None:
            caps.discard(capability)

    def set_root_grants(self, grants: dict[str, list[str]]) -> None:
        self._root_grants = {k: set(v) for k, v in grants.items()}

    # --- macaroon mint / attenuate ------------------------------------------
    def _mint(self, holder: str, caveats: tuple[str, ...]) -> Macaroon:
        identifier = f"{holder}|{uuid.uuid4().hex[:12]}"
        sig = _h(self._root_key, f"id|{identifier}")
        for c in caveats:
            sig = _h(sig, f"caveat|{c}")
        return Macaroon(
            location="decision-os-min",
            identifier=identifier,
            caveats=caveats,
            signature=sig,
        )

    def _verify_sig(self, m: Macaroon) -> bool:
        sig = _h(self._root_key, f"id|{m.identifier}")
        for c in m.caveats:
            sig = _h(sig, f"caveat|{c}")
        return hmac.compare_digest(sig, m.signature)

    def _macaroon_usable_by(self, holder: str, m: Macaroon) -> bool:
        """Signature ok AND identifier bound to this holder (no rebind)."""
        if _holder_from_identifier(m.identifier) != holder:
            return False
        return self._verify_sig(m)

    def _live_credentials(
        self, parent: str, *, now: datetime
    ) -> tuple[bool, frozenset[str], list[tuple[frozenset[str] | None, datetime | None]]]:
        """Return ``(root_star, root_tools, live_macaroons)``.

        Live macaroons are ``(tool_set, expiry)`` with signature+holder binding ok
        and not yet expired. Empty allowlists (HMAC-append wreckage) are omitted.
        Root tools are the flat grant map (minus ``*``); ``root_star`` means
        unrestricted root.
        """
        root = self._root_grants.get(parent, set())
        root_star = "*" in root
        root_tools = frozenset(
            c.split("tool:", 1)[-1] for c in root if c.startswith("tool:")
        )

        macs: list[tuple[frozenset[str] | None, datetime | None]] = []
        for m in self._macaroons.get(parent, []):
            if not self._macaroon_usable_by(parent, m):
                continue
            exp = m.expires_at()
            if exp is not None and now >= exp:
                continue  # AE-5: expired credentials are not live authority
            ts = m.tool_set()
            if ts is not None and not ts:
                continue
            macs.append((ts, exp))
        return root_star, root_tools, macs

    def _parent_authority(
        self, parent: str, *, now: datetime | None = None
    ) -> _ParentAuthority:
        """Effective parent tools + the credentials used to justify them.

        Returns ``(parent_tools, root_tools, live_macs)`` where ``parent_tools``
        is the **union** of root grants and live macaroon allowlists (``None`` =
        unrestricted). Union — not intersection — matches ``holds()``: a parent
        with two alternate credentials may exercise either. Intersecting them
        falsely emptied authority (and blocked honest delegation) while still
        letting ``holds`` succeed for each tool.
        """
        now = now or datetime.now(UTC)
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        root_star, root_tools, macs = self._live_credentials(parent, now=now)

        if root_star:
            return None, root_tools, macs

        tools: frozenset[str] | None = root_tools
        if not macs and not root_tools:
            return frozenset(), root_tools, macs

        for ts, _exp in macs:
            if ts is None:
                tools = None
                break
            tools = (tools or frozenset()) | ts
        return tools, root_tools, macs

    def delegate(
        self,
        parent: str,
        child: str,
        tools: list[str],
        *,
        expires_at: datetime | None = None,
        now: datetime | None = None,
    ) -> Macaroon:
        """Mint an attenuated macaroon for ``child``.

        AE-4: resulting tool set ⊆ parent tool set (extras dropped).
        AE-5: child expiry ≤ the ceiling of the *credentials that cover* the
        granted tools; expired parents cannot mint; root-only tools are not
        time-clamped by unrelated macaroons.
        """
        now = now or datetime.now(UTC)
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)

        parent_tools, root_tools, macs = self._parent_authority(parent, now=now)
        requested = frozenset(t.removeprefix("tool:") for t in tools)

        if parent_tools is not None:
            allowed = requested & parent_tools
        else:
            allowed = requested

        if not allowed:
            raise AttenuationError(
                f"delegation from '{parent}' to '{child}' grants nothing after attenuation"
            )

        # AE-5: tools not covered by (unexpired) root must be covered by a live
        # macaroon; their expiry ceiling is the min expiry of covering macaroons.
        root_star = "*" in self._root_grants.get(parent, set())
        if root_star:
            remainder: frozenset[str] = frozenset()
        else:
            remainder = frozenset(t for t in allowed if t not in root_tools)

        child_expiry = expires_at
        if remainder:
            covering_expiries: list[datetime] = []
            covered: set[str] = set()
            for ts, exp in macs:
                if ts is None:
                    hit = set(remainder)
                else:
                    hit = set(ts & remainder)
                if not hit:
                    continue
                covered |= hit
                if exp is not None:
                    covering_expiries.append(exp)
            if covered < set(remainder):
                raise AttenuationError(
                    f"delegation from '{parent}' to '{child}' lacks live credentials "
                    f"for {sorted(set(remainder) - covered)}"
                )
            if covering_expiries:
                ceiling = min(covering_expiries)
                if child_expiry is None or child_expiry > ceiling:
                    child_expiry = ceiling

        if child_expiry is not None and child_expiry.tzinfo is None:
            child_expiry = child_expiry.replace(tzinfo=UTC)
        # Refuse minting already-expired authority (dead parent / clamped past).
        if child_expiry is not None and now >= child_expiry:
            raise AttenuationError(
                f"delegation from '{parent}' to '{child}' would mint expired authority"
            )

        # One allowlist caveat (not one tool: per name): HMAC append of another
        # tools: caveat intersects, so it cannot widen the set.
        caveats: list[str] = [f"tools:{','.join(sorted(allowed))}"]
        if child_expiry is not None:
            caveats.append(f"time < {child_expiry.astimezone(UTC).isoformat()}")

        m = self._mint(child, tuple(caveats))
        self._macaroons.setdefault(child, []).append(m)
        return m

    def holds(self, holder: str, capability: str, *, now: datetime | None = None) -> bool:
        """True iff ``holder`` currently holds ``capability`` under root grant or macaroon."""
        now = now or datetime.now(UTC)
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)

        root = self._root_grants.get(holder, set())
        if "*" in root or capability in root:
            return True

        tool = capability.removeprefix("tool:")
        for m in self._macaroons.get(holder, []):
            if not self._macaroon_usable_by(holder, m):
                continue
            exp = m.expires_at()
            if exp is not None and now >= exp:
                continue
            tools = m.tool_set()
            if tools is not None and tool in tools:
                return True
        return False

    def export_state(self) -> dict[str, Any]:
        """Debug/audit snapshot — not a security boundary."""
        return {
            "root_grants": {k: sorted(v) for k, v in self._root_grants.items()},
            "delegations": {
                h: [
                    {
                        "identifier": m.identifier,
                        "caveats": list(m.caveats),
                        "signature": m.signature.hex(),
                    }
                    for m in ms
                ]
                for h, ms in self._macaroons.items()
            },
        }
