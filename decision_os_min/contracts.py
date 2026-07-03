"""The formal contract — as types, not JSON Schema.

There is no separate contracts *repo* here, but there IS a formal contract: these
TypedDicts pin the shape of every message that crosses a boundary. They cost
nothing at runtime and give type-checkers something to catch drift against — the
lightweight version of the schema-governance the full system uses.

The advanced multi-repo Decision OS is the SAME shapes with more fields; the
decision logic and these core shapes are defined HERE first (single source of
truth) and extended there, never forked.
"""

from __future__ import annotations

from typing import Any, Literal, NotRequired, TypedDict

Verdict = Literal["ALLOW", "DENY", "LIMIT", "CONTAIN", "DEFER"]


class Action(TypedDict):
    """A request to run one tool. `capability` and `tool` must agree if both set."""

    actor: str
    tool: str
    capability: NotRequired[str]         # canonical form "tool:<name>"
    action_purpose: NotRequired[str]
    data_labels: NotRequired[list[str]]
    payload: NotRequired[dict[str, Any]]
    nonce: NotRequired[str]


class Decision(TypedDict):
    """The kernel's signed ruling. Only the kernel produces these. On a permitting
    verdict it also carries the one-time capability grant (capability/token_id/
    token_expires_at) so a SINGLE signature authenticates both the ruling and the
    token — see docs/DESIGN_NOTE_single_signature.md."""

    verdict: Verdict
    reason: str
    action_ref: str
    issued_by: str
    action_binding: str                  # sha256 of the action's security content
    transformed_payload: NotRequired[dict[str, Any]]   # LIMIT only
    containment: NotRequired[dict[str, Any]]            # CONTAIN only
    capability: NotRequired[str]         # permitting verdicts: the granted capability
    token_id: NotRequired[str]           # permitting verdicts: one-time spend id
    token_expires_at: NotRequired[str]   # permitting verdicts: TTL


class CapabilityToken(TypedDict):
    """A convenience VIEW of the token fields carried in the signed Decision. It is
    NOT independently signed — its authority is the Decision's single signature.
    The executor reads token_id/capability/expiry from the signed Decision, not
    from this view."""

    token_id: str
    actor: str
    capability: str
    action_ref: str
    action_binding: str
    issued_by: str
    expires_at: str


class AuditEntry(TypedDict):
    """One tamper-evident, hash-chained record."""

    seq: int
    ts: str
    actor: str
    tool: str
    verdict: str
    reason: str
    prev_hash: str
    entry_hash: str
