"""One tamper-evident truth: an append-only, hash-chained log.

Deliberately the ONLY audit mechanism (no separate notary / dual truth). Each
entry chains to the previous by hash, so any retroactive edit, insert, delete, or
reorder is detectable by verify(). Stdlib only.

HB-2: a plain hash chain detects edits/inserts/reorders and HEAD deletion (the
seq no longer starts at 0), but NOT tail truncation — deleting the last N entries
leaves a shorter chain that still verifies internally, silently erasing the most
recent (e.g. malicious) records. This is exactly the hardening audit-ledger's
``HashChainedAudit`` already had and the distilled ``HashLog`` had dropped. It is
restored here: ``head()`` returns the current chain head, and
``verify_against_anchor(expected_hash, expected_seq)`` proves the on-disk head
matches a head retained OUT OF BAND, so any truncation/rewrite past the anchored
point is detected even though ``verify()`` alone would return True. An optional
``anchor`` sink publishes each new head as it is written.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _hash(entry: dict[str, Any]) -> str:
    payload = {k: v for k, v in entry.items() if k != "entry_hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


class HashLog:
    def __init__(
        self,
        path: str | Path,
        anchor: Callable[[int, str], None] | None = None,
    ) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        self._last = GENESIS
        # Optional EXTERNAL-ANCHOR sink (default off, so existing callers are
        # unchanged). Called with (seq, entry_hash) after each durable write so an
        # operator can publish the chain head to a trust root the attacker cannot
        # rewrite (a WORM bucket, a notary, a separate signer). Combined with
        # verify_against_anchor() this is what makes tail truncation detectable.
        self._anchor = anchor
        if self._path.exists():
            for line in self._path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    last = json.loads(line)
            if self._path.read_text(encoding="utf-8").strip():
                self._seq = last["seq"] + 1
                self._last = last["entry_hash"]

    def head(self) -> tuple[int, str]:
        """Return ``(last_seq, last_entry_hash)`` — the current chain head.

        This is the single value an operator retains/publishes out of band to get
        real tamper-EVIDENCE (not just in-process tamper-detection). For an empty
        chain returns ``(-1, GENESIS)``."""
        return (self._seq - 1, self._last)

    def record(
        self,
        actor: str,
        tool: str,
        verdict: str,
        reason: str,
        *,
        executed: bool | None = None,
        payload_digest: str | None = None,
    ) -> dict[str, Any]:
        """Append one chained audit entry.

        W-3: ``executed`` (did the effect actually run?) and ``payload_digest`` (a
        sha256 over the executed payload) are recorded when known, so an
        ALLOW-but-refused entry is distinguishable from ALLOW-and-ran, and $1 vs
        $1M are distinguishable by digest. Both default to None for the
        pre-execution/legacy call shape."""
        entry: dict[str, Any] = {
            "seq": self._seq,
            "ts": datetime.now(UTC).isoformat(),
            "actor": actor,
            "tool": tool,
            "verdict": verdict,
            "reason": reason,
            "executed": executed,
            "payload_digest": payload_digest,
            "prev_hash": self._last,
        }
        entry["entry_hash"] = _hash(entry)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        self._seq += 1
        self._last = entry["entry_hash"]
        # Publish the new head to the external anchor last, so the durable log is
        # the source of truth; a fail-closed anchor sink may raise and propagate.
        if self._anchor is not None:
            self._anchor(entry["seq"], entry["entry_hash"])
        return entry

    def verify(self) -> bool:
        prev = GENESIS
        lines = [x for x in self._path.read_text(encoding="utf-8").splitlines() if x.strip()]
        for i, line in enumerate(lines):
            e = json.loads(line)
            if e["seq"] != i or e["prev_hash"] != prev or e["entry_hash"] != _hash(e):
                return False
            prev = e["entry_hash"]
        return True

    def verify_against_anchor(
        self, expected_hash: str, expected_seq: int | None = None
    ) -> tuple[bool, str]:
        """Verify the chain AND that its head matches an externally-retained one.

        Plain :meth:`verify` cannot catch tail truncation: deleting the last N
        entries leaves a shorter chain that is still internally consistent. But any
        truncation/rewrite changes the HEAD (seq and/or hash). An auditor who kept
        the last known-good head out of band (via :meth:`head` / the ``anchor``
        sink) passes it here; a divergence is then provable even though
        :meth:`verify` alone returns True. This is the piece that closes HB-2 —
        provided the anchor lives somewhere the attacker cannot rewrite."""
        if not self.verify():
            return False, "chain does not verify (edit/insert/reorder/head-delete)"
        last_seq, last_hash = self._current_head_on_disk()
        if last_hash != expected_hash:
            return False, (
                f"head hash diverges from anchor (local {last_hash[:12]}…, "
                f"anchor {expected_hash[:12]}…) — truncation/rewrite past the anchored point"
            )
        if expected_seq is not None and last_seq != expected_seq:
            return False, (
                f"head seq diverges from anchor (local {last_seq}, anchor {expected_seq}) "
                f"— entries dropped/added"
            )
        return True, "ok"

    def _current_head_on_disk(self) -> tuple[int, str]:
        """Re-read the file and return its (last_seq, last_entry_hash). Unlike
        :meth:`head` (in-memory), this reflects what is actually on disk NOW — so
        a truncation done by another process is seen."""
        last_entry: dict[str, Any] | None = None
        if self._path.exists():
            for line in self._path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    last_entry = json.loads(line)
        if last_entry is None:
            return (-1, GENESIS)
        return (int(last_entry["seq"]), last_entry["entry_hash"])

    def entries(self) -> list[dict[str, Any]]:
        lines = self._path.read_text(encoding="utf-8").splitlines()
        return [json.loads(x) for x in lines if x.strip()]
