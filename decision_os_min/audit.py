"""One tamper-evident truth: an append-only, hash-chained log.

Deliberately the ONLY audit mechanism (no separate notary / dual truth). Each
entry chains to the previous by hash, so any retroactive edit, insert, delete, or
reorder is detectable by verify(). Stdlib only.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _hash(entry: dict[str, Any]) -> str:
    payload = {k: v for k, v in entry.items() if k != "entry_hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


class HashLog:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        self._last = GENESIS
        if self._path.exists():
            for line in self._path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    last = json.loads(line)
            if self._path.read_text(encoding="utf-8").strip():
                self._seq = last["seq"] + 1
                self._last = last["entry_hash"]

    def record(self, actor: str, tool: str, verdict: str, reason: str) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "seq": self._seq,
            "ts": datetime.now(UTC).isoformat(),
            "actor": actor,
            "tool": tool,
            "verdict": verdict,
            "reason": reason,
            "prev_hash": self._last,
        }
        entry["entry_hash"] = _hash(entry)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        self._seq += 1
        self._last = entry["entry_hash"]
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

    def entries(self) -> list[dict[str, Any]]:
        lines = self._path.read_text(encoding="utf-8").splitlines()
        return [json.loads(x) for x in lines if x.strip()]
