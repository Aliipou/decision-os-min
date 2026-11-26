"""A cross-process ``HashLog``.

``decision_os_min.audit.HashLog`` caches the chain head in memory, which is
correct for one writer. The gateway has many writers (one proxy per MCP server)
appending to one log, so this subclass takes an exclusive file lock and re-reads
the head from disk before every append. The on-disk format is unchanged, so
``HashLog.verify`` and ``verify_against_anchor`` work on the result as-is.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..audit import GENESIS, HashLog, _hash
from .locking import file_lock


def _last_line(path: Path) -> str | None:
    """Return the last non-empty line of ``path`` without reading the whole file."""
    if not path.exists():
        return None
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        if end == 0:
            return None
        block = 4096
        data = b""
        pos = end
        while pos > 0:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            data = f.read(step) + data
            stripped = data.rstrip(b"\r\n")
            if b"\n" in stripped:
                return stripped.rsplit(b"\n", 1)[1].decode("utf-8")
        stripped = data.strip()
        return stripped.decode("utf-8") if stripped else None


class LockedHashLog(HashLog):
    def __init__(self, path: str | Path, lock_path: str | Path | None = None) -> None:
        super().__init__(path)
        self._lock_path = Path(lock_path) if lock_path else self._path.with_suffix(".lock")

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
        with file_lock(self._lock_path):
            last = _last_line(self._path)
            if last:
                head = json.loads(last)
                seq, prev = int(head["seq"]) + 1, head["entry_hash"]
            else:
                seq, prev = 0, GENESIS
            entry: dict[str, Any] = {
                "seq": seq,
                "ts": datetime.now(UTC).isoformat(),
                "actor": actor,
                "tool": tool,
                "verdict": verdict,
                "reason": reason,
                "executed": executed,
                "payload_digest": payload_digest,
                "prev_hash": prev,
            }
            entry["entry_hash"] = _hash(entry)
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._seq = seq + 1
            self._last = entry["entry_hash"]
        return entry

    def tail(self, n: int = 100) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        lines = [x for x in self._path.read_text(encoding="utf-8").splitlines() if x.strip()]
        return [json.loads(x) for x in lines[-n:]]
