"""Durable, atomic spent-token store — makes a one-time token one-time ACROSS
Executor instances (workers, replicas, restarts), not merely within one process.

HB-1: the original executor tracked spent token_ids in an in-memory ``set``. A
second executor (a fresh process, a second replica behind a load balancer, or the
same process after a restart) starts with an empty set, so a captured signed
decision can be spent again inside its 30s TTL — one decision, two effects.

The fix is a shared spend-record whose "have I seen this token_id?" test is
ATOMIC and DURABLE. This module provides:

  * :class:`SpentStore` — the protocol the executor depends on. Its one required
    method, :meth:`try_spend`, must atomically record a token_id and report
    whether THIS caller was the one that recorded it (True == first spender).
  * :class:`FileSpentStore` — the default. One file per token_id, created with
    ``O_CREAT | O_EXCL`` (the POSIX/Windows atomic "create only if absent"). The
    kernel of the OS filesystem does the compare-and-set, so two processes racing
    the same token_id: exactly one ``open`` succeeds, the other gets
    ``FileExistsError``. No DB, no daemon — stdlib only, and durable because the
    record is on disk before the effect runs.
  * :class:`SqliteSpentStore` — an alternative using a ``UNIQUE`` constraint on
    ``token_id`` (also stdlib). Useful when one file-per-token is undesirable.
  * :class:`InMemorySpentStore` — the OLD behaviour, kept as an EXPLICIT opt-in
    for genuinely single-process use. It is NOT durable and MUST NOT be used
    across replicas; using it is now a deliberate choice, not the silent default.

FAIL CLOSED: if the store cannot be reached (I/O error, permission denied, disk
full), :meth:`try_spend` raises :class:`SpentStoreUnavailable`. The executor
turns that into a refusal — it never falls back to "assume unspent", because that
is exactly the double-spend the store exists to prevent.

HONEST LIMIT: :class:`FileSpentStore`/:class:`SqliteSpentStore` are durable and
atomic on a SINGLE shared filesystem/volume. They make replay across processes
sharing that volume impossible. They are NOT a distributed consensus store: two
replicas on two machines with independent local disks would each accept the token
once. For a multi-machine deployment, back the store with a shared volume (NFS
with proper O_EXCL support, a shared block device) or implement :class:`SpentStore`
over Redis ``SETNX`` / a DB ``UNIQUE`` on a shared database. The protocol is the
seam for that; the file backend is the correct default for single-host / shared-
volume deployments, which is the common case.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path
from typing import Protocol, runtime_checkable


class SpentStoreUnavailable(RuntimeError):
    """The spent-store could not be reached. The executor MUST fail closed."""


@runtime_checkable
class SpentStore(Protocol):
    """A durable, atomic record of which token_ids have been spent.

    Implementations MUST make :meth:`try_spend` atomic: if two callers race the
    same token_id, exactly one gets ``True`` and every other gets ``False``.
    """

    def try_spend(self, token_id: str) -> bool:
        """Atomically record ``token_id`` as spent.

        Returns True iff THIS call was the first to record it (i.e. the token was
        previously unspent). Returns False if it was already spent (replay).

        Raises :class:`SpentStoreUnavailable` if the store cannot be reached — the
        caller must treat that as a refusal (fail closed), never as "unspent".
        """
        ...


class FileSpentStore:
    """Default durable store: one marker file per spent token_id, created with
    ``O_CREAT | O_EXCL`` so the "first to spend" test is an atomic filesystem
    operation shared by every process pointed at the same directory."""

    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory)
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:  # pragma: no cover - environment dependent
            raise SpentStoreUnavailable(f"cannot create spent-store dir {self._dir}: {e}") from e

    @staticmethod
    def _safe_name(token_id: str) -> str:
        # token_ids are kernel-minted (``tok-<hex>``); still, never trust an input
        # as a path component. Keep only path-safe chars; fold everything else.
        return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in token_id) or "_empty"

    def try_spend(self, token_id: str) -> bool:
        path = self._dir / self._safe_name(token_id)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            return False  # already spent — replay
        except OSError as e:
            raise SpentStoreUnavailable(f"spent-store unreachable for {token_id!r}: {e}") from e
        try:
            os.write(fd, token_id.encode("utf-8"))
            os.fsync(fd)  # durable before we let the effect run
        except OSError as e:  # pragma: no cover - environment dependent
            raise SpentStoreUnavailable(f"spent-store write failed for {token_id!r}: {e}") from e
        finally:
            os.close(fd)
        return True


class SqliteSpentStore:
    """Alternative durable store: a single sqlite DB with a UNIQUE constraint on
    token_id. The atomic compare-and-set is the failed INSERT (IntegrityError)."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = str(db_path)
        self._lock = threading.Lock()
        try:
            p = Path(self._path)
            if p.parent and not p.parent.exists():
                p.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS spent (token_id TEXT PRIMARY KEY)")
        except sqlite3.Error as e:  # pragma: no cover - environment dependent
            raise SpentStoreUnavailable(f"cannot init sqlite spent-store {self._path}: {e}") from e

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=30, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def try_spend(self, token_id: str) -> bool:
        try:
            with self._lock, self._connect() as conn:
                try:
                    conn.execute("INSERT INTO spent (token_id) VALUES (?)", (token_id,))
                except sqlite3.IntegrityError:
                    return False  # UNIQUE violation — already spent
                return True
        except sqlite3.Error as e:
            raise SpentStoreUnavailable(f"sqlite spent-store unreachable: {e}") from e


class InMemorySpentStore:
    """The ORIGINAL in-process set. Fast, but NOT durable and NOT shared across
    processes. Kept as an EXPLICIT opt-in for single-process use only — passing it
    is now a deliberate choice, so the cross-instance replay (HB-1) can only
    happen if a deployer knowingly selects it."""

    def __init__(self) -> None:
        self._spent: set[str] = set()
        self._lock = threading.Lock()

    def try_spend(self, token_id: str) -> bool:
        with self._lock:
            if token_id in self._spent:
                return False
            self._spent.add(token_id)
            return True
