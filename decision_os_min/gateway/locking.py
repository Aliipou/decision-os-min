"""A tiny cross-process exclusive file lock (POSIX flock / Windows msvcrt).

Many gateway processes run at once (one MCP proxy per wrapped server, plus the
LLM gateway and the dashboard). They share one audit chain and one learned-rules
file, so writes to those must be serialized across processes.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

if os.name == "nt":  # pragma: no cover - exercised on Windows only
    import msvcrt

    def _lock(fd: int) -> None:
        while True:
            try:
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
                return
            except OSError:
                time.sleep(0.01)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]

else:
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == "nt":  # msvcrt needs at least one byte to lock
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
        _lock(fd)
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)
