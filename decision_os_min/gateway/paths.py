"""Where the gateway keeps its state.

Everything lives under one directory (default ``~/.decision-os``, override with
``DECISION_OS_HOME``). The guardrails treat this directory as protected: no
governed tool call may read or write inside it, so an agent cannot approve its
own request, edit the policy or delete the audit log through a tool.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


def default_home() -> Path:
    env = os.environ.get("DECISION_OS_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".decision-os"


@dataclass(frozen=True)
class Home:
    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root).expanduser())

    @classmethod
    def resolve(cls, root: str | Path | None = None) -> Home:
        return cls(Path(root).expanduser() if root else default_home())

    @property
    def policy(self) -> Path:
        return self.root / "policy.toml"

    @property
    def learned(self) -> Path:
        return self.root / "learned.json"

    @property
    def audit(self) -> Path:
        return self.root / "audit.jsonl"

    @property
    def key(self) -> Path:
        return self.root / "kernel.pem"

    @property
    def spent(self) -> Path:
        return self.root / "spent.sqlite"

    @property
    def approvals(self) -> Path:
        return self.root / "approvals"

    @property
    def backups(self) -> Path:
        return self.root / "backups"

    @property
    def state(self) -> Path:
        return self.root / "state.json"

    @property
    def ui(self) -> Path:
        return self.root / "ui.json"

    @property
    def locks(self) -> Path:
        return self.root / "locks"

    @property
    def sessions(self) -> Path:
        return self.root / "sessions"

    def ensure(self) -> Home:
        """Create the directory tree with owner-only permissions."""
        for d in (self.root, self.approvals, self.backups, self.locks, self.sessions):
            d.mkdir(parents=True, exist_ok=True)
            _owner_only(d, directory=True)
        return self


def _owner_only(path: Path, *, directory: bool) -> None:
    if os.name != "posix":
        return
    mode = stat.S_IRWXU if directory else (stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def write_private(path: Path, data: str) -> None:
    """Atomically write ``data`` to ``path`` with mode 0600 (where supported)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    try:
        os.write(fd, data.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
