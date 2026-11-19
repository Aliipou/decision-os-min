"""Out-of-process signer: the Ed25519 private key lives only in a child process.

The parent (which also hosts in-process evaluators) never loads the key, so
neither a stack walk nor ``gc.get_objects()`` can find it in the evaluator's
address space. The parent holds a pipe and the public key.

Residual (see docs/THREAT_MODEL.md): an in-process evaluator can still ask the
signer to sign bytes (signing oracle) and, if it runs as the same OS user, read
the PEM at ``key_path``. This closes memory extraction, not those two.
"""

from __future__ import annotations

import multiprocessing as mp
import threading
from typing import Any


def _serve(conn: Any, key_path: str) -> None:  # runs in the child
    from .kernel import load_or_create_signing_key

    key = load_or_create_signing_key(key_path)
    conn.send(key.public_key().public_bytes_raw().hex())
    while True:
        try:
            msg = conn.recv_bytes()
        except (EOFError, OSError):
            return
        conn.send_bytes(key.sign(msg))


class SignerProcess:
    def __init__(self, key_path: str) -> None:
        ctx = mp.get_context("spawn")
        self._conn, child = ctx.Pipe()
        self._lock = threading.Lock()
        self._proc = ctx.Process(target=_serve, args=(child, key_path), daemon=True)
        self._proc.start()
        child.close()
        if not self._conn.poll(30):
            self._proc.terminate()
            raise RuntimeError("signer process failed to start")
        self.public_key_hex: str = self._conn.recv()

    def sign(self, data: bytes) -> bytes:
        with self._lock:
            self._conn.send_bytes(data)
            return self._conn.recv_bytes()

    def close(self) -> None:
        try:
            self._conn.close()
        finally:
            self._proc.join(2)
            if self._proc.is_alive():
                self._proc.terminate()
