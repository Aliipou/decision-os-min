"""Trusted agent entry: bootstrap Python, then lock process creation, then run agent.

Lifecycle:
  docker/runc may execve(python) once
  → this module installs seccomp deny(execve, execveat) + NO_NEW_PRIVS
  → untrusted agent code runs via runpy (no further trusted ops)

If lockdown fails, exit non-zero (do not silently run unlocked agent).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import runpy
import sys

PR_SET_NO_NEW_PRIVS = 38
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO = 0x00050000  # base; OR errno in low bits via libseccomp API


class LockdownError(RuntimeError):
    pass


def _install_no_new_privs() -> None:
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise LockdownError(f"prctl(NO_NEW_PRIVS) failed errno={err}")


def install_process_lock() -> None:
    """Deny further execve/execveat in this process (and threads)."""
    libname = ctypes.util.find_library("seccomp")
    if not libname:
        # Common on Debian slim once libseccomp2 is installed.
        for candidate in ("libseccomp.so.2", "libseccomp.so"):
            if os.path.exists(f"/usr/lib/x86_64-linux-gnu/{candidate}") or os.path.exists(
                f"/lib/x86_64-linux-gnu/{candidate}"
            ):
                libname = candidate
                break
    if not libname:
        raise LockdownError("libseccomp not found — agent image incomplete")

    sec = ctypes.CDLL(libname, use_errno=True)
    sec.seccomp_init.restype = ctypes.c_void_p
    sec.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    sec.seccomp_load.argtypes = [ctypes.c_void_p]
    sec.seccomp_release.argtypes = [ctypes.c_void_p]
    sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    sec.seccomp_syscall_resolve_name.restype = ctypes.c_int

    # Allow by default; deny process image replacement.
    ctx = sec.seccomp_init(SCMP_ACT_ALLOW)
    if not ctx:
        raise LockdownError("seccomp_init failed")

    try:
        deny = SCMP_ACT_ERRNO | 1  # EPERM
        for name in (b"execve", b"execveat"):
            nr = sec.seccomp_syscall_resolve_name(name)
            if nr < 0:
                raise LockdownError(f"cannot resolve syscall {name!r}")
            if sec.seccomp_rule_add(ctx, deny, nr, 0) != 0:
                raise LockdownError(f"seccomp_rule_add({name!r}) failed")
        _install_no_new_privs()
        if sec.seccomp_load(ctx) != 0:
            err = ctypes.get_errno()
            raise LockdownError(f"seccomp_load failed errno={err}")
    finally:
        sec.seccomp_release(ctx)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: lock_and_run.py <agent.py> [args...]", file=sys.stderr)
        return 2
    target = args[0]
    if not os.path.isfile(target):
        print(f"missing agent script: {target}", file=sys.stderr)
        return 2

    try:
        install_process_lock()
    except LockdownError as exc:
        print(f"LOCKDOWN_FAIL:{exc}", file=sys.stderr)
        return 3

    # Handoff: untrusted code. sys.argv rewritten so probe sees its own argv.
    sys.argv = [target, *args[1:]]
    runpy.run_path(target, run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
