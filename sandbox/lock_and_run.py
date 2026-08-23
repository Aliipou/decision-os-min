"""Trusted agent entry: warm imports → lock → run untrusted agent.

Lifecycle:
  runc execve(python)
  → warm-import stdlib extension modules (needs mmap PROT_EXEC once)
  → NO_NEW_PRIVS + seccomp:
       deny execve/execveat
       deny fork/vfork/clone/clone3
       deny mmap/mprotect when PROT_EXEC (blocks later W^X + new .so)
       deny ptrace / process_vm_* / userfaultfd
  → runpy untrusted agent

New native modules after lock cannot map executable segments — intentional.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import runpy
import sys

PR_SET_NO_NEW_PRIVS = 38
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO = 0x00050000
SCMP_CMP_MASKED_EQ = 7
PROT_EXEC = 0x4

# Modules an agent/probe may need; must load before W^X lock.
_WARM_IMPORTS = (
    "json",
    "os",
    "sys",
    "socket",
    "subprocess",
    "ctypes",
    "ctypes.util",
    "mmap",
    "select",
    "errno",
    "io",
    "threading",
    "time",
    "re",
    "struct",
    "signal",
    "pathlib",
    "typing",
)


class LockdownError(RuntimeError):
    pass


class _ArgCmp(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


def warm_imports() -> None:
    for name in _WARM_IMPORTS:
        try:
            __import__(name)
        except Exception as exc:  # noqa: BLE001 — best-effort warm
            print(f"WARM_SKIP:{name}:{type(exc).__name__}", file=sys.stderr)


def _install_no_new_privs() -> None:
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise LockdownError(f"prctl(NO_NEW_PRIVS) failed errno={ctypes.get_errno()}")


def _load_libseccomp() -> ctypes.CDLL:
    libname = ctypes.util.find_library("seccomp")
    if not libname:
        for candidate in ("libseccomp.so.2", "libseccomp.so"):
            for prefix in ("/usr/lib/x86_64-linux-gnu/", "/lib/x86_64-linux-gnu/", "/usr/lib/"):
                path = prefix + candidate
                if os.path.exists(path):
                    libname = path
                    break
            if libname:
                break
    if not libname:
        raise LockdownError("libseccomp not found — agent image incomplete")
    return ctypes.CDLL(libname, use_errno=True)


def install_process_lock() -> None:
    sec = _load_libseccomp()
    sec.seccomp_init.restype = ctypes.c_void_p
    sec.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    sec.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(_ArgCmp),
    ]
    sec.seccomp_load.argtypes = [ctypes.c_void_p]
    sec.seccomp_release.argtypes = [ctypes.c_void_p]
    sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    sec.seccomp_syscall_resolve_name.restype = ctypes.c_int

    ctx = sec.seccomp_init(SCMP_ACT_ALLOW)
    if not ctx:
        raise LockdownError("seccomp_init failed")

    deny = SCMP_ACT_ERRNO | 1

    def resolve(name: bytes) -> int:
        nr = sec.seccomp_syscall_resolve_name(name)
        if nr < 0:
            raise LockdownError(f"cannot resolve syscall {name!r}")
        return int(nr)

    def deny_simple(name: bytes) -> None:
        if sec.seccomp_rule_add(ctx, deny, resolve(name), 0) != 0:
            raise LockdownError(f"seccomp_rule_add({name!r}) failed")

    def deny_prot_exec(name: bytes, prot_arg: int) -> None:
        cmp = _ArgCmp(prot_arg, SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC)
        arr = (_ArgCmp * 1)(cmp)
        if sec.seccomp_rule_add_array(ctx, deny, resolve(name), 1, arr) != 0:
            raise LockdownError(f"seccomp_rule_add_array({name!r}) failed")

    try:
        for name in (b"execve", b"execveat"):
            deny_simple(name)
        for name in (b"fork", b"vfork", b"clone"):
            deny_simple(name)
        try:
            deny_simple(b"clone3")
        except LockdownError:
            # Older kernels/libseccomp may not know clone3.
            pass
        for name in (b"mmap", b"mmap2", b"mprotect", b"pkey_mprotect"):
            try:
                deny_prot_exec(name, 2)
            except LockdownError:
                if name in (b"mmap", b"mprotect"):
                    raise
        for name in (b"ptrace", b"process_vm_writev", b"process_vm_readv", b"userfaultfd"):
            try:
                deny_simple(name)
            except LockdownError:
                if name == b"ptrace":
                    raise
        _install_no_new_privs()
        if sec.seccomp_load(ctx) != 0:
            raise LockdownError(f"seccomp_load failed errno={ctypes.get_errno()}")
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

    warm_imports()
    try:
        install_process_lock()
    except LockdownError as exc:
        print(f"LOCKDOWN_FAIL:{exc}", file=sys.stderr)
        return 3

    sys.argv = [target, *args[1:]]
    runpy.run_path(target, run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
