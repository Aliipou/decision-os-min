"""TM-A ambient probes — must fail under agent-noambient-v1 + lock_and_run.

Includes process-creation and non-exec (W^X / ptrace) destructor classes.
"""

from __future__ import annotations

import ctypes
import json
import mmap
import os
import socket
import subprocess
import sys


def try_direct_effects() -> dict[str, str]:
    out: dict[str, str] = {}

    try:
        path = os.environ.get("AGENT_PROBE_PATH", "/agent_wrote.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("agent-bypass")
        out["filesystem"] = "WROTE"
    except Exception as exc:
        out["filesystem"] = f"BLOCKED:{type(exc).__name__}"

    try:
        s = socket.create_connection(("1.1.1.1", 443), timeout=0.5)
        s.close()
        out["network"] = "CONNECTED"
    except Exception as exc:
        out["network"] = f"BLOCKED:{type(exc).__name__}"

    try:
        r = subprocess.run(
            [sys.executable, "-c", "print(1)"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        out["subprocess"] = "RAN" if r.returncode == 0 else f"RC:{r.returncode}"
    except Exception as exc:
        out["subprocess"] = f"BLOCKED:{type(exc).__name__}"

    # Fork without exec: a distinct process-creation bypass class. Blocking
    # execve alone is insufficient because the child can continue Python code.
    try:
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        out["fork"] = "FORKED" if os.WIFEXITED(status) else f"STATUS:{status}"
    except Exception as exc:
        out["fork"] = f"BLOCKED:{type(exc).__name__}"

    leaked = [k for k in os.environ if k.startswith(("AWS_", "OPENAI_", "DECISION_OS_HOST_"))]
    out["credentials"] = f"LEAKED:{leaked}" if leaked else "ABSENT"

    try:
        mm = mmap.mmap(
            -1,
            4096,
            flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
            prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
        )
        mm.close()
        out["mmap_exec"] = "MAPPED"
    except Exception as exc:
        out["mmap_exec"] = f"BLOCKED:{type(exc).__name__}"

    try:
        mm = mmap.mmap(
            -1,
            4096,
            flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
            prot=mmap.PROT_READ | mmap.PROT_WRITE,
        )
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            buf_addr = ctypes.addressof(ctypes.c_char.from_buffer(mm))
            page = buf_addr - (buf_addr % 4096)
            rc = libc.mprotect(
                ctypes.c_void_p(page),
                ctypes.c_size_t(4096),
                mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
            )
            if rc != 0:
                out["mprotect_exec"] = f"BLOCKED:errno={ctypes.get_errno()}"
            else:
                out["mprotect_exec"] = "EXEC_GRANTED"
        finally:
            mm.close()
    except Exception as exc:
        out["mprotect_exec"] = f"BLOCKED:{type(exc).__name__}"

    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        rc = libc.ptrace(0, 0, None, None)  # PTRACE_TRACEME
        out["ptrace"] = "ATTACHED" if rc != -1 else f"BLOCKED:errno={ctypes.get_errno()}"
    except Exception as exc:
        out["ptrace"] = f"BLOCKED:{type(exc).__name__}"

    return out


def main() -> None:
    report = {
        "profile": "agent-noambient-v1",
        "has_deploy_ranking": "deploy_ranking" in globals(),
        "direct_effects": try_direct_effects(),
    }
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
