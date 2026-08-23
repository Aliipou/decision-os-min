"""Untrusted half of the real Docker/stdio governed-effect boundary test."""

from __future__ import annotations

import ctypes
import json
import mmap
import os
import socket
import subprocess
import sys
import threading


def exchange(message: str) -> dict[str, object]:
    print(message, flush=True)
    line = sys.stdin.readline()
    if not line:
        raise RuntimeError("trusted host closed the allowed IPC pipe")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise RuntimeError("trusted host returned a non-object frame")
    return value


def direct_effect_probes() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with open("/agent-bypass.txt", "w", encoding="utf-8") as handle:
            handle.write("bypass")
        out["filesystem"] = "WROTE"
    except Exception as exc:
        out["filesystem"] = f"BLOCKED:{type(exc).__name__}"

    try:
        sock = socket.create_connection(("1.1.1.1", 443), timeout=0.5)
        sock.close()
        out["network"] = "CONNECTED"
    except Exception as exc:
        out["network"] = f"BLOCKED:{type(exc).__name__}"

    try:
        subprocess.run([sys.executable, "-c", "pass"], check=True, timeout=5)
        out["exec"] = "RAN"
    except Exception as exc:
        out["exec"] = f"BLOCKED:{type(exc).__name__}"

    try:
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        os.waitpid(pid, 0)
        out["fork"] = "FORKED"
    except Exception as exc:
        out["fork"] = f"BLOCKED:{type(exc).__name__}"

    try:
        thread = threading.Thread(target=lambda: None)
        thread.start()
        thread.join(timeout=1)
        out["thread"] = "THREADED"
    except Exception as exc:
        out["thread"] = f"BLOCKED:{type(exc).__name__}"

    handles = []
    try:
        for _ in range(256):
            handles.append(open("/dev/null", "rb"))
        out["fd_limit"] = "UNLIMITED:256"
    except OSError:
        out["fd_limit"] = f"LIMITED:{len(handles)}"
    finally:
        for handle in handles:
            handle.close()

    try:
        page = mmap.mmap(
            -1,
            4096,
            flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
            prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
        )
        page.close()
        out["mmap_exec"] = "MAPPED"
    except Exception as exc:
        out["mmap_exec"] = f"BLOCKED:{type(exc).__name__}"

    try:
        page = mmap.mmap(
            -1,
            4096,
            flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
            prot=mmap.PROT_READ | mmap.PROT_WRITE,
        )
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            address = ctypes.addressof(ctypes.c_char.from_buffer(page))
            rc = libc.mprotect(
                ctypes.c_void_p(address - (address % 4096)),
                ctypes.c_size_t(4096),
                mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
            )
            out["mprotect_exec"] = (
                "EXEC_GRANTED" if rc == 0 else f"BLOCKED:errno={ctypes.get_errno()}"
            )
        finally:
            page.close()
    except Exception as exc:
        out["mprotect_exec"] = f"BLOCKED:{type(exc).__name__}"

    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        rc = libc.ptrace(0, 0, None, None)
        out["ptrace"] = "ATTACHED" if rc != -1 else f"BLOCKED:errno={ctypes.get_errno()}"
    except Exception as exc:
        out["ptrace"] = f"BLOCKED:{type(exc).__name__}"

    leaked = [key for key in os.environ if key.startswith(("AWS_", "OPENAI_", "DECISION_OS_"))]
    out["credentials"] = f"LEAKED:{leaked}" if leaked else "ABSENT"
    return out


def main() -> None:
    governed = exchange(
        json.dumps(
            {
                "v": 1,
                "type": "intent",
                "request_id": "e2e-governed",
                "agent_id": "sandbox-agent",
                "tool": "host_write_receipt",
                "payload": {"value": "governed-effect"},
                "intent": "record",
                "resource": "receipt",
            }
        )
    )
    malformed = exchange("{")
    bypass = exchange(
        json.dumps(
            {
                "v": 1,
                "type": "adapter_call",
                "tool": "host_write_receipt",
                "payload": {"value": "bypass"},
            }
        )
    )

    try:
        from decision_os_min.host import AgentHost  # type: ignore[import-not-found]  # noqa: F401

        direct_adapter = "IMPORTED"
    except Exception as exc:
        direct_adapter = f"BLOCKED:{type(exc).__name__}"

    print(
        json.dumps(
            {
                "type": "evidence",
                "governed": governed,
                "malformed": malformed,
                "bypass": bypass,
                "direct_adapter": direct_adapter,
                "direct_effects": direct_effect_probes(),
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
