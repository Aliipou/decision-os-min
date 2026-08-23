"""Bounded/contained resource-exhaustion destructor probes."""

from __future__ import annotations

import json
import os
import sys
import threading


def fork_loop() -> str:
    children: list[int] = []
    try:
        for _ in range(256):
            pid = os.fork()
            if pid == 0:
                os._exit(0)
            children.append(pid)
        return "UNBOUNDED"
    except OSError as exc:
        return f"BLOCKED:{exc.errno}" if not children else f"LIMITED:{len(children)}"
    finally:
        for pid in children:
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass


def thread_loop() -> str:
    stop = threading.Event()
    threads: list[threading.Thread] = []
    try:
        for _ in range(256):
            thread = threading.Thread(target=stop.wait, daemon=True)
            thread.start()
            threads.append(thread)
        return "UNBOUNDED"
    except RuntimeError:
        return "BLOCKED:clone" if not threads else f"LIMITED:{len(threads)}"
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=0.1)


def fd_loop() -> str:
    fds: list[int] = []
    try:
        for _ in range(256):
            fds.append(os.open("/dev/null", os.O_RDONLY))
        return "UNBOUNDED"
    except OSError as exc:
        return f"LIMITED:{len(fds)}:errno={exc.errno}"
    finally:
        for fd in fds:
            os.close(fd)


def memory_pressure() -> None:
    chunks: list[bytearray] = []
    while True:
        chunks.append(bytearray(8 * 1024 * 1024))


def cpu_loop() -> None:
    while True:
        pass


def main() -> None:
    mode = sys.argv[1]
    if mode == "fork":
        result = fork_loop()
    elif mode == "thread":
        result = thread_loop()
    elif mode == "fd":
        result = fd_loop()
    elif mode == "memory":
        memory_pressure()
        return
    elif mode == "cpu":
        cpu_loop()
        return
    else:
        raise SystemExit(f"unknown mode: {mode}")
    print(json.dumps({"attack": mode, "outcome": result}), flush=True)


if __name__ == "__main__":
    main()
