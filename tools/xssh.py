#!/usr/bin/env python3
"""Run a shell script on the Mac (192.168.68.52, zoe/0000) over ssh with a pty.

Usage:
    python3 xssh.py script.sh [timeout_s]     # run local script file remotely
    python3 xssh.py - [timeout_s] < script.sh # run stdin remotely
"""
import base64
import os
import pty
import select
import sys
import time

HOST = "192.168.68.52"
USER = "zoe"
PASS = "0000"


def run_remote(command: str, timeout: float = 180.0) -> int:
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("ssh", [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            f"{USER}@{HOST}", command,
        ])
        os._exit(127)

    buf = ""
    tried = False
    deadline = time.time() + timeout
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 1.0)
        if fd in r:
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            text = data.decode(errors="replace")
            buf += text
            sys.stdout.write(text)
            sys.stdout.flush()
            if "password:" in buf.lower() and not tried:
                os.write(fd, (PASS + "\n").encode())
                tried = True
    try:
        _, status = os.waitpid(pid, 0)
        rc = os.waitstatus_to_exitcode(status)
    except ChildProcessError:
        rc = -1
    return rc


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    src = sys.argv[1]
    if src == "-":
        script = sys.stdin.read()
    else:
        with open(src, "r", encoding="utf-8") as f:
            script = f.read()
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 180.0
    b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
    cmd = f"echo {b64} | base64 -d | bash"
    return run_remote(cmd, timeout)


if __name__ == "__main__":
    sys.exit(main())
