#!/usr/bin/env python3
"""SSH helper with password auto-answer over a PTY (no sshpass needed).

Usage:
    python3 _ssh_pty.py "remote command"                  # run command, stream output
    python3 _ssh_pty.py --put LOCAL REMOTE                # upload file/dir
    python3 _ssh_pty.py --get REMOTE LOCAL                # download file/dir

Environment overrides: MAC_HOST (default 192.168.68.52), MAC_USER (zoe), MAC_PASS (0000)
"""
import os, pty, select, sys, time

HOST = os.getenv("MAC_HOST", "192.168.68.52")
USER = os.getenv("MAC_USER", "zoe")
PASS = os.getenv("MAC_PASS", "0000")
REMOTE_PATH = f'export PATH="$HOME/.local/bin:$PATH"; '


def run(args, timeout=1800.0):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("ssh", ["ssh", "-o", "StrictHostKeyChecking=no",
                          "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
                          f"{USER}@{HOST}", *args])
        os._exit(127)
    buf, tried, sent = "", False, False
    deadline = time.time() + timeout
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 1.0)
        if fd not in r:
            continue
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        text = data.decode(errors="replace")
        buf += text
        if "assword:" in buf and not tried:
            os.write(fd, (PASS + "\n").encode())
            tried = True
            buf = ""
            continue
        low = text.lower()
        if not sent and ("are you sure you want to continue connecting" in low or "authenticity of host" in low):
            os.write(fd, b"yes\n")
            sent = True
            continue
        sys.stdout.write(text)
        sys.stdout.flush()
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def main():
    argv = sys.argv[1:]
    if not argv:
        run([REMOTE_PATH + "echo REMOTE_OK; id -un; uname -m; sw_vers -productVersion"])
        return
    if argv[0] == "--put":
        # scp -r over ssh is not available without sshpass; use tar over ssh stream
        local, remote = argv[1], argv[2]
        os.system(f'tar cf - -C "$(dirname "{local}")" "$(basename "{local}")" | '
                  f'ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR '
                  f'-o PreferredAuthentications=password -o PubkeyAuthentication=no '
                  f'{USER}@{HOST} "mkdir -p \\"$(dirname {remote})\\" && tar xf - -C \\"$(dirname {remote})\\""')
        return
    if argv[0] == "--get":
        remote, local = argv[1], argv[2]
        os.system(f'ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR '
                  f'-o PreferredAuthentications=password -o PubkeyAuthentication=no '
                  f'{USER}@{HOST} "tar cf - -C \\"$(dirname {remote})\\" \\"$(basename {remote})\\"" | '
                  f'tar xf - -C "{local}"')
        return
    run([REMOTE_PATH + argv[0]])


if __name__ == "__main__":
    main()
