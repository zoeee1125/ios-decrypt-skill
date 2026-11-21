#!/usr/bin/env python3
"""Drive scp with automatic password answer over a PTY (no sshpass required).

Usage:
    python3 _scp_pty.py put <local> <remote>
    python3 _scp_pty.py get <remote> <local>

Env: MAC_HOST (192.168.68.52) MAC_USER (zoe) MAC_PASS (0000) MAC_PORT (22)
"""
import os, pty, select, sys, time

HOST = os.environ.get('MAC_HOST', '192.168.68.52')
USER = os.environ.get('MAC_USER', 'zoe')
PASS = os.environ.get('MAC_PASS', '0000')
PORT = os.environ.get('MAC_PORT', '22')
KH = os.path.join(os.path.expanduser('~'), '.ssh', 'known_hosts_dsh_scp')


def drive(argv, timeout=1800):
    os.makedirs(os.path.dirname(KH), exist_ok=True)
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    out, sent = [], False
    deadline = time.time() + timeout
    while True:
        if time.time() > deadline:
            try:
                os.kill(pid, 9)
            except OSError:
                pass
            out.append('\n[_scp_pty] TIMEOUT\n')
            break
        r, _, _ = select.select([fd], [], [], 1.0)
        if fd in r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            text = data.decode('utf-8', 'replace')
            out.append(text)
            low = text.lower()
            if not sent and ('assword' in text or 'password' in low):
                os.write(fd, (PASS + '\n').encode())
                sent = True
        else:
            wpid, _ = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                break
    try:
        _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        status = 0
    try:
        os.close(fd)
    except OSError:
        pass
    return (os.waitstatus_to_exitcode(status) if status is not None else -1), ''.join(out)


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ('put', 'get'):
        print(__doc__)
        return 2
    mode, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
    if mode == 'put':
        src, dst = a, '%s@%s:%s' % (USER, HOST, b)
    else:
        src, dst = '%s@%s:%s' % (USER, HOST, a), b
    argv = ['scp', '-q', '-r', '-P', PORT,
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'UserKnownHostsFile=' + KH,
            '-o', 'PreferredAuthentications=password',
            '-o', 'PubkeyAuthentication=no',
            '-o', 'NumberOfPasswordPrompts=1',
            src, dst]
    rc, out = drive(argv)
    print('[_scp_pty] %s %s -> %s  rc=%d' % (mode, a, b, rc))
    for line in out.strip().splitlines()[-5:]:
        print('   | ' + line)
    return 0 if rc == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
