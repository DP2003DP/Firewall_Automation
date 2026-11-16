"""Log sources. Each yields (timestamp, message) tuples as lines arrive."""

import json
import subprocess
import time

# sshd logs as "sshd" (older) or "sshd-session" (OpenSSH 9.8+); UFW logs
# through the kernel. "+" is journalctl's OR.
JOURNAL_CMD = [
    "journalctl", "--follow", "--lines=0", "--output=json",
    "SYSLOG_IDENTIFIER=sshd", "+",
    "SYSLOG_IDENTIFIER=sshd-session", "+",
    "_TRANSPORT=kernel",
]


def follow_journal():
    """Follow the systemd journal for sshd and kernel (UFW) messages."""
    proc = subprocess.Popen(JOURNAL_CMD, stdout=subprocess.PIPE, text=True)
    try:
        for line in proc.stdout:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            message = entry.get("MESSAGE")
            if not isinstance(message, str):
                continue
            try:
                stamp = int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000
            except (KeyError, ValueError):
                stamp = time.time()
            yield stamp, message
    finally:
        proc.terminate()


def follow_file(path, from_start=False, follow=True):
    """Tail a plain log file such as /var/log/auth.log."""
    with open(path, errors="replace") as fh:
        if not from_start:
            fh.seek(0, 2)
        while True:
            line = fh.readline()
            if line:
                yield time.time(), line.rstrip("\n")
            elif follow:
                time.sleep(0.5)
            else:
                return
