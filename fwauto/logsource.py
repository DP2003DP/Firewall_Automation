"""Log sources. Each yields (timestamp, message) tuples as lines arrive."""

import json
import os
import re
import subprocess
import time
from datetime import datetime

# Filter on fields journald sets itself: any user can fake SYSLOG_IDENTIFIER
# with "logger -t sshd". sshd-session and sshd-auth are OpenSSH 9.8+ and 10+.
SSH_PROGRAMS = ("sshd", "sshd-session", "sshd-auth")
JOURNAL_CMD = [
    "journalctl", "--follow", "--lines=0", "--output=json",
    "_UID=0", *["_COMM=" + p for p in SSH_PROGRAMS], "+",
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


# rsyslog on current Ubuntu: "2026-11-16T14:03:22.123456-05:00 host sshd[1]: ..."
RE_ISO = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s")
# classic syslog: "Nov 16 14:03:22 host sshd[1]: ..."
RE_BSD = re.compile(r"^([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d)\s")


def line_time(line, now=None):
    """Timestamp at the start of a syslog line, or None if there isn't one."""
    m = RE_ISO.match(line)
    if m:
        text = m.group(1).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text).timestamp()
        except ValueError:
            return None
    m = RE_BSD.match(line)
    if m:
        now = time.time() if now is None else now
        year = datetime.fromtimestamp(now).year
        try:
            stamp = datetime.strptime("%d %s" % (year, m.group(1)),
                                      "%Y %b %d %H:%M:%S").timestamp()
        except ValueError:
            return None
        # no year in the line: a December entry read in January is last year's
        if stamp > now + 86400:
            stamp = datetime.strptime("%d %s" % (year - 1, m.group(1)),
                                      "%Y %b %d %H:%M:%S").timestamp()
        return stamp
    return None


def follow_file(path, from_start=False, follow=True):
    """Tail a plain log file such as /var/log/auth.log, across logrotate.

    Lines carry their own timestamps, so replaying an old file keeps its pace.
    """
    fh = open(path, errors="replace")
    try:
        if not from_start:
            fh.seek(0, 2)
        while True:
            line = fh.readline()
            if line:
                line = line.rstrip("\n")
                stamp = line_time(line)
                yield (time.time() if stamp is None else stamp), line
                continue
            if not follow:
                return
            if _rotated(fh, path):
                fh.close()
                fh = open(path, errors="replace")
                continue
            time.sleep(0.5)
    finally:
        fh.close()


def _rotated(fh, path):
    try:
        st = os.stat(path)
    except OSError:
        return False  # mid-rotation; the new file isn't there yet
    return st.st_ino != os.fstat(fh.fileno()).st_ino or st.st_size < fh.tell()
