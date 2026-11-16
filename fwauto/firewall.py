"""Thin wrapper around the ufw command."""

import ipaddress
import re
import shutil
import subprocess


class FirewallError(RuntimeError):
    pass


class Firewall:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run

    def _run(self, *args):
        if self.dry_run:
            return "(dry run) ufw " + " ".join(args)
        if shutil.which("ufw") is None:
            raise FirewallError("ufw is not installed")
        proc = subprocess.run(["ufw", *args], capture_output=True, text=True)
        if proc.returncode != 0:
            raise FirewallError((proc.stderr or proc.stdout).strip())
        return proc.stdout.strip()

    def block(self, ip, comment="fwauto"):
        ip = str(ipaddress.ip_address(ip))  # never hand ufw unvalidated text
        # "prepend" puts the rule above any "allow" rule (for example
        # "allow 22/tcp"), which a plain "deny" appended at the end would not beat.
        self._run("prepend", "deny", "from", ip, "to", "any", "comment", comment)
        self._drop_open_connections(ip)

    def unblock(self, ip):
        ip = str(ipaddress.ip_address(ip))
        self._run("delete", "deny", "from", ip, "to", "any")

    def _drop_open_connections(self, ip):
        """Best effort: ufw only stops new connections, so close live ones."""
        if self.dry_run or shutil.which("ss") is None:
            return
        subprocess.run(["ss", "-K", "dst", ip], capture_output=True, text=True)

    def status(self):
        return self._run("status")

    def denied_sources(self):
        """Addresses that have a "deny from <ip>" rule in ufw right now."""
        if self.dry_run:
            return None
        return parse_denied(self._run("status"))

    def is_active(self):
        return self.dry_run or self.status().startswith("Status: active")


# "Anywhere                   DENY        10.0.0.5                   # fwauto ..."
# "Anywhere (v6)              DENY        2001:db8::1"
# Only a blanket deny counts; "80/tcp DENY 10.0.0.5" still lets ssh through.
RE_DENY = re.compile(r"^Anywhere(?: \(v6\))?\s+DENY(?: IN)?\s+(\S+)\s*$")


def parse_denied(status):
    found = set()
    for line in status.splitlines():
        m = RE_DENY.match(line.split("#", 1)[0])
        if m:
            try:
                found.add(str(ipaddress.ip_address(m.group(1))))
            except ValueError:
                pass
    return found
