"""Detection logic. Pure Python with no side effects, so it is easy to test.

Feed log messages to Detector.process(); it returns an Incident whenever an
IP address crosses a threshold.
"""

import ipaddress
import re
from collections import defaultdict, deque
from dataclasses import dataclass

# The username is attacker-controlled and may contain spaces, so a client can
# log in as "x from 192.0.2.10 port 22" to plant a fake address in the line.
# The real address is always the last "from ... port ..." in the message, so
# match the username greedily and anchor the address at the end of the line.

# sshd: "Failed password for [invalid user ]bob from 10.0.0.5 port 4242 ssh2"
RE_FAILED = re.compile(
    r"Failed (?:password|keyboard-interactive/pam) for "
    r"(?P<invalid>invalid user )?(?P<user>.*) from (?P<ip>\S+) port (?P<port>\d+)"
    r"(?: ssh2)?(?: \[preauth\])?\s*$"
)
# sshd: "Invalid user admin from 10.0.0.5 port 4242"
RE_INVALID = re.compile(
    r"Invalid user (?P<user>.*) from (?P<ip>\S+) port (?P<port>\d+)"
    r"(?: \[preauth\])?\s*$"
)
# kernel: "[UFW BLOCK] IN=eth0 OUT= MAC=... SRC=10.0.0.5 DST=10.0.0.1 ... PROTO=TCP SPT=1 DPT=23 ... SYN URGP=0"
RE_UFW = re.compile(
    r"\[UFW BLOCK\].*?\bSRC=(?P<ip>\S+) DST=(?P<dst>\S+).*?"
    r"\bPROTO=(?P<proto>TCP|UDP)\b.*?\bDPT=(?P<dport>\d+)(?P<rest>.*)$"
)
RE_MAC = re.compile(r"\bMAC=(?P<mac>\S*)")
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

SSH_BRUTE_FORCE = "ssh_brute_force"
PORT_SCAN = "port_scan"


@dataclass
class Incident:
    ip: str
    kind: str
    reason: str
    details: str
    timestamp: float


def _valid_ip(text):
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _is_new_connection(proto, rest):
    """True for a packet that starts a connection.

    A scan is a run of connection attempts. Counting only those keeps any
    stray ACK/FIN/RST packets that reach the deny rule (say, from a server
    after its connection state expired) from adding up to a fake scan.
    """
    if proto != "TCP":
        return True
    flags = set(rest.split())
    return "SYN" in flags and "ACK" not in flags


def _is_broadcast(message, dst):
    addr = ipaddress.ip_address(dst)
    if addr.is_multicast or dst == "255.255.255.255":
        return True
    # The kernel logs MAC=<dst mac>:<src mac>:<type>. A subnet broadcast
    # (192.168.1.255 on a /24) goes to the broadcast MAC, whatever the netmask.
    m = RE_MAC.search(message)
    return bool(m and m["mac"].lower().startswith(BROADCAST_MAC))


def _span(seconds):
    return "%ds" % max(1, round(seconds))


class Detector:
    def __init__(self, cfg):
        self.ssh_max = int(cfg["ssh_max_failures"])
        self.ssh_window = float(cfg["ssh_window_seconds"])
        self.scan_max = int(cfg["scan_max_ports"])
        self.scan_window = float(cfg["scan_window_seconds"])
        self.scan_enabled = bool(cfg["scan_detection"])
        self._failures = defaultdict(deque)   # ip -> deque[(timestamp, user)]
        self._ports = defaultdict(dict)       # ip -> {port: last seen}
        self._invalid_seen = {}               # (ip, source port) -> timestamp

    def process(self, message, timestamp):
        """Inspect one log message. Returns an Incident or None."""
        m = RE_FAILED.search(message)
        if m:
            ip = _valid_ip(m["ip"])
            if ip is None:
                return None
            # sshd logs "Invalid user" and then "Failed password for invalid
            # user" for the same attempt. Count that attempt once.
            if m["invalid"] and (ip, m["port"]) in self._invalid_seen:
                del self._invalid_seen[(ip, m["port"])]
                return None
            return self._ssh_failure(ip, m["user"], timestamp)

        m = RE_INVALID.search(message)
        if m:
            ip = _valid_ip(m["ip"])
            if ip is None:
                return None
            self._invalid_seen[(ip, m["port"])] = timestamp
            return self._ssh_failure(ip, m["user"], timestamp)

        if self.scan_enabled:
            m = RE_UFW.search(message)
            if m:
                ip, dst = _valid_ip(m["ip"]), _valid_ip(m["dst"])
                if ip is None or dst is None:
                    return None
                if _is_broadcast(message, dst):
                    return None
                if not _is_new_connection(m["proto"], m["rest"]):
                    return None
                return self._blocked_packet(ip, int(m["dport"]), timestamp)
        return None

    def _ssh_failure(self, ip, user, now):
        events = self._failures[ip]
        events.append((now, user))
        while events and now - events[0][0] > self.ssh_window:
            events.popleft()
        if len(events) < self.ssh_max:
            return None
        users = sorted({u for _, u in events if u})
        count = len(events)
        span = now - events[0][0]
        del self._failures[ip]
        return Incident(
            ip=ip,
            kind=SSH_BRUTE_FORCE,
            reason="%d failed SSH logins in %s" % (count, _span(span)),
            details="usernames tried: " + (", ".join(users) or "(none)"),
            timestamp=now,
        )

    def _blocked_packet(self, ip, port, now):
        ports = self._ports[ip]
        ports[port] = now
        for p in [p for p, seen in ports.items() if now - seen > self.scan_window]:
            del ports[p]
        if len(ports) < self.scan_max:
            return None
        hit = sorted(ports)
        span = now - min(ports.values())
        del self._ports[ip]
        return Incident(
            ip=ip,
            kind=PORT_SCAN,
            reason="probed %d ports in %s" % (len(hit), _span(span)),
            details="ports: " + ", ".join(map(str, hit)),
            timestamp=now,
        )

    def prune(self, now):
        """Drop stale state so memory stays flat on a long-running server."""
        horizon = max(self.ssh_window, self.scan_window)
        for ip in [ip for ip, ev in self._failures.items()
                   if not ev or now - ev[-1][0] > self.ssh_window]:
            del self._failures[ip]
        for ip in [ip for ip, ports in self._ports.items()
                   if not ports or now - max(ports.values()) > self.scan_window]:
            del self._ports[ip]
        for key in [k for k, ts in self._invalid_seen.items() if now - ts > horizon]:
            del self._invalid_seen[key]
