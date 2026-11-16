"""The monitor loop: read logs, detect, block, record."""

import queue
import threading
import time
from datetime import datetime

from . import config
from .detector import Detector
from .firewall import FirewallError


def duration(seconds):
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size and seconds % size == 0:
            return "%d%s" % (seconds // size, unit)
    return "%ds" % seconds


def log(text):
    print("%s  %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), text), flush=True)


class Monitor:
    def __init__(self, cfg, storage, firewall, clock=time.time):
        self.clock = clock
        self.cfg = cfg
        self.storage = storage
        self.firewall = firewall
        self.detector = Detector(cfg)

    def handle(self, message, timestamp):
        """Process one log message. Returns the action taken, if any."""
        incident = self.detector.process(message, timestamp)
        if incident is None:
            return None
        action, note = self._respond(incident)
        self.storage.add_incident(
            incident.ip, incident.kind, incident.reason,
            incident.details, action, incident.timestamp,
        )
        log("%s from %s: %s -> %s" % (
            incident.kind, incident.ip, incident.reason, action + note))
        return action

    def _respond(self, incident):
        if config.is_whitelisted(self.cfg, incident.ip):
            return "ignored (whitelisted)", ""
        if self.storage.is_blocked(incident.ip):
            return "already blocked", ""
        offences = self.storage.offences(incident.ip)
        length = config.ban_length(self.cfg, offences)
        expires = incident.timestamp + length if length else None
        if expires is not None and expires <= self.clock():
            # replaying an old log: this ban would already be over
            return "not blocked (ban would have expired)", ""
        try:
            self.firewall.block(incident.ip, "fwauto " + incident.kind)
        except FirewallError as exc:
            return "block failed: %s" % exc, ""
        self.storage.set_blocked(incident.ip, incident.reason, incident.timestamp, expires)
        note = " for " + duration(length) if length else " until unblocked"
        if offences:
            note += ", repeat offence %d" % (offences + 1)
        return "blocked", note

    def expire_bans(self, now=None):
        for row in self.storage.expired_blocks(now):
            self.release(row["ip"], "ban expired", now)

    def release(self, ip, why, now=None):
        try:
            self.firewall.unblock(ip)
        except FirewallError as exc:
            log("could not unblock %s: %s" % (ip, exc))
            return
        self.storage.set_unblocked(ip, now)
        self.storage.add_incident(ip, "unblock", why, "", "unblocked", now)
        log("%s, unblocked %s" % (why, ip))

    def reconcile(self):
        """Put back blocks that the database has but ufw lost (ufw reset,
        a rule deleted by hand). Returns the addresses re-blocked."""
        self.expire_bans(self.clock())
        for row in self.storage.active_blocks():
            if config.is_whitelisted(self.cfg, row["ip"]):
                self.release(row["ip"], "whitelisted")
        rules = self.firewall.denied_sources()
        if rules is None:
            return []
        restored = []
        for row in self.storage.active_blocks():
            if row["ip"] in rules:
                continue
            try:
                self.firewall.block(row["ip"], "fwauto restored")
            except FirewallError as exc:
                log("could not restore block on %s: %s" % (row["ip"], exc))
                continue
            restored.append(row["ip"])
            log("restored missing ufw rule for %s" % row["ip"])
        return restored

    def run(self, source):
        """Consume a log source until it ends or the user presses Ctrl+C."""
        lines = queue.Queue()
        done = object()

        def reader():
            try:
                for item in source:
                    lines.put(item)
            finally:
                lines.put(done)

        threading.Thread(target=reader, daemon=True).start()
        last_housekeeping = 0.0
        while True:
            try:
                item = lines.get(timeout=5)
            except queue.Empty:
                item = None
            if item is done:
                return
            now = self.clock()
            if item is not None:
                self.handle(item[1], item[0])
            if now - last_housekeeping >= 5:
                self.expire_bans(now)
                # prune by log time: when replaying an old file, wall-clock
                # time would wipe every window before it fills
                self.detector.prune(item[0] if item is not None else now)
                last_housekeeping = now
