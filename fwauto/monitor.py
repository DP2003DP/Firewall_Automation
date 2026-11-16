"""The monitor loop: read logs, detect, block, record."""

import queue
import threading
import time
from datetime import datetime

from . import config
from .detector import Detector
from .firewall import FirewallError


def log(text):
    print("%s  %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), text), flush=True)


class Monitor:
    def __init__(self, cfg, storage, firewall):
        self.cfg = cfg
        self.storage = storage
        self.firewall = firewall
        self.detector = Detector(cfg)

    def handle(self, message, timestamp):
        """Process one log message. Returns the action taken, if any."""
        incident = self.detector.process(message, timestamp)
        if incident is None:
            return None
        if config.is_whitelisted(self.cfg, incident.ip):
            action = "ignored (whitelisted)"
        elif self.storage.is_blocked(incident.ip):
            action = "already blocked"
        else:
            try:
                self.firewall.block(incident.ip, "fwauto " + incident.kind)
                self.storage.set_blocked(incident.ip, incident.reason, incident.timestamp)
                action = "blocked"
            except FirewallError as exc:
                action = "block failed: %s" % exc
        self.storage.add_incident(
            incident.ip, incident.kind, incident.reason,
            incident.details, action, incident.timestamp,
        )
        log("%s from %s: %s -> %s" % (incident.kind, incident.ip, incident.reason, action))
        return action

    def expire_bans(self, now=None):
        ban = float(self.cfg["ban_seconds"])
        if ban <= 0:
            return
        for row in self.storage.expired_blocks(ban, now):
            try:
                self.firewall.unblock(row["ip"])
            except FirewallError as exc:
                log("could not unblock %s: %s" % (row["ip"], exc))
                continue
            self.storage.set_unblocked(row["ip"], now)
            self.storage.add_incident(
                row["ip"], "unblock", "ban expired", "", "unblocked", now)
            log("ban expired, unblocked %s" % row["ip"])

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
            if item is not None:
                self.handle(item[1], item[0])
            now = time.time()
            if now - last_housekeeping >= 5:
                self.expire_bans(now)
                self.detector.prune(now)
                last_housekeeping = now
