"""fwauto watch: a live, read-only view of attacks and blocks.

Runs its own Detector over the same log stream as the monitor, so it can
show how close each address is to a block. Blocks and incidents come from
the monitor's database. It never touches ufw.
"""

import curses
import locale
import threading
import time
from datetime import datetime

from .detector import Detector, HONEYPOT, PORT_SCAN, SSH_BRUTE_FORCE

LABELS = {SSH_BRUTE_FORCE: "ssh login failures", PORT_SCAN: "ports probed"}
BAR = 10


def ago(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "%ds" % seconds
    if seconds < 3600:
        return "%dm %02ds" % divmod(seconds, 60)
    h, rest = divmod(seconds, 3600)
    return "%dh %02dm" % (h, rest // 60)


def bar(count, limit):
    filled = min(BAR, round(BAR * count / limit))
    return "█" * filled + "·" * (BAR - filled)


def render(cfg, pending, blocks, incidents, now, live=True):
    """Return the screen as (text, style) lines. Styles: title, head, hot,
    warn, ok, dim, text."""
    stamp = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
    rules = "ssh %d/%ds · scan %s" % (
        cfg["ssh_max_failures"], cfg["ssh_window_seconds"],
        "%d/%ds" % (cfg["scan_max_ports"], cfg["scan_window_seconds"])
        if cfg["scan_detection"] else "off")
    if cfg["honeypot_ports"]:
        rules += " · honeypots " + ", ".join(map(str, cfg["honeypot_ports"]))
    lines = [("fwauto watch · %s · %s%s" % (stamp, rules, "   q quits" if live else ""),
              "title"), ("", "text")]

    lines.append(("ATTACKS IN PROGRESS", "head"))
    if not live:
        lines.append(("  (shown only while watching the live log)", "dim"))
    elif not pending:
        lines.append(("  none", "dim"))
    for ip, kind, count, limit, last in pending:
        style = "hot" if count >= limit - 1 else "warn"
        lines.append(("  %-18s %-19s %s %2d/%-2d  %s ago" % (
            ip, LABELS.get(kind, kind), bar(count, limit), count, limit, ago(now - last)),
            style))
    lines.append(("", "text"))

    lines.append(("BLOCKED NOW (%d)" % len(blocks), "head"))
    if not blocks:
        lines.append(("  none", "dim"))
    for b in blocks:
        left = ("expires in " + ago(b["expires_at"] - now)) if b["expires_at"] else "no expiry"
        lines.append(("  %-18s %-19s %s" % (b["ip"], left, b["reason"]), "ok"))
    lines.append(("", "text"))

    lines.append(("RECENT INCIDENTS", "head"))
    if not incidents:
        lines.append(("  none", "dim"))
    for r in incidents:
        style = "ok" if r["action"] == "blocked" else "dim" if r["kind"] == "unblock" else "text"
        if r["kind"] == HONEYPOT and r["action"] == "blocked":
            style = "hot"
        lines.append(("  %s  %-18s %-15s %-9s %s" % (
            datetime.fromtimestamp(r["timestamp"]).strftime("%H:%M:%S"), r["ip"],
            r["kind"], r["action"][:9], r["reason"]), style))
    return lines


class Watcher:
    def __init__(self, cfg, storage, source=None, clock=time.time):
        self.cfg = cfg
        self.storage = storage
        self.clock = clock
        self.detector = Detector(cfg)
        self.lock = threading.Lock()
        self.source = source

    def feed(self, timestamp, message):
        with self.lock:
            self.detector.process(message, timestamp)

    def _read(self):
        for stamp, message in self.source:
            self.feed(stamp, message)

    def lines(self, recent=8):
        now = self.clock()
        with self.lock:
            self.detector.prune(now)
            pending = self.detector.pending(now)
        return render(self.cfg, pending, self.storage.active_blocks(),
                      self.storage.incidents(limit=recent), now,
                      live=self.source is not None)

    def run(self, refresh=0.5):
        if self.source is not None:
            threading.Thread(target=self._read, daemon=True).start()
        locale.setlocale(locale.LC_ALL, "")
        curses.wrapper(self._loop, refresh)

    def _loop(self, screen, refresh):
        curses.curs_set(0)
        screen.timeout(int(refresh * 1000))
        styles = _styles()
        while True:
            height, width = screen.getmaxyx()
            screen.erase()
            for y, (text, style) in enumerate(self.lines(recent=max(3, height - 16))):
                if y >= height:
                    break
                try:
                    screen.addnstr(y, 0, text, width - 1, styles[style])
                except curses.error:
                    pass
            screen.refresh()
            if screen.getch() in (ord("q"), ord("Q"), 27):
                return


def _styles():
    base = {"title": curses.A_BOLD, "head": curses.A_BOLD, "hot": curses.A_BOLD,
            "warn": curses.A_NORMAL, "ok": curses.A_NORMAL, "dim": curses.A_DIM,
            "text": curses.A_NORMAL}
    if not curses.has_colors():
        return base
    curses.start_color()
    curses.use_default_colors()
    for n, color in enumerate((curses.COLOR_CYAN, curses.COLOR_RED,
                               curses.COLOR_YELLOW, curses.COLOR_GREEN), start=1):
        curses.init_pair(n, color, -1)
    base.update(head=curses.color_pair(1) | curses.A_BOLD,
                hot=curses.color_pair(2) | curses.A_BOLD,
                warn=curses.color_pair(3), ok=curses.color_pair(4))
    return base
