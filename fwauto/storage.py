"""SQLite record of incidents and blocks."""

import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    ip        TEXT NOT NULL,
    kind      TEXT NOT NULL,
    reason    TEXT NOT NULL,
    details   TEXT NOT NULL DEFAULT '',
    action    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blocks (
    ip           TEXT PRIMARY KEY,
    blocked_at   REAL NOT NULL,
    reason       TEXT NOT NULL,
    active       INTEGER NOT NULL DEFAULT 1,
    unblocked_at REAL,
    expires_at   REAL
);
CREATE INDEX IF NOT EXISTS incidents_ip ON incidents (ip);
"""

AUTO_KINDS = ("ssh_brute_force", "port_scan", "honeypot")
_AUTO_SQL = "(%s)" % ", ".join("'%s'" % k for k in AUTO_KINDS)


class Storage:
    def __init__(self, path):
        directory = os.path.dirname(path) if path != ":memory:" else ""
        if directory:
            os.makedirs(directory, exist_ok=True)
        # the monitor and the CLI write to the same file
        self.db = sqlite3.connect(path, timeout=15)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self._migrate()

    def _migrate(self):
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(blocks)")}
        if "expires_at" not in cols:
            # blocks from 1.0 had no expiry stored; they stay until unblocked
            self.db.execute("ALTER TABLE blocks ADD COLUMN expires_at REAL")
            self.db.commit()

    def add_incident(self, ip, kind, reason, details, action, timestamp=None):
        self.db.execute(
            "INSERT INTO incidents (timestamp, ip, kind, reason, details, action)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp or time.time(), ip, kind, reason, details, action),
        )
        self.db.commit()

    def incidents(self, ip=None, limit=50):
        sql, args = "SELECT * FROM incidents", []
        if ip:
            sql += " WHERE ip = ?"
            args.append(ip)
        sql += " ORDER BY timestamp DESC, id DESC LIMIT ?"
        args.append(limit)
        return self.db.execute(sql, args).fetchall()

    def set_blocked(self, ip, reason, timestamp=None, expires_at=None):
        self.db.execute(
            "INSERT INTO blocks (ip, blocked_at, reason, active, expires_at)"
            " VALUES (?, ?, ?, 1, ?)"
            " ON CONFLICT(ip) DO UPDATE SET blocked_at = excluded.blocked_at,"
            " reason = excluded.reason, active = 1, unblocked_at = NULL,"
            " expires_at = excluded.expires_at",
            (ip, timestamp or time.time(), reason, expires_at),
        )
        self.db.commit()

    def set_unblocked(self, ip, timestamp=None):
        self.db.execute(
            "UPDATE blocks SET active = 0, unblocked_at = ? WHERE ip = ?",
            (timestamp or time.time(), ip),
        )
        self.db.commit()

    def forget(self, ip):
        """Drop an address's history, so its next ban starts from the first."""
        self.db.execute("DELETE FROM incidents WHERE ip = ?", (ip,))
        self.db.execute("DELETE FROM blocks WHERE ip = ? AND active = 0", (ip,))
        self.db.commit()

    def is_blocked(self, ip):
        row = self.db.execute(
            "SELECT 1 FROM blocks WHERE ip = ? AND active = 1", (ip,)
        ).fetchone()
        return row is not None

    def active_blocks(self):
        return self.db.execute(
            "SELECT * FROM blocks WHERE active = 1 ORDER BY blocked_at DESC"
        ).fetchall()

    def expired_blocks(self, now=None):
        return self.db.execute(
            "SELECT * FROM blocks WHERE active = 1 AND expires_at IS NOT NULL"
            " AND expires_at <= ?", (now or time.time(),)
        ).fetchall()

    def offences(self, ip):
        """How many times this address was blocked automatically before."""
        marks = ",".join("?" * len(AUTO_KINDS))
        return self.db.execute(
            "SELECT COUNT(*) FROM incidents WHERE ip = ? AND action = 'blocked'"
            " AND kind IN (%s)" % marks, (ip, *AUTO_KINDS)
        ).fetchone()[0]

    def stats(self, since=0.0, top=5):
        q = self.db.execute
        by_kind = q(
            "SELECT kind, COUNT(*) AS n FROM incidents WHERE timestamp >= ?"
            " AND kind != 'unblock' GROUP BY kind ORDER BY n DESC", (since,)).fetchall()
        attackers = q(
            "SELECT ip, COUNT(*) AS n, MAX(timestamp) AS last,"
            " GROUP_CONCAT(DISTINCT kind) AS kinds FROM incidents"
            " WHERE timestamp >= ? AND kind IN " + _AUTO_SQL +
            " GROUP BY ip ORDER BY n DESC, last DESC LIMIT ?", (since, top)).fetchall()
        details = [r["details"] for r in q(
            "SELECT details FROM incidents WHERE timestamp >= ?"
            " AND kind IN " + _AUTO_SQL, (since,))]
        return {
            "by_kind": by_kind,
            "attackers": attackers,
            "usernames": _tally(details, "usernames tried: ", top),
            "ports": _tally(details, "ports: ", top),
            "active_blocks": len(self.active_blocks()),
        }


def _tally(details, prefix, top):
    counts = {}
    for d in details:
        if d.startswith(prefix):
            for item in d[len(prefix):].split(", "):
                if item and item != "(none)":
                    counts[item] = counts.get(item, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
