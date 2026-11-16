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
    unblocked_at REAL
);
"""


class Storage:
    def __init__(self, path):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

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

    def set_blocked(self, ip, reason, timestamp=None):
        self.db.execute(
            "INSERT INTO blocks (ip, blocked_at, reason, active) VALUES (?, ?, ?, 1)"
            " ON CONFLICT(ip) DO UPDATE SET blocked_at = excluded.blocked_at,"
            " reason = excluded.reason, active = 1, unblocked_at = NULL",
            (ip, timestamp or time.time(), reason),
        )
        self.db.commit()

    def set_unblocked(self, ip, timestamp=None):
        self.db.execute(
            "UPDATE blocks SET active = 0, unblocked_at = ? WHERE ip = ?",
            (timestamp or time.time(), ip),
        )
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

    def expired_blocks(self, ban_seconds, now=None):
        cutoff = (now or time.time()) - ban_seconds
        return self.db.execute(
            "SELECT * FROM blocks WHERE active = 1 AND blocked_at <= ?", (cutoff,)
        ).fetchall()
