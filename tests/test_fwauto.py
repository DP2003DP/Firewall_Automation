import io
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from unittest import mock

from fwauto import cli, config, logsource
from fwauto.detector import Detector, PORT_SCAN, SSH_BRUTE_FORCE
from fwauto.firewall import Firewall, parse_denied
from fwauto.monitor import Monitor
from fwauto.storage import Storage


def make_cfg(**overrides):
    return config.from_dict(**overrides)


def failed(ip, user="root", port=4000):
    return "Failed password for %s from %s port %d ssh2" % (user, ip, port)


def ufw(ip, dport, flags="SYN", proto="TCP", dst="10.0.2.15",
        mac="08:00:27:aa:bb:cc:52:54:00:12:35:02:08:00"):
    return ("[UFW BLOCK] IN=enp0s3 OUT= MAC=%s SRC=%s DST=%s LEN=60 "
            "TOS=0x00 TTL=64 ID=1 DF PROTO=%s SPT=5555 DPT=%d WINDOW=1 RES=0x00 %s URGP=0"
            % (mac, ip, dst, proto, dport, flags))


class DetectorTests(unittest.TestCase):
    def test_triggers_on_fifth_failure(self):
        d = Detector(make_cfg())
        for i in range(4):
            self.assertIsNone(d.process(failed("10.0.0.5"), 100 + i))
        inc = d.process(failed("10.0.0.5"), 104)
        self.assertEqual((inc.ip, inc.kind), ("10.0.0.5", SSH_BRUTE_FORCE))
        self.assertEqual(inc.reason, "5 failed SSH logins in 4s")

    def test_slow_failures_do_not_trigger(self):
        d = Detector(make_cfg())
        for i in range(20):
            self.assertIsNone(d.process(failed("10.0.0.5"), i * 30))

    def test_ips_are_counted_separately(self):
        d = Detector(make_cfg())
        for i in range(4):
            self.assertIsNone(d.process(failed("10.0.0.5"), i))
            self.assertIsNone(d.process(failed("10.0.0.6"), i))

    def test_successful_login_is_ignored(self):
        d = Detector(make_cfg())
        for i in range(10):
            self.assertIsNone(d.process(
                "Accepted password for divyam from 10.0.0.5 port 1 ssh2", i))

    def test_invalid_user_attempt_counted_once(self):
        d = Detector(make_cfg(ssh_max_failures=3))
        seq = []
        for i in range(2):
            seq.append("Invalid user admin from 10.0.0.9 port %d" % (5000 + i))
            seq.append("Failed password for invalid user admin from 10.0.0.9 port %d ssh2"
                       % (5000 + i))
        results = [d.process(m, 10) for m in seq]
        self.assertEqual(results, [None] * 4)  # 2 attempts, not 4
        self.assertIsNotNone(d.process("Invalid user x from 10.0.0.9 port 5002", 11))

    def test_more_password_tries_on_one_connection_all_count(self):
        d = Detector(make_cfg(ssh_max_failures=3))
        d.process("Invalid user admin from 10.0.0.9 port 5000", 1)
        msg = "Failed password for invalid user admin from 10.0.0.9 port 5000 ssh2"
        self.assertIsNone(d.process(msg, 1))
        self.assertIsNone(d.process(msg, 2))
        self.assertIsNotNone(d.process(msg, 3))

    def test_preauth_suffix(self):
        d = Detector(make_cfg(ssh_max_failures=1))
        inc = d.process("Invalid user bob from 10.0.0.9 port 22 [preauth]", 1)
        self.assertEqual(inc.ip, "10.0.0.9")

    def test_ipv6_and_garbage_addresses(self):
        d = Detector(make_cfg(ssh_max_failures=1))
        self.assertEqual(d.process(failed("2001:db8::1"), 1).ip, "2001:db8::1")
        self.assertIsNone(d.process(failed("1.2.3.4;reboot"), 1))

    def test_port_scan(self):
        d = Detector(make_cfg())
        for port in range(20, 25):
            self.assertIsNone(d.process(ufw("10.0.0.7", port), 50))
        inc = d.process(ufw("10.0.0.7", 25), 51)
        self.assertEqual((inc.ip, inc.kind), ("10.0.0.7", PORT_SCAN))
        self.assertEqual(inc.details, "ports: 20, 21, 22, 23, 24, 25")

    def test_repeated_hits_on_one_port_are_not_a_scan(self):
        d = Detector(make_cfg())
        for i in range(50):
            self.assertIsNone(d.process(ufw("10.0.0.7", 23), i))

    def test_multicast_noise_ignored(self):
        d = Detector(make_cfg(scan_max_ports=1))
        self.assertIsNone(d.process(ufw("10.0.2.2", 5353, proto="UDP", dst="224.0.0.251"), 1))

    def test_subnet_broadcast_ignored_by_mac(self):
        d = Detector(make_cfg(scan_max_ports=1))
        msg = ufw("192.168.1.7", 137, proto="UDP", dst="192.168.1.127",
                  mac="ff:ff:ff:ff:ff:ff:52:54:00:12:35:02:08:00")
        self.assertIsNone(d.process(msg, 1))

    def test_dot_255_host_is_not_assumed_broadcast(self):
        # 10.0.1.255 is an ordinary host on a /23
        d = Detector(make_cfg(scan_max_ports=1))
        self.assertIsNotNone(d.process(ufw("10.0.0.7", 23, dst="10.0.1.255"), 1))

    def test_stray_tcp_packets_are_not_a_scan(self):
        d = Detector(make_cfg(scan_max_ports=2))
        for i, flags in enumerate(["ACK", "ACK FIN", "ACK RST", "RST", "ACK SYN",
                                   "ACK PSH"]):
            self.assertIsNone(d.process(ufw("151.101.1.1", 40000 + i, flags), 1))

    def test_udp_probes_count(self):
        d = Detector(make_cfg(scan_max_ports=2))
        self.assertIsNone(d.process(ufw("10.0.0.7", 53, "", proto="UDP"), 1))
        self.assertIsNotNone(d.process(ufw("10.0.0.7", 161, "", proto="UDP"), 1))

    def test_scan_detection_can_be_disabled(self):
        d = Detector(make_cfg(scan_detection=False, scan_max_ports=1))
        self.assertIsNone(d.process(ufw("10.0.0.7", 23), 1))


class InjectionTests(unittest.TestCase):
    """The username is chosen by the attacker and sshd logs it as given."""

    FAKE = "x from 192.0.2.10 port 22"

    def test_invalid_user_line_blames_real_address(self):
        d = Detector(make_cfg(ssh_max_failures=1))
        inc = d.process("Invalid user %s from 203.0.113.5 port 51234" % self.FAKE, 1)
        self.assertEqual(inc.ip, "203.0.113.5")
        self.assertIn(self.FAKE, inc.details)

    def test_failed_password_line_blames_real_address(self):
        d = Detector(make_cfg(ssh_max_failures=1))
        inc = d.process(failed("203.0.113.5", "invalid user " + self.FAKE, 51234), 1)
        self.assertEqual(inc.ip, "203.0.113.5")

    def test_attack_never_counts_against_the_planted_address(self):
        d = Detector(make_cfg())
        incs = []
        for i in range(10):
            port = 51000 + i
            incs.append(d.process(
                "Invalid user %s from 203.0.113.5 port %d" % (self.FAKE, port), i))
            incs.append(d.process(failed("203.0.113.5", "invalid user " + self.FAKE,
                                         port), i))
        ips = {inc.ip for inc in incs if inc}
        self.assertEqual(ips, {"203.0.113.5"})

    def test_syslog_prefix_in_file_mode(self):
        d = Detector(make_cfg(ssh_max_failures=1))
        line = ("2026-11-16T10:00:00.000000-05:00 srv sshd-session[811]: "
                "Invalid user %s from 203.0.113.5 port 4444" % self.FAKE)
        self.assertEqual(d.process(line, 1).ip, "203.0.113.5")


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.storage = Storage(os.path.join(self.dir.name, "t.db"))
        quiet = mock.patch("fwauto.monitor.log")
        quiet.start()
        self.addCleanup(quiet.stop)

    def tearDown(self):
        self.storage.db.close()
        self.dir.cleanup()

    def monitor(self, firewall=None, **overrides):
        return Monitor(make_cfg(**overrides), self.storage,
                       firewall or Firewall(dry_run=True), clock=lambda: 0)

    def attack(self, m, ip="10.0.0.5", start=0):
        return [m.handle(failed(ip), start + i) for i in range(5)][-1]

    def test_blocks_and_records(self):
        m = self.monitor()
        actions = [m.handle(failed("10.0.0.5", "root"), 100 + i) for i in range(5)]
        self.assertEqual(actions, [None] * 4 + ["blocked"])
        self.assertTrue(self.storage.is_blocked("10.0.0.5"))
        row = self.storage.incidents()[0]
        self.assertEqual((row["ip"], row["kind"], row["action"]),
                         ("10.0.0.5", SSH_BRUTE_FORCE, "blocked"))

    def test_whitelisted_ip_is_never_blocked(self):
        m = self.monitor(whitelist=["127.0.0.0/8", "192.168.1.0/24"])
        actions = [m.handle(failed("192.168.1.20"), i) for i in range(5)]
        self.assertEqual(actions[-1], "ignored (whitelisted)")
        self.assertFalse(self.storage.is_blocked("192.168.1.20"))

    def test_ban_expiry(self):
        m = self.monitor(ban_seconds=600)
        self.attack(m, start=1000)
        m.expire_bans(now=1300)
        self.assertTrue(self.storage.is_blocked("10.0.0.5"))
        m.expire_bans(now=1700)
        self.assertFalse(self.storage.is_blocked("10.0.0.5"))

    def test_repeat_offenders_get_longer_bans(self):
        m = self.monitor(ban_seconds=600, ban_max_seconds=1800)
        expected = [600, 1200, 1800, 1800]
        t = 0
        for length in expected:
            self.assertEqual(self.attack(m, start=t), "blocked")
            row = self.storage.active_blocks()[0]
            self.assertEqual(row["expires_at"] - row["blocked_at"], length)
            t = row["expires_at"] + 1
            m.expire_bans(now=t)
            self.assertFalse(self.storage.is_blocked("10.0.0.5"))
            t += 100

    def test_zero_ban_seconds_means_permanent(self):
        m = self.monitor(ban_seconds=0)
        self.attack(m)
        self.assertIsNone(self.storage.active_blocks()[0]["expires_at"])
        m.expire_bans(now=10 ** 10)
        self.assertTrue(self.storage.is_blocked("10.0.0.5"))

    def test_unblock_then_reoffend(self):
        m = self.monitor()
        self.attack(m)
        self.storage.set_unblocked("10.0.0.5")
        self.assertEqual(self.attack(m, start=100), "blocked")
        self.assertEqual(len(self.storage.active_blocks()), 1)

    def test_replayed_attack_whose_ban_is_over_is_not_blocked(self):
        m = Monitor(make_cfg(ban_seconds=600), self.storage, Firewall(dry_run=True),
                    clock=lambda: 10_000)
        self.assertEqual(self.attack(m), "not blocked (ban would have expired)")
        self.assertFalse(self.storage.is_blocked("10.0.0.5"))

    def test_reconcile_restores_lost_rules(self):
        fw = mock.Mock()
        fw.denied_sources.return_value = {"10.0.0.6"}
        m = self.monitor(firewall=fw)
        self.storage.set_blocked("10.0.0.5", "x")
        self.storage.set_blocked("10.0.0.6", "x")
        self.assertEqual(m.reconcile(), ["10.0.0.5"])
        fw.block.assert_called_once_with("10.0.0.5", "fwauto restored")

    def test_reconcile_expires_before_restoring(self):
        fw = mock.Mock()
        fw.denied_sources.return_value = set()
        m = Monitor(make_cfg(), self.storage, fw, clock=lambda: 5000)
        self.storage.set_blocked("10.0.0.5", "x", 0, expires_at=3600)
        self.assertEqual(m.reconcile(), [])
        fw.block.assert_not_called()
        self.assertFalse(self.storage.is_blocked("10.0.0.5"))

    def test_reconcile_releases_newly_whitelisted(self):
        fw = mock.Mock()
        fw.denied_sources.return_value = {"192.168.1.20"}
        m = self.monitor(firewall=fw, whitelist=["192.168.1.0/24"])
        self.storage.set_blocked("192.168.1.20", "x")
        m.reconcile()
        fw.unblock.assert_called_once_with("192.168.1.20")
        self.assertFalse(self.storage.is_blocked("192.168.1.20"))

    def test_stats(self):
        m = self.monitor()
        self.attack(m, "10.0.0.5")
        for port in range(20, 26):
            m.handle(ufw("10.0.0.7", port), 50)
        st = self.storage.stats()
        self.assertEqual(st["active_blocks"], 2)
        self.assertEqual({r["kind"]: r["n"] for r in st["by_kind"]},
                         {SSH_BRUTE_FORCE: 1, PORT_SCAN: 1})
        self.assertEqual(st["usernames"], [("root", 1)])
        self.assertEqual(len(st["ports"]), 5)


class StorageTests(unittest.TestCase):
    def test_upgrades_old_database(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "old.db")
            db = sqlite3.connect(path)
            db.executescript("""
                CREATE TABLE blocks (ip TEXT PRIMARY KEY, blocked_at REAL NOT NULL,
                    reason TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
                    unblocked_at REAL);
                INSERT INTO blocks (ip, blocked_at, reason) VALUES ('10.0.0.5', 1, 'old');
            """)
            db.commit()
            db.close()
            s = Storage(path)
            row = s.active_blocks()[0]
            self.assertIsNone(row["expires_at"])
            self.assertEqual(s.expired_blocks(now=10 ** 10), [])
            s.db.close()


class ConfigTests(unittest.TestCase):
    def test_rejects_bad_values(self):
        for bad in [{"ssh_max_failures": "5"}, {"ssh_max_failures": 0},
                    {"ban_seconds": -1}, {"scan_detection": "yes"},
                    {"whitelist": "10.0.0.0/8"}, {"bogus": 1}]:
            with self.assertRaises(ValueError, msg=bad):
                make_cfg(**bad)

    def test_ban_length(self):
        cfg = make_cfg(ban_seconds=3600, ban_max_seconds=4 * 3600)
        self.assertEqual([config.ban_length(cfg, n) for n in range(4)],
                         [3600, 7200, 14400, 14400])
        self.assertIsNone(config.ban_length(make_cfg(ban_seconds=0), 3))

    def test_example_config_loads(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cfg = config.load(os.path.join(here, "config.example.json"))
        self.assertEqual(cfg["ban_seconds"], 3600)


class LogSourceTests(unittest.TestCase):
    def test_iso_timestamp(self):
        t = logsource.line_time("2026-11-16T10:00:00.250000-05:00 srv sshd[1]: hi")
        self.assertEqual(t, datetime.fromisoformat("2026-11-16T15:00:00.25+00:00").timestamp())

    def test_bsd_timestamp_and_year_rollover(self):
        jan = datetime(2027, 1, 2, 12, 0).timestamp()
        t = logsource.line_time("Dec 31 23:59:00 srv sshd[1]: hi", now=jan)
        self.assertEqual(datetime.fromtimestamp(t), datetime(2026, 12, 31, 23, 59))
        t = logsource.line_time("Jan  2 11:00:00 srv sshd[1]: hi", now=jan)
        self.assertEqual(datetime.fromtimestamp(t), datetime(2027, 1, 2, 11, 0))

    def test_no_timestamp(self):
        self.assertIsNone(logsource.line_time("Failed password for x"))

    def test_old_file_is_replayed_at_its_own_pace(self):
        # one failure a day for a week is not a brute-force attack
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
            for day in range(1, 8):
                fh.write("2026-11-%02dT10:00:00+00:00 srv sshd[1]: %s\n"
                         % (day, failed("10.0.0.5")))
        self.addCleanup(os.unlink, fh.name)
        d = Detector(make_cfg(ssh_max_failures=3))
        hits = [d.process(msg, t) for t, msg in
                logsource.follow_file(fh.name, from_start=True, follow=False)]
        self.assertEqual(hits, [None] * 7)

    def test_follows_file_across_rotation(self):
        import threading
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "auth.log")
            with open(path, "w") as fh:
                fh.write("one\n")
            got = []
            src = logsource.follow_file(path, from_start=True)

            def read():
                for _, line in src:
                    got.append(line)
                    if line == "three":
                        return
            t = threading.Thread(target=read, daemon=True)
            t.start()
            with open(path, "a") as fh:
                fh.write("two\n")
            import time as _t
            _t.sleep(0.7)
            os.rename(path, path + ".1")
            with open(path, "w") as fh:
                fh.write("three\n")
            t.join(5)
            self.assertEqual(got, ["one", "two", "three"])

    def test_journal_filter_uses_trusted_fields(self):
        cmd = logsource.JOURNAL_CMD
        self.assertFalse(any(a.startswith("SYSLOG_IDENTIFIER") for a in cmd))
        self.assertIn("_UID=0", cmd)


class FirewallTests(unittest.TestCase):
    STATUS = """Status: active

To                         Action      From
--                         ------      ----
Anywhere                   DENY        10.99.0.2                  # fwauto ssh_brute_force
22/tcp                     ALLOW       Anywhere                   # ssh
Anywhere (v6)              DENY        2001:db8::1                # fwauto port_scan
22/tcp (v6)                ALLOW       Anywhere (v6)              # ssh
80/tcp                     DENY IN     203.0.113.0/24
"""

    def test_parse_denied(self):
        # the port-specific deny for 203.0.113.9 is not a full block
        status = self.STATUS + "80/tcp                     DENY        203.0.113.9\n"
        self.assertEqual(parse_denied(status), {"10.99.0.2", "2001:db8::1"})


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.cfg = os.path.join(self.dir.name, "c.json")
        with open(self.cfg, "w") as fh:
            json.dump({"whitelist": []}, fh)
        self.db = os.path.join(self.dir.name, "t.db")

    def run_cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(["-c", self.cfg, "--db", self.db, "--dry-run", *argv])
        return code, out.getvalue()

    def test_monitor_file_once(self):
        log = os.path.join(self.dir.name, "auth.log")
        start = datetime.now().astimezone().replace(microsecond=0)
        with open(log, "w") as fh:
            for i in range(5):
                fh.write("%s srv sshd[1]: %s\n" % (
                    (start + timedelta(seconds=i)).isoformat(), failed("10.0.0.5")))
        code, out = self.run_cli("monitor", "--file", log, "--from-start", "--once")
        self.assertEqual(code, 0)
        self.assertIn("blocked for 1h", out)
        code, out = self.run_cli("blocked")
        self.assertIn("10.0.0.5", out)
        code, out = self.run_cli("stats")
        self.assertIn("ssh_brute_force", out)

    def test_monitor_exits_nonzero_when_journal_ends(self):
        with mock.patch.object(logsource, "follow_journal", return_value=iter([])):
            code, out = self.run_cli("monitor")
        self.assertEqual(code, 1)
        self.assertIn("ended unexpectedly", out)

    def test_block_for_and_unblock(self):
        code, out = self.run_cli("block", "203.0.113.9", "--for", "30m")
        self.assertEqual((code, out.strip()), (0, "Blocked 203.0.113.9 for 30m."))
        code, out = self.run_cli("unblock", "203.0.113.9")
        self.assertEqual(code, 0)

    def test_dry_run_leaves_real_database_alone(self):
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.dict(config.DEFAULTS, db_path=self.db):
            cli.main(["-c", self.cfg, "--dry-run", "block", "203.0.113.9"])
        self.assertFalse(os.path.exists(self.db))

    def test_duration_arg(self):
        self.assertEqual(cli.duration_arg("90"), 90)
        self.assertEqual(cli.duration_arg("2h"), 7200)
        self.assertEqual(cli.duration_arg("0.5s"), 1)
        for bad in ["", "abc", "-5m", "0"]:
            with self.assertRaises(Exception):
                cli.duration_arg(bad)


if __name__ == "__main__":
    unittest.main()
