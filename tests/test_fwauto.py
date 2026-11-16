import os
import tempfile
import unittest

from fwauto import config
from fwauto.detector import Detector, PORT_SCAN, SSH_BRUTE_FORCE
from fwauto.firewall import Firewall
from fwauto.monitor import Monitor
from fwauto.storage import Storage


def make_cfg(**overrides):
    cfg = dict(config.DEFAULTS)
    cfg.update(overrides)
    path = tempfile.mktemp(suffix=".json")
    import json
    with open(path, "w") as fh:
        json.dump(cfg, fh)
    try:
        return config.load(path)
    finally:
        os.unlink(path)


def failed(ip, user="root", port=4000):
    return "Failed password for %s from %s port %d ssh2" % (user, ip, port)


def ufw(ip, dport):
    return ("[UFW BLOCK] IN=enp0s3 OUT= MAC=aa SRC=%s DST=10.0.2.15 LEN=60 "
            "TOS=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=5555 DPT=%d WINDOW=1 SYN" % (ip, dport))


class DetectorTests(unittest.TestCase):
    def test_triggers_on_fifth_failure(self):
        d = Detector(make_cfg())
        for i in range(4):
            self.assertIsNone(d.process(failed("10.0.0.5"), 100 + i))
        inc = d.process(failed("10.0.0.5"), 104)
        self.assertEqual((inc.ip, inc.kind), ("10.0.0.5", SSH_BRUTE_FORCE))
        self.assertIn("5 failed", inc.reason)

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

    def test_repeated_hits_on_one_port_are_not_a_scan(self):
        d = Detector(make_cfg())
        for i in range(50):
            self.assertIsNone(d.process(ufw("10.0.0.7", 23), i))

    def test_multicast_noise_ignored(self):
        d = Detector(make_cfg(scan_max_ports=1))
        msg = ufw("10.0.2.2", 5353).replace("DST=10.0.2.15", "DST=224.0.0.251")
        self.assertIsNone(d.process(msg, 1))

    def test_scan_detection_can_be_disabled(self):
        d = Detector(make_cfg(scan_detection=False, scan_max_ports=1))
        self.assertIsNone(d.process(ufw("10.0.0.7", 23), 1))


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.storage = Storage(os.path.join(self.dir.name, "t.db"))

    def tearDown(self):
        self.dir.cleanup()

    def monitor(self, **overrides):
        return Monitor(make_cfg(**overrides), self.storage, Firewall(dry_run=True))

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
        for i in range(5):
            m.handle(failed("10.0.0.5"), 1000 + i)
        m.expire_bans(now=1300)
        self.assertTrue(self.storage.is_blocked("10.0.0.5"))
        m.expire_bans(now=1700)
        self.assertFalse(self.storage.is_blocked("10.0.0.5"))

    def test_unblock_then_reoffend(self):
        m = self.monitor()
        for i in range(5):
            m.handle(failed("10.0.0.5"), i)
        self.storage.set_unblocked("10.0.0.5")
        actions = [m.handle(failed("10.0.0.5"), 100 + i) for i in range(5)]
        self.assertEqual(actions[-1], "blocked")
        self.assertEqual(len(self.storage.active_blocks()), 1)


if __name__ == "__main__":
    unittest.main()
