"""Command line interface."""

import argparse
import ipaddress
import os
import sqlite3
import sys
from datetime import datetime

from . import __version__, config, logsource
from .firewall import Firewall, FirewallError
from .monitor import Monitor, log
from .storage import Storage


def fmt_time(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def table(headers, rows):
    rows = [[str(c) for c in row] for row in rows]
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h)
              for i, h in enumerate(headers)]
    line = "  ".join("%-" + str(w) + "s" for w in widths)
    print(line % tuple(headers))
    print(line % tuple("-" * w for w in widths))
    for row in rows:
        print(line % tuple(row))


def ip_arg(text):
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise argparse.ArgumentTypeError("%r is not an IP address" % text)


def need_root(args):
    if not args.dry_run and os.geteuid() != 0:
        sys.exit("This command changes firewall rules. Run it with sudo.")


def cmd_monitor(args, cfg, storage, firewall):
    need_root(args)
    if not firewall.is_active():
        sys.exit("UFW is not active. Enable it first: sudo ufw enable")
    if args.file:
        source = logsource.follow_file(args.file, args.from_start, not args.once)
        where = args.file
    else:
        source = logsource.follow_journal()
        where = "systemd journal"
    log("fwauto %s watching %s" % (__version__, where))
    log("ssh: %s failures / %ss   port scan: %s   ban: %s" % (
        cfg["ssh_max_failures"], cfg["ssh_window_seconds"],
        "%s ports / %ss" % (cfg["scan_max_ports"], cfg["scan_window_seconds"])
        if cfg["scan_detection"] else "off",
        "%ss" % cfg["ban_seconds"] if cfg["ban_seconds"] else "until unblocked",
    ))
    try:
        Monitor(cfg, storage, firewall).run(source)
    except KeyboardInterrupt:
        log("stopped")
    return 0


def cmd_blocked(args, cfg, storage, firewall):
    rows = storage.active_blocks()
    if not rows:
        print("No IP addresses are blocked.")
        return 0
    table(["IP ADDRESS", "BLOCKED AT", "REASON"],
          [(r["ip"], fmt_time(r["blocked_at"]), r["reason"]) for r in rows])
    return 0


def cmd_incidents(args, cfg, storage, firewall):
    rows = storage.incidents(args.ip, args.limit)
    if not rows:
        print("No incidents recorded.")
        return 0
    table(["ID", "TIME", "IP ADDRESS", "TYPE", "REASON", "ACTION", "DETAILS"],
          [(r["id"], fmt_time(r["timestamp"]), r["ip"], r["kind"], r["reason"],
            r["action"], r["details"]) for r in rows])
    return 0


def cmd_block(args, cfg, storage, firewall):
    need_root(args)
    if config.is_whitelisted(cfg, args.ip):
        sys.exit("%s is whitelisted and cannot be blocked." % args.ip)
    if storage.is_blocked(args.ip):
        print("%s is already blocked." % args.ip)
        return 0
    try:
        firewall.block(args.ip, "fwauto manual")
    except FirewallError as exc:
        sys.exit("ufw failed: %s" % exc)
    storage.set_blocked(args.ip, args.reason)
    storage.add_incident(args.ip, "manual", args.reason, "", "blocked")
    print("Blocked %s." % args.ip)
    return 0


def cmd_unblock(args, cfg, storage, firewall):
    need_root(args)
    if not storage.is_blocked(args.ip):
        print("%s is not blocked by fwauto." % args.ip)
        return 1
    try:
        firewall.unblock(args.ip)
    except FirewallError as exc:
        sys.exit("ufw failed: %s" % exc)
    storage.set_unblocked(args.ip)
    storage.add_incident(args.ip, "unblock", "manual unblock", "", "unblocked")
    print("Unblocked %s." % args.ip)
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="fwauto",
        description="Detect SSH brute-force attacks and port scans, "
                    "and block the source with UFW.")
    p.add_argument("--version", action="version", version="fwauto " + __version__)
    p.add_argument("-c", "--config", help="config file (default %s)"
                   % config.DEFAULT_CONFIG_PATH)
    p.add_argument("--db", help="database path (overrides the config file)")
    p.add_argument("--dry-run", action="store_true",
                   help="record incidents but do not touch UFW")
    sub = p.add_subparsers(dest="command", required=True)

    m = sub.add_parser("monitor", help="watch the logs and block attackers")
    m.add_argument("--file", help="tail this log file instead of the journal")
    m.add_argument("--from-start", action="store_true",
                   help="with --file: read from the beginning")
    m.add_argument("--once", action="store_true",
                   help="with --file: stop at end of file")
    m.set_defaults(func=cmd_monitor)

    b = sub.add_parser("blocked", aliases=["status"],
                       help="list blocked IP addresses")
    b.set_defaults(func=cmd_blocked)

    i = sub.add_parser("incidents", help="show past security incidents")
    i.add_argument("--ip", type=ip_arg, help="only this address")
    i.add_argument("-n", "--limit", type=int, default=50, help="rows to show")
    i.set_defaults(func=cmd_incidents)

    k = sub.add_parser("block", help="block an IP address by hand")
    k.add_argument("ip", type=ip_arg)
    k.add_argument("--reason", default="manual block")
    k.set_defaults(func=cmd_block)

    u = sub.add_parser("unblock", help="remove a block")
    u.add_argument("ip", type=ip_arg)
    u.set_defaults(func=cmd_unblock)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        cfg = config.load(args.config)
    except (OSError, ValueError) as exc:
        sys.exit("config error: %s" % exc)
    if args.db:
        cfg["db_path"] = args.db
    try:
        storage = Storage(cfg["db_path"])
    except (OSError, sqlite3.Error) as exc:
        sys.exit("cannot open database %s: %s (try sudo)" % (cfg["db_path"], exc))
    return args.func(args, cfg, storage, Firewall(dry_run=args.dry_run))
