"""Configuration: built-in defaults, optionally overridden by a JSON file."""

import ipaddress
import json
import os

DEFAULT_CONFIG_PATH = "/etc/fwauto/config.json"

DEFAULTS = {
    # SSH brute force: block after this many failed logins ...
    "ssh_max_failures": 5,
    # ... from one IP inside this many seconds.
    "ssh_window_seconds": 60,
    # Port scan: block after new connections to this many different ports ...
    "scan_max_ports": 6,
    # ... from one IP inside this many seconds.
    "scan_window_seconds": 60,
    "scan_detection": True,
    # First ban length. Each repeat offence doubles it, up to ban_max_seconds.
    # 0 = blocks stay until someone runs "fwauto unblock".
    "ban_seconds": 3600,
    "ban_max_seconds": 7 * 24 * 3600,
    # One connection attempt to any of these blocks the source. Don't allow
    # them in ufw, or the packets are never logged.
    "honeypot_ports": [],
    # Addresses or networks that are never blocked.
    "whitelist": ["127.0.0.0/8", "::1/128"],
    "db_path": "/var/lib/fwauto/fwauto.db",
}

_POSITIVE = ("ssh_max_failures", "scan_max_ports")
_SECONDS = ("ssh_window_seconds", "scan_window_seconds",
            "ban_seconds", "ban_max_seconds")


def _is_int(v):
    # json true/false load as bool, which is a subclass of int
    return isinstance(v, int) and not isinstance(v, bool)


def _check(cfg):
    for key in _POSITIVE:
        if not _is_int(cfg[key]) or cfg[key] < 1:
            raise ValueError("%s must be a whole number of at least 1" % key)
    for key in _SECONDS:
        v = cfg[key]
        if not (_is_int(v) or isinstance(v, float)) or v < 0:
            raise ValueError("%s must be a number of seconds (0 or more)" % key)
    if not isinstance(cfg["scan_detection"], bool):
        raise ValueError("scan_detection must be true or false")
    ports = cfg["honeypot_ports"]
    if not isinstance(ports, list) or not all(_is_int(p) and 1 <= p <= 65535 for p in ports):
        raise ValueError("honeypot_ports must be a list of port numbers")
    if not isinstance(cfg["whitelist"], list):
        raise ValueError("whitelist must be a list of addresses or networks")
    if not isinstance(cfg["db_path"], str) or not cfg["db_path"]:
        raise ValueError("db_path must be a file path")


def load(path=None):
    """Return the config dict. A missing default file just means defaults."""
    explicit = path is not None
    path = path or DEFAULT_CONFIG_PATH
    if os.path.exists(path):
        with open(path) as fh:
            user = json.load(fh)
        if not isinstance(user, dict):
            raise ValueError("%s must hold a JSON object" % path)
        return from_dict(**user)
    if explicit:
        raise FileNotFoundError(path)
    return from_dict()


def from_dict(**overrides):
    unknown = set(overrides) - set(DEFAULTS)
    if unknown:
        raise ValueError("unknown config keys: " + ", ".join(sorted(unknown)))
    cfg = dict(DEFAULTS, **overrides)
    _check(cfg)
    # Fail early on a bad whitelist rather than at block time.
    cfg["whitelist_networks"] = [
        ipaddress.ip_network(entry, strict=False) for entry in cfg["whitelist"]
    ]
    return cfg


def is_whitelisted(cfg, ip):
    addr = ipaddress.ip_address(ip)
    return any(
        addr.version == net.version and addr in net
        for net in cfg["whitelist_networks"]
    )


def ban_length(cfg, offences):
    """Seconds to ban for after this many earlier bans; None means forever."""
    base = cfg["ban_seconds"]
    if not base:
        return None
    length = base * (2 ** min(offences, 30))
    cap = cfg["ban_max_seconds"]
    return min(length, cap) if cap else length
