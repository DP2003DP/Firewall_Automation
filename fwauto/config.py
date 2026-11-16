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
    # Addresses or networks that are never blocked.
    "whitelist": ["127.0.0.0/8", "::1/128"],
    "db_path": "/var/lib/fwauto/fwauto.db",
}

_POSITIVE = ("ssh_max_failures", "scan_max_ports")
_SECONDS = ("ssh_window_seconds", "scan_window_seconds",
            "ban_seconds", "ban_max_seconds")


def _check(cfg):
    for key in _POSITIVE:
        v = cfg[key]
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise ValueError("%s must be a whole number of at least 1" % key)
    for key in _SECONDS:
        v = cfg[key]
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
            raise ValueError("%s must be a number of seconds (0 or more)" % key)
    if not isinstance(cfg["scan_detection"], bool):
        raise ValueError("scan_detection must be true or false")
    if not isinstance(cfg["whitelist"], list):
        raise ValueError("whitelist must be a list of addresses or networks")
    if not isinstance(cfg["db_path"], str) or not cfg["db_path"]:
        raise ValueError("db_path must be a file path")


def load(path=None):
    """Return the config dict. A missing default file just means defaults."""
    cfg = dict(DEFAULTS)
    explicit = path is not None
    path = path or DEFAULT_CONFIG_PATH
    if os.path.exists(path):
        with open(path) as fh:
            user = json.load(fh)
        if not isinstance(user, dict):
            raise ValueError("%s must hold a JSON object" % path)
        unknown = set(user) - set(DEFAULTS)
        if unknown:
            raise ValueError("unknown config keys: " + ", ".join(sorted(unknown)))
        cfg.update(user)
    elif explicit:
        raise FileNotFoundError(path)
    return _finish(cfg)


def from_dict(**overrides):
    """Defaults plus overrides, validated the same way as a config file."""
    cfg = dict(DEFAULTS)
    unknown = set(overrides) - set(DEFAULTS)
    if unknown:
        raise ValueError("unknown config keys: " + ", ".join(sorted(unknown)))
    cfg.update(overrides)
    return _finish(cfg)


def _finish(cfg):
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
    """Seconds to ban for, given how many times the address was banned before.

    None means no expiry.
    """
    base = cfg["ban_seconds"]
    if not base:
        return None
    length = base * (2 ** min(offences, 30))
    cap = cfg["ban_max_seconds"]
    return min(length, cap) if cap else length
