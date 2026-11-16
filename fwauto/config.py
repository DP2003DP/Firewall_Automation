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
    # Port scan: block after blocked packets to this many different ports ...
    "scan_max_ports": 6,
    # ... from one IP inside this many seconds.
    "scan_window_seconds": 60,
    "scan_detection": True,
    # 0 = blocks stay until someone runs "fwauto unblock".
    "ban_seconds": 0,
    # Addresses or networks that are never blocked.
    "whitelist": ["127.0.0.0/8", "::1/128"],
    "db_path": "/var/lib/fwauto/fwauto.db",
}


def load(path=None):
    """Return the config dict. A missing default file just means defaults."""
    cfg = dict(DEFAULTS)
    explicit = path is not None
    path = path or DEFAULT_CONFIG_PATH
    if os.path.exists(path):
        with open(path) as fh:
            user = json.load(fh)
        unknown = set(user) - set(DEFAULTS)
        if unknown:
            raise ValueError("unknown config keys: " + ", ".join(sorted(unknown)))
        cfg.update(user)
    elif explicit:
        raise FileNotFoundError(path)
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
