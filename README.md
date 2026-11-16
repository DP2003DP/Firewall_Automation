# fwauto - Linux Firewall Automation Tool

Group members: Brady Gibson, Agilan Gunalan, Divyam Patel

`fwauto` watches a Linux server's logs, detects SSH brute-force attacks and
port scans, and blocks the source IP address with UFW. It keeps a record of
every incident and has a small command line interface for reviewing and
undoing blocks.

Python 3 standard library only. Tested on Ubuntu 25.04 with UFW and OpenSSH.

## How it works

| Threat | Signal | Default threshold |
| --- | --- | --- |
| SSH brute force | `Failed password` / `Invalid user` lines from sshd | 5 failures from one IP in 60 s |
| Port scan | `[UFW BLOCK]` kernel lines (packets UFW already dropped) | 6 different ports from one IP in 60 s |

1. `fwauto monitor` follows the systemd journal (sshd and kernel messages).
2. The detector keeps a sliding window of events per IP address.
3. When an address crosses a threshold, fwauto runs
   `ufw prepend deny from <ip>` so the rule sits above `allow OpenSSH`,
   closes that address's open connections, and saves the incident to SQLite
   (`/var/lib/fwauto/fwauto.db`).

Whitelisted addresses (loopback by default) are recorded but never blocked.

## Install

```bash
sudo ./install.sh
```

This installs UFW and OpenSSH server if missing, copies the tool to
`/opt/fwauto`, allows SSH, sets UFW to deny other incoming traffic with
logging on, and starts the `fwauto` systemd service.

## Usage

```bash
sudo fwauto blocked                 # blocked IP addresses
sudo fwauto incidents               # incident history (--ip X, -n 20)
sudo fwauto unblock 10.99.0.2       # remove a block
sudo fwauto block 203.0.113.9       # block by hand
journalctl -u fwauto -f             # live activity
```

Settings live in `/etc/fwauto/config.json` (see `config.example.json`):
thresholds, time windows, `ban_seconds` (0 = until unblocked), and the
whitelist. Restart with `sudo systemctl restart fwauto` after editing.

## Testing

Unit tests (no root, no firewall changes):

```bash
python3 -m unittest discover -s tests
```

### One VM

`scripts/lab_setup.sh` creates a network namespace named `attacker`
(10.99.0.2) wired to the server (10.99.0.1) by a virtual cable, so attack
traffic arrives on a real interface and UFW treats it like an outside host.

```bash
sudo scripts/lab_setup.sh
sudo scripts/attack_bruteforce.sh        # 8 wrong-password SSH logins
sudo fwauto blocked
sudo fwauto unblock 10.99.0.2
sudo scripts/attack_portscan.sh          # probes TCP ports 20-40
sudo fwauto incidents
sudo scripts/lab_teardown.sh
```

### Two VMs

Put both VMs on the same VirtualBox internal or host-only network. Install
fwauto on the server VM. On the attacker VM (needs `sshpass`):

```bash
NETNS= scripts/attack_bruteforce.sh <server-ip>
NETNS= scripts/attack_portscan.sh <server-ip>
```

## Limitations

- UFW rate-limits its block log (about 10 lines in a burst, then 3 per
  minute), so slow or very small scans can go unnoticed.
- Only password and keyboard-interactive failures count. Failed public-key
  attempts are ignored, because normal clients often try several keys.
- A blocked address stays blocked until `fwauto unblock`, unless
  `ban_seconds` is set.

## Layout

```
fwauto/detector.py    detection logic (pure Python, unit tested)
fwauto/monitor.py     log loop: detect, block, record
fwauto/firewall.py    ufw wrapper
fwauto/storage.py     SQLite incidents and blocks
fwauto/logsource.py   journal and log-file readers
fwauto/cli.py         command line interface
scripts/              single-VM lab and attack simulators
tests/                unit tests
```
