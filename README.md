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
| Port scan | `[UFW BLOCK]` kernel lines for new connections (TCP SYN, or UDP) | 6 different ports from one IP in 60 s |

1. `fwauto monitor` follows the systemd journal: sshd messages from root
   processes, and kernel messages. It matches on fields journald fills in
   itself, so a local user can't fake sshd lines with `logger`.
2. The detector keeps a sliding window of events per IP address.
3. When an address crosses a threshold, fwauto runs
   `ufw prepend deny from <ip>` so the rule sits above the ssh allow rule,
   closes that address's open connections, and saves the incident to SQLite
   (`/var/lib/fwauto/fwauto.db`).
4. Bans last an hour and double for each repeat offence, up to a week.
5. On startup fwauto checks that every block in its database still has a
   ufw rule, and puts back any that went missing.

Whitelisted addresses (loopback, and the address you installed from) are
recorded but never blocked.

The SSH username is chosen by the client and sshd logs it as sent, spaces
and all. A client logging in as `x from 10.0.0.9 port 22` produces
`Invalid user x from 10.0.0.9 port 22 from <real ip> port 5555`. fwauto
always takes the last address on the line, so this can't be used to get
someone else blocked (`scripts/attack_injection.sh` tries it).

## Install

```bash
sudo ./install.sh
```

This installs UFW and OpenSSH server if missing, copies the tool to
`/opt/fwauto`, allows SSH on the port(s) sshd listens on, sets UFW to deny
other incoming traffic with logging on, and starts the `fwauto` systemd
service. It adds the address you are connected from to the whitelist (or
pass `ADMIN_IP=...`), and warns about other listening ports that UFW will
start blocking.

## Usage

```bash
sudo fwauto blocked                 # blocked IP addresses
sudo fwauto incidents               # incident history (--ip X, -n 20)
sudo fwauto stats                   # top attackers, usernames, ports (--hours 24)
sudo fwauto unblock 10.99.0.2       # remove a block
sudo fwauto block 203.0.113.9       # block by hand (--for 2h, default forever)
journalctl -u fwauto -f             # live activity
```

`--dry-run` never touches UFW and uses a throwaway database unless you pass
`--db`.

Settings live in `/etc/fwauto/config.json` (see `config.example.json`):
thresholds, time windows, `ban_seconds` (first ban; 0 = until unblocked),
`ban_max_seconds` (cap for repeat offenders), and the whitelist. Restart
with `sudo systemctl restart fwauto` after editing. Removing a block by
adding the address to the whitelist takes effect on restart.

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
sudo fwauto unblock 10.99.0.2
sudo scripts/attack_injection.sh         # tries to frame 10.99.0.77
sudo fwauto stats
sudo scripts/lab_teardown.sh
```

`sudo scripts/demo.sh` runs the whole sequence with a pause between steps
(`NOPAUSE=1` to run straight through).

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
- Port scans are judged by the packet's source address, which an attacker
  can forge for a SYN or UDP packet. Someone could spoof a scan "from" your
  gateway and get it banned for an hour. Whitelist the addresses you can't
  afford to lose.
- `--file` mode trusts the log file. Any local user can add lines to
  `/var/log/auth.log` with `logger -p auth.info`, so prefer the journal.
- IPv6 addresses are counted one by one; an attacker with a /64 has plenty.

## Layout

```
fwauto/detector.py    detection logic (pure Python, unit tested)
fwauto/monitor.py     log loop: detect, block, record
fwauto/firewall.py    ufw wrapper
fwauto/storage.py     SQLite incidents and blocks
fwauto/logsource.py   journal and log-file readers
fwauto/cli.py         command line interface
scripts/              single-VM lab, attack simulators, demo.sh
tests/                unit tests
```
