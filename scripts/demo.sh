#!/bin/bash
# Guided live demo for the single-VM lab. Press Enter between steps.
# NOPAUSE=1 runs straight through (rehearsal, or a backup recording).
# Run "sudo fwauto watch" in a second terminal to show attacks building up.
# Needs fwauto installed (sudo ./install.sh). Run with: sudo scripts/demo.sh
set -u
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }
cd "$(dirname "$0")"
ATTACKER=10.99.0.2
VICTIM=10.99.0.77

step() {
    printf '\n\033[1;36m== %s\033[0m\n' "$1"
    [ -n "${NOPAUSE:-}" ] || read -rp "(enter) " _
}
reset_attacker() { fwauto unblock "$ATTACKER" >/dev/null 2>&1 || true; }
show_log() { sleep 2; journalctl -u fwauto -o cat --no-pager -n "${1:-1}"; }

step "setup: attacker namespace $ATTACKER -> server 10.99.0.1"
./lab_setup.sh 2>/dev/null | tail -1
# start from a clean slate so bans read 1h, 2h, 4h even after a rehearsal
fwauto unblock --forget "$ATTACKER" >/dev/null 2>&1 || true
ufw status | sed -n '1,8p'

step "1. SSH brute force: 8 wrong passwords"
./attack_bruteforce.sh
show_log
fwauto blocked

step "2. the attacker is cut off: one more login attempt"
ip netns exec attacker timeout 5 bash -c "exec 3<>/dev/tcp/10.99.0.1/22" 2>/dev/null \
    && echo "connected (not blocked?)" || echo "connection refused/timed out: blocked"

step "3. log injection: the attacker tries to frame $VICTIM"
reset_attacker
./attack_injection.sh 10.99.0.1 "$VICTIM"
echo; echo "what sshd wrote:"
journalctl -o cat --no-pager -n 40 _COMM=sshd-session _COMM=sshd-auth _COMM=sshd \
    | grep -m1 "Invalid user x from"
show_log
fwauto blocked

step "4. honeypot: a single connection attempt to port 3389"
reset_attacker
ip netns exec attacker timeout 2 bash -c "exec 3<>/dev/tcp/10.99.0.1/3389" 2>/dev/null
echo "one SYN sent to 3389 (RDP), nothing listens there"
show_log
fwauto blocked

step "5. port scan, and a repeat offender gets a longer ban"
reset_attacker
./attack_portscan.sh 10.99.0.1 | tail -3
show_log
fwauto blocked

step "6. what fwauto saw"
fwauto stats

step "cleanup"
reset_attacker
./lab_teardown.sh
