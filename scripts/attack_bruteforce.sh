#!/bin/bash
# Simulate an SSH brute-force attack with wrong passwords.
# Usage: sudo scripts/attack_bruteforce.sh [target] [attempts]
# By default it attacks from the "attacker" namespace made by lab_setup.sh.
# On a second VM, run it as: NETNS= ./attack_bruteforce.sh <server-ip>
set -u
TARGET=${1:-10.99.0.1}
ATTEMPTS=${2:-8}
NETNS=${NETNS-attacker}
RUN=""
[ -n "$NETNS" ] && RUN="ip netns exec $NETNS"
USERS=(root admin test oracle ubuntu guest pi user)

for i in $(seq 1 "$ATTEMPTS"); do
    user=${USERS[$(( (i - 1) % ${#USERS[@]} ))]}
    printf 'attempt %d  user=%-7s ' "$i" "$user"
    $RUN sshpass -p "wrong-password-$i" ssh \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 -o ConnectTimeout=4 -o LogLevel=ERROR \
        "$user@$TARGET" true 2>&1 | tail -n 1
    sleep 1
done
