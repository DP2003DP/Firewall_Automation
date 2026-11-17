#!/bin/bash
# Try to frame an innocent address by hiding it in the SSH username.
# fwauto should block the attacker, not the victim.
# Usage: sudo scripts/attack_injection.sh [target] [victim] [attempts]
set -u
TARGET=${1:-10.99.0.1}
VICTIM=${2:-10.99.0.77}
ATTEMPTS=${3:-6}
NETNS=${NETNS-attacker}
RUN=""
[ -n "$NETNS" ] && RUN="ip netns exec $NETNS"

echo "framing $VICTIM: username is \"x from $VICTIM port 22\""
for i in $(seq 1 "$ATTEMPTS"); do
    printf 'attempt %d  ' "$i"
    $RUN sshpass -p "wrong-password-$i" ssh \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 -o ConnectTimeout=4 -o LogLevel=ERROR \
        -l "x from $VICTIM port 22" "$TARGET" true 2>&1 | tail -n 1
    sleep 1
done
