#!/bin/bash
# Simulate a TCP port scan (one connection attempt per port).
# Usage: sudo scripts/attack_portscan.sh [target] [first-port] [last-port]
# The default range avoids the example honeypot ports (23, 3389).
# On a second VM, run it as: NETNS= ./attack_portscan.sh <server-ip>
set -u
TARGET=${1:-10.99.0.1}
FIRST=${2:-1000}
LAST=${3:-1020}
NETNS=${NETNS-attacker}
RUN=""
[ -n "$NETNS" ] && RUN="ip netns exec $NETNS"

for port in $(seq "$FIRST" "$LAST"); do
    if $RUN timeout 0.5 bash -c "exec 3<>/dev/tcp/$TARGET/$port" 2>/dev/null; then
        echo "port $port open"
    else
        echo "port $port closed/filtered"
    fi
done
