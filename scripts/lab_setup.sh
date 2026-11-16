#!/bin/bash
# Single-VM test lab. Creates a network namespace called "attacker" that is
# wired to this machine with a virtual cable, so attack traffic arrives on a
# real interface from a separate IP address and UFW treats it like any
# outside host.
#   server (this machine): 10.99.0.1      attacker namespace: 10.99.0.2
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }

ip netns del attacker 2>/dev/null || true
ip link del veth-fw 2>/dev/null || true

ip netns add attacker
ip link add veth-fw type veth peer name veth-atk
ip link set veth-atk netns attacker
ip addr add 10.99.0.1/24 dev veth-fw
ip link set veth-fw up
ip netns exec attacker ip addr add 10.99.0.2/24 dev veth-atk
ip netns exec attacker ip link set veth-atk up
ip netns exec attacker ip link set lo up

command -v sshpass >/dev/null || apt-get install -y -qq sshpass >/dev/null
echo "Lab ready: attacker 10.99.0.2 -> server 10.99.0.1"
