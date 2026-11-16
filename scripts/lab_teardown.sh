#!/bin/bash
# Remove the single-VM test lab.
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }
ip netns del attacker 2>/dev/null
ip link del veth-fw 2>/dev/null
echo "Lab removed."
