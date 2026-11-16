#!/bin/bash
# Install fwauto on an Ubuntu server. Run with: sudo ./install.sh
# Set ADMIN_IP=1.2.3.4 to whitelist your own address explicitly.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }
cd "$(dirname "$0")"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ufw openssh-server python3 >/dev/null

install -d /opt/fwauto /etc/fwauto /var/lib/fwauto
rm -rf /opt/fwauto/fwauto
cp -r fwauto /opt/fwauto/

# Whitelist the address this install is being run from, so a few mistyped
# passwords can't lock the admin out. sudo drops SSH_CLIENT, so look for it
# in the parent processes (the login shell still has it).
admin_ip=${ADMIN_IP:-}
pid=$$
while [ -z "$admin_ip" ] && [ "${pid:-1}" -gt 1 ]; do
    client=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | sed -n 's/^SSH_CLIENT=//p')
    admin_ip=${client%% *}
    pid=$(ps -o ppid= -p "$pid" | tr -d ' ')
done
if [ ! -f /etc/fwauto/config.json ]; then
    python3 -I - "$admin_ip" <<'PY'
import ipaddress, json, sys
cfg = json.load(open("config.example.json"))
ip = sys.argv[1]
try:
    ip = str(ipaddress.ip_address(ip))
except ValueError:
    ip = None
if ip and not any(ipaddress.ip_address(ip) in ipaddress.ip_network(n)
                  for n in cfg["whitelist"]):
    cfg["whitelist"].append(ip)
    print("whitelisted your address %s in /etc/fwauto/config.json" % ip)
else:
    print("note: could not tell your address; add it to the whitelist in"
          " /etc/fwauto/config.json (or rerun with ADMIN_IP=...)")
with open("/etc/fwauto/config.json", "w") as fh:
    json.dump(cfg, fh, indent=2)
    fh.write("\n")
PY
fi

cat > /usr/local/bin/fwauto <<'WRAP'
#!/bin/sh
PYTHONPATH=/opt/fwauto exec python3 -m fwauto "$@"
WRAP
chmod 755 /usr/local/bin/fwauto

cp fwauto.service /etc/systemd/system/fwauto.service
systemctl daemon-reload

# Firewall: keep SSH reachable on whatever port sshd really uses, deny
# everything else inbound, and log what gets denied (the port-scan detector
# reads those log lines).
ssh_ports=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | sort -u)
for p in ${ssh_ports:-22}; do
    ufw allow "$p/tcp" comment "ssh" >/dev/null
done

if [ "$(ufw status | head -1)" != "Status: active" ]; then
    others=$(ss -Htln | awk '{print $4}' | sed 's/.*://' | sort -un |
             grep -vxF -f <(printf '%s\n' ${ssh_ports:-22}) || true)
    others=$(echo $others)
    if [ -n "$others" ]; then
        echo "warning: these TCP ports are listening and will be blocked from"
        echo "  outside once UFW denies incoming traffic: $others"
        echo "  allow the ones you need with: sudo ufw allow PORT/tcp"
    fi
fi
ufw default deny incoming >/dev/null
ufw logging low >/dev/null
ufw --force enable >/dev/null
systemctl enable --now ssh >/dev/null 2>&1 || true
systemctl enable fwauto >/dev/null 2>&1
systemctl restart fwauto

echo "fwauto installed and running."
echo "  sudo fwauto blocked      list blocked addresses"
echo "  sudo fwauto incidents    show incident history"
echo "  sudo fwauto stats        attack summary"
echo "  sudo fwauto unblock IP   remove a block"
echo "  journalctl -u fwauto -f  watch it work"
