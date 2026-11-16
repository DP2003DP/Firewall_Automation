#!/bin/bash
# Install fwauto on an Ubuntu server. Run with: sudo ./install.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }
cd "$(dirname "$0")"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ufw openssh-server python3 >/dev/null

install -d /opt/fwauto /etc/fwauto /var/lib/fwauto
rm -rf /opt/fwauto/fwauto
cp -r fwauto /opt/fwauto/
[ -f /etc/fwauto/config.json ] || cp config.example.json /etc/fwauto/config.json

cat > /usr/local/bin/fwauto <<'WRAP'
#!/bin/sh
PYTHONPATH=/opt/fwauto exec python3 -m fwauto "$@"
WRAP
chmod 755 /usr/local/bin/fwauto

cp fwauto.service /etc/systemd/system/fwauto.service
systemctl daemon-reload

# Firewall: keep SSH reachable, deny everything else inbound, and log what
# gets denied (the port-scan detector reads those log lines).
ufw allow OpenSSH >/dev/null
ufw default deny incoming >/dev/null
ufw logging low >/dev/null
ufw --force enable >/dev/null
systemctl enable --now ssh >/dev/null 2>&1 || true
systemctl enable fwauto >/dev/null 2>&1
systemctl restart fwauto

echo "fwauto installed and running."
echo "  sudo fwauto blocked      list blocked addresses"
echo "  sudo fwauto incidents    show incident history"
echo "  sudo fwauto unblock IP   remove a block"
echo "  journalctl -u fwauto -f  watch it work"
