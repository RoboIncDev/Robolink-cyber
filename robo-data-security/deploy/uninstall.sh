#!/usr/bin/env bash
# Remove robosec from THIS computer and switch enforcement off. Safe to run twice. Run as root.
set -uo pipefail
echo "[uninstall] stopping services and removing our nft table (fail-open)"
for u in robosec-gatewayd robosec-agent robosec-server; do systemctl disable --now "$u" 2>/dev/null; rm -f "/etc/systemd/system/$u.service"; done
systemctl daemon-reload 2>/dev/null
( cd /opt/robosec 2>/dev/null && PYTHONPATH=/opt/robosec python3 -m robosec.gatewayd --remove ) || nft delete table inet robosec 2>/dev/null
echo "[uninstall] config and data are kept: /etc/robosec  /var/lib/robosec  (delete by hand if you want them gone)"
rm -rf /opt/robosec
echo "[uninstall] done. Verify nothing of ours is left:  nft list tables | grep robosec || echo clean"
