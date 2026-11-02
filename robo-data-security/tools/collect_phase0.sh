#!/usr/bin/env bash
# Phase 0: run tools/probe.sh on PC1, PC2 and PC3 from the workstation and save the results.
#   tools/collect_phase0.sh [PC2_ADDRESS]
# Read-only on the robot. Needs: PC2 reachable, and key login (NO passwords are ever typed by this script):
#   workstation -> agi@PC2 works with the workstation's key.
#   PC2 -> run@10.0.1.40 (PC1) and run@10.0.1.42 (PC3) need `-i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes`
#   because /etc/ssh/ssh_config.d/run.conf on PC2 forces another default key for 10.0.1.4x.
# If PC2's key is not on PC1/PC3 yet, a HUMAN must run once, on PC2:   ssh-copy-id -i ~/.ssh/id_ed25519 run@10.0.1.40
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../phase0/$(date +%Y%m%d_%H%M%S)"; mkdir -p "$OUT"
PC2="${1:-}"
if [[ -z "$PC2" ]]; then
  # PC2's Wi-Fi address changes (DHCP). Find it by its Wi-Fi MAC bc:d2:2c:20:f9:68 on the workstation's /24.
  net="$(ip -4 route | awk '/dev wl/ && /src/ {print $1; exit}')"
  echo "scanning ${net:-192.168.30.0/24} for PC2 (MAC bc:d2:2c:20:f9:68) ..."
  base="${net%.*}"; for i in $(seq 1 254); do ping -c1 -W1 "${base:-192.168.30}.$i" >/dev/null 2>&1 & done; wait
  PC2="$(ip neigh | awk 'tolower($0) ~ /bc:d2:2c:20:f9:68/ {print $1; exit}')"
fi
[[ -n "$PC2" ]] || { echo "PC2 not found on the network. Is the robot on?" >&2; exit 1; }
echo "PC2 = $PC2   output -> $OUT"
SSH2=(ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new "agi@$PC2")
INNER='ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=6'
echo "== PC2";  "${SSH2[@]}" 'bash -s' < "$HERE/probe.sh" | tee "$OUT/pc2.txt"
echo "== PC1";  "${SSH2[@]}" "$INNER run@10.0.1.40 'bash -s'" < "$HERE/probe.sh" | tee "$OUT/pc1.txt"
echo "== PC3";  "${SSH2[@]}" "$INNER run@10.0.1.42 'bash -s'" < "$HERE/probe.sh" | tee "$OUT/pc3.txt"
echo "== PC2 forwarding / NAT (is PC2 really the egress gateway?)"
"${SSH2[@]}" 'echo "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)"; ip route | head -8; (nft list ruleset 2>&1 || true) | grep -iE "masquerade|snat|table " | head; (iptables -t nat -S 2>&1 || true) | head -8' | tee "$OUT/pc2_forwarding.txt"
echo "== PC1/PC3 default route and external reachability"
for h in 10.0.1.40 10.0.1.42; do "${SSH2[@]}" "$INNER run@$h 'ip route | head -3; timeout 4 curl -s -o /dev/null -w \"internet via \$HOSTNAME: %{http_code}\n\" https://example.com || echo \"no internet from \$HOSTNAME\"'" | tee -a "$OUT/egress.txt"; done
echo "saved in $OUT"
