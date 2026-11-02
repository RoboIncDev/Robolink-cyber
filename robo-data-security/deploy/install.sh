#!/usr/bin/env bash
# Install robosec on THIS computer. Run as root by the robot's owner (agi has no unrestricted sudo).
#   ./deploy/install.sh --role agent|server|gateway|all [--enable] [--dry-run]
# Without --enable it installs files and units but starts nothing. Nothing here touches the robot's
# own services, firewall tables, or motion stack. Test hook: ROBOSEC_PREFIX=/tmp/x puts everything under /tmp/x.
set -euo pipefail
ROLE=""; ENABLE=0; DRY=0
while [[ $# -gt 0 ]]; do case "$1" in
  --role) ROLE="$2"; shift 2;; --enable) ENABLE=1; shift;; --dry-run) DRY=1; shift;;
  *) echo "unknown arg $1" >&2; exit 2;; esac; done
[[ "$ROLE" =~ ^(agent|server|gateway|all)$ ]] || { echo "usage: $0 --role agent|server|gateway|all [--enable] [--dry-run]" >&2; exit 2; }
P="${ROBOSEC_PREFIX:-}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
say() { echo "[install] $*"; }
do_() { if (( DRY )); then echo "DRY: $*"; else eval "$*"; fi; }
if [[ -z "$P" && $EUID -ne 0 && $DRY -eq 0 ]]; then echo "run as root (or use --dry-run)" >&2; exit 1; fi
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 1; }
python3 - <<'PY' || { echo "python >= 3.9 required" >&2; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)
PY
say "role=$ROLE prefix='${P:-/}' enable=$ENABLE dry=$DRY"
do_ "mkdir -p '$P/opt/robosec' '$P/etc/robosec' '$P/var/lib/robosec'"
do_ "cp -a '$SRC/robosec' '$SRC/config' '$SRC/dashboard' '$P/opt/robosec/'"
if [[ -z "$P" ]]; then
  id robosec >/dev/null 2>&1 || do_ "useradd --system --no-create-home --shell /usr/sbin/nologin robosec"
  do_ "chown -R robosec:robosec /var/lib/robosec"
fi
for f in agent server gatewayd; do
  case "$ROLE:$f" in
    agent:agent|all:agent|server:server|all:server|gateway:gatewayd|all:gatewayd)
      [[ -e "$P/etc/robosec/$f.json" ]] || do_ "cp '$SRC/config/$f.example.json' '$P/etc/robosec/$f.json' && chmod 600 '$P/etc/robosec/$f.json'";;
  esac
done
if [[ -z "$P" ]]; then
  for u in agent server gatewayd; do
    case "$ROLE:$u" in agent:agent|all:agent|server:server|all:server|gateway:gatewayd|all:gatewayd)
      do_ "cp '$SRC/deploy/robosec-$u.service' /etc/systemd/system/";; esac
  done
  do_ "systemctl daemon-reload"
  if (( ENABLE )); then
    for u in agent server gatewayd; do
      case "$ROLE:$u" in agent:agent|all:agent|server:server|all:server|gateway:gatewayd|all:gatewayd)
        do_ "systemctl enable --now robosec-$u";; esac
    done
  else
    say "installed, NOT started. Edit /etc/robosec/*.json (tokens!), then: systemctl enable --now robosec-<name>"
  fi
fi
say "done"
