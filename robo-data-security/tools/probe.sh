#!/usr/bin/env bash
# Phase 0 probe. READ-ONLY: changes nothing. Run on each robot computer (see collect_phase0.sh).
# Answers: can this computer run the agent / eBPF / nftables, what is it talking to right now, and can we install.
echo "host=$(hostname) kernel=$(uname -r) arch=$(uname -m) user=$(id -un) uid=$(id -u)"
echo "python3=$(python3 --version 2>&1) sqlite=$(python3 -c 'import sqlite3;print(sqlite3.sqlite_version)' 2>&1)"
echo "cpu=$(nproc) mem=$(free -m | awk '/Mem:/{print $2"MB"}') root_free=$(df -h / | awk 'NR==2{print $4}') load=$(cut -d' ' -f1-3 /proc/loadavg)"
echo "systemd=$(systemctl --version 2>/dev/null | head -1) | sudo_without_password=$(sudo -n true 2>/dev/null && echo yes || echo no)"
echo "groups=$(id -Gn)"
echo "-- kernel config (eBPF / netfilter):"
cfg=""; [ -r /proc/config.gz ] && cfg=/proc/config.gz; [ -z "$cfg" ] && [ -r "/boot/config-$(uname -r)" ] && cfg="/boot/config-$(uname -r)"
if [ -z "$cfg" ]; then echo "  no readable kernel config (/proc/config.gz, /boot/config-*): feature checks below are unknown"; fi
for k in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_BPF_JIT CONFIG_KPROBES CONFIG_FTRACE CONFIG_DEBUG_FS CONFIG_NF_TABLES \
         CONFIG_NFT_CT CONFIG_NFT_COUNTER CONFIG_NFT_DYNSET CONFIG_NF_CONNTRACK CONFIG_CGROUP_BPF CONFIG_DEBUG_INFO_BTF CONFIG_NETFILTER_NETLINK_QUEUE; do
  if [ -n "$cfg" ]; then
    if [[ "$cfg" == *.gz ]]; then v=$(zcat "$cfg" 2>/dev/null | grep -E "^$k=" | head -1); else v=$(grep -E "^$k=" "$cfg" | head -1); fi
  fi
  echo "  $k: ${v:-not set / unknown}"; v=""
done
echo "BTF: $([ -e /sys/kernel/btf/vmlinux ] && echo present || echo missing)  bpffs: $(mount | grep -c ' type bpf ') mounted"
echo "debugfs/tracefs readable: $(ls /sys/kernel/debug >/dev/null 2>&1 && echo debugfs-yes || echo debugfs-no) $(ls /sys/kernel/tracing >/dev/null 2>&1 && echo tracefs-yes || echo tracefs-no)"
echo "-- tools present:"
for t in nft iptables bpftool tcpdump ss conntrack python3 go tmux suricata zeek curl; do command -v $t >/dev/null 2>&1 && printf '  %s=%s\n' $t "$(command -v $t)"; done
echo "nft version: $(nft --version 2>&1 | head -1)"
echo "-- forwarding / NAT (does this computer route for the others?):"
echo "  ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null) ipv6_forward=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)"
echo "  default route: $(ip route 2>/dev/null | grep '^default' | head -2 | tr '\n' ';')"
(nft list tables 2>&1 | head -12) | sed 's/^/  nft table: /'
(iptables -t nat -S 2>&1 | head -6) | sed 's/^/  iptables nat: /'
echo "-- interfaces:"; ip -br addr 2>/dev/null | grep -v DOWN | sed 's/^/  /'
echo "-- DNS: $(grep -h '^nameserver' /etc/resolv.conf 2>/dev/null | tr '\n' ' ') $(command -v resolvectl >/dev/null && resolvectl status 2>/dev/null | grep -m2 'DNS Server' | tr -s ' ' | tr '\n' ' ')"
echo "-- current established connections to peers OUTSIDE 10.x/127.x/::1 (peer  <-  local), first 25:"
ss -tnH state established 2>/dev/null | awk '{loc=$3; peer=$4; p=peer; sub(/:[0-9]+$/,"",p); if (p !~ /^(10\.|127\.|\[?::1\]?$|\[?fe80|\[?fdc7)/) print "  " peer "  <-  " loc}' | head -25
echo "-- listening on all interfaces: $(ss -tlnH 2>/dev/null | awk '$4 ~ /^(0\.0\.0\.0|\*|\[::\]):/{print $4}' | sed 's/.*://' | sort -un | tr '\n' ' ')"
echo "-- processes with sockets visible to this user: $(ls /proc/[0-9]*/fd 2>/dev/null | wc -l) fd dirs readable (root sees all; non-root only its own)"
