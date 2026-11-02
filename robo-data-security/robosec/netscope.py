"""Classify an IP address into a scope relative to the robot.

Scopes (the policy only ever acts on 'internet'):
  local     loopback, link-local, multicast, unspecified
  robot     the robot's own internal networks (PC1/PC2/PC3 links, sensor port)
  vpn       overlay networks (Tailscale CGNAT 100.64.0.0/10)
  lan       any other private range (the Wi-Fi the operator is on, the PC1 hotspot, ...)
  internet  everything else
"""
from __future__ import annotations

import ipaddress

# Verified on the Cadet (2026-10): develop0 10.0.1.0/24, ssh0 10.0.200.0/24, sensor0 10.11.1.0/24,
# IPv6 ULA fdc7:e2f2:388f:d514::/64. The Wi-Fi LAN (192.168.30.0/24) and the PC1 hotspot
# (192.168.88.0/24) are NOT robot-internal: they are the outside world from the robot's view.
DEFAULT_ROBOT_NETS = ["10.0.1.0/24", "10.0.200.0/24", "10.11.1.0/24", "fdc7:e2f2:388f:d514::/64"]
DEFAULT_VPN_NETS = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]
DEFAULT_LAN_NETS = ["192.168.30.0/24", "192.168.88.0/24"]
# Any other private address is still "lan", but only these exact ranges: Python's is_private is broader
# (it also covers documentation and reserved space), which would hide internet-facing addresses.
_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


class Scoper:
    def __init__(self, robot_nets=None, lan_nets=None, vpn_nets=None) -> None:
        self.robot = [ipaddress.ip_network(n, strict=False) for n in (robot_nets or DEFAULT_ROBOT_NETS)]
        self.lan = [ipaddress.ip_network(n, strict=False) for n in (lan_nets or DEFAULT_LAN_NETS)]
        self.vpn = [ipaddress.ip_network(n, strict=False) for n in (vpn_nets or DEFAULT_VPN_NETS)]

    @classmethod
    def from_config(cls, cfg: dict | None) -> "Scoper":
        cfg = cfg or {}
        return cls(cfg.get("robot_nets"), cfg.get("lan_nets"), cfg.get("vpn_nets"))

    def scope(self, addr: str) -> str:
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            return "internet"          # unparseable: treat as the riskiest class, never as trusted
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return "local"
        for name, nets in (("robot", self.robot), ("vpn", self.vpn), ("lan", self.lan)):
            if any(ip in n for n in nets):
                return name
        if any(ip in n for n in _PRIVATE):
            return "lan"
        return "internet"      # includes documentation and reserved ranges: never trust what we cannot name

    def as_config(self) -> dict:
        return {"robot_nets": [str(n) for n in self.robot], "lan_nets": [str(n) for n in self.lan],
                "vpn_nets": [str(n) for n in self.vpn]}
