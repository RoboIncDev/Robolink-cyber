"""Render the gateway's nftables ruleset from the policy. Pure function: no I/O, easy to test.

Design rules (each one protects the robot):
  * Own table only (`inet robosec`). We never `flush ruleset` and never touch the vendor's tables.
  * Base chains run at priority -5 with policy accept. An `accept` here ends only OUR chain, so the
    vendor's own filter chains still run afterwards; a `drop` here is final, so every drop is explicit.
  * Robot-internal, trusted (LAN/VPN) and local destinations are accepted first and are never counted,
    delayed or logged: the control plane (DDS, EtherCAT-adjacent traffic, SSH) is never in the path.
  * `observe` mode renders every verdict as accept. `enforce` renders real drops.
  * Atomic replace: the file starts with `add table` + `delete table` + `table {...}`, which nft loads as
    one transaction, so there is never a half-applied ruleset.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Iterable

from .netscope import Scoper

DEFAULT_POLICY = {
    "version": 1,
    "mode": "observe",                  # observe | enforce
    "default_internet": "allow",        # verdict for internet destinations nobody has classified
    "categories": {},                   # category id -> "allow" | "block"   (missing = allow)
    "allow_cidrs": [],
    "block_cidrs": [],
    "always_allow": {"udp_ports": [53, 123], "tcp_ports": []},
}


def sanitize_id(cat: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", cat.lower())


def validate_policy(p: dict) -> dict:
    """Return a normalised copy or raise ValueError. Used by the API and by the renderer."""
    out = {**DEFAULT_POLICY, **{k: v for k, v in p.items() if k in DEFAULT_POLICY or k == "updated"}}
    if out["mode"] not in ("observe", "enforce"):
        raise ValueError("mode must be observe or enforce")
    if out["default_internet"] not in ("allow", "block"):
        raise ValueError("default_internet must be allow or block")
    cats = out.get("categories") or {}
    if not isinstance(cats, dict) or any(v not in ("allow", "block") for v in cats.values()):
        raise ValueError("categories must map ids to allow|block")
    for key in ("allow_cidrs", "block_cidrs"):
        out[key] = [str(ipaddress.ip_network(c, strict=False)) for c in (out.get(key) or [])]
    aa = dict(out.get("always_allow") or {})          # copy: never mutate the shared DEFAULT_POLICY
    for key in ("udp_ports", "tcp_ports"):
        ports = [int(x) for x in aa.get(key, [])]
        if any(not 0 < x < 65536 for x in ports):
            raise ValueError("ports must be 1..65535")
        aa[key] = sorted(set(ports))
    out["always_allow"] = {"udp_ports": aa.get("udp_ports", []), "tcp_ports": aa.get("tcp_ports", [])}
    out["categories"] = dict(cats)
    return out


def _split(addrs: Iterable[str]) -> tuple[list, list]:
    v4, v6 = [], []
    for a in addrs:
        try:
            n = ipaddress.ip_network(a, strict=False)
        except ValueError:
            continue
        (v4 if n.version == 4 else v6).append(n)
    return (list(ipaddress.collapse_addresses(v4)), list(ipaddress.collapse_addresses(v6)))


def _set(name: str, family: int, nets: list) -> str:
    typ = "ipv4_addr" if family == 4 else "ipv6_addr"
    body = f"    set {name} {{\n        type {typ}\n        flags interval\n"
    if nets:
        body += "        elements = { " + ", ".join(str(n) for n in nets) + " }\n"
    return body + "    }\n"


def render(policy: dict, scoper: Scoper, learned: dict[str, list[str]] | None = None) -> str:
    """`learned` maps category id -> destination addresses observed for that category."""
    p = validate_policy(policy)
    learned = learned or {}
    enforce = p["mode"] == "enforce"
    verdict = lambda v: ("drop" if (v == "block" and enforce) else "accept")      # noqa: E731
    cfg = scoper.as_config()
    robot4, robot6 = _split(cfg["robot_nets"])
    trusted4, trusted6 = _split(cfg["lan_nets"] + cfg["vpn_nets"])
    block4, block6 = _split(p["block_cidrs"])
    allow4, allow6 = _split(p["allow_cidrs"])

    sets: list[str] = [
        _set("robot4", 4, robot4), _set("robot6", 6, robot6),
        _set("trusted4", 4, trusted4), _set("trusted6", 6, trusted6),
        _set("block4", 4, block4), _set("block6", 6, block6),
        _set("allow4", 4, allow4), _set("allow6", 6, allow6),
    ]
    # Per-destination byte counters for everything leaving to the internet (the "data sent" metric).
    for fam, typ in (("4", "ipv4_addr"), ("6", "ipv6_addr")):
        sets.append(f"    set flows{fam} {{\n        type {typ}\n        flags dynamic, timeout\n"
                    f"        timeout 12h\n        size 16384\n        counter\n    }}\n")

    decide: list[str] = []
    for fam, s in (("4", "ip"), ("6", "ip6")):
        decide.append(f"        {s} daddr @block{fam} counter {verdict('block')}\n")
        decide.append(f"        {s} daddr @allow{fam} counter accept\n")
    cat_lines: list[str] = []
    for cat in sorted(learned):
        v4, v6 = _split(learned[cat])
        sid = sanitize_id(cat)
        v = verdict(p["categories"].get(cat, "allow"))
        for fam, nets, s in (("4", v4, "ip"), ("6", v6, "ip6")):
            if not nets:
                continue
            sets.append(_set(f"cat_{sid}_v{fam}", int(fam), nets))
            cat_lines.append(f"        {s} daddr @cat_{sid}_v{fam} counter {v}    # {cat}: "
                             f"{p['categories'].get(cat, 'allow')}\n")
    decide.extend(cat_lines)
    decide.append(f"        counter {verdict(p['default_internet'])}    # unclassified internet destinations: "
                  f"{p['default_internet']}\n")

    aa = p["always_allow"]
    always = ""
    if aa["udp_ports"]:
        always += "        udp dport { " + ", ".join(map(str, aa["udp_ports"])) + " } accept\n"
    if aa["tcp_ports"]:
        always += "        tcp dport { " + ", ".join(map(str, aa["tcp_ports"])) + " } accept\n"

    digest = hashlib.sha256(repr((p, sorted((k, sorted(v)) for k, v in learned.items()))).encode()).hexdigest()[:12]
    text = (
        f"# robosec ruleset  policy_version={p['version']}  mode={p['mode']}  digest={digest}\n"
        "add table inet robosec\n"
        "delete table inet robosec\n"
        "table inet robosec {\n"
        + "".join(sets) +
        "    chain screen {\n"
        "        # 1. never touch robot-internal, trusted, local traffic\n"
        "        ip daddr @robot4 accept\n"
        "        ip6 daddr @robot6 accept\n"
        "        ip daddr @trusted4 accept\n"
        "        ip6 daddr @trusted6 accept\n"
        "        ip daddr { 127.0.0.0/8, 224.0.0.0/4, 169.254.0.0/16, 255.255.255.255 } accept\n"
        "        ip6 daddr { ::1, ff00::/8, fe80::/10 } accept\n"
        "        # 2. count bytes sent to each internet destination (read by robosec-gatewayd)\n"
        "        add @flows4 { ip daddr counter }\n"
        "        add @flows6 { ip6 daddr counter }\n"
        "        # 3. packets of connections that already exist are never re-judged\n"
        "        ct state { established, related } accept\n"
        "        ct state != new accept\n"
        + always +
        "        jump decide\n"
        "    }\n"
        "    chain decide {\n"
        "        # reached only by NEW connections to internet destinations\n"
        + "".join(decide) +
        "    }\n"
        "    chain forward {\n"
        "        type filter hook forward priority -5; policy accept;\n"
        "        jump screen\n"
        "    }\n"
        "    chain output {\n"
        "        type filter hook output priority -5; policy accept;\n"
        "        oifname \"lo\" accept\n"
        "        jump screen\n"
        "    }\n"
        "}\n"
    )
    return text


def header_info(text: str) -> dict:
    m = re.match(r"# robosec ruleset\s+policy_version=(\d+)\s+mode=(\w+)\s+digest=(\w+)", text)
    return {"version": int(m.group(1)), "mode": m.group(2), "digest": m.group(3)} if m else {}
