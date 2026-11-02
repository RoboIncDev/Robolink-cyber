"""Findings: plain statements about what could be wrong, each with the evidence and the fix. Pure functions, no I/O.

Severity uses the same three words as the rest of the dashboard: fault (act now), caution (look at it), info (good to know).
A finding has a stable `id`, so the owner can accept one ("known and fine") and it stays accepted while the cause stays the same.
"""
from __future__ import annotations

RISKY_PORTS = {
    23: ("Telnet", "Unencrypted remote login. Turn it off."),
    21: ("FTP", "Unencrypted file transfer. Turn it off or use SFTP."),
    111: ("rpcbind", "Needed only for NFS. Turn it off if nothing uses NFS."),
    445: ("SMB file sharing", "Turn it off unless this computer is meant to share files."),
    2049: ("NFS file sharing", "Limit it to the robot's own network."),
    3389: ("Remote Desktop", "Remote control of the screen. Limit it to the robot's own network or a VPN."),
    5900: ("VNC remote screen", "Remote control of the screen, often without encryption. Limit it or use a VPN."),
    50080: ("Robot app manager", "It can start and stop the robot's programs. Limit it to the robot's own network."),
}
OUTSIDE = ("all", "lan")                     # reaches beyond the robot's own network (all = every interface, lan = the Wi-Fi side)
_RANK = {"fault": 0, "caution": 1, "info": 2}


def _f(id_: str, sev: str, host: str, title: str, detail: str, fix: str = "") -> dict:
    return {"id": id_, "severity": sev, "host": host, "title": title, "detail": detail, "fix": fix}


def evaluate(postures: dict[str, dict], hosts: list[dict], enforcers: dict[str, dict], now: float, accepted: set[str],
             silent_s: float = 120.0, enforcer_stale_s: float = 45.0) -> list[dict]:
    """postures: host -> {"ts", "body"}; hosts: rows of the hosts table; enforcers: host -> row."""
    out: list[dict] = []
    for h in hosts:
        host = h["host"]
        if now - h["last_seen"] > silent_s:
            out.append(_f(f"agent:{host}", "caution", host, f"{host} stopped reporting",
                          f"The last report was {int(now - h['last_seen'])} s ago, so nothing is known about this computer right now.",
                          "Check that the robosec agent is running there."))
        elif (h.get("stats") or {}).get("unattributed", 0) > 0:
            out.append(_f(f"unattributed:{host}", "info", host, f"{host}: some connections have no program name",
                          f"{h['stats']['unattributed']} connections could not be tied to a program, because the agent is not running as root there.",
                          "Run the agent as root on this computer to see which program owns each connection."))
        e = enforcers.get(host)
        if e is None:
            out.append(_f(f"enforcer:{host}", "info", host, f"{host} has no enforcer",
                          "Without one, Secure data cannot block anything on this computer and sent bytes are not counted.",
                          "Install the enforcer here (deploy/ENFORCER.md)."))
        elif now - e["ts"] > enforcer_stale_s:
            out.append(_f(f"enforcer-silent:{host}", "caution", host, f"The enforcer on {host} is silent",
                          "Blocking on this computer is not active.", "Restart the enforcer service."))
        p = postures.get(host)
        if p is None:
            out.append(_f(f"posture:{host}", "info", host, f"{host} does not report its ports and devices",
                          "Its agent is older than this dashboard or the reading is switched off.", "Update the agent there."))
            continue
        b = p["body"]
        ports = [r for r in (b.get("listeners") or []) if r["reach"] in OUTSIDE]
        other = []
        for r in ports:
            if r["proto"] == "tcp" and r["port"] in RISKY_PORTS:
                name, fix = RISKY_PORTS[r["port"]]
                where = "every network this computer is on" if r["reach"] == "all" else "the Wi-Fi network"
                out.append(_f(f"listen:{host}:{r['proto']}:{r['port']}", "caution", host, f"{host}: {name} (port {r['port']}) is open to {where}",
                              f"Anyone who can reach {host} can try to connect to it. It listens on {where}." + (f" Program: {r['comm']}." if r.get("comm") else ""), fix))
            else:
                other.append(r)
        if other:
            names = ", ".join(sorted({f"{r['port']}/{r['proto']}" for r in other}, key=lambda s: int(s.split("/")[0])))
            out.append(_f(f"ports:{host}", "info", host, f"{host}: {len({r['port'] for r in other})} more {'port reaches' if len({r['port'] for r in other}) == 1 else 'ports reach'} beyond this computer",
                          names, "Close the ones nothing needs, or limit them to the robot's own network."))
        bt = b.get("bluetooth")
        c = (bt or {}).get("controller") or {}
        if c.get("powered") and c.get("discoverable"):
            out.append(_f(f"bt-discoverable:{host}", "caution", host, f"{host}: Bluetooth is visible to anyone nearby",
                          "A discoverable adapter can be found and paired with by a stranger in range.", "Turn discoverable off after pairing."))
        elif c.get("powered") and c.get("pairable"):
            out.append(_f(f"bt-pairable:{host}", "info", host, f"{host}: Bluetooth accepts new pairings",
                          "Hidden from a scan, but anyone who knows the address can still try to pair.", "Turn pairable off when not pairing."))
        for s in (b.get("sessions") or []):
            if s.get("from") and not s["from"].startswith((":", "tmux")):
                out.append(_f(f"session:{host}:{s['user']}:{s['from']}", "info", host, f"{s['user']} is logged in to {host} from {s['from']}",
                              f"Terminal {s['tty']}.", "Nothing to do if this is you."))
    for f in out:
        f["accepted"] = f["id"] in accepted
    return sorted(out, key=lambda f: (f["accepted"], _RANK[f["severity"]], f["host"], f["id"]))
