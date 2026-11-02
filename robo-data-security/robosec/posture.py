"""What is connected to this computer and what it exposes: read-only readings for the agent (stdlib only, no root needed).

Every reader takes the roots it reads from, so tests feed it a fake /proc and /sys. A reading that is not available on this
computer comes back as None (never as an empty list), so the dashboard can show a dash instead of a false "nothing".

  listeners   sockets in LISTEN state (tcp) or bound with no peer (udp), and how far each one reaches
  bluetooth   adapters, whether the computer is discoverable / pairable, paired and connected devices
  usb         devices plugged in (hubs left out)
  neighbors   devices this computer has talked to on its networks (ARP table)
  wifi        interface, signal and the access point it is joined to
  sessions    people logged in, and from where
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess

from .netscope import Scoper
from .procnet import TCP_LISTEN, read_sockets

UDP_BOUND = "07"
MAX_ITEMS = 200


def _read(path: str, limit: int = 512) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _clean(s: str, n: int = 80) -> str:
    return "".join(c for c in str(s) if c.isprintable())[:n]


# --- open ports -----------------------------------------------------------------------------------------------
def reach(laddr: str, scoper: Scoper) -> str:
    """How far a socket bound to `laddr` reaches: local (this computer only) | robot | vpn | lan | all (every interface)."""
    if laddr in ("0.0.0.0", "::"):
        return "all"
    scope = scoper.scope(laddr)
    return "local" if scope == "local" else scope


def listeners(scoper: Scoper, proc_root: str = "/proc") -> list[dict]:
    seen: dict[tuple, dict] = {}
    for s in read_sockets(proc_root):
        listening = (s["proto"] == "tcp" and s["state"] == TCP_LISTEN) or (s["proto"] == "udp" and s["state"] == UDP_BOUND and s["rport"] == 0)
        if not listening or s["lport"] == 0:
            continue
        r = reach(s["laddr"], scoper)
        key = (s["proto"], s["lport"], r)
        row = seen.setdefault(key, {"proto": s["proto"], "port": s["lport"], "reach": r, "uid": s["uid"], "inode": s["inode"]})
        row["inode"] = min(row["inode"], s["inode"])
    rows = sorted(seen.values(), key=lambda x: (x["port"], x["proto"]))
    return rows[:MAX_ITEMS]


def owners(rows: list[dict], proc_root: str = "/proc") -> None:
    """Add the program name where this user may read /proc/<pid>/fd; leave `comm` out otherwise (the caller shows a dash)."""
    from .procnet import inode_owner_map, proc_info
    owner_of, _ = inode_owner_map(proc_root)
    for r in rows:
        pid = owner_of.get(r.pop("inode", 0))
        if pid:
            r["comm"] = _clean(proc_info(pid, proc_root)["comm"], 40)
    for r in rows:
        r.pop("inode", None)


# --- bluetooth ------------------------------------------------------------------------------------------------
def parse_devices(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^Device\s+((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s*(.*)$", line.strip())
        if m:
            out.append({"mac": m.group(1).upper(), "name": _clean(m.group(2), 60)})
    return out[:MAX_ITEMS]


def parse_show(text: str) -> dict:
    """`bluetoothctl show` -> {address, name, powered, discoverable, pairable}."""
    f = {}
    for line in text.splitlines():
        if ":" in line and not line.startswith("Controller"):
            k, v = line.strip().split(":", 1)
            f[k.strip().lower()] = v.strip()
    m = re.search(r"Controller\s+((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})", text)
    yes = lambda k: f.get(k, "").lower() == "yes"     # noqa: E731
    if not m:
        return {}
    return {"address": m.group(1).upper(), "name": _clean(f.get("name", ""), 40), "powered": yes("powered"),
            "discoverable": yes("discoverable"), "pairable": yes("pairable")}


def _run(argv: list[str], timeout: float = 4.0) -> str | None:
    if not shutil.which(argv[0]):
        return None
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def bluetooth(sys_root: str = "/sys", run=_run) -> dict | None:
    """None when this computer has no Bluetooth adapter. Device lists are None when the tool to read them is missing."""
    adapters = []
    try:
        adapters = sorted(n for n in os.listdir(os.path.join(sys_root, "class", "bluetooth")) if re.fullmatch(r"hci\d+", n))
    except OSError:
        pass
    if not adapters:
        return None
    out = {"adapters": adapters, "controller": None, "paired": None, "connected": None}
    show = run(["bluetoothctl", "show"])
    if show is not None:
        out["controller"] = parse_show(show) or None
        paired = run(["bluetoothctl", "devices", "Paired"])
        if paired is None:
            paired = run(["bluetoothctl", "paired-devices"])
        conn = run(["bluetoothctl", "devices", "Connected"])
        out["paired"] = parse_devices(paired) if paired is not None else None
        out["connected"] = parse_devices(conn) if conn is not None else None
    return out


# --- usb ------------------------------------------------------------------------------------------------------
def usb(sys_root: str = "/sys") -> list[dict] | None:
    base = os.path.join(sys_root, "bus", "usb", "devices")
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return None
    out = []
    for n in names:
        d = os.path.join(base, n)
        vid, pid = _read(os.path.join(d, "idVendor")), _read(os.path.join(d, "idProduct"))
        if not vid or _read(os.path.join(d, "bDeviceClass")) == "09":       # root hubs and hubs are plumbing, not devices
            continue
        out.append({"bus": _clean(n, 16), "id": f"{vid}:{pid}", "vendor": _clean(_read(os.path.join(d, "manufacturer")), 40),
                    "product": _clean(_read(os.path.join(d, "product")), 60)})
    return out[:MAX_ITEMS]


# --- neighbours and wifi --------------------------------------------------------------------------------------
def neighbors(proc_root: str = "/proc") -> list[dict] | None:
    try:
        with open(os.path.join(proc_root, "net", "arp")) as fh:
            lines = fh.read().splitlines()[1:]
    except OSError:
        return None
    out = []
    for line in lines:
        f = line.split()
        if len(f) >= 6 and f[2] != "0x0" and f[3] != "00:00:00:00:00:00":     # 0x0 = incomplete entry
            mac = f[3].upper()
            out.append({"ip": f[0], "mac": mac, "dev": _clean(f[5], 16), "random": bool(int(mac[1], 16) & 2)})   # locally administered
    return out[:MAX_ITEMS]


def parse_iw_link(text: str) -> dict:
    ssid = re.search(r"SSID:\s*(.+)", text)
    bssid = re.search(r"Connected to\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", text, re.I)
    sig = re.search(r"signal:\s*(-?\d+)", text)
    return {"ssid": _clean(ssid.group(1), 40) if ssid else None, "bssid": bssid.group(1).upper() if bssid else None,
            "signal_dbm": int(sig.group(1)) if sig else None}


def wifi(proc_root: str = "/proc", run=_run) -> dict | None:
    try:
        with open(os.path.join(proc_root, "net", "wireless")) as fh:
            lines = fh.read().splitlines()[2:]
    except OSError:
        return None
    if not lines:
        return None
    dev = lines[0].split(":")[0].strip()
    out = {"dev": _clean(dev, 16), "ssid": None, "bssid": None, "signal_dbm": None}
    text = run(["iw", "dev", dev, "link"])
    if text:
        out.update(parse_iw_link(text))
    return out


# --- sessions -------------------------------------------------------------------------------------------------
def parse_who(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 2:
            frm = re.search(r"\(([^)]*)\)\s*$", line)
            out.append({"user": _clean(f[0], 32), "tty": _clean(f[1], 16), "from": _clean(frm.group(1), 64) if frm else ""})
    return out[:MAX_ITEMS]


def sessions(run=_run) -> list[dict] | None:
    text = run(["who"])
    return parse_who(text) if text is not None else None


# --- everything -----------------------------------------------------------------------------------------------
def collect(scoper: Scoper, proc_root: str = "/proc", sys_root: str = "/sys") -> dict:
    rows = listeners(scoper, proc_root)
    owners(rows, proc_root)
    return {"listeners": rows, "bluetooth": bluetooth(sys_root), "usb": usb(sys_root), "neighbors": neighbors(proc_root),
            "wifi": wifi(proc_root), "sessions": sessions()}
