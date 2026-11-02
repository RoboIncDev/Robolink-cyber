"""Read sockets and their owning processes straight from /proc (no root-only tools, no pip).

Honest limits (also in HANDOFF.md):
  * It sees sockets that exist at sampling time. A connection shorter than the sampling interval
    can be missed; the gateway's conntrack/flow counters are the cross-check for those.
  * It cannot count bytes per socket. Bytes come from the gateway (nftables counters).
  * /proc/<pid>/fd of other users is readable only by root (or CAP_SYS_PTRACE / CAP_DAC_READ_SEARCH).
    Unreadable processes show up as exe "?" and are counted in `unattributed`.
"""
from __future__ import annotations

import os
import socket
import struct
from typing import Iterator

TCP_ESTABLISHED = "01"
TCP_SYN_SENT = "02"
TCP_LISTEN = "0A"


def _hex_ip(h: str) -> str:
    if len(h) == 8:                                   # IPv4: one little-endian 32-bit word
        return socket.inet_ntoa(struct.pack("<I", int(h, 16)))
    words = [struct.pack("<I", int(h[i:i + 8], 16)) for i in range(0, 32, 8)]   # IPv6: four LE words
    return socket.inet_ntop(socket.AF_INET6, b"".join(words))


def parse_net_file(text: str, proto: str) -> Iterator[dict]:
    """Parse the text of /proc/net/{tcp,tcp6,udp,udp6}."""
    lines = text.splitlines()
    for line in lines[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        try:
            lip, lport = f[1].rsplit(":", 1)
            rip, rport = f[2].rsplit(":", 1)
            yield {"proto": proto, "laddr": _hex_ip(lip), "lport": int(lport, 16),
                   "raddr": _hex_ip(rip), "rport": int(rport, 16), "state": f[3].upper(),
                   "uid": int(f[7]), "inode": int(f[9])}
        except (ValueError, struct.error, OSError):
            continue


def read_sockets(proc_root: str = "/proc") -> list[dict]:
    out: list[dict] = []
    for name, proto in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
        try:
            with open(os.path.join(proc_root, "net", name), "r") as fh:
                out.extend(parse_net_file(fh.read(), proto))
        except OSError:
            continue
    return out


def inode_owner_map(proc_root: str = "/proc") -> tuple[dict[int, int], int]:
    """Map socket inode -> pid. Returns (map, number of processes whose fds were unreadable)."""
    owners: dict[int, int] = {}
    unreadable = 0
    try:
        pids = [p for p in os.listdir(proc_root) if p.isdigit()]
    except OSError:
        return owners, 0
    for pid in pids:
        fd_dir = os.path.join(proc_root, pid, "fd")
        try:
            fds = os.listdir(fd_dir)
        except PermissionError:
            unreadable += 1
            continue
        except OSError:
            continue                                   # the process exited while we looked
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target.startswith("socket:["):
                try:
                    owners.setdefault(int(target[8:-1]), int(pid))
                except ValueError:
                    pass
    return owners, unreadable


def _read(path: str, limit: int = 4096) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def cgroup_unit(text: str) -> str:
    """Last systemd unit (.service/.scope) named in /proc/<pid>/cgroup, or ''."""
    unit = ""
    for line in text.splitlines():
        for part in line.rsplit(":", 1)[-1].split("/"):
            if part.endswith((".service", ".scope")):
                unit = part
    return unit


def proc_info(pid: int, proc_root: str = "/proc") -> dict:
    base = os.path.join(proc_root, str(pid))
    try:
        exe = os.readlink(os.path.join(base, "exe"))
    except OSError:
        exe = ""
    comm = _read(os.path.join(base, "comm")).strip()
    cmd = _read(os.path.join(base, "cmdline")).replace("\x00", " ").strip()[:200]
    try:
        uid = os.stat(base).st_uid
    except OSError:
        uid = -1
    return {"pid": pid, "exe": exe or (comm and f"[{comm}]") or "?", "comm": comm or "?", "cmd": cmd,
            "uid": uid, "unit": cgroup_unit(_read(os.path.join(base, "cgroup")))}
