"""robosec agent: runs on each robot computer, read-only, reports who talks to whom.

    python3 -m robosec.agent --config /etc/robosec/agent.json            # run forever
    python3 -m robosec.agent --once --host pc2                           # one sample as JSON, no server

It never opens a listening socket, never modifies firewall state, and sends only to the one server
URL in its config. Per-process attribution needs root (or CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH).
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request

from . import __version__
from .netscope import Scoper
from .procnet import (TCP_ESTABLISHED, TCP_LISTEN, TCP_SYN_SENT, inode_owner_map, proc_info,
                      read_sockets)

DEFAULTS = {
    "host": "",                     # logical name, e.g. pc1 / pc2 / pc3 (defaults to the hostname)
    "server": "http://127.0.0.1:8750",
    "token": "",
    "interval_s": 2.0,              # sampling period; shorter misses fewer short flows but costs CPU
    "flush_s": 10.0,                # how often changed edges are sent
    "ignore_local": True,           # drop loopback / link-local / multicast peers
    "spool_dir": "/var/lib/robosec",
    "spool_max_bytes": 20 * 1024 * 1024,
    "max_edges_per_report": 500,
    "nice": 10,
    "networks": {},                 # overrides for robot_nets / lan_nets / vpn_nets
}


def load_config(path: str | None) -> dict:
    cfg = dict(DEFAULTS)
    if path:
        with open(path) as fh:
            cfg.update(json.load(fh))
    if not cfg["host"]:
        cfg["host"] = socket.gethostname()
    return cfg


class Sampler:
    """One pass over /proc: returns observations (one per live connection)."""

    def __init__(self, scoper: Scoper, proc_root: str = "/proc", ignore_local: bool = True) -> None:
        self.scoper = scoper
        self.proc_root = proc_root
        self.ignore_local = ignore_local
        self._info_cache: dict[int, dict] = {}

    def sample(self) -> tuple[list[dict], dict]:
        t0 = time.monotonic()
        socks = read_sockets(self.proc_root)
        owners, unreadable = inode_owner_map(self.proc_root)

        # Direction heuristic: /proc/net has no direction. A connection whose local port is a port some
        # socket on this machine is LISTENing/bound on is inbound; anything else is outbound.
        listen_ports = {s["lport"] for s in socks if s["proto"] == "tcp" and s["state"] == TCP_LISTEN}
        listen_ports |= {s["lport"] for s in socks if s["proto"] == "udp" and s["rport"] == 0 and s["lport"]}

        observations: list[dict] = []
        unattributed = 0
        live_pids: set[int] = set()
        for s in socks:
            if s["proto"] == "tcp" and s["state"] not in (TCP_ESTABLISHED, TCP_SYN_SENT):
                continue
            if s["rport"] == 0 or s["raddr"] in ("0.0.0.0", "::"):
                continue                                   # listening or unconnected socket
            scope = self.scoper.scope(s["raddr"])
            if scope == "local" and self.ignore_local:
                continue
            pid = owners.get(s["inode"])
            if pid is None:
                unattributed += 1
                info = {"pid": 0, "exe": "?", "comm": "?", "cmd": "", "uid": s["uid"], "unit": ""}
            else:
                live_pids.add(pid)
                info = self._info_cache.get(pid)
                if info is None:
                    info = self._info_cache[pid] = proc_info(pid, self.proc_root)
            direction = "in" if s["lport"] in listen_ports else "out"
            observations.append({"dir": direction, "exe": info["exe"], "comm": info["comm"], "unit": info["unit"],
                                 "uid": info["uid"], "cmd": info["cmd"], "proto": s["proto"],
                                 "raddr": s["raddr"], "rport": s["rport"], "scope": scope})
        for pid in list(self._info_cache):
            if pid not in live_pids:
                del self._info_cache[pid]                  # pids are reused; never keep a stale identity
        stats = {"sample_ms": round((time.monotonic() - t0) * 1000, 1), "sockets": len(socks),
                 "observations": len(observations), "unattributed": unattributed,
                 "unreadable_procs": unreadable}
        return observations, stats


class EdgeTable:
    """Aggregates observations into edges: (dir, exe, proto, raddr, rport) with counts and times."""

    def __init__(self) -> None:
        self.edges: dict[tuple, dict] = {}
        self._dirty: set[tuple] = set()

    def update(self, observations: list[dict], now: float) -> None:
        seen_now: set[tuple] = set()
        for o in observations:
            key = (o["dir"], o["exe"], o["proto"], o["raddr"], o["rport"])
            e = self.edges.get(key)
            if e is None:
                e = self.edges[key] = {**o, "n": 0, "first": now, "last": now}
                self._dirty.add(key)
            if key not in seen_now:
                seen_now.add(key)
            e["last"] = now
        for key in seen_now:
            self.edges[key]["n"] += 1                    # number of samples this edge was alive in
            self._dirty.add(key)

    def drain(self, limit: int) -> list[dict]:
        keys = sorted(self._dirty)[:limit]
        for k in keys:
            self._dirty.discard(k)
        return [dict(self.edges[k]) for k in keys]

    def pending(self) -> int:
        return len(self._dirty)


class Reporter:
    def __init__(self, cfg: dict, opener=urllib.request.urlopen) -> None:
        self.cfg = cfg
        self.opener = opener
        self.seq = 0
        if cfg.get("spool_dir"):
            try:
                os.makedirs(cfg["spool_dir"], exist_ok=True)
            except OSError:
                cfg["spool_dir"] = ""          # no writable spool: still run, just without offline buffering

    def _spool_path(self) -> str:
        return os.path.join(self.cfg["spool_dir"], "spool.jsonl")

    def post(self, payload: dict) -> bool:
        req = urllib.request.Request(self.cfg["server"].rstrip("/") + "/api/v1/report",
                                     data=json.dumps(payload).encode(), method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Authorization": "Bearer " + self.cfg["token"]})
        try:
            with self.opener(req, timeout=8) as r:
                return 200 <= r.status < 300
        except (urllib.error.URLError, OSError, ValueError):
            return False

    def spool(self, payload: dict) -> None:
        if not self.cfg.get("spool_dir"):
            return
        path = self._spool_path()
        try:
            if os.path.exists(path) and os.path.getsize(path) > self.cfg["spool_max_bytes"]:
                os.replace(path, path + ".old")            # bounded: keep one previous generation only
            with open(path, "a") as fh:
                fh.write(json.dumps(payload) + "\n")
        except OSError:
            pass

    def replay_spool(self) -> None:
        path = self._spool_path()
        if not os.path.exists(path):
            return
        try:
            with open(path) as fh:
                lines = fh.readlines()
        except OSError:
            return
        remaining: list[str] = []
        for i, line in enumerate(lines):
            try:
                ok = self.post(json.loads(line))
            except ValueError:
                continue                                    # a corrupt line is dropped, not retried forever
            if not ok:
                remaining = lines[i:]
                break
        try:
            if remaining:
                with open(path, "w") as fh:
                    fh.writelines(remaining)
            else:
                os.remove(path)
        except OSError:
            pass

    def send(self, edges: list[dict], stats: dict) -> bool:
        self.seq += 1
        payload = {"host": self.cfg["host"], "agent_version": __version__, "ts": time.time(),
                   "seq": self.seq, "edges": edges, "stats": stats}
        if self.post(payload):
            self.replay_spool()
            return True
        self.spool(payload)
        return False


def run(cfg: dict, once: bool = False) -> int:
    try:
        os.nice(int(cfg.get("nice", 10)))
    except (OSError, ValueError):
        pass
    scoper = Scoper.from_config(cfg.get("networks"))
    sampler = Sampler(scoper, ignore_local=cfg["ignore_local"])
    table = EdgeTable()
    if once:
        obs, stats = sampler.sample()
        table.update(obs, time.time())
        json.dump({"host": cfg["host"], "stats": stats, "edges": table.drain(10_000)}, sys.stdout, indent=1)
        print()
        return 0
    reporter = Reporter(cfg)
    last_flush = 0.0
    cpu0 = time.process_time()
    while True:
        t = time.time()
        obs, stats = sampler.sample()
        table.update(obs, t)
        if t - last_flush >= cfg["flush_s"]:
            stats.update(interval_s=cfg["interval_s"], cpu_s=round(time.process_time() - cpu0, 2),
                         edges_total=len(table.edges), pending=table.pending())
            while True:
                batch = table.drain(cfg["max_edges_per_report"])
                reporter.send(batch, stats)
                if not table.pending():
                    break
            last_flush = t
        time.sleep(max(0.2, cfg["interval_s"]))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config")
    ap.add_argument("--once", action="store_true", help="print one sample as JSON and exit")
    ap.add_argument("--host", help="override the logical host name")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    if a.host:
        cfg["host"] = a.host
    if a.once:
        cfg["spool_dir"] = ""
    return run(cfg, once=a.once)


if __name__ == "__main__":
    raise SystemExit(main())
