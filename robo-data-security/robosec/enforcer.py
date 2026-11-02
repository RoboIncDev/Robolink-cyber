"""robosec-enforcer: the "Secure data" switch on one computer. Needs CAP_NET_ADMIN (root). stdlib only; uses iptables / ip6tables.

    python3 -m robosec.enforcer --config /etc/robosec/enforcer.json            # run forever
    python3 -m robosec.enforcer --config ... --once                            # one cycle, print what it did
    python3 -m robosec.enforcer --config ... --dry-run                         # fetch and show the rules it WOULD install
    python3 -m robosec.enforcer --remove                                       # delete our chain and its hooks (fail-open)

What it does: every few seconds it asks the server for two address lists (block, count). In the chain ROBOSEC_SECURE it keeps one
rule per address: `-d ADDR -j DROP` for blocked addresses and `-d ADDR -j RETURN` for the others. The RETURN rules do nothing to the
traffic, they only give exact per-destination byte counters; the DROP rules show how much was stopped. Counters are sent back.

SAFETY (each point has a test)
  * It only ever touches its own chain and ONE `-j ROBOSEC_SECURE` rule at the top of OUTPUT (and FORWARD if configured).
  * Defence in depth: it re-checks every address itself and refuses anything that is not a public internet address (robot-internal,
    LAN, VPN, loopback, multicast, link-local), whatever the server says. A wrong or hijacked server can not use it to cut the robot's own links.
  * Fail open: if the server is unreachable for `failopen_s` seconds, every DROP is turned into RETURN (traffic flows). Any unexpected error does the same.
    Stopping the service removes the chain completely (`--remove`, run by the unit's ExecStopPost).
  * Rules do not survive a reboot: after one, nothing is blocked until this service runs again.
  * At most `max_rules` addresses; the first start rebuilds the chain from scratch so it never inherits stale rules.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
import urllib.error
import urllib.request

from . import __version__
from .gatewayd import run_cmd
from .netscope import Scoper

CHAIN = "ROBOSEC_SECURE"
DEFAULTS = {"host": "", "server": "http://10.0.1.41:8750", "token": "", "poll_s": 3.0, "failopen_s": 120.0, "max_rules": 4096,
            "forward": False, "iptables": "iptables", "ip6tables": "ip6tables", "networks": {}}


def parse_counters(text: str) -> list[dict]:
    """Parse `iptables -L CHAIN -n -v -x`: lines `pkts bytes target prot opt in out source destination`."""
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 9 and f[0].isdigit() and f[1].isdigit() and f[2] in ("DROP", "RETURN"):
            addr = f[8].split("/")[0]
            out.append({"addr": addr, "verdict": f[2], "packets": int(f[0]), "bytes": int(f[1])})
    return out


class Enforcer:
    def __init__(self, cfg: dict, runner=run_cmd, opener=urllib.request.urlopen, clock=time.time, dry_run: bool = False) -> None:
        self.cfg = {**DEFAULTS, **cfg}
        self.run, self.opener, self.now, self.dry = runner, opener, clock, dry_run
        self.scoper = Scoper.from_config(self.cfg.get("networks"))
        self.installed: dict[str, str] = {}          # address -> DROP | RETURN, as we believe the kernel has it
        self.refused: set[str] = set()
        self.last_ok = clock()
        self.failed_open = False
        self.started = False
        self.generation = ""
        self.errors: list[str] = []

    # --- plumbing ---------------------------------------------------------------------------------------
    def _tool(self, addr: str | None = None, v6: bool = False) -> str:
        return self.cfg["ip6tables"] if (v6 or (addr is not None and ":" in addr)) else self.cfg["iptables"]

    def _ipt(self, tool: str, *args: str) -> tuple[int, str]:
        return self.run([tool, "-w", "5", *args])

    def _http(self, path: str, data: dict | None = None):
        req = urllib.request.Request(self.cfg["server"].rstrip("/") + path, method="POST" if data is not None else "GET",
                                     data=json.dumps(data).encode() if data is not None else None,
                                     headers={"Authorization": "Bearer " + self.cfg["token"], "Content-Type": "application/json"})
        return self.opener(req, timeout=6)

    # --- chain and hooks --------------------------------------------------------------------------------
    def ensure_chain(self) -> None:
        for tool in (self.cfg["iptables"], self.cfg["ip6tables"]):
            self._ipt(tool, "-N", CHAIN)                                             # exists already is fine
            for hook in ("OUTPUT", "FORWARD") if self.cfg["forward"] else ("OUTPUT",):
                if self._ipt(tool, "-C", hook, "-j", CHAIN)[0] != 0:
                    rc, out = self._ipt(tool, "-I", hook, "1", "-j", CHAIN)
                    if rc != 0 and tool == self.cfg["iptables"]:
                        raise RuntimeError(f"cannot hook {CHAIN} into {hook}: {out[:160]}")

    def _fresh_start(self) -> None:
        """First cycle: rebuild from scratch so stale rules from a crashed run can not survive."""
        self.ensure_chain()
        for tool in (self.cfg["iptables"], self.cfg["ip6tables"]):
            self._ipt(tool, "-F", CHAIN)
        self.installed = {}
        self.started = True

    def remove(self) -> tuple[bool, str]:
        if self.dry:
            return True, "dry-run: would remove the chain and its hooks"
        for tool in (self.cfg["iptables"], self.cfg["ip6tables"]):
            for hook in ("OUTPUT", "FORWARD"):
                for _ in range(5):                                                  # a duplicate hook (crashed run) is removed too
                    if self._ipt(tool, "-D", hook, "-j", CHAIN)[0] != 0:
                        break
            self._ipt(tool, "-F", CHAIN)
            self._ipt(tool, "-X", CHAIN)
        self.installed = {}
        self.started = False
        return True, "chain and hooks removed (fail-open)"

    # --- rule sync --------------------------------------------------------------------------------------
    def _valid(self, addr: str) -> bool:
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            return False
        return self.scoper.scope(addr) == "internet"

    def _rule(self, op: str, addr: str, verdict: str) -> tuple[int, str]:
        v6 = ":" in addr
        return self._ipt(self._tool(addr), op, CHAIN, "-d", f"{addr}/{128 if v6 else 32}", "-j", verdict)

    def apply(self, block: list[str], count: list[str]) -> dict:
        desired: dict[str, str] = {}
        for a in count:
            desired[a] = "RETURN"
        for a in block:
            desired[a] = "DROP"                                                     # block wins over count
        for a in list(desired):
            if not self._valid(a):
                self.refused.add(a); del desired[a]
        if len(desired) > self.cfg["max_rules"]:
            keep = sorted(desired, key=lambda a: (desired[a] != "DROP", a))[: self.cfg["max_rules"]]
            desired = {a: desired[a] for a in keep}
            self.errors.append("rule cap reached")
        if self.dry:
            return {"would_install": desired, "refused": sorted(self.refused)}
        if not self.started:
            self._fresh_start()
        else:
            self.ensure_chain()                                                     # re-hook if someone flushed the hook
        changes = 0
        for a, v in list(self.installed.items()):
            if desired.get(a) != v:                                                 # gone or verdict changed
                self._rule("-D", a, v); del self.installed[a]; changes += 1
        for a, v in desired.items():
            if a not in self.installed:
                rc, out = self._rule("-A", a, v)
                if rc == 0:
                    self.installed[a] = v; changes += 1
                else:
                    self.errors.append(f"{a}: {out[:80]}")
        return {"installed": len(self.installed), "changes": changes, "dropping": sum(1 for v in self.installed.values() if v == "DROP")}

    def fail_open(self, why: str) -> None:
        """Keep counting, stop blocking."""
        if self.failed_open:
            return
        self.failed_open = True
        self.errors.append("failed open: " + why)
        if self.dry or not self.started:
            return
        for a, v in list(self.installed.items()):
            if v == "DROP":
                self._rule("-D", a, "DROP")
                rc, _ = self._rule("-A", a, "RETURN")
                if rc == 0:
                    self.installed[a] = "RETURN"
                else:
                    del self.installed[a]

    # --- counters and the heartbeat ---------------------------------------------------------------------
    def counters(self) -> list[dict]:
        rows = []
        for tool in (self.cfg["iptables"], self.cfg["ip6tables"]):
            rc, out = self._ipt(tool, "-L", CHAIN, "-n", "-v", "-x")
            if rc == 0:
                rows.extend(parse_counters(out))
        return rows

    def heartbeat(self, summary: dict) -> bool:
        body = {"host": self.cfg["host"], "version": __version__, "enforcing": bool(self.started and not self.failed_open),
                "rules": len(self.installed), "counters": self.counters() if self.started else [],
                "detail": ("failed open: " if self.failed_open else "") + (self.errors[-1] if self.errors else "ok"), "generation_applied": 0}
        try:
            with self._http("/api/v1/secure/report", body):
                return True
        except (urllib.error.URLError, OSError, ValueError):
            return False

    # --- one cycle --------------------------------------------------------------------------------------
    def step(self) -> dict:
        try:
            with self._http("/api/v1/secure/blocklist") as r:
                bl = json.loads(r.read().decode())
            self.last_ok = self.now()
            if self.failed_open:                                                    # control is back: leave fail-open
                self.failed_open = False
            summary = self.apply(bl.get("block", []), bl.get("count", []))
            summary.update(enabled=bl.get("enabled"), generation=bl.get("generation"), refused=len(self.refused))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            if self.now() - self.last_ok > self.cfg["failopen_s"]:
                self.fail_open(f"server unreachable for {int(self.now() - self.last_ok)} s ({type(exc).__name__})")
            return {"error": f"{type(exc).__name__}: {exc}", "failed_open": self.failed_open}
        except Exception as exc:                                                    # noqa: BLE001  never leave a half-state blocking
            self.fail_open(f"{type(exc).__name__}: {exc}")
            return {"error": str(exc), "failed_open": True}
        if not self.dry:
            summary["heartbeat"] = self.heartbeat(summary)
        return summary

    def run_forever(self) -> None:
        while True:
            print(f"[enforcer] {self.step()}", flush=True)
            time.sleep(self.cfg["poll_s"])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config"); ap.add_argument("--once", action="store_true"); ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--remove", action="store_true", help="delete our chain and hooks, then exit")
    a = ap.parse_args(argv)
    cfg = {}
    if a.config:
        with open(a.config) as fh:
            cfg = json.load(fh)
    e = Enforcer(cfg, dry_run=a.dry_run)
    if a.remove:
        ok, msg = e.remove(); print(msg); return 0 if ok else 1
    if not e.cfg["token"] or not e.cfg["host"]:
        print("config: host and token are required", file=sys.stderr); return 2
    if a.once or a.dry_run:
        print(json.dumps(e.step(), indent=1, default=sorted)); return 0
    print(f"[enforcer] {__version__} host={e.cfg['host']} server={e.cfg['server']}", flush=True)
    try:
        e.run_forever()
    except KeyboardInterrupt:
        e.remove()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
