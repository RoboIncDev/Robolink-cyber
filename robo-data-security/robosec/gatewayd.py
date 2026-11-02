"""robosec-gatewayd: runs as root on the egress gateway (PC2). Pulls the ruleset, applies it safely,
and reports per-destination byte counters back to the server.

    python3 -m robosec.gatewayd --config /etc/robosec/gatewayd.json             # run forever
    python3 -m robosec.gatewayd --config ... --once --dry-run                   # fetch, check, print
    python3 -m robosec.gatewayd --remove                                        # delete our table (fail-open)

SAFETY MODEL
  * Fail OPEN. Any error after our table was touched, any failed health check, or --remove deletes
    `table inet robosec` so traffic flows as if this tool were absent. A security tool on a robot must
    never be the reason a safety-relevant link goes down. (A `fail_closed` option is a future decision.)
  * Check before apply (`nft -c -f`), apply atomically (one transaction), verify (can we still reach the
    server?), roll back to the previous table on failure.
  * Only `table inet robosec` is ever created, replaced or deleted.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from . import __version__

DEFAULTS = {
    "host": "pc2", "server": "http://127.0.0.1:8750", "token": "",
    "poll_s": 15, "flows_s": 30, "verify_s": 10, "state_file": "/var/lib/robosec/gateway.state",
    "nft": "nft",
}
TABLE = "inet robosec"


def run_cmd(argv: list[str], inp: str | None = None, timeout: int = 20) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, input=inp, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, f"{type(exc).__name__}: {exc}"


def parse_flows(nft_json: dict) -> list[dict]:
    """Extract [{addr, bytes, packets}] from `nft -j list set inet robosec flows4|flows6`."""
    out = []
    for item in nft_json.get("nftables", []):
        s = item.get("set")
        if not s:
            continue
        for el in s.get("elem", []) or []:
            if not isinstance(el, dict):
                continue                                   # nft prints bare values for sets without counters
            e = el.get("elem", el)
            if not isinstance(e, dict):
                continue
            val, ctr = e.get("val"), e.get("counter")
            if isinstance(val, str) and isinstance(ctr, dict):
                out.append({"addr": val, "bytes": int(ctr.get("bytes", 0)), "packets": int(ctr.get("packets", 0))})
    return out


class Gatewayd:
    def __init__(self, cfg: dict, runner=run_cmd, opener=urllib.request.urlopen, dry_run: bool = False) -> None:
        self.cfg = {**DEFAULTS, **cfg}
        self.run = runner
        self.opener = opener
        self.dry = dry_run
        self.applied_digest = ""
        self.applied_version = 0

    # --- http -------------------------------------------------------------------------------------------
    def _req(self, path: str, data: dict | None = None):
        r = urllib.request.Request(self.cfg["server"].rstrip("/") + path, method="POST" if data is not None else "GET",
                                   data=json.dumps(data).encode() if data is not None else None,
                                   headers={"Authorization": "Bearer " + self.cfg["token"],
                                            "Content-Type": "application/json"})
        return self.opener(r, timeout=8)

    def fetch(self) -> tuple[str, dict] | None:
        try:
            with self._req("/api/v1/gateway/ruleset") as r:
                return r.read().decode(), {k.lower(): v for k, v in r.headers.items()}
        except (urllib.error.URLError, OSError, ValueError):
            return None

    def ack(self, version: int, ok: bool, detail: str) -> None:
        try:
            with self._req("/api/v1/gateway/ack", {"host": self.cfg["host"], "version": version, "ok": ok, "detail": detail}):
                pass
        except (urllib.error.URLError, OSError, ValueError):
            pass

    def server_reachable(self) -> bool:
        try:
            with self.opener(urllib.request.Request(self.cfg["server"].rstrip("/") + "/healthz"), timeout=5) as r:
                return r.status == 200
        except (urllib.error.URLError, OSError, ValueError):
            return False

    # --- nft --------------------------------------------------------------------------------------------
    def table_exists(self) -> bool:
        rc, _ = self.run([self.cfg["nft"], "list", "table", *TABLE.split()])
        return rc == 0

    def remove(self) -> tuple[bool, str]:
        if self.dry:
            return True, "dry-run: would delete table"
        if not self.table_exists():
            return True, "no robosec table present"
        rc, out = self.run([self.cfg["nft"], "delete", "table", *TABLE.split()])
        return rc == 0, out or "table deleted (fail-open)"

    def apply(self, text: str, version: int, digest: str) -> tuple[bool, str]:
        with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as fh:
            fh.write(text)
            path = fh.name
        try:
            rc, out = self.run([self.cfg["nft"], "-c", "-f", path])
            if rc != 0:
                return False, f"check failed, nothing applied: {out[:300]}"
            if self.dry:
                return True, "dry-run: ruleset passes nft -c"
            backup = ""
            if self.table_exists():
                rc, backup = self.run([self.cfg["nft"], "list", "table", *TABLE.split()])
                if rc != 0:
                    backup = ""
            rc, out = self.run([self.cfg["nft"], "-f", path])
            if rc != 0:
                self._restore(backup)
                return False, f"apply failed, restored previous: {out[:300]}"
            deadline = time.time() + self.cfg["verify_s"]
            healthy = False
            while time.time() < deadline:
                if self.server_reachable():
                    healthy = True
                    break
                time.sleep(1)
            if not healthy:
                self._restore(backup)
                return False, "server unreachable after apply, restored previous ruleset (or removed ours)"
            self.applied_digest, self.applied_version = digest, version
            self._save_state()
            return True, "applied"
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _restore(self, backup: str) -> None:
        if backup:
            with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as fh:
                fh.write(f"add table {TABLE}\ndelete table {TABLE}\n{backup}\n")
                path = fh.name
            rc, _ = self.run([self.cfg["nft"], "-f", path])
            os.unlink(path)
            if rc == 0:
                return
        self.remove()                                          # fail-open if we cannot restore

    def _save_state(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.cfg["state_file"]), exist_ok=True)
            with open(self.cfg["state_file"], "w") as fh:
                json.dump({"digest": self.applied_digest, "version": self.applied_version, "ts": time.time()}, fh)
        except OSError:
            pass

    # --- flows ------------------------------------------------------------------------------------------
    def collect_flows(self) -> list[dict]:
        flows: list[dict] = []
        for name in ("flows4", "flows6"):
            rc, out = self.run([self.cfg["nft"], "-j", "list", "set", *TABLE.split(), name])
            if rc == 0:
                try:
                    flows.extend(parse_flows(json.loads(out)))
                except ValueError:
                    pass
        return flows

    def push_flows(self) -> None:
        flows = self.collect_flows()
        if not flows:
            return
        try:
            with self._req("/api/v1/gateway/flows", {"host": self.cfg["host"], "flows": flows}):
                pass
        except (urllib.error.URLError, OSError, ValueError):
            pass

    # --- loop -------------------------------------------------------------------------------------------
    def step(self) -> str:
        got = self.fetch()
        if got is None:
            return "server unreachable; leaving the current ruleset as is"
        text, hdr = got
        digest = hdr.get("x-robosec-digest", "")
        version = int(hdr.get("x-robosec-version", "0") or 0)
        if digest and digest == self.applied_digest and self.table_exists():
            return "up to date"
        ok, detail = self.apply(text, version, digest)
        self.ack(version, ok, detail)
        return detail

    def run_forever(self) -> None:
        last_flows = 0.0
        while True:
            try:
                msg = self.step()
                print(f"[gatewayd] {msg}", flush=True)
                if time.time() - last_flows >= self.cfg["flows_s"]:
                    self.push_flows()
                    last_flows = time.time()
            except Exception as exc:                            # noqa: BLE001  (never die; never leave a bad table)
                print(f"[gatewayd] error {type(exc).__name__}: {exc}; failing open", file=sys.stderr, flush=True)
                self.remove()
            time.sleep(self.cfg["poll_s"])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--remove", action="store_true", help="delete table inet robosec and exit (fail-open)")
    a = ap.parse_args(argv)
    cfg = {}
    if a.config:
        with open(a.config) as fh:
            cfg = json.load(fh)
    g = Gatewayd(cfg, dry_run=a.dry_run)
    if a.remove:
        ok, msg = g.remove()
        print(msg)
        return 0 if ok else 1
    if not g.cfg["token"]:
        print("config: token required", file=sys.stderr)
        return 2
    if a.once:
        print(g.step())
        return 0
    print(f"[gatewayd] {__version__} host={g.cfg['host']} server={g.cfg['server']}", flush=True)
    g.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
