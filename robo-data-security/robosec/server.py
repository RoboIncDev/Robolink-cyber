"""robosec server: collects agent reports, categorises, raises alerts, owns the policy, serves the dashboard.

    python3 -m robosec.server --config /etc/robosec/server.json

Stdlib only (http.server + sqlite3). Binds to 127.0.0.1 by default. Three bearer tokens:
  agent_token    agents POST /api/v1/report
  gateway_token  robosec-gatewayd GET /api/v1/gateway/ruleset, POST /api/v1/gateway/{ack,flows}
  admin_token    everything else (dashboard, policy changes, alert acks)
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import sqlite3
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .categorize import UNCLASSIFIED, categorize, load_rules
from .geodb import ATTRIBUTION, ATTRIBUTION_URL, GeoDB
from .netscope import Scoper
from .nftrender import DEFAULT_POLICY, header_info, render, validate_policy

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_BODY = 2 * 1024 * 1024

DEFAULT_CFG = {
    "listen": "127.0.0.1", "port": 8750, "db": "robosec.db",
    "agent_token": "", "admin_token": "", "gateway_token": "",
    "learning_hours": 24.0,
    "categories": os.path.join(HERE, "..", "config", "categories.json"),
    "dashboard": os.path.join(HERE, "..", "dashboard", "index.html"),
    "networks": {},
    "max_learned_per_category": 4096,
    "geodb": os.path.join(HERE, "..", "geo"),       # directory built by tools/build_geodb.py; absent = locations unknown
    "home": None,                                    # {"lat": 52.5, "lon": 13.4, "label": "Berlin lab"}: where the robot is
    "static_dir": os.path.join(HERE, "..", "dashboard"),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts(host TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, agent_version TEXT, stats TEXT);
CREATE TABLE IF NOT EXISTS edges(id INTEGER PRIMARY KEY, host TEXT, dir TEXT, exe TEXT, comm TEXT, unit TEXT, cmd TEXT,
  uid INTEGER, proto TEXT, raddr TEXT, rport INTEGER, scope TEXT, category TEXT, count INTEGER, first_seen REAL,
  last_seen REAL, UNIQUE(host, dir, exe, proto, raddr, rport));
CREATE INDEX IF NOT EXISTS edges_scope ON edges(scope, dir);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts REAL, host TEXT, kind TEXT, detail TEXT, edge_id INTEGER,
  acked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS policy(id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER, body TEXT, updated REAL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts REAL, actor TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS flows(host TEXT, addr TEXT, bytes INTEGER, packets INTEGER, last_bytes INTEGER,
  last_packets INTEGER, first_seen REAL, last_seen REAL, PRIMARY KEY(host, addr));
CREATE TABLE IF NOT EXISTS gateway(host TEXT PRIMARY KEY, version INTEGER, ok INTEGER, detail TEXT, ts REAL);
"""


class Store:
    def __init__(self, path: str) -> None:
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.db.executescript(SCHEMA)
            have = {r[1] for r in self.db.execute("PRAGMA table_info(edges)")}
            for col, typ in (("cc", "TEXT"), ("asn", "INTEGER"), ("org", "TEXT")):      # databases made before geo support
                if col not in have:
                    self.db.execute(f"ALTER TABLE edges ADD COLUMN {col} {typ}")
            if not self.db.execute("SELECT 1 FROM policy").fetchone():
                body = json.dumps({k: v for k, v in DEFAULT_POLICY.items() if k != "version"})
                self.db.execute("INSERT INTO policy(id, version, body, updated) VALUES (1, 1, ?, ?)", (body, time.time()))
            self.db.commit()

    def q(self, sql: str, args: tuple = ()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def one(self, sql: str, args: tuple = ()) -> dict | None:
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args: tuple = ()) -> int:
        with self.lock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur.lastrowid or 0

    def meta(self, key: str, default: str = "") -> str:
        r = self.one("SELECT value FROM meta WHERE key=?", (key,))
        return r["value"] if r else default

    def set_meta(self, key: str, value: str) -> None:
        self.x("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def audit(self, actor: str, action: str, detail: str = "") -> None:
        self.x("INSERT INTO audit(ts, actor, action, detail) VALUES (?,?,?,?)", (time.time(), actor, action, detail))


class App:
    def __init__(self, cfg: dict) -> None:
        self.cfg = {**DEFAULT_CFG, **cfg}
        for k in ("agent_token", "admin_token", "gateway_token"):
            if not self.cfg[k] or str(self.cfg[k]).startswith("CHANGE-ME"):
                raise SystemExit(f"config: {k} must be set to a long random string "
                                 "(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')")
        if len({self.cfg["agent_token"], self.cfg["admin_token"], self.cfg["gateway_token"]}) != 3:
            raise SystemExit("config: the three tokens must be different")
        self.store = Store(self.cfg["db"])
        self.rules = load_rules(self.cfg["categories"])
        self.scoper = Scoper.from_config(self.cfg["networks"])
        try:
            self.geo = GeoDB.load(self.cfg["geodb"])
        except (OSError, ValueError) as exc:                  # a corrupt database must not stop the server
            print(f"[robosec-server] geo database not loaded: {exc}", flush=True)
            self.geo = GeoDB()
        if not self.store.meta("learning_started"):
            self.store.set_meta("learning_started", str(time.time()))

    # --- learning window --------------------------------------------------------------------------------
    def learning(self, now: float | None = None) -> bool:
        started = float(self.store.meta("learning_started", str(time.time())))
        return ((now or time.time()) - started) < self.cfg["learning_hours"] * 3600

    # --- ingest -----------------------------------------------------------------------------------------
    def ingest(self, rep: dict) -> dict:
        host = str(rep.get("host", ""))[:64]
        if not host:
            raise ValueError("host required")
        now = time.time()
        new_alerts = 0
        learning = self.learning(now)
        self.store.x("INSERT INTO hosts(host, first_seen, last_seen, agent_version, stats) VALUES(?,?,?,?,?) "
                     "ON CONFLICT(host) DO UPDATE SET last_seen=excluded.last_seen, agent_version=excluded.agent_version, "
                     "stats=excluded.stats", (host, now, now, str(rep.get("agent_version", "")),
                                              json.dumps(rep.get("stats", {}))))
        for e in rep.get("edges", [])[:2000]:
            try:
                edge = {"dir": e["dir"], "exe": str(e.get("exe", "?"))[:300], "comm": str(e.get("comm", ""))[:64],
                        "unit": str(e.get("unit", ""))[:128], "cmd": str(e.get("cmd", ""))[:200], "uid": int(e.get("uid", -1)),
                        "proto": e["proto"], "raddr": str(e["raddr"])[:64], "rport": int(e["rport"]),
                        "n": max(1, int(e.get("n", 1))), "first": float(e.get("first", now)), "last": float(e.get("last", now))}
            except (KeyError, ValueError, TypeError):
                continue
            if edge["dir"] not in ("in", "out") or edge["proto"] not in ("tcp", "udp"):
                continue
            edge["scope"] = self.scoper.scope(edge["raddr"])      # server decides scope: one source of truth
            edge["category"] = categorize(edge, self.rules)
            g = self.geo.lookup(edge["raddr"]) if edge["scope"] == "internet" else {"cc": None, "asn": 0, "org": ""}
            row = self.store.one("SELECT id FROM edges WHERE host=? AND dir=? AND exe=? AND proto=? AND raddr=? AND rport=?",
                                 (host, edge["dir"], edge["exe"], edge["proto"], edge["raddr"], edge["rport"]))
            if row is None:
                eid = self.store.x(
                    "INSERT INTO edges(host, dir, exe, comm, unit, cmd, uid, proto, raddr, rport, scope, category, count, "
                    "first_seen, last_seen, cc, asn, org) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (host, edge["dir"], edge["exe"], edge["comm"], edge["unit"], edge["cmd"], edge["uid"], edge["proto"],
                     edge["raddr"], edge["rport"], edge["scope"], edge["category"], edge["n"], edge["first"], edge["last"],
                     g["cc"], g["asn"], g["org"]))
                if edge["scope"] == "internet" and not learning:
                    kind = "new_internet_destination" if edge["dir"] == "out" else "inbound_from_internet"
                    self.store.x("INSERT INTO alerts(ts, host, kind, detail, edge_id) VALUES (?,?,?,?,?)",
                                 (now, host, kind, f"{edge['exe']} {edge['proto']} {edge['raddr']}:{edge['rport']} "
                                                   f"[{edge['category']}]", eid))
                    new_alerts += 1
            else:
                self.store.x("UPDATE edges SET count=count+?, last_seen=MAX(last_seen, ?), category=?, scope=?, comm=?, "
                             "unit=?, cmd=?, cc=COALESCE(?, cc), asn=CASE WHEN ? > 0 THEN ? ELSE asn END, "
                             "org=CASE WHEN ? != '' THEN ? ELSE org END WHERE id=?",
                             (edge["n"], edge["last"], edge["category"], edge["scope"], edge["comm"], edge["unit"],
                              edge["cmd"], g["cc"], g["asn"], g["asn"], g["org"], g["org"], row["id"]))
        return {"ok": True, "alerts": new_alerts, "learning": learning}

    def recategorize(self) -> int:
        n = 0
        for e in self.store.q("SELECT * FROM edges"):
            cat = categorize(e, self.rules)
            if cat != e["category"]:
                self.store.x("UPDATE edges SET category=? WHERE id=?", (cat, e["id"]))
                n += 1
        return n

    # --- geography --------------------------------------------------------------------------------------
    def regeocode(self) -> int:
        """Re-run the geo lookup for every internet edge (after installing a newer database). Returns rows changed."""
        n = 0
        for e in self.store.q("SELECT id, raddr, cc, asn, org FROM edges WHERE scope='internet'"):
            g = self.geo.lookup(e["raddr"])
            if (g["cc"], g["asn"], g["org"]) != (e["cc"], e["asn"] or 0, e["org"] or ""):
                self.store.x("UPDATE edges SET cc=?, asn=?, org=? WHERE id=?", (g["cc"], g["asn"], g["org"], e["id"]))
                n += 1
        return n

    def bytes_known(self) -> bool:
        return bool(self.store.one("SELECT 1 AS x FROM flows LIMIT 1"))

    def geo_summary(self, qs: dict) -> dict:
        """Where outbound internet traffic goes, by country, with the owners behind each country and which processes sent it."""
        where, args = ["scope='internet'", "dir='out'"], []
        if qs.get("host"):
            where.append("host=?"); args.append(qs["host"][0])
        if qs.get("since"):
            where.append("last_seen>=?"); args.append(time.time() - float(qs["since"][0]))
        rows = self.store.q("SELECT e.host, e.exe, e.raddr, e.rport, e.cc, e.asn, e.org, e.count, e.category, "
                            "COALESCE((SELECT SUM(bytes) FROM flows f WHERE f.addr=e.raddr), 0) AS bytes "
                            f"FROM edges e WHERE {' AND '.join(where)}", tuple(args))
        known = self.bytes_known()
        by_cc: dict = {}
        dest_seen: dict = {}
        for r in rows:
            key = r["cc"] or ""
            c = by_cc.setdefault(key, {"cc": key or None, "destinations": set(), "edges": 0, "bytes": 0, "orgs": {}, "processes": {},
                                       "computers": set(), "categories": {}})
            c["destinations"].add(r["raddr"]); c["edges"] += 1; c["computers"].add(r["host"])
            first = (key, r["raddr"]) not in dest_seen
            dest_seen[(key, r["raddr"])] = True
            if first:
                c["bytes"] += r["bytes"]                       # bytes belong to the address: count each address once
            o = c["orgs"].setdefault((r["asn"] or 0, r["org"] or ""), {"asn": r["asn"] or 0, "org": r["org"] or "", "dests": set(), "bytes": 0})
            if r["raddr"] not in o["dests"]:
                o["bytes"] += r["bytes"]
            o["dests"].add(r["raddr"])
            p = c["processes"].setdefault(r["exe"], {"exe": r["exe"], "edges": 0}); p["edges"] += 1
            c["categories"][r["category"]] = c["categories"].get(r["category"], 0) + 1
        out = []
        for c in by_cc.values():
            orgs = sorted(({"asn": o["asn"], "org": o["org"], "destinations": len(o["dests"]), "bytes": o["bytes"] if known else None}
                           for o in c["orgs"].values()), key=lambda o: -o["destinations"])
            out.append({"cc": c["cc"], "destinations": len(c["destinations"]), "edges": c["edges"],
                        "bytes": c["bytes"] if known else None, "computers": sorted(c["computers"]),
                        "orgs": orgs[:12], "processes": sorted(c["processes"].values(), key=lambda p: -p["edges"])[:8],
                        "categories": c["categories"]})
        located = sorted((c for c in out if c["cc"]), key=lambda c: -c["destinations"])
        unlocated = next((c for c in out if not c["cc"]), None)
        return {"available": self.geo.available, "release": self.geo.meta.get("release", ""), "built": self.geo.meta.get("built", ""),
                "attribution": ATTRIBUTION, "attribution_url": ATTRIBUTION_URL, "home": self.cfg.get("home"),
                "bytes_known": known, "countries": located,
                "unlocated": {"destinations": unlocated["destinations"], "edges": unlocated["edges"]} if unlocated else None}

    # --- flows (bytes) ----------------------------------------------------------------------------------
    def ingest_flows(self, host: str, flows: list[dict]) -> int:
        now, n = time.time(), 0
        for f in flows[:20000]:
            try:
                addr, b, p = str(f["addr"]), int(f["bytes"]), int(f.get("packets", 0))
            except (KeyError, ValueError, TypeError):
                continue
            row = self.store.one("SELECT bytes, packets, last_bytes, last_packets FROM flows WHERE host=? AND addr=?", (host, addr))
            if row is None:
                self.store.x("INSERT INTO flows(host, addr, bytes, packets, last_bytes, last_packets, first_seen, last_seen) "
                             "VALUES (?,?,?,?,?,?,?,?)", (host, addr, b, p, b, p, now, now))
            else:
                db = b - row["last_bytes"] if b >= row["last_bytes"] else b       # counter reset after a rule reload
                dp = p - row["last_packets"] if p >= row["last_packets"] else p
                self.store.x("UPDATE flows SET bytes=bytes+?, packets=packets+?, last_bytes=?, last_packets=?, last_seen=? "
                             "WHERE host=? AND addr=?", (db, dp, b, p, now, host, addr))
            n += 1
        return n

    # --- policy -----------------------------------------------------------------------------------------
    def policy(self) -> dict:
        r = self.store.one("SELECT version, body, updated FROM policy WHERE id=1")
        body = json.loads(r["body"])
        return validate_policy({**body, "version": r["version"]}) | {"updated": r["updated"]}

    def set_policy(self, patch: dict, actor: str) -> dict:
        cur = self.policy()
        merged = {k: v for k, v in cur.items() if k not in ("version", "updated")}
        for k, v in patch.items():
            if k in ("version", "updated"):
                continue
            if k == "categories":
                merged["categories"] = {**merged.get("categories", {}), **v}
            else:
                merged[k] = v
        merged = validate_policy(merged)
        merged.pop("version", None)
        self.store.x("UPDATE policy SET version=version+1, body=?, updated=? WHERE id=1", (json.dumps(merged), time.time()))
        self.store.audit(actor, "policy_update", json.dumps(patch)[:500])
        return self.policy()

    def learned(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        cap = self.cfg["max_learned_per_category"]
        for r in self.store.q("SELECT category, raddr FROM edges WHERE scope='internet' AND dir='out' "
                              "GROUP BY category, raddr ORDER BY category, raddr"):
            lst = out.setdefault(r["category"], [])
            if len(lst) < cap:
                lst.append(r["raddr"])
        return out

    def ruleset(self) -> str:
        return render(self.policy(), self.scoper, self.learned())

    # --- read models ------------------------------------------------------------------------------------
    def summary(self) -> dict:
        s = self.store
        hosts = s.q("SELECT host, first_seen, last_seen, agent_version, stats FROM hosts ORDER BY host")
        for h in hosts:
            h["stats"] = json.loads(h["stats"] or "{}")
        by_scope = s.q("SELECT host, scope, COUNT(*) AS edges FROM edges GROUP BY host, scope")
        cats = s.q("SELECT category, COUNT(*) AS edges, COUNT(DISTINCT raddr) AS destinations FROM edges "
                   "WHERE scope='internet' AND dir='out' GROUP BY category ORDER BY edges DESC")
        sent = {r["addr"]: r["bytes"] for r in s.q("SELECT addr, SUM(bytes) AS bytes FROM flows GROUP BY addr")}
        for c in cats:
            addrs = [r["raddr"] for r in s.q("SELECT DISTINCT raddr FROM edges WHERE category=? AND scope='internet' "
                                             "AND dir='out'", (c["category"],))]
            c["bytes_sent"] = sum(sent.get(a, 0) for a in addrs)
        started = float(s.meta("learning_started", str(time.time())))
        return {"version": __version__, "now": time.time(), "hosts": hosts, "by_scope": by_scope,
                "internet_categories": cats, "open_alerts": s.one("SELECT COUNT(*) AS n FROM alerts WHERE acked=0")["n"],
                "learning": self.learning(), "learning_ends": started + self.cfg["learning_hours"] * 3600,
                "learning_hours": self.cfg["learning_hours"],
                "policy": self.policy(), "bytes_known": self.bytes_known(),
                "geo": {"available": self.geo.available, "release": self.geo.meta.get("release", ""),
                        "attribution": ATTRIBUTION, "attribution_url": ATTRIBUTION_URL},
                "gateway": s.q("SELECT host, version, ok, detail, ts FROM gateway")}

    def edges(self, qs: dict) -> list[dict]:
        where, args = [], []
        for col in ("host", "scope", "category", "dir", "cc"):
            if qs.get(col):
                where.append(f"{col}=?")
                args.append(qs[col][0])
        if qs.get("q"):
            where.append("(exe LIKE ? OR raddr LIKE ? OR cmd LIKE ?)")
            args += [f"%{qs['q'][0]}%"] * 3
        limit = min(int(qs.get("limit", ["500"])[0]), 5000)
        sql = ("SELECT e.*, COALESCE((SELECT SUM(bytes) FROM flows f WHERE f.addr=e.raddr), 0) AS bytes_to_dest FROM edges e"
               + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY last_seen DESC LIMIT ?")
        return self.store.q(sql, tuple(args) + (limit,))


class Handler(BaseHTTPRequestHandler):
    app: App
    server_version = "robosec"

    def log_message(self, *a) -> None:      # silence per-request logging
        pass

    # --- helpers ---------------------------------------------------------------------------------------
    def _send(self, code: int, body, ctype: str = "application/json", extra: dict | None = None) -> None:
        data = body if isinstance(body, bytes) else (body.encode() if isinstance(body, str) else json.dumps(body).encode())
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if "Cache-Control" not in (extra or {}):
            self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _role(self) -> str:
        auth = self.headers.get("Authorization", "")
        tok = auth[7:] if auth.startswith("Bearer ") else ""
        for role in ("admin", "gateway", "agent"):
            want = self.app.cfg[f"{role}_token"]
            if tok and hmac.compare_digest(tok.encode(), want.encode()):
                return role
        return ""

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", "0") or 0)
        if n > MAX_BODY:
            raise ValueError("body too large")
        raw = self.rfile.read(n) if n else b"{}"
        obj = json.loads(raw or b"{}")
        if not isinstance(obj, dict):
            raise ValueError("JSON object expected")
        return obj

    def _need(self, *roles: str) -> bool:
        role = self._role()
        if role not in roles and role != "admin":
            self._send(401 if not role else 403, {"error": "unauthorized"})
            return False
        return True

    STATIC_TYPES = {".woff2": "font/woff2", ".json": "application/json", ".svg": "image/svg+xml"}

    def _static(self, rel: str) -> None:
        """Serve a file from dashboard/fonts or dashboard/map only. No path tricks, no other directories, no other types."""
        parts = rel.split("/")
        ext = os.path.splitext(rel)[1].lower()
        if (len(parts) != 2 or parts[0] not in ("fonts", "map") or ext not in self.STATIC_TYPES
                or not re.fullmatch(r"[A-Za-z0-9._-]+", parts[1]) or parts[1].startswith(".")):
            return self._send(404, {"error": "not found"})
        path = os.path.join(self.app.cfg["static_dir"], parts[0], parts[1])
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            return self._send(404, {"error": "not found"})
        return self._send(200, data, self.STATIC_TYPES[ext], {"Cache-Control": "public, max-age=3600"})

    # --- routes ----------------------------------------------------------------------------------------
    def do_GET(self) -> None:                 # noqa: N802
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        a = self.app
        try:
            if u.path == "/healthz":
                return self._send(200, {"ok": True, "version": __version__})
            if u.path in ("/", "/index.html"):
                try:
                    with open(a.cfg["dashboard"], "rb") as fh:
                        return self._send(200, fh.read(), "text/html; charset=utf-8")
                except OSError:
                    return self._send(404, {"error": "dashboard not installed"})
            if u.path.startswith("/static/"):
                return self._static(u.path[len("/static/"):])
            if u.path == "/api/v1/gateway/ruleset":
                if not self._need("gateway"):
                    return
                text = a.ruleset()
                info = header_info(text)
                return self._send(200, text, "text/plain; charset=utf-8",
                                  {"X-Robosec-Version": str(info.get("version", 0)),
                                   "X-Robosec-Digest": info.get("digest", ""), "X-Robosec-Mode": info.get("mode", "")})
            if not self._need("admin"):
                return
            if u.path == "/api/v1/summary":
                return self._send(200, a.summary())
            if u.path == "/api/v1/geo/summary":
                return self._send(200, a.geo_summary(qs))
            if u.path == "/api/v1/edges":
                return self._send(200, {"edges": a.edges(qs)})
            if u.path == "/api/v1/alerts":
                return self._send(200, {"alerts": a.store.q("SELECT * FROM alerts ORDER BY ts DESC LIMIT 500")})
            if u.path == "/api/v1/policy":
                return self._send(200, a.policy())
            if u.path == "/api/v1/audit":
                return self._send(200, {"audit": a.store.q("SELECT * FROM audit ORDER BY ts DESC LIMIT 200")})
            if u.path == "/api/v1/categories":
                return self._send(200, {"categories": a.rules})
            return self._send(404, {"error": "not found"})
        except Exception as exc:               # noqa: BLE001
            return self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

    def do_POST(self) -> None:                # noqa: N802
        u = urllib.parse.urlparse(self.path)
        a = self.app
        try:
            if u.path == "/api/v1/report":
                if not self._need("agent"):
                    return
                return self._send(200, a.ingest(self._body()))
            if u.path == "/api/v1/gateway/ack":
                if not self._need("gateway"):
                    return
                b = self._body()
                a.store.x("INSERT INTO gateway(host, version, ok, detail, ts) VALUES (?,?,?,?,?) ON CONFLICT(host) DO UPDATE "
                          "SET version=excluded.version, ok=excluded.ok, detail=excluded.detail, ts=excluded.ts",
                          (str(b.get("host", "gateway")), int(b.get("version", 0)), 1 if b.get("ok") else 0,
                           str(b.get("detail", ""))[:300], time.time()))
                return self._send(200, {"ok": True})
            if u.path == "/api/v1/gateway/flows":
                if not self._need("gateway"):
                    return
                b = self._body()
                return self._send(200, {"ok": True, "updated": a.ingest_flows(str(b.get("host", "gateway")), b.get("flows", []))})
            if not self._need("admin"):
                return
            if u.path.startswith("/api/v1/alerts/") and u.path.endswith("/ack"):
                aid = int(u.path.split("/")[4])
                a.store.x("UPDATE alerts SET acked=1 WHERE id=?", (aid,))
                a.store.audit("admin", "alert_ack", str(aid))
                return self._send(200, {"ok": True})
            if u.path == "/api/v1/regeocode":
                return self._send(200, {"ok": True, "changed": a.regeocode()})
            if u.path == "/api/v1/recategorize":
                return self._send(200, {"ok": True, "changed": a.recategorize()})
            if u.path == "/api/v1/learning/restart":
                a.store.set_meta("learning_started", str(time.time()))
                a.store.audit("admin", "learning_restart")
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "not found"})
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            return self._send(400, {"error": str(exc)})
        except Exception as exc:               # noqa: BLE001
            return self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

    def do_PUT(self) -> None:                 # noqa: N802
        u = urllib.parse.urlparse(self.path)
        try:
            if u.path == "/api/v1/policy":
                if not self._need("admin"):
                    return
                return self._send(200, self.app.set_policy(self._body(), "admin"))
            return self._send(404, {"error": "not found"})
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            return self._send(400, {"error": str(exc)})


def make_server(cfg: dict) -> tuple[ThreadingHTTPServer, App]:
    app = App(cfg)
    handler = type("BoundHandler", (Handler,), {"app": app})
    srv = ThreadingHTTPServer((app.cfg["listen"], int(app.cfg["port"])), handler)
    srv.daemon_threads = True
    return srv, app


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True)
    a = ap.parse_args(argv)
    with open(a.config) as fh:
        cfg = json.load(fh)
    srv, app = make_server(cfg)
    print(f"[robosec-server] {__version__} listening on {app.cfg['listen']}:{app.cfg['port']} "
          f"(learning window {app.cfg['learning_hours']} h)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
