"""'Secure data': state, the block list the enforcers pull, and the "Data sent abroad" report.

What "abroad" means here: an outbound connection whose destination is an INTERNET address located in a country other than the
configured home country. Addresses the geo database cannot place are reported as "not located" and are NOT blocked: blocking what
we cannot name would be guessing. Robot-internal, LAN, VPN and local destinations are never part of any list.

Honesty rules this module keeps: a country comes from a registry database (approximate); bytes are None (never 0) when no counter
exists; "secured" is claimed only for computers that have an enforcer reporting in, and the status says which ones do not.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import time

SECURE_DEFAULT = {"enabled": False, "until": None, "exempt_categories": ["remote-access", "dns", "time-sync"], "set_at": None, "set_by": None}
DURATIONS = (0, 3600, 28800, 86400)          # 0 = until switched off
MAX_LIST = 4096


class SecureService:
    def __init__(self, app) -> None:
        self.app = app
        self._names: dict | None = None

    # --- home ------------------------------------------------------------------------------------------
    def home(self) -> dict | None:
        h = self.app.cfg.get("home")
        return h if isinstance(h, dict) and h.get("country") else None

    def home_cc(self) -> str | None:
        h = self.home()
        return str(h["country"]).upper() if h else None

    def names(self) -> dict:
        if self._names is None:
            self._names = {}
            try:
                with open(os.path.join(self.app.cfg["static_dir"], "map", "world.json")) as fh:
                    m = json.load(fh)
                for c in list(m.get("countries", [])) + list(m.get("points", [])):
                    self._names[c["cc"]] = c["name"]
            except (OSError, ValueError, KeyError):
                pass
        return self._names

    def name(self, cc: str | None) -> str:
        return self.names().get(cc or "", cc or "Not located")

    # --- state -----------------------------------------------------------------------------------------
    def _load(self) -> dict:
        raw = self.app.store.meta("secure", "")
        try:
            return {**SECURE_DEFAULT, **json.loads(raw)} if raw else dict(SECURE_DEFAULT)
        except ValueError:
            return dict(SECURE_DEFAULT)

    def state(self, now: float | None = None) -> dict:
        now = now or time.time()
        s = self._load()
        if s["enabled"] and s["until"] and now >= s["until"]:
            s["enabled"] = False
            self.app.store.set_meta("secure", json.dumps(s))
            self.app.store.audit("system", "secure_expired", "timer ran out")
        s["seconds_left"] = max(0, int(s["until"] - now)) if s["enabled"] and s["until"] else None
        return s

    def set_state(self, body: dict, actor: str = "admin") -> dict:
        cur = self._load()
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be true or false")
        known = {c["id"] for c in self.app.rules} | {"unclassified"}
        ex = body.get("exempt_categories", cur["exempt_categories"])
        if not isinstance(ex, list) or any(x not in known for x in ex):
            raise ValueError("exempt_categories must list known category ids")
        until = None
        if enabled:
            if not self.home_cc():
                raise ValueError("home country is not set (add \"home\": {\"country\": \"US\", ...} to server.json)")
            dur = int(body.get("duration_s", 3600))
            if dur not in DURATIONS:
                raise ValueError("duration_s must be one of %s" % (DURATIONS,))
            until = time.time() + dur if dur else None
        s = {"enabled": enabled, "until": until, "exempt_categories": sorted(set(ex)), "set_at": time.time(), "set_by": actor}
        self.app.store.set_meta("secure", json.dumps(s))
        self.app.store.audit(actor, "secure_on" if enabled else "secure_off", json.dumps({k: s[k] for k in ("until", "exempt_categories")}))
        return self.state()

    # --- address sets ----------------------------------------------------------------------------------
    def _internet_out(self) -> list[dict]:
        return self.app.store.q("SELECT host, exe, raddr, rport, cc, org, category, count, first_seen, last_seen FROM edges "
                                "WHERE scope='internet' AND dir='out'")

    def sets(self, st: dict | None = None) -> tuple[set, set, set, set]:
        """(foreign_all, exempt, block, count_only). An address shared by an exempt and a non-exempt edge is exempt (fail open)."""
        st = st or self.state()
        home = self.home_cc()
        rows = self._internet_out()
        exempt_cats = set(st["exempt_categories"])
        exempt = {r["raddr"] for r in rows if r["category"] in exempt_cats}
        foreign = {r["raddr"] for r in rows if r["cc"] and home and r["cc"] != home}
        block = foreign - exempt
        return foreign, exempt & foreign, block, foreign - block

    def blocklist(self) -> dict:
        st = self.state()
        foreign, _, block, count = self.sets(st)
        if not st["enabled"]:
            block, count = set(), foreign                  # not secured: count bytes, block nothing
        b, c = sorted(block)[:MAX_LIST], sorted(count)[:MAX_LIST]
        gen = hashlib.sha1(json.dumps([st["enabled"], b, c]).encode()).hexdigest()[:12]
        return {"enabled": st["enabled"], "until": st["until"], "home_cc": self.home_cc(), "block": b, "count": c, "generation": gen}

    def lookup(self, ips: list) -> dict:
        out = {}
        home = self.home_cc()
        for ip in list(ips)[:200]:
            ip = str(ip)
            if self.app.scoper.scope(ip) != "internet":
                out[ip] = {"cc": None, "foreign": False}
                continue
            g = self.app.geo.lookup(ip)
            out[ip] = {"cc": g["cc"], "foreign": bool(g["cc"] and home and g["cc"] != home)}
        return out

    # --- enforcer reports ------------------------------------------------------------------------------
    def ingest_report(self, host: str, body: dict) -> dict:
        now = time.time()
        host = str(host)[:64]
        self.app.store.x("INSERT INTO enforcers(host, ts, enforcing, rules, detail, version) VALUES (?,?,?,?,?,?) ON CONFLICT(host) DO UPDATE SET "
                         "ts=excluded.ts, enforcing=excluded.enforcing, rules=excluded.rules, detail=excluded.detail, version=excluded.version",
                         (host, now, 1 if body.get("enforcing") else 0, int(body.get("rules", 0)), str(body.get("detail", ""))[:300], int(body.get("generation_applied", 0) or 0)))
        sent = [c for c in body.get("counters", []) if c.get("verdict") == "RETURN"]
        dropped = [c for c in body.get("counters", []) if c.get("verdict") == "DROP"]
        self.app.ingest_counters("flows", host, sent)
        self.app.ingest_counters("blocked", host, dropped)
        return {"ok": True}

    def active_enforcers(self, now: float | None = None) -> dict:
        now = now or time.time()
        stale = self.app.cfg.get("enforcer_stale_s", 45)
        return {r["host"]: r for r in self.app.store.q("SELECT * FROM enforcers WHERE ts >= ?", (now - stale,))}

    def status(self) -> dict:
        st = self.state()
        foreign, exempt, block, count = self.sets(st)
        hosts = [h["host"] for h in self.app.store.q("SELECT host FROM hosts ORDER BY host")]
        act = self.active_enforcers()
        missing = [h for h in hosts if h not in act]
        bl = self.app.store.one("SELECT SUM(bytes) AS b, SUM(packets) AS p FROM blocked")
        if not self.home_cc():
            label = "needs_home"
        elif not st["enabled"]:
            label = "open" if foreign else "quiet"
        elif not act:
            label = "waiting"
        elif missing:
            label = "partial"
        else:
            label = "secured"
        return {"label": label, "home": self.home(), "home_cc": self.home_cc(), "state": st,
                "enforcers": [{"host": h, "active": h in act, "blocking": bool(act[h]["enforcing"]) if h in act else False,
                               "rules": act[h]["rules"] if h in act else 0, "detail": act[h]["detail"] if h in act else "not installed or not reporting",
                               "age_s": round(time.time() - act[h]["ts"], 1) if h in act else None} for h in hosts],
                "coverage": {"active": len(act), "total": len(hosts), "missing": missing},
                "foreign": {"destinations": len(foreign), "would_block": len(block), "exempt": len(exempt),
                            "countries": len({r["cc"] for r in self._internet_out() if r["cc"] and r["cc"] != self.home_cc()})},
                "blocked": {"bytes": bl["b"], "packets": bl["p"]} if bl and bl["b"] is not None else None}

    # --- report ----------------------------------------------------------------------------------------
    def _bytes_maps(self) -> tuple[dict | None, dict | None]:
        sent = {r["addr"]: r["b"] for r in self.app.store.q("SELECT addr, SUM(bytes) AS b FROM flows GROUP BY addr")}
        blk = {r["addr"]: r["b"] for r in self.app.store.q("SELECT addr, SUM(bytes) AS b FROM blocked GROUP BY addr")}
        return (sent or None), (blk or None)

    def rows(self, since: float = 0) -> list[dict]:
        home = self.home_cc()
        if not home:
            return []
        now = time.time()
        st = self.state()
        _, _, block, _ = self.sets(st)
        act = self.active_enforcers()
        sent, blk = self._bytes_maps()
        out = []
        for r in self._internet_out():
            if not r["cc"] or r["cc"] == home or (since and r["last_seen"] < now - since):
                continue
            blocked_now = st["enabled"] and r["raddr"] in block
            if blocked_now and r["host"] in act:
                status = "secured"
            elif blocked_now:
                status = "not enforced on " + r["host"]
            elif st["enabled"]:
                status = "exempt"
            else:
                status = "open"
            r = dict(r, program=(r["exe"] or "?").split("/")[-1], status=status,
                     bytes_sent=(sent or {}).get(r["raddr"]) if sent is not None else None,
                     bytes_blocked=(blk or {}).get(r["raddr"]) if blk is not None else None)
            out.append(r)
        return out

    def report(self, since: float = 86400) -> dict:
        now = time.time()
        home = self.home_cc()
        if not home:
            return {"needs_home": True, "home": None, "generated": now}
        rows = self.rows(since)
        sent, blk = self._bytes_maps()
        by: dict = {}
        for r in rows:
            c = by.setdefault(r["cc"], {"cc": r["cc"], "name": self.name(r["cc"]), "addrs": set(), "edges": 0, "computers": set(), "orgs": {},
                                        "programs": {}, "first_seen": r["first_seen"], "last_seen": r["last_seen"], "statuses": {}})
            c["addrs"].add(r["raddr"]); c["edges"] += 1; c["computers"].add(r["host"])
            c["first_seen"] = min(c["first_seen"], r["first_seen"]); c["last_seen"] = max(c["last_seen"], r["last_seen"])
            o = c["orgs"].setdefault(r["org"] or "Unknown owner", set()); o.add(r["raddr"])
            p = c["programs"].setdefault((r["host"], r["program"]), {"host": r["host"], "program": r["program"], "category": r["category"], "edges": 0}); p["edges"] += 1
            c["statuses"][r["status"]] = c["statuses"].get(r["status"], 0) + 1
        countries = []
        for c in by.values():
            addrs = c["addrs"]
            countries.append({
                "cc": c["cc"], "name": c["name"], "destinations": len(addrs), "edges": c["edges"], "computers": sorted(c["computers"]),
                "owners": sorted(({"org": k, "destinations": len(v)} for k, v in c["orgs"].items()), key=lambda o: -o["destinations"])[:8],
                "programs": sorted(c["programs"].values(), key=lambda p: -p["edges"])[:8], "first_seen": c["first_seen"], "last_seen": c["last_seen"],
                "new": bool(since and c["first_seen"] >= now - since), "statuses": c["statuses"],
                "bytes_sent": sum((sent or {}).get(a, 0) for a in addrs) if sent is not None else None,
                "bytes_blocked": sum((blk or {}).get(a, 0) for a in addrs) if blk is not None else None})
        countries.sort(key=lambda c: -c["destinations"])
        allad = {r["raddr"] for r in rows}
        unl = [r for r in self._internet_out() if not r["cc"] and (not since or r["last_seen"] >= now - since)]
        return {"home": self.home(), "home_cc": home, "home_name": self.name(home), "generated": now, "since_s": since,
                "totals": {"destinations": len(allad), "countries": len(countries), "computers": len({r["host"] for r in rows}),
                           "programs": len({(r["host"], r["program"]) for r in rows}),
                           "bytes_sent": sum((sent or {}).get(a, 0) for a in allad) if sent is not None else None,
                           "bytes_blocked": sum((blk or {}).get(a, 0) for a in allad) if blk is not None else None},
                "countries": countries, "unlocated": {"destinations": len({r["raddr"] for r in unl}), "edges": len(unl)} if unl else None,
                "secure": self.state(), "notes": ["Countries come from a registry database and are approximate; a content network is placed where it is registered.",
                                                  "This report shows who the robot connected to and where, not what was sent."]}

    def csv(self, since: float = 86400) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["computer", "program", "destination", "port", "country_code", "country", "owner", "category", "first_seen_utc", "last_seen_utc",
                    "samples_seen", "bytes_sent", "bytes_blocked", "status"])
        iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) if t else ""
        safe = lambda v: ("'" + v) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v    # spreadsheet formula guard
        for r in sorted(self.rows(since), key=lambda r: (r["cc"], r["host"], r["program"], r["raddr"])):
            w.writerow([safe(x) for x in (r["host"], r["program"], r["raddr"], r["rport"], r["cc"], self.name(r["cc"]), r["org"] or "", r["category"], iso(r["first_seen"]),
                        iso(r["last_seen"]), r["count"], "" if r["bytes_sent"] is None else r["bytes_sent"], "" if r["bytes_blocked"] is None else r["bytes_blocked"], r["status"])])
        return buf.getvalue()
