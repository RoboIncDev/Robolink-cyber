import csv, io, json, os, re, tempfile, threading, time, unittest, urllib.error, urllib.request
from robosec.server import make_server
from tests.test_geodb import make_db
from tests.test_server import AD, AG, GW, CATS, DASH, call, edge

HERE = os.path.dirname(__file__)
HOME_US = {"country": "US", "lat": 39.83, "lon": -98.58, "label": "United States"}


class Base(unittest.TestCase):
    home = HOME_US

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="robosec-secure-")
        cfg = {"listen": "127.0.0.1", "port": 0, "db": os.path.join(self.tmp, "t.db"), "agent_token": AG, "gateway_token": GW, "admin_token": AD,
               "learning_hours": 0.0, "categories": CATS, "dashboard": DASH, "geodb": make_db()[2], "static_dir": os.path.join(HERE, "..", "dashboard"),
               "home": self.home}
        self.srv, self.app = make_server(cfg)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()

    def report(self, edges, host="pc3"):
        return call(self.base, "POST", "/api/v1/report", AG, {"host": host, "edges": edges, "stats": {}})

    def seed(self):
        """pc3 -> AU and GB (vendor cloud), US (home), unlocated; pc1 -> AU; pc2 tailscale -> GB (exempt category)."""
        self.report([edge(raddr="1.0.0.9", exe="/opt/aima-agent-app"), edge(raddr="81.2.69.10", exe="/opt/aima-agent-app"),
                     edge(raddr="8.8.8.8", exe="/usr/bin/curl"), edge(raddr="7.7.7.7", exe="/opt/x"), edge(raddr="10.0.1.40", rport=50080)], host="pc3")
        self.report([edge(raddr="1.0.0.9", exe="/opt/aima-cloud_proxy-app")], host="pc1")
        self.report([edge(raddr="81.2.69.77", exe="/usr/sbin/tailscaled")], host="pc2")


class NeedsHome(Base):
    home = None

    def test_nothing_can_be_enabled_without_a_home_country(self):
        self.seed()
        self.assertEqual(call(self.base, "GET", "/api/v1/secure", AD)[1]["label"], "needs_home")
        self.assertTrue(call(self.base, "GET", "/api/v1/report/abroad", AD)[1]["needs_home"])
        self.assertEqual(call(self.base, "GET", "/api/v1/report/abroad.csv", AD)[0], 409)
        st, body, _ = call(self.base, "PUT", "/api/v1/secure", AD, {"enabled": True})
        self.assertEqual(st, 400); self.assertIn("home country", body["error"])


class State(Base):
    def test_validation_and_expiry(self):
        put = lambda b: call(self.base, "PUT", "/api/v1/secure", AD, b)
        self.assertEqual(put({"enabled": "yes"})[0], 400)
        self.assertEqual(put({"enabled": True, "duration_s": 5})[0], 400)
        self.assertEqual(put({"enabled": True, "exempt_categories": ["nope"]})[0], 400)
        st, s, _ = put({"enabled": True, "duration_s": 3600})
        self.assertEqual(st, 200); self.assertTrue(s["state"]["enabled"]); self.assertTrue(3500 < s["state"]["seconds_left"] <= 3600)
        self.assertEqual(s["state"]["exempt_categories"], ["dns", "remote-access", "time-sync"])
        # indefinite
        self.assertIsNone(put({"enabled": True, "duration_s": 0})[1]["state"]["until"])
        # timer runs out -> disabled and audited, no request needed to notice
        put({"enabled": True, "duration_s": 3600})
        saved = json.loads(self.app.store.meta("secure")); saved["until"] = time.time() - 1; self.app.store.set_meta("secure", json.dumps(saved))
        self.assertFalse(call(self.base, "GET", "/api/v1/secure", AD)[1]["state"]["enabled"])
        self.assertTrue(any(a["action"] == "secure_expired" for a in call(self.base, "GET", "/api/v1/audit", AD)[1]["audit"]))
        self.assertEqual(call(self.base, "GET", "/api/v1/secure/blocklist", GW)[1]["block"], [])

    def test_auth(self):
        self.assertEqual(call(self.base, "GET", "/api/v1/secure", GW)[0], 403)
        self.assertEqual(call(self.base, "PUT", "/api/v1/secure", GW, {"enabled": True})[0], 403)
        self.assertEqual(call(self.base, "GET", "/api/v1/secure/blocklist", AG)[0], 403)
        self.assertEqual(call(self.base, "POST", "/api/v1/secure/report", AG, {"host": "x"})[0], 403)
        self.assertEqual(call(self.base, "GET", "/api/v1/secure/blocklist")[0], 401)


class Blocklist(Base):
    def test_foreign_only_with_exemptions_and_fail_open_on_shared_addresses(self):
        self.seed()
        call(self.base, "PUT", "/api/v1/secure", AD, {"enabled": False})
        off = call(self.base, "GET", "/api/v1/secure/blocklist", GW)[1]
        self.assertEqual((off["enabled"], off["block"]), (False, [])); self.assertEqual(off["count"], ["1.0.0.9", "81.2.69.10", "81.2.69.77"])   # bytes counted, nothing blocked
        call(self.base, "PUT", "/api/v1/secure", AD, {"enabled": True, "duration_s": 3600})
        on = call(self.base, "GET", "/api/v1/secure/blocklist", GW)[1]
        self.assertTrue(on["enabled"]); self.assertEqual(on["home_cc"], "US")
        self.assertEqual(on["block"], ["1.0.0.9", "81.2.69.10"])          # the tailscale (remote-access) address 81.2.69.77 is exempt; US, unlocated and robot addresses never appear
        self.assertEqual(on["count"], ["81.2.69.77"])
        self.assertNotIn("8.8.8.8", on["block"]); self.assertNotIn("7.7.7.7", on["block"]); self.assertNotIn("10.0.1.40", on["block"])
        # an address shared by an exempt and a non-exempt program is exempt: fail open
        self.report([edge(raddr="1.0.0.9", exe="/usr/sbin/tailscaled")], host="pc2")
        self.assertNotIn("1.0.0.9", call(self.base, "GET", "/api/v1/secure/blocklist", GW)[1]["block"])
        # removing the exemption puts it back
        call(self.base, "PUT", "/api/v1/secure", AD, {"enabled": True, "exempt_categories": []})
        self.assertEqual(call(self.base, "GET", "/api/v1/secure/blocklist", GW)[1]["block"], ["1.0.0.9", "81.2.69.10", "81.2.69.77"])

    def test_generation_changes_with_content(self):
        self.seed()
        g1 = call(self.base, "GET", "/api/v1/secure/blocklist", GW)[1]["generation"]
        self.assertEqual(g1, call(self.base, "GET", "/api/v1/secure/blocklist", GW)[1]["generation"])
        call(self.base, "PUT", "/api/v1/secure", AD, {"enabled": True})
        self.assertNotEqual(g1, call(self.base, "GET", "/api/v1/secure/blocklist", GW)[1]["generation"])

    def test_lookup_never_calls_internal_addresses_foreign(self):
        r = call(self.base, "POST", "/api/v1/secure/lookup", GW, {"ips": ["10.0.1.40", "192.168.30.69", "100.67.102.59", "127.0.0.1", "8.8.8.8", "1.0.0.9", "7.7.7.7", "x"]})[1]["result"]
        self.assertEqual({k: v["foreign"] for k, v in r.items()}, {"10.0.1.40": False, "192.168.30.69": False, "100.67.102.59": False, "127.0.0.1": False,
                                                                  "8.8.8.8": False, "1.0.0.9": True, "7.7.7.7": False, "x": False})
        self.assertEqual(r["1.0.0.9"]["cc"], "AU")


class Coverage(Base):
    def test_status_labels_follow_what_is_really_enforcing(self):
        self.seed()
        st = lambda: call(self.base, "GET", "/api/v1/secure", AD)[1]
        self.assertEqual(st()["label"], "open")
        call(self.base, "PUT", "/api/v1/secure", AD, {"enabled": True})
        self.assertEqual(st()["label"], "waiting")                         # intent saved, nobody enforcing yet
        rep = lambda h, **kw: call(self.base, "POST", "/api/v1/secure/report", GW, {"host": h, "enforcing": True, "rules": 2, "counters": [], **kw})
        rep("pc3"); s = st()
        self.assertEqual((s["label"], s["coverage"]["missing"]), ("partial", ["pc1", "pc2"]))
        rep("pc1"); rep("pc2"); s = st()
        self.assertEqual((s["label"], s["coverage"]["missing"], s["coverage"]["active"]), ("secured", [], 3))
        self.app.store.x("UPDATE enforcers SET ts = ? WHERE host='pc1'", (time.time() - 600,))          # pc1 goes silent
        s = st(); self.assertEqual((s["label"], s["coverage"]["missing"]), ("partial", ["pc1"]))
        rows = {(r["host"], r["raddr"]): r["status"] for r in self.app.secure.rows(0)}
        self.assertEqual(rows[("pc3", "1.0.0.9")], "secured"); self.assertEqual(rows[("pc1", "1.0.0.9")], "not enforced on pc1")
        self.assertEqual(rows[("pc2", "81.2.69.77")], "exempt")

    def test_counters_become_bytes_sent_and_bytes_blocked(self):
        self.seed()
        r = call(self.base, "GET", "/api/v1/report/abroad", AD)[1]
        self.assertIsNone(r["totals"]["bytes_sent"]); self.assertIsNone(r["totals"]["bytes_blocked"])        # unknown is null, not 0
        call(self.base, "PUT", "/api/v1/secure", AD, {"enabled": True})
        call(self.base, "POST", "/api/v1/secure/report", GW, {"host": "pc3", "enforcing": True, "rules": 2, "counters": [
            {"addr": "1.0.0.9", "verdict": "RETURN", "bytes": 4000, "packets": 40}, {"addr": "81.2.69.10", "verdict": "DROP", "bytes": 900, "packets": 9}]})
        call(self.base, "POST", "/api/v1/secure/report", GW, {"host": "pc3", "enforcing": True, "rules": 2, "counters": [
            {"addr": "1.0.0.9", "verdict": "RETURN", "bytes": 100, "packets": 1}]})                      # counter reset: +100, not -3900
        r = call(self.base, "GET", "/api/v1/report/abroad", AD)[1]; by = {c["cc"]: c for c in r["countries"]}
        self.assertEqual((by["AU"]["bytes_sent"], by["GB"]["bytes_blocked"]), (4100, 900))
        self.assertEqual(call(self.base, "GET", "/api/v1/secure", AD)[1]["blocked"], {"bytes": 900, "packets": 9})


class Report(Base):
    def test_report_content(self):
        self.seed()
        r = call(self.base, "GET", "/api/v1/report/abroad?since=3600", AD)[1]
        self.assertEqual((r["home_cc"], r["home_name"]), ("US", "United States"))
        self.assertEqual([c["cc"] for c in r["countries"]], ["GB", "AU"])      # most destinations first
        by = {c["cc"]: c for c in r["countries"]}
        self.assertEqual(set(by), {"AU", "GB"})                            # the home country and unlocated addresses are not "abroad"
        self.assertEqual(by["AU"]["name"], "Australia"); self.assertEqual(by["AU"]["computers"], ["pc1", "pc3"]); self.assertEqual(by["AU"]["destinations"], 1)
        self.assertEqual(by["GB"]["destinations"], 2)
        self.assertEqual({(p["host"], p["program"]) for p in by["AU"]["programs"]}, {("pc3", "aima-agent-app"), ("pc1", "aima-cloud_proxy-app")})
        self.assertEqual(r["totals"], {"destinations": 3, "countries": 2, "computers": 3, "programs": 3, "bytes_sent": None, "bytes_blocked": None})
        self.assertEqual(r["unlocated"], {"destinations": 1, "edges": 1}); self.assertTrue(by["AU"]["new"])
        self.assertTrue(any("not what was sent" in n for n in r["notes"]))

    def test_csv_export_and_formula_guard(self):
        self.report([edge(raddr="1.0.0.9", exe="/opt/=HYPERLINK(1)"), edge(raddr="81.2.69.10", exe="/usr/bin/ok")])
        self.app.store.x("UPDATE edges SET org='+SUM(1,1)' WHERE raddr='81.2.69.10'")
        st, text, hdr = call(self.base, "GET", "/api/v1/report/abroad.csv", AD)
        self.assertEqual(st, 200); self.assertIn("attachment", hdr["Content-Disposition"])
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(rows[0][:6], ["computer", "program", "destination", "port", "country_code", "country"])
        body = {r[2]: r for r in rows[1:]}
        self.assertTrue(body["1.0.0.9"][1].startswith("'=")); self.assertTrue(body["81.2.69.10"][6].startswith("'+"))      # cannot run as a formula
        self.assertEqual(body["1.0.0.9"][13], "open")
        for r in rows[1:]: self.assertTrue(all(not c.startswith(("=", "+", "@")) for c in r))


class Flags(Base):
    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=5) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, b""

    def test_flag_served_with_a_locked_down_policy(self):
        st, h, body = self.get("/static/flags/us.svg")
        self.assertEqual((st, h["Content-Type"]), (200, "image/svg+xml")); self.assertIn("default-src 'none'", h["Content-Security-Policy"]); self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertTrue(body.startswith(b"<svg"))
        for bad in ("/static/flags/../../server.json", "/static/flags/xx.svg", "/static/flags/us.png", "/static/flags/.us.svg", "/static/flags/us.svg/x", "/static/flags/"):
            self.assertEqual(self.get(bad)[0], 404, bad)

    def test_every_map_country_has_a_safe_flag(self):
        m = json.load(open(os.path.join(HERE, "..", "dashboard", "map", "world.json")))
        d = os.path.join(HERE, "..", "dashboard", "flags")
        for c in m["countries"] + m["points"]:
            f = os.path.join(d, c["cc"].lower() + ".svg"); self.assertTrue(os.path.exists(f), c["cc"])
            t = open(f, encoding="utf-8").read()
            self.assertTrue(t.lstrip().startswith("<svg"), c["cc"])
            self.assertIsNone(re.search(r"<script|\son\w+\s*=|javascript:|<foreignObject|<iframe|href\s*=\s*[\"']\s*(https?:)?//|@import|<!ENTITY", t, re.I), c["cc"])
        self.assertTrue(os.path.exists(os.path.join(d, "LICENSE")))

if __name__ == "__main__":
    unittest.main()
