import json, os, sqlite3, tempfile, threading, time, unittest, urllib.error, urllib.request
from robosec.server import Store, make_server
from tests.test_geodb import make_db
from tests.test_server import AD, AG, GW, CATS, DASH, call, edge

HERE = os.path.dirname(__file__)


class GeoServer(unittest.TestCase):
    geodir = "make"          # "make" = synthetic database, "none" = no database, or a path

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="robosec-geo-")
        geodir = make_db()[2] if self.geodir == "make" else (self.geodir if self.geodir != "none" else os.path.join(self.tmp, "nope"))
        cfg = {"listen": "127.0.0.1", "port": 0, "db": os.path.join(self.tmp, "t.db"), "agent_token": AG, "gateway_token": GW,
               "admin_token": AD, "learning_hours": 0.0, "categories": CATS, "dashboard": DASH, "geodb": geodir,
               "static_dir": os.path.join(HERE, "..", "dashboard"), "home": {"lat": 52.5, "lon": 13.4, "label": "Lab"}}
        self.srv, self.app = make_server(cfg)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()

    def report(self, edges, host="pc2"):
        return call(self.base, "POST", "/api/v1/report", AG, {"host": host, "edges": edges, "stats": {}})

    def geo(self, q=""):
        return call(self.base, "GET", "/api/v1/geo/summary" + q, AD)[1]


class Enrichment(GeoServer):
    def test_edges_get_country_and_owner(self):
        self.report([edge(raddr="8.8.8.8", exe="/usr/bin/a"), edge(raddr="1.0.0.9", exe="/usr/bin/b"),
                     edge(raddr="10.0.1.40", rport=50080), edge(raddr="7.7.7.7", exe="/usr/bin/c")])
        rows = {e["raddr"]: e for e in call(self.base, "GET", "/api/v1/edges", AD)[1]["edges"]}
        self.assertEqual((rows["8.8.8.8"]["cc"], rows["8.8.8.8"]["org"]), ("US", "GOOGLE"))
        self.assertEqual((rows["1.0.0.9"]["cc"], rows["1.0.0.9"]["asn"]), ("AU", 13335))
        self.assertIsNone(rows["10.0.1.40"]["cc"])                       # robot-internal addresses are never geolocated
        self.assertIsNone(rows["7.7.7.7"]["cc"])                         # internet but unknown to the database

    def test_summary_by_country_without_bytes(self):
        self.report([edge(raddr="8.8.8.8", exe="/usr/bin/a"), edge(raddr="8.8.8.9", exe="/usr/bin/a"), edge(raddr="1.0.0.9", exe="/usr/bin/b"),
                     edge(raddr="7.7.7.7"), edge(raddr="192.168.30.69", rport=22)], host="pc3")
        g = self.geo()
        self.assertTrue(g["available"]); self.assertEqual(g["release"], "2026-11"); self.assertEqual(g["home"]["label"], "Lab")
        self.assertEqual(g["attribution"], "IP Geolocation by DB-IP (CC BY 4.0)")
        self.assertFalse(g["bytes_known"])
        by = {c["cc"]: c for c in g["countries"]}
        self.assertEqual(set(by), {"US", "AU"})
        self.assertEqual((by["US"]["destinations"], by["US"]["edges"], by["US"]["computers"]), (2, 2, ["pc3"]))
        self.assertIsNone(by["US"]["bytes"])                             # "no data" is null, never a fake 0
        self.assertEqual(by["US"]["orgs"][0]["org"], "GOOGLE"); self.assertEqual(by["US"]["processes"][0], {"exe": "/usr/bin/a", "edges": 2})
        self.assertEqual(g["unlocated"], {"destinations": 1, "edges": 1})   # 7.7.7.7; the LAN address is not "internet"
        self.assertEqual(g["countries"][0]["cc"], "US")                   # sorted by destinations

    def test_bytes_once_flows_exist(self):
        self.report([edge(raddr="8.8.8.8", exe="/usr/bin/a"), edge(raddr="8.8.8.8", exe="/usr/bin/other"), edge(raddr="1.0.0.9")])
        call(self.base, "POST", "/api/v1/gateway/flows", GW, {"host": "pc2", "flows": [{"addr": "8.8.8.8", "bytes": 5000, "packets": 10},
                                                                                       {"addr": "1.0.0.9", "bytes": 700, "packets": 2}]})
        g = self.geo(); by = {c["cc"]: c for c in g["countries"]}
        self.assertTrue(g["bytes_known"])
        self.assertEqual(by["US"]["bytes"], 5000)                         # two processes talk to one address: its bytes count once
        self.assertEqual(by["AU"]["bytes"], 700)
        self.assertTrue(call(self.base, "GET", "/api/v1/summary", AD)[1]["bytes_known"])

    def test_filters(self):
        self.report([edge(raddr="8.8.8.8")], host="pc2"); self.report([edge(raddr="1.0.0.9")], host="pc3")
        self.assertEqual([c["cc"] for c in self.geo("?host=pc3")["countries"]], ["AU"])
        self.assertEqual(self.geo("?since=3600")["countries"].__len__(), 2)

    def test_connections_can_be_filtered_by_country(self):
        self.report([edge(raddr="8.8.8.8"), edge(raddr="1.0.0.9"), edge(raddr="8.8.8.9", exe="/usr/bin/z")])
        us = call(self.base, "GET", "/api/v1/edges?cc=US", AD)[1]["edges"]
        self.assertEqual(sorted(e["raddr"] for e in us), ["8.8.8.8", "8.8.8.9"])
        self.assertEqual([e["raddr"] for e in call(self.base, "GET", "/api/v1/edges?cc=AU&scope=internet", AD)[1]["edges"]], ["1.0.0.9"])
        self.assertEqual(call(self.base, "GET", "/api/v1/edges?cc=ZZ", AD)[1]["edges"], [])
        self.assertEqual(call(self.base, "GET", "/api/v1/edges?cc=US%27%20OR%201%3D1--", AD)[1]["edges"], [])   # bound parameter, not string-built SQL

    def test_geo_requires_admin(self):
        self.assertEqual(call(self.base, "GET", "/api/v1/geo/summary", AG)[0], 403)
        self.assertEqual(call(self.base, "GET", "/api/v1/geo/summary")[0], 401)


class NoDatabase(GeoServer):
    geodir = "none"

    def test_everything_works_with_locations_unknown(self):
        self.assertEqual(self.report([edge(raddr="8.8.8.8")])[0], 200)
        g = self.geo()
        self.assertFalse(g["available"]); self.assertEqual(g["countries"], []); self.assertEqual(g["unlocated"], {"destinations": 1, "edges": 1})
        self.assertFalse(call(self.base, "GET", "/api/v1/summary", AD)[1]["geo"]["available"])

    def test_installing_a_database_later_and_regeocoding(self):
        self.report([edge(raddr="8.8.8.8")])
        from robosec.geodb import GeoDB
        self.app.geo = GeoDB.load(make_db()[2])
        self.assertEqual(call(self.base, "POST", "/api/v1/regeocode", AD, {})[1]["changed"], 1)
        self.assertEqual(self.geo()["countries"][0]["cc"], "US")
        self.assertEqual(call(self.base, "POST", "/api/v1/regeocode", AD, {})[1]["changed"], 0)       # idempotent


class CorruptDatabase(GeoServer):
    def test_corrupt_files_do_not_stop_the_server(self):
        d = make_db()[2]; open(os.path.join(d, "country4.bin"), "wb").write(b"junk")
        cfg = {"db": os.path.join(self.tmp, "c.db"), "agent_token": AG, "gateway_token": GW, "admin_token": AD, "categories": CATS, "geodb": d}
        from robosec.server import App
        self.assertFalse(App(cfg).geo.available)


class Migration(unittest.TestCase):
    def test_old_database_gains_columns_and_keeps_rows(self):
        p = os.path.join(tempfile.mkdtemp(), "old.db")
        db = sqlite3.connect(p)
        db.executescript("""CREATE TABLE edges(id INTEGER PRIMARY KEY, host TEXT, dir TEXT, exe TEXT, comm TEXT, unit TEXT, cmd TEXT,
          uid INTEGER, proto TEXT, raddr TEXT, rport INTEGER, scope TEXT, category TEXT, count INTEGER, first_seen REAL, last_seen REAL,
          UNIQUE(host, dir, exe, proto, raddr, rport));
          INSERT INTO edges(host,dir,exe,proto,raddr,rport,scope,category,count,first_seen,last_seen) VALUES('pc2','out','/x','tcp','8.8.8.8',443,'internet','dns',3,1,2);""")
        db.commit(); db.close()
        s = Store(p)
        cols = {r["name"] for r in s.q("PRAGMA table_info(edges)")}
        self.assertTrue({"cc", "asn", "org"} <= cols)
        self.assertEqual(s.q("SELECT host, raddr, count, cc FROM edges"), [{"host": "pc2", "raddr": "8.8.8.8", "count": 3, "cc": None}])
        Store(p)                                                         # opening twice is harmless


class Static(GeoServer):
    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=5) as r:
                return r.status, r.headers.get("Content-Type"), r.headers.get("Cache-Control"), r.read()
        except urllib.error.HTTPError as e:
            return e.code, None, None, b""

    def test_serves_only_whitelisted_assets(self):
        st, ctype, cache, body = self.get("/static/map/world.json")
        self.assertEqual((st, ctype), (200, "application/json")); self.assertIn("public", cache); self.assertIn("countries", json.loads(body))
        for bad in ("/static/../robosec/server.py", "/static/fonts/../../robosec/server.py", "/static/%2e%2e/robosec/server.py",
                    "/static/fonts/..%2fserver.py", "/static/index.html", "/static/fonts/nothing.woff2", "/static/fonts/",
                    "/static/map/.hidden.json", "/static/fonts/a.py", "/static/other/x.json", "/static/"):
            self.assertEqual(self.get(bad)[0], 404, bad)

    def test_fonts_have_the_right_type_when_present(self):
        fonts = os.path.join(HERE, "..", "dashboard", "fonts")
        names = [n for n in os.listdir(fonts) if n.endswith(".woff2")] if os.path.isdir(fonts) else []
        if not names:
            self.skipTest("fonts not installed yet")
        st, ctype, _, body = self.get("/static/fonts/" + names[0])
        self.assertEqual((st, ctype), (200, "font/woff2")); self.assertEqual(body[:4], b"wOF2")

if __name__ == "__main__":
    unittest.main()
