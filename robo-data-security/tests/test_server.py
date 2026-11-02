import json, os, tempfile, threading, time, unittest, urllib.error, urllib.request
from robosec.server import make_server, App

CATS = os.path.join(os.path.dirname(__file__), "..", "config", "categories.json")
DASH = os.path.join(os.path.dirname(__file__), "..", "dashboard", "index.html")
AG, GW, AD = "a" * 30, "g" * 30, "m" * 30


def call(base, method, path, token=None, body=None):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if r.headers.get("Content-Type", "").startswith("application/json") else raw.decode()), dict(r.headers)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw), {}
        except ValueError: return e.code, raw.decode(), {}


def edge(**kw):
    e = {"dir": "out", "exe": "/usr/bin/python3", "comm": "python3", "unit": "", "uid": 1001, "cmd": "python3 x.py", "proto": "tcp",
         "raddr": "8.8.8.8", "rport": 443, "n": 2, "first": time.time() - 5, "last": time.time()}
    e.update(kw); return e


class Server(unittest.TestCase):
    learning_hours = 0.0

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="robosec-test-")
        cfg = {"listen": "127.0.0.1", "port": 0, "db": os.path.join(self.tmp, "t.db"), "agent_token": AG, "gateway_token": GW,
               "admin_token": AD, "learning_hours": self.learning_hours, "categories": CATS, "dashboard": DASH}
        self.srv, self.app = make_server(cfg)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()

    def report(self, edges, host="pc2"):
        return call(self.base, "POST", "/api/v1/report", AG, {"host": host, "agent_version": "t", "ts": time.time(), "edges": edges, "stats": {"sample_ms": 3.0, "unattributed": 0}})

    # --- auth ---
    def test_auth_matrix(self):
        self.assertEqual(call(self.base, "GET", "/healthz")[0], 200)
        self.assertEqual(call(self.base, "POST", "/api/v1/report", None, {"host": "x"})[0], 401)
        self.assertEqual(call(self.base, "POST", "/api/v1/report", "wrong", {"host": "x"})[0], 401)
        self.assertEqual(call(self.base, "POST", "/api/v1/report", GW, {"host": "x"})[0], 403)      # gateway token cannot report
        self.assertEqual(call(self.base, "GET", "/api/v1/summary", AG)[0], 403)                      # agent token cannot read
        self.assertEqual(call(self.base, "GET", "/api/v1/gateway/ruleset", AG)[0], 403)
        self.assertEqual(call(self.base, "PUT", "/api/v1/policy", GW, {"mode": "enforce"})[0], 403)  # nor change policy
        self.assertEqual(call(self.base, "GET", "/api/v1/summary", AD)[0], 200)
        self.assertEqual(call(self.base, "GET", "/api/v1/gateway/ruleset", AD)[0], 200)             # admin may do anything

    def test_placeholder_or_equal_tokens_refused(self):
        base = {"db": os.path.join(self.tmp, "x.db"), "categories": CATS}
        for t in ({"agent_token": "CHANGE-ME", "gateway_token": GW, "admin_token": AD},
                  {"agent_token": AG, "gateway_token": AG, "admin_token": AD}):
            with self.assertRaises(SystemExit): App({**base, **t})

    # --- ingest + categorise + alerts ---
    def test_ingest_classifies_and_alerts(self):
        st, body, _ = self.report([edge(exe="/agibot/software/cloud_proxy/bin/x"), edge(raddr="10.0.1.40", rport=50080),
                                   edge(raddr="192.168.30.69", rport=22, dir="in"), edge(raddr="not-valid-type", proto="icmp")])
        self.assertEqual(st, 200); self.assertEqual(body["alerts"], 1)          # only the new internet destination alerts
        edges = call(self.base, "GET", "/api/v1/edges?scope=internet", AD)[1]["edges"]
        self.assertEqual(len(edges), 1); self.assertEqual(edges[0]["category"], "robot-vendor-cloud")
        self.assertEqual(call(self.base, "GET", "/api/v1/edges", AD)[1]["edges"].__len__(), 3)   # bad-typed edge was skipped
        alerts = call(self.base, "GET", "/api/v1/alerts", AD)[1]["alerts"]
        self.assertEqual(alerts[0]["kind"], "new_internet_destination")
        # same edge again: counted, not re-alerted
        self.assertEqual(self.report([edge(exe="/agibot/software/cloud_proxy/bin/x")])[1]["alerts"], 0)
        self.assertEqual(call(self.base, "GET", "/api/v1/edges?scope=internet", AD)[1]["edges"][0]["count"], 4)
        aid = alerts[0]["id"]
        self.assertEqual(call(self.base, "POST", f"/api/v1/alerts/{aid}/ack", AD, {})[0], 200)
        self.assertEqual(call(self.base, "GET", "/api/v1/summary", AD)[1]["open_alerts"], 0)

    def test_inbound_from_internet_is_its_own_alert(self):
        self.report([edge(dir="in", raddr="203.0.113.50", rport=40000, exe="/usr/sbin/sshd")])
        self.assertEqual(call(self.base, "GET", "/api/v1/alerts", AD)[1]["alerts"][0]["kind"], "inbound_from_internet")

    def test_bad_reports_are_400_not_500(self):
        self.assertEqual(call(self.base, "POST", "/api/v1/report", AG, {"edges": []})[0], 400)         # host missing
        req = urllib.request.Request(self.base + "/api/v1/report", method="POST", data=b"{not json", headers={"Authorization": "Bearer " + AG})
        with self.assertRaises(urllib.error.HTTPError) as cm: urllib.request.urlopen(req, timeout=5)
        self.assertEqual(cm.exception.code, 400)

    # --- policy ---
    def test_policy_roundtrip_and_validation(self):
        p = call(self.base, "GET", "/api/v1/policy", AD)[1]
        self.assertEqual((p["mode"], p["version"]), ("observe", 1))
        st, p2, _ = call(self.base, "PUT", "/api/v1/policy", AD, {"mode": "enforce", "categories": {"voice-and-audio": "block"}})
        self.assertEqual((st, p2["mode"], p2["version"], p2["categories"]), (200, "enforce", 2, {"voice-and-audio": "block"}))
        p3 = call(self.base, "PUT", "/api/v1/policy", AD, {"categories": {"dns": "allow"}})[1]
        self.assertEqual(p3["categories"], {"voice-and-audio": "block", "dns": "allow"})        # patch merges categories
        for bad in ({"mode": "yolo"}, {"categories": {"x": "maybe"}}, {"block_cidrs": ["999.1.1.1/8"]}, {"always_allow": {"udp_ports": [70000]}}):
            self.assertEqual(call(self.base, "PUT", "/api/v1/policy", AD, bad)[0], 400, bad)
        self.assertEqual(call(self.base, "GET", "/api/v1/policy", AD)[1]["version"], 3)           # rejected changes do not bump the version
        self.assertTrue(any(a["action"] == "policy_update" for a in call(self.base, "GET", "/api/v1/audit", AD)[1]["audit"]))

    # --- gateway ruleset + flows ---
    def test_ruleset_uses_learned_destinations_and_policy(self):
        self.report([edge(exe="/agibot/software/cloud_proxy/bin/x", raddr="198.51.100.7"), edge(raddr="8.8.4.4")])
        call(self.base, "PUT", "/api/v1/policy", AD, {"mode": "enforce", "categories": {"robot-vendor-cloud": "block"}})
        st, text, hdr = call(self.base, "GET", "/api/v1/gateway/ruleset", GW)
        self.assertEqual(st, 200); self.assertEqual(hdr["X-Robosec-Version"], "2"); self.assertEqual(hdr["X-Robosec-Mode"], "enforce")
        self.assertIn("198.51.100.7", text); self.assertIn("counter drop    # robot-vendor-cloud: block", text)
        self.assertIn("8.8.4.4", text)                                                           # unclassified set exists too
        self.assertIn("table inet robosec", text)

    def test_flows_survive_counter_reset(self):
        self.report([edge(raddr="8.8.8.8")])
        f = lambda b: call(self.base, "POST", "/api/v1/gateway/flows", GW, {"host": "pc2", "flows": [{"addr": "8.8.8.8", "bytes": b, "packets": b // 100}]})
        f(1000); f(3000); f(500)                    # +1000 first, +2000, then a reload reset the counter: +500
        e = call(self.base, "GET", "/api/v1/edges?scope=internet", AD)[1]["edges"][0]
        self.assertEqual(e["bytes_to_dest"], 3500)
        cats = call(self.base, "GET", "/api/v1/summary", AD)[1]["internet_categories"]
        self.assertEqual(sum(c["bytes_sent"] for c in cats), 3500)

    def test_gateway_ack_and_dashboard(self):
        self.assertEqual(call(self.base, "POST", "/api/v1/gateway/ack", GW, {"host": "pc2", "version": 3, "ok": True, "detail": "applied"})[0], 200)
        self.assertEqual(call(self.base, "GET", "/api/v1/summary", AD)[1]["gateway"][0]["version"], 3)
        st, html, _ = call(self.base, "GET", "/")
        self.assertEqual(st, 200); self.assertIn("<title>Robosec</title>", html)


class Learning(Server):
    learning_hours = 24.0

    def test_no_alerts_while_learning(self):
        st, body, _ = self.report([edge()])
        self.assertTrue(body["learning"]); self.assertEqual(body["alerts"], 0)
        self.assertEqual(call(self.base, "GET", "/api/v1/alerts", AD)[1]["alerts"], [])
        call(self.base, "POST", "/api/v1/learning/restart", AD, {})
    # inherited tests re-run with a 24 h learning window: only the alert expectations differ
    test_ingest_classifies_and_alerts = None
    test_inbound_from_internet_is_its_own_alert = None

if __name__ == "__main__":
    unittest.main()
