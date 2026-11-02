"""Agent sampler -> reporter -> real server -> ruleset, all in-process (fake /proc, real HTTP, real SQLite)."""
import json, os, tempfile, threading, unittest, urllib.request
from robosec.agent import Reporter, DEFAULTS, Sampler, EdgeTable
from robosec.netscope import Scoper
from robosec.server import make_server
from tests.test_netscope_procnet import FakeProc

CATS = os.path.join(os.path.dirname(__file__), "..", "config", "categories.json")


class E2E(FakeProc):
    def test_full_path(self):
        tmp = tempfile.mkdtemp()
        cfg = {"listen": "127.0.0.1", "port": 0, "db": os.path.join(tmp, "t.db"), "agent_token": "a" * 20, "gateway_token": "g" * 20,
               "admin_token": "m" * 20, "learning_hours": 0, "categories": CATS}
        srv, app = make_server(cfg)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            sampler, table = Sampler(Scoper(), proc_root=self.root), EdgeTable()
            obs, stats = sampler.sample(); table.update(obs, 100.0)
            rep = Reporter({**DEFAULTS, "host": "pc2", "token": "a" * 20, "server": base, "spool_dir": ""})
            self.assertTrue(rep.send(table.drain(100), stats))
            req = lambda p, tok: urllib.request.urlopen(urllib.request.Request(base + p, headers={"Authorization": "Bearer " + tok}), timeout=5).read().decode()
            internet = json.loads(req("/api/v1/edges?scope=internet", "m" * 20))["edges"]
            self.assertEqual([(e["raddr"], e["unit"], e["host"]) for e in internet], [("8.8.8.8", "robolink-voice.service", "pc2")])
            rules = req("/api/v1/gateway/ruleset", "g" * 20)
            self.assertIn("8.8.8.8", rules)                               # the learned destination reached the gateway ruleset
            self.assertEqual(json.loads(req("/api/v1/summary", "m" * 20))["hosts"][0]["stats"]["unattributed"], 1)
        finally:
            srv.shutdown(); srv.server_close()

if __name__ == "__main__":
    unittest.main()
