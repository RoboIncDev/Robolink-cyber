import json, os, tempfile, unittest, urllib.error
from robosec.agent import Reporter, DEFAULTS


class R:
    def __init__(self, status=200): self.status = status
    def __enter__(self): return self
    def __exit__(self, *a): return False


class Rep(unittest.TestCase):
    def mk(self, up):
        self.sent = []
        def opener(req, timeout=0):
            if not self.up: raise urllib.error.URLError("down")
            self.sent.append(json.loads(req.data)); self.auth = req.get_header("Authorization"); return R()
        self.up = up
        d = tempfile.mkdtemp()
        return Reporter({**DEFAULTS, "host": "pc2", "token": "tok", "spool_dir": d, "server": "http://x"}, opener=opener), d

    def test_success_sends_bearer_and_payload(self):
        r, _ = self.mk(True)
        self.assertTrue(r.send([{"a": 1}], {"s": 1}))
        self.assertEqual(self.auth, "Bearer tok"); self.assertEqual(self.sent[0]["host"], "pc2"); self.assertEqual(self.sent[0]["seq"], 1)

    def test_offline_spools_then_replays_in_order(self):
        r, d = self.mk(False)
        self.assertFalse(r.send([{"n": 1}], {})); self.assertFalse(r.send([{"n": 2}], {}))
        self.assertTrue(os.path.exists(os.path.join(d, "spool.jsonl")))
        self.up = True
        self.assertTrue(r.send([{"n": 3}], {}))
        self.assertEqual([p["edges"][0]["n"] for p in self.sent], [3, 1, 2])
        self.assertFalse(os.path.exists(os.path.join(d, "spool.jsonl")))

    def test_corrupt_spool_line_is_dropped_not_retried_forever(self):
        r, d = self.mk(True)
        open(os.path.join(d, "spool.jsonl"), "w").write("{broken\n" + json.dumps({"host": "pc2", "edges": []}) + "\n")
        r.replay_spool(); self.assertEqual(len(self.sent), 1); self.assertFalse(os.path.exists(os.path.join(d, "spool.jsonl")))

    def test_spool_is_bounded(self):
        r, d = self.mk(False); r.cfg["spool_max_bytes"] = 200
        for i in range(20): r.send([{"pad": "x" * 100}], {})
        self.assertLess(os.path.getsize(os.path.join(d, "spool.jsonl")), 1200)
        self.assertTrue(os.path.exists(os.path.join(d, "spool.jsonl.old")))

    def test_unwritable_spool_dir_is_not_fatal(self):
        r = Reporter({**DEFAULTS, "spool_dir": "/proc/nope/x", "server": "http://x"}, opener=lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("x")))
        self.assertFalse(r.send([], {}))

if __name__ == "__main__":
    unittest.main()
