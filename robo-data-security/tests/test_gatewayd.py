import json, unittest
from robosec.gatewayd import Gatewayd, parse_flows

RULES = "# robosec ruleset  policy_version=4  mode=enforce  digest=abc123\nadd table inet robosec\ndelete table inet robosec\ntable inet robosec {\n}\n"


class Resp:
    def __init__(self, body=b"", headers=None, status=200):
        self.body, self.headers, self.status = body, headers or {}, status
    def read(self): return self.body
    def __enter__(self): return self
    def __exit__(self, *a): return False


class Runner:
    """Scripted nft: a dict of argv-substring -> (rc, out). Records every call."""
    def __init__(self, script=None):
        self.script, self.calls, self.table = script or {}, [], False
    def __call__(self, argv, inp=None, timeout=20):
        self.calls.append(list(argv)); key = " ".join(argv)
        for sub, res in self.script.items():
            if sub in key:
                return res
        if "list table" in key: return (0, "table inet robosec {\n}\n") if self.table else (1, "No such file")
        if "delete table" in key: self.table = False; return 0, ""
        if "-c -f" in key: return 0, ""
        if key.endswith(".nft") and " -f " in key: self.table = True; return 0, ""
        return 0, ""
    def applied(self): return [c for c in self.calls if "-f" in c and "-c" not in c]
    def deleted(self): return [c for c in self.calls if "delete" in c]


def opener_factory(ruleset=RULES, healthy=True, server_up=True):
    def opener(req, timeout=0):
        url = req.full_url if hasattr(req, "full_url") else req
        if not server_up: raise OSError("down")
        if url.endswith("/healthz"): return Resp(b"{}", status=200 if healthy else 500)
        if url.endswith("/api/v1/gateway/ruleset"): return Resp(ruleset.encode(), {"X-Robosec-Digest": "abc123", "X-Robosec-Version": "4"})
        return Resp(b"{}")
    return opener


class Gw(unittest.TestCase):
    def mk(self, runner=None, **kw):
        return Gatewayd({"token": "t", "verify_s": 1, "state_file": "/tmp/robosec-test.state"}, runner=runner or Runner(), opener=opener_factory(**kw))

    def test_apply_then_up_to_date(self):
        r = Runner(); g = self.mk(r)
        self.assertEqual(g.step(), "applied"); self.assertEqual(len(r.applied()), 1)
        self.assertEqual(g.step(), "up to date"); self.assertEqual(len(r.applied()), 1)       # no needless reload (it would reset counters)

    def test_check_failure_applies_nothing_and_deletes_nothing(self):
        r = Runner({"-c -f": (1, "syntax error")}); g = self.mk(r)
        self.assertIn("check failed", g.step()); self.assertEqual(r.applied(), []); self.assertEqual(r.deleted(), [])

    def test_apply_failure_without_backup_fails_open(self):
        r = Runner({"nft -f /": (1, "kernel said no")})
        g = self.mk(r); r.table = False
        msg = g.step()
        self.assertIn("apply failed", msg)

    def test_unreachable_server_after_apply_rolls_back(self):
        r = Runner(); r.table = True               # a previous ruleset exists -> it must be restored, not deleted
        g = self.mk(r, healthy=False)
        self.assertIn("restored previous", g.step())
        self.assertGreaterEqual(len(r.applied()), 2)     # our ruleset, then the backup

    def test_unreachable_server_before_apply_leaves_everything_alone(self):
        r = Runner(); g = self.mk(r, server_up=False)
        self.assertIn("leaving the current ruleset", g.step()); self.assertEqual(r.applied(), []); self.assertEqual(r.deleted(), [])

    def test_dry_run_never_changes_the_system(self):
        r = Runner(); g = Gatewayd({"token": "t"}, runner=r, opener=opener_factory(), dry_run=True)
        self.assertIn("dry-run", g.step()); self.assertEqual(r.applied(), []); self.assertEqual(r.deleted(), [])
        self.assertEqual(g.remove()[1], "dry-run: would delete table")

    def test_remove_is_idempotent(self):
        r = Runner(); g = self.mk(r)
        self.assertEqual(g.remove(), (True, "no robosec table present"))
        r.table = True; ok, _ = g.remove(); self.assertTrue(ok); self.assertFalse(r.table)

    def test_parse_flows(self):
        j = {"nftables": [{"metainfo": {}}, {"set": {"name": "flows4", "elem": [
            {"elem": {"val": "8.8.8.8", "counter": {"packets": 3, "bytes": 180}, "timeout": 43200}},
            {"elem": {"val": "1.1.1.1", "counter": {"packets": 1, "bytes": 60}}}, "garbage", {"elem": {"val": "9.9.9.9"}}]}}]}
        self.assertEqual(parse_flows(j), [{"addr": "8.8.8.8", "bytes": 180, "packets": 3}, {"addr": "1.1.1.1", "bytes": 60, "packets": 1}])
        self.assertEqual(parse_flows({"nftables": [{"set": {"name": "flows4"}}]}), [])

if __name__ == "__main__":
    unittest.main()
