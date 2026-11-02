import json, unittest, urllib.error
from robosec.enforcer import CHAIN, Enforcer, parse_counters

IPT_L = """Chain ROBOSEC_SECURE (2 references)
    pkts      bytes target     prot opt in     out     source               destination
      12      3456 DROP       all  --  *      *       0.0.0.0/0            203.0.113.9
       3       180 RETURN     all  --  *      *       0.0.0.0/0            1.1.1.1
       0         0 DROP       all      *      *       ::/0                 2001:db8::1
     junk line
"""


class Resp:
    def __init__(self, body): self.body = body
    def read(self): return json.dumps(self.body).encode()
    def __enter__(self): return self
    def __exit__(self, *a): return False


class Rig:
    """Scripted iptables + server. `calls` is every command run."""
    def __init__(self, blocklist=None, hooked=False, up=True):
        self.calls, self.bl, self.hooked, self.up, self.posts = [], blocklist or {"enabled": True, "block": [], "count": [], "generation": "g1"}, hooked, True, []
        self.t = [1000.0]

    def runner(self, argv, inp=None, timeout=20):
        self.calls.append(list(argv))
        a = argv[3:] if argv[1] == "-w" else argv[1:]          # strip: tool -w 5
        if a[:1] == ["-C"]: return (0, "") if self.hooked else (1, "no such rule")
        if a[:1] == ["-I"]: self.hooked = True
        if a[:1] == ["-L"]: return 0, IPT_L
        return 0, ""

    def opener(self, req, timeout=0):
        if not self.up: raise urllib.error.URLError("down")
        if req.get_method() == "POST":
            self.posts.append(json.loads(req.data)); return Resp({"ok": True})
        return Resp(self.bl)

    def rules(self, tool="iptables"):
        return [c for c in self.calls if c[0] == tool and "-A" in c or (c[0] == tool and "-D" in c and CHAIN in c)]

    def enforcer(self, **cfg):
        return Enforcer({"host": "pc3", "token": "t", "failopen_s": 120, **cfg}, runner=self.runner, opener=self.opener, clock=lambda: self.t[0])


class Parse(unittest.TestCase):
    def test_counters(self):
        self.assertEqual(parse_counters(IPT_L), [{"addr": "203.0.113.9", "verdict": "DROP", "packets": 12, "bytes": 3456},
                                                 {"addr": "1.1.1.1", "verdict": "RETURN", "packets": 3, "bytes": 180}])      # the v6-style line has 8 fields: skipped, not guessed


class Apply(unittest.TestCase):
    def test_installs_drop_and_return_and_hooks_once(self):
        r = Rig({"enabled": True, "block": ["203.0.113.9"], "count": ["1.1.1.1"], "generation": "g"}); e = r.enforcer()
        s = e.step()
        self.assertEqual((s["installed"], s["dropping"], s["heartbeat"]), (2, 1, True))
        adds = [c[-5:] for c in r.calls if "-A" in c and CHAIN in c and c[0] == "iptables"]
        self.assertIn(["-d", "203.0.113.9/32", "-j", "DROP"], [a[-4:] for a in adds]); self.assertIn(["-d", "1.1.1.1/32", "-j", "RETURN"], [a[-4:] for a in adds])
        self.assertEqual(len([c for c in r.calls if c[0] == "iptables" and "-I" in c]), 1)           # hooked into OUTPUT exactly once
        e.step(); self.assertEqual(len([c for c in r.calls if c[0] == "iptables" and "-I" in c]), 1)  # and not again
        self.assertTrue(any(c[-4:] == ["-N", CHAIN] or CHAIN in c and "-F" in c for c in r.calls))    # chain created, flushed on the first cycle

    def test_internal_addresses_are_refused_whatever_the_server_says(self):
        bad = ["10.0.1.40", "10.0.1.41", "192.168.30.69", "192.168.88.1", "100.67.102.59", "127.0.0.1", "169.254.1.1", "224.0.0.251", "::1", "fdc7:e2f2:388f:d514::1", "fe80::1", "not-an-ip", ""]
        r = Rig({"enabled": True, "block": bad + ["203.0.113.9"], "count": bad, "generation": "g"}); e = r.enforcer()
        e.step()
        self.assertEqual(e.installed, {"203.0.113.9": "DROP"})
        self.assertGreaterEqual(len(e.refused), len(bad) - 1)
        for c in r.calls:
            for b in ("10.0.1.4", "192.168.", "100.67", "127.0.0.1"): self.assertNotIn(b, " ".join(c).replace("203.0.113.9", ""))

    def test_block_wins_over_count_and_changes_are_minimal(self):
        r = Rig({"enabled": True, "block": ["203.0.113.9"], "count": ["203.0.113.9", "1.1.1.1"], "generation": "g"}); e = r.enforcer()
        e.step(); self.assertEqual(e.installed, {"203.0.113.9": "DROP", "1.1.1.1": "RETURN"})
        n = len(r.calls); r.bl = {"enabled": True, "block": ["203.0.113.9"], "count": ["1.1.1.1"], "generation": "g"}; e.step()
        self.assertFalse([c for c in r.calls[n:] if "-A" in c or ("-D" in c and CHAIN in c and "-j" in c and "DROP" in c)])   # same lists: nothing rewritten
        r.bl = {"enabled": False, "block": [], "count": ["203.0.113.9", "1.1.1.1"], "generation": "h"}; e.step()                # secure switched off: the DROP becomes a counter
        self.assertEqual(e.installed, {"203.0.113.9": "RETURN", "1.1.1.1": "RETURN"})
        r.bl = {"enabled": False, "block": [], "count": ["1.1.1.1"], "generation": "i"}; e.step()
        self.assertEqual(e.installed, {"1.1.1.1": "RETURN"})                                                                    # an address that vanished is deleted

    def test_ipv6_uses_ip6tables_with_a_128_mask(self):
        r = Rig({"enabled": True, "block": ["2606:4700:4700::1111"], "count": [], "generation": "g"}); e = r.enforcer(); e.step()
        self.assertTrue(any(c[0] == "ip6tables" and "-A" in c and "2606:4700:4700::1111/128" in c and "DROP" in c for c in r.calls))

    def test_rule_cap(self):
        r = Rig({"enabled": True, "block": [f"203.0.{i // 250}.{i % 250 + 1}" for i in range(50)], "count": [], "generation": "g"}); e = r.enforcer(max_rules=10); e.step()
        self.assertEqual(len(e.installed), 10); self.assertIn("rule cap reached", e.errors)

    def test_dry_run_changes_nothing(self):
        r = Rig({"enabled": True, "block": ["203.0.113.9"], "count": [], "generation": "g"})
        e = Enforcer({"host": "pc3", "token": "t"}, runner=r.runner, opener=r.opener, dry_run=True)
        out = e.step(); self.assertEqual(out["would_install"], {"203.0.113.9": "DROP"}); self.assertEqual(r.calls, []); self.assertEqual(r.posts, [])


class FailOpen(unittest.TestCase):
    def test_lost_server_stops_blocking_then_recovers(self):
        r = Rig({"enabled": True, "block": ["203.0.113.9"], "count": ["1.1.1.1"], "generation": "g"}); e = r.enforcer(); e.step()
        self.assertEqual(e.installed["203.0.113.9"], "DROP")
        r.up = False; r.t[0] += 60; self.assertTrue(e.step()["error"]); self.assertEqual(e.installed["203.0.113.9"], "DROP")   # a short outage keeps the block
        r.t[0] += 100; out = e.step()
        self.assertTrue(out["failed_open"]); self.assertEqual(e.installed["203.0.113.9"], "RETURN")                              # a long one lets traffic flow
        r.up = True; e.step(); self.assertEqual(e.installed["203.0.113.9"], "DROP"); self.assertFalse(e.failed_open)

    def test_unexpected_error_fails_open(self):
        r = Rig({"enabled": True, "block": ["203.0.113.9"], "count": [], "generation": "g"}); e = r.enforcer(); e.step()
        e.apply = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        self.assertTrue(e.step()["failed_open"]); self.assertEqual(e.installed["203.0.113.9"], "RETURN")

    def test_remove_deletes_hooks_and_chain(self):
        r = Rig({"enabled": True, "block": ["203.0.113.9"], "count": [], "generation": "g"}); e = r.enforcer(); e.step(); n = len(r.calls)
        ok, _ = e.remove(); self.assertTrue(ok); self.assertEqual(e.installed, {})
        cmds = [" ".join(c) for c in r.calls[n:]]
        self.assertTrue(any("-D OUTPUT -j " + CHAIN in c for c in cmds)); self.assertTrue(any("-F " + CHAIN in c for c in cmds)); self.assertTrue(any("-X " + CHAIN in c for c in cmds))

    def test_heartbeat_reports_the_truth(self):
        r = Rig({"enabled": True, "block": ["203.0.113.9"], "count": [], "generation": "g"}); e = r.enforcer(); e.step()
        hb = r.posts[-1]; self.assertEqual((hb["host"], hb["enforcing"], hb["rules"]), ("pc3", True, 1)); self.assertEqual(hb["counters"][0]["addr"], "203.0.113.9")
        e.failed_open = True; e.errors.append("failed open: test"); e.heartbeat({})
        self.assertFalse(r.posts[-1]["enforcing"]); self.assertTrue(r.posts[-1]["detail"].startswith("failed open"))

if __name__ == "__main__":
    unittest.main()
