import copy, shutil, subprocess, tempfile, unittest
from robosec.netscope import Scoper
from robosec.nftrender import DEFAULT_POLICY, header_info, render, sanitize_id, validate_policy

LEARNED = {"voice-and-audio": ["198.51.100.7", "198.51.100.8", "2001:db8::1"], "dns": ["1.1.1.1"], "weird id!": ["9.9.9.9"]}


def pol(**kw):
    p = copy.deepcopy(DEFAULT_POLICY); p.update(kw); return p


class Render(unittest.TestCase):
    def test_observe_never_drops(self):
        t = render(pol(mode="observe", default_internet="block", categories={"voice-and-audio": "block"}, block_cidrs=["203.0.113.0/24"]), Scoper(), LEARNED)
        self.assertNotIn(" drop", t)
        self.assertIn("mode=observe", t)

    def test_enforce_drops_exactly_what_is_blocked(self):
        t = render(pol(mode="enforce", default_internet="allow", categories={"voice-and-audio": "block", "dns": "allow"}), Scoper(), LEARNED)
        drops = [l.strip() for l in t.splitlines() if l.strip().endswith("drop") or " drop " in l]
        self.assertTrue(all("voice" in l or "block" in l for l in drops), drops)
        self.assertIn("ip daddr @cat_dns_v4 counter accept", t)
        self.assertIn("ip6 daddr @cat_voice_and_audio_v6 counter drop", t)
        self.assertTrue(t.rstrip().endswith("}"))
        self.assertIn("counter accept    # unclassified internet destinations: allow", t)

    def test_default_block_in_enforce(self):
        t = render(pol(mode="enforce", default_internet="block"), Scoper(), {})
        self.assertIn("counter drop    # unclassified internet destinations: block", t)

    def test_internal_traffic_is_accepted_before_anything_that_counts_or_drops(self):
        t = render(pol(mode="enforce", default_internet="block"), Scoper(), LEARNED)
        s = t.split("chain screen {")[1].split("chain decide")[0]
        self.assertLess(s.index("@robot4"), s.index("@flows4"))
        self.assertLess(s.index("@trusted4"), s.index("@flows4"))
        self.assertLess(s.index("ct state { established, related } accept"), s.index("jump decide"))
        self.assertNotIn("flush ruleset", t)
        self.assertEqual(t.count("delete table"), 1)

    def test_only_our_table_is_touched(self):
        t = render(pol(), Scoper(), LEARNED)
        tables = [l.split()[-1] for l in t.splitlines() if l.startswith(("add table", "delete table"))]
        self.assertEqual(tables, ["robosec", "robosec"])
        self.assertNotIn("filter", t.split("table inet robosec {")[0])

    def test_empty_sets_have_no_elements_line(self):
        t = render(pol(), Scoper(), {})
        blk = t.split("set block4 {")[1].split("}")[0]
        self.assertNotIn("elements", blk)

    def test_overlapping_cidrs_collapse(self):
        t = render(pol(block_cidrs=["203.0.113.0/24", "203.0.113.128/25", "203.0.113.5"]), Scoper(), {})
        blk = t.split("set block4 {")[1].split("}")[0]
        self.assertEqual(blk.count("203.0.113"), 1)

    def test_digest_tracks_policy_and_learning(self):
        a = header_info(render(pol(), Scoper(), {}))
        b = header_info(render(pol(), Scoper(), {"dns": ["1.1.1.1"]}))
        c = header_info(render(pol(mode="enforce"), Scoper(), {}))
        self.assertEqual(len({a["digest"], b["digest"], c["digest"]}), 3)
        self.assertEqual(header_info(render(pol(), Scoper(), {}))["digest"], a["digest"])    # deterministic

    def test_validation(self):
        for bad in ({"mode": "x"}, {"default_internet": "maybe"}, {"categories": {"a": "b"}}, {"allow_cidrs": ["nope"]}, {"always_allow": {"tcp_ports": [0]}}):
            with self.assertRaises(ValueError): validate_policy(pol(**bad))
        self.assertEqual(validate_policy(pol(allow_cidrs=["1.2.3.4"]))["allow_cidrs"], ["1.2.3.4/32"])
        self.assertEqual(DEFAULT_POLICY["always_allow"], {"udp_ports": [53, 123], "tcp_ports": []})   # defaults never mutated
        self.assertEqual(sanitize_id("weird id!"), "weird_id_")

    @unittest.skipUnless(shutil.which("nft") and shutil.which("unshare"), "nft/unshare not available")
    def test_nft_accepts_the_ruleset(self):
        for p in (pol(), pol(mode="enforce", default_internet="block", categories={"voice-and-audio": "block"}, allow_cidrs=["8.8.8.0/24"], block_cidrs=["203.0.113.0/24"])):
            f = tempfile.mktemp(suffix=".nft"); open(f, "w").write(render(p, Scoper(), LEARNED))
            r = subprocess.run(["unshare", "-Urn", "nft", "-c", "-f", f], capture_output=True, text=True)
            if "Operation not permitted" in r.stderr and "unshare" in r.stderr:
                self.skipTest("user namespaces unavailable")
            self.assertEqual(r.returncode, 0, r.stderr)

if __name__ == "__main__":
    unittest.main()
