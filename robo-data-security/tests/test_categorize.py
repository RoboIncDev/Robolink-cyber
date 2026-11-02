import os, unittest
from robosec.categorize import categorize, load_rules, UNCLASSIFIED

RULES = load_rules(os.path.join(os.path.dirname(__file__), "..", "config", "categories.json"))


def edge(**kw):
    base = {"exe": "/usr/bin/x", "comm": "x", "unit": "", "cmd": "", "proto": "tcp", "raddr": "8.8.8.8", "rport": 443, "dir": "out", "scope": "internet"}
    base.update(kw); return base


class Cat(unittest.TestCase):
    def test_shipped_rules_load_and_are_unique(self):
        ids = [c["id"] for c in RULES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreater(len(ids), 8)

    def test_matches(self):
        self.assertEqual(categorize(edge(exe="/agibot/software/cloud_proxy/bin/aima-cloud_proxy-app"), RULES), "robot-vendor-cloud")
        self.assertEqual(categorize(edge(exe="/usr/sbin/sshd", rport=22), RULES), "remote-access")
        self.assertEqual(categorize(edge(cmd="python3 x2_tts.py --serve"), RULES), "voice-and-audio")
        self.assertEqual(categorize(edge(rport=53, proto="udp"), RULES), "dns")
        self.assertEqual(categorize(edge(rport=123, proto="udp"), RULES), "time-sync")
        self.assertEqual(categorize(edge(rport=123, proto="tcp", exe="/opt/zzz"), RULES), UNCLASSIFIED)
        self.assertEqual(categorize(edge(), RULES), UNCLASSIFIED)

    def test_and_semantics_and_cidr(self):
        rules = [{"id": "t", "match": [{"exe_glob": "*/curl", "cidr": "93.184.216.0/24"}]}]
        self.assertEqual(categorize(edge(exe="/usr/bin/curl", raddr="93.184.216.34"), rules), "t")
        self.assertEqual(categorize(edge(exe="/usr/bin/curl", raddr="8.8.8.8"), rules), UNCLASSIFIED)
        self.assertEqual(categorize(edge(exe="/usr/bin/wget", raddr="93.184.216.34"), rules), UNCLASSIFIED)

    def test_bad_rules_rejected(self):
        import json, tempfile
        for bad in ([{"id": "a"}, {"id": "a"}], [{"id": "bad id!"}]):
            p = tempfile.mktemp(suffix=".json")
            with open(p, "w") as fh: json.dump({"categories": bad}, fh)
            with self.assertRaises(ValueError): load_rules(p)

if __name__ == "__main__":
    unittest.main()
