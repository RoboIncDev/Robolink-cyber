import gzip, os, tempfile, unittest
from robosec.geodb import GeoDB, build, RangeTable, _packed

COUNTRY = """0.0.0.0,0.255.255.255,ZZ
1.0.0.0,1.0.0.255,AU
8.8.8.0,8.8.8.255,US
10.0.0.0,10.255.255.255,ZZ
81.2.69.0,81.2.69.255,GB
bad,line,XX
2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE
2a00:1450::,2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff,IE
"""
ASN = '''1.0.0.0,1.0.0.255,13335,"Cloudflare, Inc."
8.8.8.0,8.8.8.255,15169,"GOOGLE"
2a00:1450::,2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff,15169,"GOOGLE"
5.5.5.0,5.5.5.255,0,"Zero ASN is skipped"
9.9.9.0,9.9.9.255,19281,"Quad9   with
 newline"
'''


def make_db(country=COUNTRY, asn=ASN):
    d = tempfile.mkdtemp(prefix="geo-")
    c, a = os.path.join(d, "c.csv"), os.path.join(d, "a.csv.gz")
    open(c, "w").write(country)
    with gzip.open(a, "wt") as fh: fh.write(asn)
    meta = build(c, a, os.path.join(d, "out"), release="2026-11")
    return GeoDB.load(os.path.join(d, "out")), meta, os.path.join(d, "out")


class Geo(unittest.TestCase):
    def test_build_counts_and_skips(self):
        g, meta, _ = make_db()
        self.assertTrue(g.available)
        self.assertEqual(meta["country_ranges"], {"ipv4": 3, "ipv6": 2})     # ZZ rows and the bad row are not stored
        self.assertEqual(meta["asn_ranges"]["ipv4"], 3)                      # the ASN-0 row is skipped
        self.assertGreaterEqual(meta["skipped_rows"], 3)
        self.assertEqual(g.meta["attribution"], "IP Geolocation by DB-IP (CC BY 4.0)")

    def test_range_boundaries(self):
        g, _, _ = make_db()
        for ip, cc in (("8.8.8.0", "US"), ("8.8.8.8", "US"), ("8.8.8.255", "US"), ("1.0.0.0", "AU"), ("1.0.0.255", "AU")):
            self.assertEqual(g.lookup(ip)["cc"], cc, ip)
        for ip in ("8.8.7.255", "8.8.9.0", "0.0.0.1", "0.255.255.255", "10.1.2.3", "255.255.255.255", "1.0.1.0"):
            self.assertIsNone(g.lookup(ip)["cc"], ip)

    def test_owner(self):
        g, _, _ = make_db()
        self.assertEqual(g.lookup("1.0.0.77"), {"cc": "AU", "asn": 13335, "org": "Cloudflare, Inc."})
        self.assertEqual(g.lookup("8.8.8.8")["org"], "GOOGLE")
        self.assertEqual(g.lookup("9.9.9.9")["org"], "Quad9 with newline")      # whitespace and newlines collapsed
        self.assertEqual(g.lookup("9.9.9.9")["cc"], None)                          # owner known, country not in this tiny file

    def test_ipv6_and_mapped(self):
        g, _, _ = make_db()
        self.assertEqual(g.lookup("2001:db8::1")["cc"], "DE")
        self.assertEqual(g.lookup("2a00:1450:4009:81f::200e"), {"cc": "IE", "asn": 15169, "org": "GOOGLE"})
        self.assertEqual(g.lookup("::ffff:8.8.8.8")["cc"], "US")                    # IPv4-mapped IPv6 uses the IPv4 table
        self.assertIsNone(g.lookup("2001:db9::1")["cc"])

    def test_garbage_and_missing_database_never_raise(self):
        g, _, _ = make_db()
        for bad in ("", "not-an-ip", "999.1.1.1", None.__class__.__name__):
            self.assertEqual(g.lookup(bad), {"cc": None, "asn": 0, "org": ""})
        empty = GeoDB.load("/nonexistent/dir")
        self.assertFalse(empty.available)
        self.assertEqual(empty.lookup("8.8.8.8"), {"cc": None, "asn": 0, "org": ""})
        self.assertFalse(GeoDB.load(None).available)

    def test_corrupt_tables_are_refused(self):
        _, _, out = make_db()
        p = os.path.join(out, "country4.bin"); data = open(p, "rb").read()
        with self.assertRaises(ValueError): RangeTable(data[:-3])                  # truncated
        with self.assertRaises(ValueError): RangeTable(b"XXXXXX" + data[6:])       # wrong magic
        with self.assertRaises(ValueError): RangeTable(b"junk")                    # shorter than the header

    def test_country_only_and_asn_only(self):
        d = tempfile.mkdtemp(); c = os.path.join(d, "c.csv"); open(c, "w").write(COUNTRY)
        build(c, None, os.path.join(d, "o")); g = GeoDB.load(os.path.join(d, "o"))
        self.assertEqual(g.lookup("8.8.8.8"), {"cc": "US", "asn": 0, "org": ""})

    def test_many_ranges_binary_search(self):
        d = tempfile.mkdtemp(); c = os.path.join(d, "c.csv")
        with open(c, "w") as fh:
            for i in range(0, 50000):                       # 50k /24 blocks, out of order on purpose
                n = (i * 7919) % 50000
                fh.write(f"{n >> 8 & 255}.{n & 255}.0.0,{n >> 8 & 255}.{n & 255}.0.255,{'AB' if n % 2 else 'CD'}\n")
        build(c, None, os.path.join(d, "o")); g = GeoDB.load(os.path.join(d, "o"))
        for n in (0, 1, 49999, 25000, 12345):
            self.assertEqual(g.lookup(f"{n >> 8 & 255}.{n & 255}.0.17")["cc"], "AB" if n % 2 else "CD", n)

    @unittest.skipUnless(os.environ.get("ROBOSEC_REAL_GEO"), "set ROBOSEC_REAL_GEO=<dir with the built real database>")
    def test_real_database(self):
        g = GeoDB.load(os.environ["ROBOSEC_REAL_GEO"])
        self.assertTrue(g.available)
        self.assertEqual(g.lookup("8.8.8.8")["cc"], "US"); self.assertIn("GOOGLE", g.lookup("8.8.8.8")["org"].upper())
        self.assertIn("CLOUDFLARE", g.lookup("1.1.1.1")["org"].upper())
        self.assertIsNone(g.lookup("10.0.1.40")["cc"]); self.assertIsNone(g.lookup("192.168.30.69")["cc"])

if __name__ == "__main__":
    unittest.main()
