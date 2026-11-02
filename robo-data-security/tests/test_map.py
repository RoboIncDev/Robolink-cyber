import json, math, os, re, sys, tempfile, unittest
ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import build_map

MAP = os.path.join(ROOT, "dashboard", "map", "world.json")


class Projection(unittest.TestCase):
    def test_equal_earth_known_points(self):
        self.assertEqual(build_map.ee(0, 0), (0.0, 0.0))
        x, y = build_map.ee(180, 0); self.assertAlmostEqual(x, 2.7066, 3)                 # half-width at the equator
        _, ypole = build_map.ee(0, 90); self.assertAlmostEqual(ypole, 1.3173, 3)          # y of the pole (published aspect ~2.05)
        self.assertAlmostEqual(2 * 2.7066 / (2 * ypole), 2.055, 2)
        a, b = build_map.ee(10, 40), build_map.ee(-10, 40); self.assertAlmostEqual(a[0], -b[0], 9); self.assertAlmostEqual(a[1], b[1], 9)   # symmetric
        self.assertGreater(build_map.ee(0, 50)[1], build_map.ee(0, 20)[1])                # north is up


class Builder(unittest.TestCase):
    def test_polygon_with_a_hole_and_fixups(self):
        gj = {"features": [
            {"properties": {"NAME_LONG": "Squareland", "ISO_A2_EH": "SQ", "ADM0_A3": "SQL"},
             "geometry": {"type": "Polygon", "coordinates": [[[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]], [[3, 3], [3, 6], [6, 6], [6, 3], [3, 3]]]}},
            {"properties": {"NAME": "France", "ISO_A2_EH": "-99", "ADM0_A3": "FRA"},
             "geometry": {"type": "MultiPolygon", "coordinates": [[[[0, 40], [5, 40], [5, 45], [0, 40]]], [[[20, 0], [21, 0], [21, 1], [20, 0]]]]}},
            {"properties": {"NAME": "Somaliland", "ISO_A2_EH": "-99", "ADM0_A3": "SOL"}, "geometry": {"type": "Polygon", "coordinates": [[[1, 1], [2, 1], [2, 2], [1, 1]]]}},
            {"properties": {"NAME": "Antarctica", "ISO_A2_EH": "AQ", "ADM0_A3": "ATA"}, "geometry": {"type": "Polygon", "coordinates": [[[0, -80], [5, -80], [5, -70], [0, -80]]]}}]}
        d = tempfile.mkdtemp(); src, out = os.path.join(d, "a.geojson"), os.path.join(d, "w.json")
        json.dump(gj, open(src, "w"))
        m = build_map.build(src, out)
        by = {c["cc"]: c for c in m["countries"]}
        self.assertEqual(set(by), {"SQ", "FR"})                                          # unknown-code and Antarctica entries are dropped
        self.assertEqual(by["SQ"]["d"].count("M"), 2)                                    # outer ring + hole (drawn with even-odd fill)
        self.assertTrue(by["SQ"]["d"].endswith("z"))
        self.assertEqual(by["FR"]["name"], "France")
        self.assertLess(by["FR"]["cx"], 520)                                             # centre of the LARGEST polygon (metropolitan), not the tiny island
        self.assertIn("SG", {p["cc"] for p in m["points"]}); self.assertNotIn("FR", {p["cc"] for p in m["points"]})


@unittest.skipUnless(__import__("shutil").which("node"), "node not available")
class JsParity(unittest.TestCase):
    def test_dashboard_projection_equals_the_build_projection(self):
        """The page places the robot's home with its own copy of the Equal Earth formula; it must agree with the one that drew the map."""
        import subprocess
        html = open(os.path.join(ROOT, "dashboard", "index.html"), encoding="utf-8").read()
        fn = html[html.index("/*EE*/") + 6: html.index("/*EEEND*/")]
        pts = [(0, 0), (13.4, 52.5), (-122.4, 37.8), (151.2, -33.9), (103.8, 1.35), (-70, -55), (179.9, 65), (-179.9, -45), (0, 83.6), (28, -26)]
        js = fn + "\nconsole.log(JSON.stringify(%s.map(p=>eqearth(p[0],p[1]))))" % json.dumps([list(p) for p in pts])
        out = subprocess.run(["node", "-e", js], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        for (lon, lat), (jx, jy) in zip(pts, json.loads(out.stdout)):
            px, py = build_map.ee(lon, lat)
            self.assertAlmostEqual(jx, px, 9, (lon, lat)); self.assertAlmostEqual(jy, py, 9, (lon, lat))


@unittest.skipUnless(os.path.exists(MAP), "map asset not built")
class Asset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = json.load(open(MAP))

    def test_size_and_counts(self):
        self.assertLess(os.path.getsize(MAP), 250 * 1024)
        self.assertGreater(len(self.m["countries"]), 150)
        codes = [c["cc"] for c in self.m["countries"]] + [p["cc"] for p in self.m["points"]]
        self.assertEqual(len(codes), len(set(codes)))                                    # one shape or marker per code
        for must in ("US", "CN", "IN", "BR", "DE", "FR", "GB", "NL", "IE", "SG", "JP", "AU", "CA", "RU", "ZA", "XK", "HK"):
            self.assertIn(must, codes, must)

    def test_everything_sits_inside_the_view_box(self):
        w, h = self.m["width"], self.m["height"]
        for c in self.m["countries"] + self.m["points"]:
            self.assertTrue(0 <= c["cx"] <= w and 0 <= c["cy"] <= h, c["cc"])

    def test_paths_are_well_formed(self):
        for c in self.m["countries"]:
            self.assertRegex(c["d"], r"^(M-?\d+ -?\d+l(-?\d+ -?\d+)( -?\d+ -?\d+)*z)+$", c["cc"])

    def test_home_projection_constants_reproduce_the_centroids(self):
        # the dashboard places the robot's home with: px = tx + scale*x ; py = ty - scale*y
        x, y = build_map.ee(0, 0)
        self.assertAlmostEqual(self.m["tx"] + self.m["scale"] * x, self.m["width"] / 2)
        _, ypole = build_map.ee(0, 90); self.assertAlmostEqual(self.m["ty"] - self.m["scale"] * ypole, 0, 6)
        sg = [p for p in self.m["points"] if p["cc"] == "SG"][0]
        gx, gy = build_map.ee(103.82, 1.35)
        self.assertAlmostEqual(self.m["tx"] + self.m["scale"] * gx, sg["cx"], 1); self.assertAlmostEqual(self.m["ty"] - self.m["scale"] * gy, sg["cy"], 1)

if __name__ == "__main__":
    unittest.main()
