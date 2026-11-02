import os, re, unittest
from tests.test_secure import Base, AD, AG, call, HERE
import urllib.error, urllib.request


class RobotProfile(Base):
    def test_default_is_the_cadet_and_needs_admin(self):
        st, r, _ = call(self.base, "GET", "/api/v1/robot", AD)
        self.assertEqual((st, r["id"], r["maker"], r["name"]), (200, "x2-ultra", "AgiBot", "X2 Ultra"))
        self.assertEqual([c["id"] for c in r["catalog"]], ["x2-ultra", "a3", "g1"])
        self.assertEqual(call(self.base, "GET", "/api/v1/robot", AG)[0], 403)

    def test_choose_a_robot_and_it_is_remembered(self):
        st, r, _ = call(self.base, "PUT", "/api/v1/robot", AD, {"model": "g1", "label": "Lab G1", "serial": "G1-0042"})
        self.assertEqual((st, r["id"], r["label"], r["serial"], r["computers"]), (200, "g1", "Lab G1", "G1-0042", []))
        self.assertEqual(call(self.base, "GET", "/api/v1/robot", AD)[1]["id"], "g1")
        self.assertEqual(call(self.base, "PUT", "/api/v1/robot", AG, {"model": "a3"})[0], 403)

    def test_bad_input_is_refused(self):
        for body in ({"model": "optimus"}, {"model": "g1", "serial": "x" * 41}, {"model": "g1", "label": "a\nb"}, {"model": 5}, []):
            self.assertEqual(call(self.base, "PUT", "/api/v1/robot", AD, body)[0], 400, str(body))

    def test_images_are_served_and_exist_for_every_catalog_entry(self):
        for rid in ("x2-ultra", "a3", "g1"):
            with urllib.request.urlopen(f"{self.base}/static/robots/{rid}.png") as r:
                self.assertEqual(r.headers["Content-Type"], "image/png"); self.assertTrue(r.read(8).startswith(b"\x89PNG"))

    def test_the_dashboard_has_the_banner(self):
        html = open(os.path.join(HERE, "..", "dashboard", "index.html")).read()
        for needle in ('id="robot"', "/api/v1/robot", "static/robots/"):
            self.assertIn(needle, html)


if __name__ == "__main__":
    unittest.main()
