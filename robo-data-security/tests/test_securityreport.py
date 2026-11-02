import unittest
from robosec import securityreport as sr
from tests.test_secure import Base, AD, AG, call

NOW = 1000.0
ROBOT = {"maker": "AgiBot", "name": "X2 Ultra", "serial": "X1"}
OKSEC = {"label": "secured", "home_cc": "US", "coverage": {"active": 3, "total": 3, "missing": []}, "foreign": {"destinations": 5, "would_block": 4}}
ABROAD = {"home_name": "the United States", "totals": {"destinations": 5, "countries": 2, "computers": 2, "programs": 3, "bytes_sent": None},
          "countries": [{"cc": "CN", "name": "China", "destinations": 3, "owners": [{"org": "Volcano Engine"}], "programs": [{"program": "aima-cloud"}]}], "unlocated": None}
HOSTS = [{"host": "pc1", "last_seen": NOW}, {"host": "pc2", "last_seen": NOW}]


def f(id_, sev, title="t", fix="do it", accepted=False):
    return {"id": id_, "severity": sev, "host": "pc2", "title": title, "detail": "d", "fix": fix, "accepted": accepted}


class Build(unittest.TestCase):
    def go(self, findings=(), secure=OKSEC, abroad=ABROAD, hosts=HOSTS, learning=False):
        return sr.build(ROBOT, list(findings), secure, abroad, hosts, NOW, learning)

    def test_quiet_robot_is_in_good_shape_with_one_keep_going_recommendation(self):
        r = self.go()
        self.assertEqual((r["level"], len(r["recommendations"])), ("good", 1))
        self.assertIn("Keep it this way", r["recommendations"][0]["title"])

    def test_a_caution_means_needs_a_look_and_becomes_a_recommendation(self):
        r = self.go([f("listen:pc2:tcp:50080", "caution", "App manager open")])
        self.assertEqual(r["level"], "review")
        self.assertEqual([x["title"] for x in r["recommendations"]], ["App manager open"])
        self.assertIn("App manager open", " ".join(r["sections"][2]["body"]))

    def test_a_fault_is_act_now_and_first(self):
        r = self.go([f("a", "caution", "later"), f("b", "fault", "now")])
        self.assertEqual((r["level"], r["recommendations"][0]["title"]), ("act", "now"))

    def test_accepted_findings_are_left_out_but_counted(self):
        r = self.go([f("a", "caution", "known", accepted=True)])
        self.assertEqual((r["level"], r["counts"]["accepted_findings"]), ("good", 1))
        self.assertIn("Review the findings you marked", r["recommendations"][-1]["title"])

    def test_secure_off_with_foreign_data_recommends_a_one_hour_test(self):
        sec = {**OKSEC, "label": "open"}
        r = self.go(secure=sec)
        self.assertEqual(r["level"], "review")
        self.assertTrue(any("one hour" in x["title"] for x in r["recommendations"]))

    def test_missing_enforcer_and_silent_computer(self):
        sec = {**OKSEC, "label": "partial", "coverage": {"active": 1, "total": 2, "missing": ["pc1"]}}
        r = self.go(secure=sec, hosts=[{"host": "pc1", "last_seen": NOW - 900}, {"host": "pc2", "last_seen": NOW}])
        titles = [x["title"] for x in r["recommendations"]]
        self.assertIn("Install the enforcer on pc1", titles); self.assertIn("Get pc1 reporting again", titles)

    def test_unknown_bytes_are_said_to_be_unknown(self):
        self.assertIn("Bytes are unknown", " ".join(self.go()["sections"][0]["body"]))

    def test_markdown_has_the_headline_and_numbered_steps(self):
        md = sr.markdown(self.go([f("a", "caution", "App manager open")]))
        self.assertIn("# Security report: AgiBot X2 Ultra (X1)", md); self.assertIn("1. **App manager open**", md)


class Api(Base):
    def test_report_needs_admin_and_has_both_formats(self):
        self.seed()
        self.assertEqual(call(self.base, "GET", "/api/v1/report/security", AG)[0], 403)
        st, r, _ = call(self.base, "GET", "/api/v1/report/security", AD)
        self.assertEqual(st, 200); self.assertIn(r["level"], ("good", "review", "act")); self.assertTrue(r["recommendations"])
        import urllib.request
        req = urllib.request.Request(self.base + "/api/v1/report/security.md", headers={"Authorization": "Bearer " + AD})
        with urllib.request.urlopen(req) as resp:
            self.assertIn("attachment", resp.headers["Content-Disposition"]); self.assertIn("# Security report", resp.read().decode())

    def test_the_dashboard_has_the_button(self):
        import os
        html = open(os.path.join(os.path.dirname(__file__), "..", "dashboard", "index.html")).read()
        for needle in ('id="mkrep"', "/api/v1/report/security", "What to do, in order"):
            self.assertIn(needle, html)


if __name__ == "__main__":
    unittest.main()
