"""Static checks on the dashboard against the Robo Inc. Signal System (Draft 0.3) and this tool's own rules."""
import json, os, re, shutil, subprocess, tempfile, unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
HTML = open(os.path.join(ROOT, "dashboard", "index.html"), encoding="utf-8").read()
CSS = re.search(r"<style>(.*?)</style>", HTML, re.S).group(1)
JS = re.search(r"<script>(.*?)</script>", HTML, re.S).group(1)

# Palette copied from the published design system. A later draft changes these in ONE place (and here).
PALETTE = {"--ink": "#0A0A0B", "--white": "#FFFFFF", "--brand": "#03C6D9", "--st-stop": "#E01414", "--g-100": "#EEEFF1", "--g-300": "#AEB2B8",
           "--g-500": "#82868D", "--g-700": "#45494F", "--g-900": "#1A1B1E", "--b-100": "#D9F5F8", "--b-300": "#2ED3E4", "--b-400": "#03C6D9",
           "--b-600": "#027884", "--b-800": "#063F46"}
STATE = {"dark": {"--st-nominal": "#3FBF7F", "--st-nominal-bg": "#0E2A1E", "--st-caution": "#E0A22B", "--st-caution-bg": "#2E2210", "--st-fault": "#E7565A", "--st-fault-bg": "#2E1214", "--run": "#C9A227"},
         "light": {"--st-nominal": "#117955", "--st-nominal-bg": "#DDF0E7", "--st-caution": "#8A5B08", "--st-caution-bg": "#FAEEDA", "--st-fault": "#C2262B", "--st-fault-bg": "#FBE3E4", "--run": "#8A6F1C"}}


def block(selector):
    """Text between the braces that follow `selector` (brace-depth aware); '' if absent."""
    i = CSS.find(selector)
    if i < 0:
        return ""
    j = CSS.index("{", i)
    depth, k = 0, j
    while k < len(CSS):
        depth += CSS[k] == "{"; depth -= CSS[k] == "}"
        if depth == 0:
            return CSS[j + 1:k]
        k += 1
    return ""


def tokens(text):
    return dict(re.findall(r"(--[a-z0-9-]+):\s*([^;]+);", text))


DARK = tokens(block(":root{"))


class Dashboard(unittest.TestCase):
    def test_no_external_requests(self):
        self.assertNotRegex(HTML, r"""(src|href)\s*=\s*["']\s*(https?:)?//""")
        self.assertNotRegex(CSS, r"url\(\s*['\"]?(https?:)?//")
        self.assertNotIn("@import", CSS)
        self.assertNotRegex(JS, r"fetch\(\s*['\"`]https?://")
        literal = [u for u in re.findall(r"https?://[^\s\"'<>)]+", HTML) if u != "http://www.w3.org/2000/svg"]   # an XML namespace label, never fetched
        self.assertEqual(literal, [], literal)          # the only external link is built from the server's attribution field

    def test_fonts_are_local_and_exist(self):
        urls = re.findall(r"url\(([^)]+)\)", CSS)
        self.assertGreaterEqual(len(urls), 5)
        for u in urls:
            self.assertTrue(u.startswith("/static/fonts/"), u)
            self.assertTrue(os.path.exists(os.path.join(ROOT, "dashboard", u[len("/static/"):])), u)
        self.assertIn("'Poppins'", CSS); self.assertIn("'IBM Plex Mono'", CSS)

    def test_palette_matches_the_signal_system(self):
        t = DARK
        for name, value in PALETTE.items():
            self.assertEqual(t.get(name, "").upper(), value.upper(), name)

    def test_state_colours_in_both_themes(self):
        dark, light = DARK, tokens(block(':root[data-theme="light"]'))
        for k, v in STATE["dark"].items(): self.assertEqual(dark.get(k, "").upper(), v.upper(), "dark " + k)
        for k, v in STATE["light"].items(): self.assertEqual(light.get(k, "").upper(), v.upper(), "light " + k)

    def test_light_and_auto_override_the_same_tokens(self):
        light = set(tokens(block(':root[data-theme="light"]')))
        auto = set(tokens(block(':root[data-theme="auto"]')))
        dark = set(DARK)
        self.assertEqual(light, auto)
        self.assertTrue(light <= dark, light - dark)       # nothing is defined only in the light theme

    def test_dark_is_the_default(self):
        self.assertIn('<html lang="en" data-theme="dark">', HTML)
        self.assertIn("--bg:var(--ink)", CSS)

    def test_no_gradients_and_no_glow(self):
        self.assertNotRegex(CSS.lower(), r"gradient")
        self.assertNotIn("text-shadow", CSS)

    def test_hit_targets_and_type_floor(self):
        for sel in (".btn{", ".seg button{", ".sw{", ".field input,.field select{"):
            self.assertRegex(block(sel) or CSS[CSS.index(sel):CSS.index(sel) + 200], r"min-height:44px", sel)
        scale = [DARK["--t-%d" % i] for i in range(1, 8)]
        self.assertEqual(scale, ["12px", "14px", "16px", "18px", "20px", "24px", "32px"])          # the published type scale
        raw = [float(x) for x in re.findall(r"font(?:-size)?:[^;}]*?\b(\d+(?:\.\d+)?)px", CSS)]
        self.assertTrue(all(x >= 12 for x in raw), raw)                                              # no literal text size under 12 px

    def test_map_follows_the_data_colour_rules(self):
        """Signal System: data categories avoid state hues and blue. Blue appears only for selection and keyboard focus."""
        css = CSS[CSS.index("/* map:"): CSS.index("/* dialogs */")]
        self.assertNotIn("--st-", css)
        for rule in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
            sel, body = rule
            if "--blue" in body:
                self.assertTrue(any(k in sel for k in (".sel", "focus-visible", "[aria-pressed=true]")), sel)

    def test_map_has_a_text_equivalent_and_accessible_names(self):
        self.assertIn('<svg id="map" role="img" aria-label=', HTML)
        self.assertIn('id="ctable"', HTML)                                   # the same numbers as a table
        self.assertIn('aria-label="Select', JS)                              # each country row is a labelled button
        self.assertIn('setAttribute("tabindex","0")', JS); self.assertIn('ev.key==="Enter"', JS)   # shapes with traffic are keyboard reachable
        for control in ('data-win="3600"', 'data-win="86400"', 'data-win="0"', 'data-metric="destinations"', 'data-metric="bytes"'):
            self.assertIn(control, HTML)

    def test_map_is_honest_about_what_it_does_not_know(self):
        self.assertIn("Locations are approximate", JS)
        self.assertIn("Home location is not set", JS)                        # no invented home, no arcs without one
        self.assertIn("The gateway is not reporting bytes", JS)              # the bytes view is disabled, not zero
        self.assertIn("Not located", JS)

    def test_hidden_attribute_always_wins(self):
        self.assertIn("[hidden]{display:none!important}", CSS)

    def test_reduced_motion_is_respected(self):
        self.assertIn("prefers-reduced-motion:reduce", CSS)

    def test_missing_values_are_dashes_not_zeros(self):
        self.assertIn('const DASH="—"', JS)
        self.assertIn("SUM.bytes_known", JS)                # bytes are only shown when the gateway has reported

    def test_state_is_a_word_plus_a_dot(self):
        self.assertRegex(CSS, r"\.chip i\{width:8px")
        for word in ("Nominal", "Reporting", "Silent", "Observing", "Enforcing", "Review"):
            self.assertIn(word, JS)

    def test_untrusted_text_is_escaped(self):
        self.assertIn("const esc=", JS)
        self.assertNotRegex(JS, r"innerHTML\s*=\s*[^;]*\+\s*x\.exe")      # no raw process names in markup

    @unittest.skipUnless(shutil.which("node"), "node not available")
    def test_script_parses(self):
        f = tempfile.mktemp(suffix=".js"); open(f, "w").write(JS)
        r = subprocess.run(["node", "--check", f], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_size_budget(self):
        self.assertLess(len(HTML.encode()), 60 * 1024)
        fonts = sum(os.path.getsize(os.path.join(ROOT, "dashboard", "fonts", f)) for f in os.listdir(os.path.join(ROOT, "dashboard", "fonts")) if f.endswith(".woff2"))
        self.assertLess(fonts, 100 * 1024)

if __name__ == "__main__":
    unittest.main()
