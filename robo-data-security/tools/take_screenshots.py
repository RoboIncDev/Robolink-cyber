"""Take the dashboard screenshots used in docs/DASHBOARD.md. Needs `pip install playwright` and a Chromium.

    ROBOSEC_TOKEN=<admin token> ROBOSEC_URL=http://10.0.1.41:8750/ python3 tools/take_screenshots.py

ROBOSEC_CHROME points at a Chromium binary if Playwright's own is not installed. The token is read from the environment and never written anywhere.
Check the result before committing: it shows whatever the live dashboard shows.
"""
import os, sys
from playwright.sync_api import sync_playwright
URL = os.environ.get("ROBOSEC_URL", "http://127.0.0.1:8750/")
TOK = os.environ["ROBOSEC_TOKEN"]
OUT = os.environ.get("ROBOSEC_OUT", os.path.join(os.path.dirname(__file__), "..", "docs", "screenshots"))
os.makedirs(OUT, exist_ok=True)
with sync_playwright() as p:
    b = p.chromium.launch(executable_path=os.environ.get('ROBOSEC_CHROME') or None)
    def page(w, h, scheme="dark", theme="dark"):
        ctx = b.new_context(viewport={"width": w, "height": h}, device_scale_factor=1, color_scheme=scheme)
        ctx.add_init_script(f"try{{localStorage.setItem('robosec-theme','{theme}')}}catch(e){{}}")
        pg = ctx.new_page(); pg.goto(URL); pg.fill("#tok", TOK); pg.press("#tok", "Enter")
        pg.wait_for_selector("#app:not([hidden])", timeout=15000); pg.wait_for_timeout(5000)
        return pg
    pg = page(1280, 900)
    def shot(sel, name):
        el = pg.query_selector(sel)
        if el and el.is_visible():
            el.scroll_into_view_if_needed(); el.screenshot(path=f"{OUT}/{name}.png"); print("ok", name)
        else: print("missing", sel)
    shot("#robot", "01-robot-banner"); shot("#strip", "02-status-strip"); shot("#secure", "03-secure-data")
    shot("#findsec", "04-findings"); shot("#report", "05-data-sent-abroad"); shot("#mapsec", "06-where-data-goes")
    shot("#devsec", "07-connected-and-exposed"); shot("#leavesec", "08-what-is-leaving"); shot("#compsec", "09-computers")
    shot("#alsec", "10-alerts"); shot("#consec", "11-connections")
    pg.click("#mkrep"); pg.wait_for_timeout(2500); shot("#secrepsec", "12-security-report")
    pg.click("#sr-close")
    pg.click("#rb-change"); pg.wait_for_timeout(800); shot("#robotdlg", "13-choose-robot"); pg.keyboard.press("Escape")
    if pg.query_selector("#sec-on"):
        pg.click("#sec-on"); pg.wait_for_timeout(800); shot("#securedlg", "14-secure-data-dialog"); pg.keyboard.press("Escape")
    pg.screenshot(path=f"{OUT}/00-overview.png", full_page=False)
    pg2 = page(1280, 900, "light", "light"); pg2.screenshot(path=f"{OUT}/15-light-theme.png"); 
    pg3 = page(390, 844); pg3.screenshot(path=f"{OUT}/16-phone.png"); print("done")
    b.close()
