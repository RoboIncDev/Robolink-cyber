import os, tempfile, time, unittest
from robosec import findings, posture
from robosec.netscope import Scoper
from tests.test_secure import Base, AD, AG, call

SC = Scoper()


def tcp_line(i, laddr_hex, lport, state="0A", rport=0, uid=0, inode=1000):
    return f"  {i}: {laddr_hex}:{lport:04X} 00000000:{rport:04X} {state} 00000000:00000000 00:00000000 00000000 {uid} 0 {inode} 1 0 100 0 0 10 0\n"


HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def fake_proc(tmp, tcp="", udp=""):
    os.makedirs(os.path.join(tmp, "net"), exist_ok=True)
    for name, text in (("tcp", tcp), ("tcp6", ""), ("udp", udp), ("udp6", "")):
        open(os.path.join(tmp, "net", name), "w").write(HEADER + text)


class Collectors(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="posture-")

    def test_listeners_say_how_far_each_port_reaches(self):
        fake_proc(self.tmp, tcp=tcp_line(0, "00000000", 50080) + tcp_line(1, "0100007F", 5000) + tcp_line(2, "2801000A", 1883)
                  + tcp_line(3, "7701A8C0", 22) + tcp_line(4, "0100007F", 9, state="01", rport=80))     # last one is a live connection, not a listener
        got = {r["port"]: r["reach"] for r in posture.listeners(SC, self.tmp)}
        self.assertEqual(got, {50080: "all", 5000: "local", 1883: "robot", 22: "lan"})

    def test_a_udp_socket_with_no_peer_is_a_listener(self):
        fake_proc(self.tmp, udp=tcp_line(0, "00000000", 5353, state="07"))
        self.assertEqual([(r["proto"], r["port"]) for r in posture.listeners(SC, self.tmp)], [("udp", 5353)])

    def test_bluetooth_output_is_parsed(self):
        show = "Controller AA:BB:CC:00:11:22 (public)\n\tName: cadet\n\tPowered: yes\n\tDiscoverable: yes\n\tPairable: no\n"
        self.assertEqual(posture.parse_show(show), {"address": "AA:BB:CC:00:11:22", "name": "cadet", "powered": True, "discoverable": True, "pairable": False})
        self.assertEqual(posture.parse_devices("Device 00:11:22:33:44:55 DualSense\nDevice 66:77:88:99:AA:BB \n"),
                         [{"mac": "00:11:22:33:44:55", "name": "DualSense"}, {"mac": "66:77:88:99:AA:BB", "name": ""}])

    def test_bluetooth_is_none_without_an_adapter_and_devices_none_without_the_tool(self):
        self.assertIsNone(posture.bluetooth(self.tmp))
        os.makedirs(os.path.join(self.tmp, "class", "bluetooth", "hci0"))
        got = posture.bluetooth(self.tmp, run=lambda argv: None)
        self.assertEqual((got["adapters"], got["controller"], got["paired"]), (["hci0"], None, None))   # tool missing: unknown, not "no devices"

    def test_bluetooth_with_the_tool(self):
        os.makedirs(os.path.join(self.tmp, "class", "bluetooth", "hci0"))
        out = {"show": "Controller AA:BB:CC:00:11:22 (public)\n\tPowered: yes\n\tPairable: yes\n", "Paired": "Device 00:11:22:33:44:55 DualSense\n", "Connected": ""}
        run = lambda argv: out["show"] if argv[1] == "show" else out[argv[-1]]    # noqa: E731
        got = posture.bluetooth(self.tmp, run=run)
        self.assertTrue(got["controller"]["pairable"]); self.assertEqual(got["paired"][0]["name"], "DualSense"); self.assertEqual(got["connected"], [])

    def test_usb_skips_hubs(self):
        for name, vid, cls, prod in (("1-1", "054c", "00", "DualSense"), ("usb1", "1d6b", "09", "Root Hub")):
            d = os.path.join(self.tmp, "bus", "usb", "devices", name); os.makedirs(d)
            for f, v in (("idVendor", vid), ("idProduct", "0ce6"), ("bDeviceClass", cls), ("product", prod)):
                open(os.path.join(d, f), "w").write(v + "\n")
        self.assertEqual([(d["id"], d["product"]) for d in posture.usb(self.tmp)], [("054c:0ce6", "DualSense")])
        self.assertIsNone(posture.usb(os.path.join(self.tmp, "nowhere")))

    def test_neighbours_drop_incomplete_entries_and_flag_random_macs(self):
        os.makedirs(os.path.join(self.tmp, "net"))
        open(os.path.join(self.tmp, "net", "arp"), "w").write(
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.30.1     0x1         0x2         bc:d2:2c:20:f9:01     *        wifi0\n"
            "192.168.30.9     0x1         0x2         7a:11:22:33:44:55     *        wifi0\n"
            "192.168.30.7     0x1         0x0         00:00:00:00:00:00     *        wifi0\n")
        got = posture.neighbors(self.tmp)
        self.assertEqual([(n["ip"], n["random"]) for n in got], [("192.168.30.1", False), ("192.168.30.9", True)])

    def test_wifi_and_sessions(self):
        self.assertEqual(posture.parse_iw_link("Connected to aa:bb:cc:dd:ee:ff (on wifi0)\n\tSSID: Lab\n\tsignal: -48 dBm\n"),
                         {"ssid": "Lab", "bssid": "AA:BB:CC:DD:EE:FF", "signal_dbm": -48})
        self.assertEqual(posture.parse_who("agi  pts/0  2026-11-02 10:00 (192.168.30.5)\nrun  tty1  2026-11-02 09:00\n"),
                         [{"user": "agi", "tty": "pts/0", "from": "192.168.30.5"}, {"user": "run", "tty": "tty1", "from": ""}])


def reading(**kw):
    base = {"listeners": [], "bluetooth": None, "usb": [], "neighbors": [], "wifi": None, "sessions": []}
    return {**base, **kw}


class Findings(unittest.TestCase):
    now = 1000.0

    def run_eval(self, host_posture, accepted=(), enforcer=True, last_seen=None):
        hosts = [{"host": "pc2", "last_seen": last_seen or self.now, "stats": {}}]
        return findings.evaluate({"pc2": {"ts": self.now, "body": host_posture}} if host_posture else {}, hosts,
                                 {"pc2": {"ts": self.now}} if enforcer else {}, self.now, set(accepted))

    def ids(self, items):
        return [f["id"] for f in items]

    def test_the_app_manager_on_wifi_is_a_caution(self):
        items = self.run_eval(reading(listeners=[{"proto": "tcp", "port": 50080, "reach": "all", "uid": 0},
                                                 {"proto": "tcp", "port": 1883, "reach": "robot", "uid": 0}]))
        self.assertEqual(self.ids(items), ["listen:pc2:tcp:50080"]); self.assertEqual(items[0]["severity"], "caution")

    def test_ports_only_on_the_robot_network_or_loopback_are_not_findings(self):
        self.assertEqual(self.run_eval(reading(listeners=[{"proto": "tcp", "port": 50080, "reach": "robot"}, {"proto": "tcp", "port": 5000, "reach": "local"}])), [])

    def test_other_open_ports_are_grouped_into_one_info(self):
        items = self.run_eval(reading(listeners=[{"proto": "tcp", "port": 8899, "reach": "all"}, {"proto": "tcp", "port": 22, "reach": "all"}]))
        self.assertEqual(self.ids(items), ["ports:pc2"]); self.assertEqual(items[0]["detail"], "22/tcp, 8899/tcp")

    def test_discoverable_bluetooth_is_a_caution_and_pairable_only_an_info(self):
        bt = lambda **c: reading(bluetooth={"adapters": ["hci0"], "controller": {"powered": True, "discoverable": False, "pairable": False, **c}})  # noqa: E731
        self.assertEqual(self.run_eval(bt(discoverable=True))[0]["severity"], "caution")
        self.assertEqual(self.run_eval(bt(pairable=True))[0]["severity"], "info")
        self.assertEqual(self.run_eval(bt()), [])
        self.assertEqual(self.run_eval(reading(bluetooth={"adapters": ["hci0"], "controller": None})), [])         # unknown is not a finding

    def test_silent_agent_missing_enforcer_and_missing_reading(self):
        self.assertEqual(self.ids(self.run_eval(None, enforcer=False)), ["enforcer:pc2", "posture:pc2"])
        self.assertIn("agent:pc2", self.ids(self.run_eval(reading(), last_seen=self.now - 500)))

    def test_remote_sessions_are_listed_local_ones_are_not(self):
        items = self.run_eval(reading(sessions=[{"user": "agi", "tty": "pts/0", "from": "192.168.30.5"}, {"user": "run", "tty": "tty1", "from": ":0"}]))
        self.assertEqual(self.ids(items), ["session:pc2:agi:192.168.30.5"])

    def test_accepted_findings_sort_last_and_are_marked(self):
        r = reading(listeners=[{"proto": "tcp", "port": 50080, "reach": "all"}, {"proto": "tcp", "port": 111, "reach": "all"}])
        items = self.run_eval(r, accepted=["listen:pc2:tcp:111"])
        self.assertEqual([(f["id"], f["accepted"]) for f in items], [("listen:pc2:tcp:50080", False), ("listen:pc2:tcp:111", True)])


class Api(Base):
    def post(self, host="pc2", **kw):
        return call(self.base, "POST", "/api/v1/report", AG, {"host": host, "edges": [], "stats": {}, "posture": reading(**kw)})

    def test_reading_is_stored_findings_need_admin_and_accept_works(self):
        self.assertEqual(self.post(listeners=[{"proto": "tcp", "port": 50080, "reach": "all", "uid": 0, "comm": "app_manager"}])[0], 200)
        self.assertEqual(call(self.base, "GET", "/api/v1/findings", AG)[0], 403)
        r = call(self.base, "GET", "/api/v1/findings", AD)[1]
        f = [x for x in r["findings"] if x["id"] == "listen:pc2:tcp:50080"][0]
        self.assertIn("app_manager", f["detail"])
        before = r["open"]
        st, r2, _ = call(self.base, "POST", "/api/v1/findings/accept", AD, {"id": f["id"], "accept": True})
        self.assertEqual((st, r2["open"]), (200, before - 1))
        self.assertEqual(call(self.base, "POST", "/api/v1/findings/accept", AD, {"id": "nope"})[0], 400)
        self.assertEqual(call(self.base, "POST", "/api/v1/findings/accept", AG, {"id": f["id"]})[0], 403)
        self.assertEqual(call(self.base, "POST", "/api/v1/findings/accept", AD, {"id": f["id"], "accept": False})[1]["open"], before)

    def test_posture_view_has_the_latest_reading(self):
        self.post(usb=[{"bus": "1-1", "id": "054c:0ce6", "vendor": "Sony", "product": "DualSense"}])
        v = call(self.base, "GET", "/api/v1/posture", AD)[1]
        self.assertEqual(v["hosts"][0]["host"], "pc2"); self.assertEqual(v["hosts"][0]["usb"][0]["product"], "DualSense")
        self.assertIn("pc2|usb|1-1/054c:0ce6", v["first_seen"])

    def test_a_new_device_after_the_learning_window_raises_an_alert_once(self):
        self.post(usb=[])                                                    # first reading, nothing yet
        dev = {"bus": "1-2", "id": "0951:1666", "vendor": "Kingston", "product": "DataTraveler"}
        self.post(usb=[dev]); self.post(usb=[dev])
        alerts = [a for a in call(self.base, "GET", "/api/v1/alerts", AD)[1]["alerts"] if a["kind"] == "new_usb_device"]
        self.assertEqual(len(alerts), 1); self.assertIn("DataTraveler", alerts[0]["detail"])

    def test_the_first_reading_from_a_computer_is_a_baseline_not_a_flood_of_alerts(self):
        self.post(usb=[{"bus": "1-2", "id": "0951:1666", "vendor": "K", "product": "P"}], neighbors=[{"ip": "10.0.0.2", "mac": "AA:BB:CC:DD:EE:01", "dev": "x", "random": False}])
        self.assertEqual(call(self.base, "GET", "/api/v1/alerts", AD)[1]["alerts"], [])

    def test_bluetooth_and_lan_devices_alert_too(self):
        self.post(bluetooth={"adapters": ["hci0"], "controller": None, "paired": [], "connected": []}, neighbors=[])
        self.post(bluetooth={"adapters": ["hci0"], "controller": None, "paired": [{"mac": "00:11:22:33:44:55", "name": "Phone"}], "connected": []},
                  neighbors=[{"ip": "192.168.30.9", "mac": "7A:11:22:33:44:55", "dev": "wifi0", "random": True}])
        kinds = sorted(a["kind"] for a in call(self.base, "GET", "/api/v1/alerts", AD)[1]["alerts"])
        self.assertEqual(kinds, ["new_bluetooth_device", "new_lan_device"])

    def test_an_oversized_or_malformed_posture_does_not_break_the_report(self):
        st, _, _ = call(self.base, "POST", "/api/v1/report", AG, {"host": "pc2", "edges": [], "stats": {}, "posture": "junk"})
        self.assertEqual(st, 200)
        st, _, _ = call(self.base, "POST", "/api/v1/report", AG, {"host": "pc2", "edges": [], "stats": {},
                                                                  "posture": {"usb": [{"bus": "x", "id": "y", "product": "z" * 300000}]}})
        self.assertEqual(st, 400)


if __name__ == "__main__":
    unittest.main()
