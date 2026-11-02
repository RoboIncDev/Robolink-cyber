"""FUNCTIONAL test of the enforcer with the real iptables (nf_tables) in a throwaway user+net namespace: no root, no effect on the host.
A dummy interface plays 'the internet'; the interface's transmit counter says whether a packet left ("tx") or was dropped ("dropped")."""
import json, os, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
INNER = r'''
import json, socket, subprocess, sys, time, urllib.error
sys.path.insert(0, %(root)r)
from robosec.enforcer import Enforcer, CHAIN

def sh(*a, check=True):
    r = subprocess.run(a, capture_output=True, text=True)
    if check: assert r.returncode == 0, (a, r.stderr)
    return r.stdout

sh("ip", "link", "set", "lo", "up"); sh("ip", "link", "add", "d0", "type", "dummy"); sh("ip", "addr", "add", "10.0.1.41/24", "dev", "d0")
sh("ip", "link", "set", "d0", "up"); sh("ip", "route", "add", "default", "dev", "d0")
try: open("/proc/sys/net/ipv6/conf/d0/disable_ipv6", "w").write("1")
except OSError: pass
time.sleep(1.5)

def tx():
    for line in open("/proc/net/dev"):
        if line.strip().startswith("d0:"): return int(line.split(":", 1)[1].split()[9])
def probe(proto, addr, port=443):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM); s.settimeout(0.25); before = tx()
    try:
        s.connect((addr, port)) if proto == "tcp" else s.sendto(b"x" * 200, (addr, port))
    except OSError: pass
    finally: s.close()
    time.sleep(0.05); return "tx" if tx() > before else "dropped"

class R:
    def __init__(s, b): s.b = b
    def read(s): return json.dumps(s.b).encode()
    def __enter__(s): return s
    def __exit__(s, *a): return False
state = {"bl": None, "up": True, "posts": []}
def opener(req, timeout=0):
    if not state["up"]: raise urllib.error.URLError("down")
    if req.get_method() == "POST": state["posts"].append(json.loads(req.data)); return R({"ok": True})
    return R(state["bl"])
clock = [1000.0]
e = Enforcer({"host": "pc3", "token": "t", "failopen_s": 120}, opener=opener, clock=lambda: clock[0])

T = {"blocked_a": ("tcp", "203.0.113.9"), "blocked_b": ("udp", "198.51.100.7"), "counted": ("tcp", "1.1.1.1"), "unlisted": ("tcp", "8.8.8.8"),
     "internal": ("tcp", "10.0.1.40"), "lan": ("tcp", "192.168.30.69")}
out = {}
state["bl"] = {"enabled": True, "block": ["203.0.113.9", "198.51.100.7", "10.0.1.40", "192.168.30.69"], "count": ["1.1.1.1"], "generation": "g1"}
out["step1"] = {k: v for k, v in e.step().items() if k in ("installed", "dropping", "refused", "heartbeat")}
out["secured"] = {k: probe(*v) for k, v in T.items()}
out["rules"] = sorted(l for l in sh("iptables", "-S", CHAIN).splitlines() if l.startswith("-A"))
out["hook"] = [l for l in sh("iptables", "-S", "OUTPUT").splitlines() if CHAIN in l]
c = {(r["addr"], r["verdict"]): r for r in e.counters()}
out["counters"] = {"drop_bytes_203": c[("203.0.113.9", "DROP")]["bytes"], "drop_packets_198": c[("198.51.100.7", "DROP")]["packets"], "return_bytes_1111": c[("1.1.1.1", "RETURN")]["bytes"]}
e.step(); out["hb"] = {k: state["posts"][-1][k] for k in ("host", "enforcing", "rules")}
out["hb_counters"] = sorted((x["addr"], x["verdict"]) for x in state["posts"][-1]["counters"])
# secure OFF: the same addresses become counters, nothing is dropped
state["bl"] = {"enabled": False, "block": [], "count": ["203.0.113.9", "198.51.100.7", "1.1.1.1"], "generation": "g2"}; e.step()
out["off"] = {k: probe(*v) for k, v in T.items()}
# secure ON again, then the server disappears for too long: fail open
state["bl"] = {"enabled": True, "block": ["203.0.113.9"], "count": ["1.1.1.1"], "generation": "g3"}; e.step()
out["on_again"] = probe(*T["blocked_a"])
state["up"] = False; clock[0] += 200; e.step(); out["server_lost"] = probe(*T["blocked_a"]); out["failed_open"] = e.failed_open
state["up"] = True; e.step(); out["server_back"] = probe(*T["blocked_a"])
# stop: chain and hook are gone, traffic flows
e.remove()
out["after_remove"] = {"blocked_a": probe(*T["blocked_a"]), "chain_left": CHAIN in sh("iptables", "-S"), "hook_left": CHAIN in sh("iptables", "-S", "OUTPUT")}
print("RESULT=" + json.dumps(out))
'''


@unittest.skipUnless(shutil.which("iptables") and shutil.which("unshare") and shutil.which("ip"), "iptables/unshare/ip not available")
class Functional(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        f = tempfile.mktemp(suffix=".py"); open(f, "w").write(INNER % {"root": os.path.abspath(ROOT)})
        r = subprocess.run(["unshare", "-Urn", sys.executable, f], capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            if "unshare" in r.stderr or ("Operation not permitted" in r.stderr and "unshare" in r.stderr):
                raise unittest.SkipTest("user namespaces unavailable: " + r.stderr[:200])
            raise AssertionError(r.stdout + r.stderr)
        cls.res = json.loads([l for l in r.stdout.splitlines() if l.startswith("RESULT=")][0][7:])

    def test_secured_blocks_only_the_chosen_foreign_addresses(self):
        s = self.res["secured"]
        self.assertEqual((s["blocked_a"], s["blocked_b"]), ("dropped", "dropped"))        # TCP and UDP
        self.assertEqual((s["counted"], s["unlisted"]), ("tx", "tx"))                      # counted and unknown addresses are untouched

    def test_internal_addresses_cannot_be_blocked_even_if_the_server_asks(self):
        self.assertEqual((self.res["secured"]["internal"], self.res["secured"]["lan"]), ("tx", "tx"))
        self.assertTrue(all("10.0.1.40" not in r and "192.168.30.69" not in r for r in self.res["rules"]))
        self.assertEqual(self.res["step1"]["refused"], 2)

    def test_only_our_chain_and_a_single_hook(self):
        self.assertEqual(len(self.res["hook"]), 1)
        self.assertEqual(self.res["rules"], ["-A ROBOSEC_SECURE -d 1.1.1.1/32 -j RETURN", "-A ROBOSEC_SECURE -d 198.51.100.7/32 -j DROP", "-A ROBOSEC_SECURE -d 203.0.113.9/32 -j DROP"])

    def test_counters_measure_what_was_blocked_and_what_was_sent(self):
        c = self.res["counters"]
        self.assertGreater(c["drop_bytes_203"], 0); self.assertGreater(c["drop_packets_198"], 0); self.assertGreater(c["return_bytes_1111"], 0)
        self.assertEqual(self.res["hb"], {"host": "pc3", "enforcing": True, "rules": 3})
        self.assertEqual(self.res["hb_counters"], [["1.1.1.1", "RETURN"], ["198.51.100.7", "DROP"], ["203.0.113.9", "DROP"]])

    def test_switching_secure_off_lets_everything_through(self):
        self.assertNotIn("dropped", [v for k, v in self.res["off"].items()])

    def test_fail_open_and_recovery(self):
        self.assertEqual(self.res["on_again"], "dropped")
        self.assertEqual((self.res["server_lost"], self.res["failed_open"]), ("tx", True))       # control lost for too long: traffic flows
        self.assertEqual(self.res["server_back"], "dropped")                                       # control back: protection resumes

    def test_removal_leaves_nothing_behind(self):
        self.assertEqual(self.res["after_remove"], {"blocked_a": "tx", "chain_left": False, "hook_left": False})

if __name__ == "__main__":
    unittest.main()
