"""FUNCTIONAL test of the ruleset in the real kernel, in a throwaway user+net namespace (no root, no effect on the host).

A dummy interface plays 'the internet'. We attempt a connection or datagram to each target and read the interface's
transmit counter: if the packet left the machine the counter moved ("tx"), if netfilter dropped it, it did not ("dropped").
(TCP gives no error on an OUTPUT drop: connect() just times out, so the counter is the only reliable witness.)
"""
import json, os, shutil, subprocess, sys, tempfile, textwrap, unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
INNER = r'''
import json, socket, subprocess, sys, time
sys.path.insert(0, %(root)r)
from robosec.netscope import Scoper
from robosec.nftrender import DEFAULT_POLICY, render
from robosec.gatewayd import parse_flows
import copy

def sh(*a):
    r = subprocess.run(a, capture_output=True, text=True)
    assert r.returncode == 0, (a, r.stderr)
    return r.stdout

sh("ip", "link", "set", "lo", "up")
sh("ip", "link", "add", "d0", "type", "dummy")
sh("ip", "addr", "add", "10.0.1.41/24", "dev", "d0")
sh("ip", "link", "set", "d0", "up")
try:
    open("/proc/sys/net/ipv6/conf/d0/disable_ipv6", "w").write("1")
except OSError:
    pass
time.sleep(1.5)
sh("ip", "route", "add", "default", "dev", "d0")

def tx():
    # /proc/net/dev is per network namespace (unlike /sys, which still shows the host's interfaces)
    for line in open("/proc/net/dev"):
        if line.strip().startswith("d0:"):
            return int(line.split(":", 1)[1].split()[9])
    raise RuntimeError("d0 missing")

def probe(proto, addr, port):
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    s = socket.socket(socket.AF_INET, kind); s.settimeout(0.3)
    before = tx()
    try:
        if proto == "tcp":
            s.connect((addr, port))
        else:
            s.sendto(b"x" * 100, (addr, port))
    except OSError:
        pass                    # EPERM (udp drop) or timeout (tcp): the counter decides
    finally:
        s.close()
    time.sleep(0.05)
    return "tx" if tx() > before else "dropped"

learned = {"voice-and-audio": ["198.51.100.7"], "dns": ["1.1.1.1"]}
def load(**kw):
    p = copy.deepcopy(DEFAULT_POLICY); p.update(kw)
    open("/tmp/r.nft", "w").write(render(p, Scoper(), learned)); sh("nft", "-f", "/tmp/r.nft")

targets = {"blockcidr": ("tcp", "203.0.113.9", 443), "voice": ("tcp", "198.51.100.7", 443), "dns": ("tcp", "1.1.1.1", 443),
           "unknown": ("tcp", "8.8.8.8", 443), "robot": ("tcp", "10.0.1.40", 50080), "lan": ("tcp", "192.168.30.69", 22),
           "udp53": ("udp", "9.9.9.9", 53), "udp-other": ("udp", "9.9.9.9", 9999)}
out = {}
load(mode="observe", default_internet="block", categories={"voice-and-audio": "block"}, block_cidrs=["203.0.113.0/24"])
out["observe"] = {k: probe(*v) for k, v in targets.items()}
load(mode="enforce", default_internet="block", categories={"voice-and-audio": "block", "dns": "allow"}, block_cidrs=["203.0.113.0/24"])
out["enforce_default_block"] = {k: probe(*v) for k, v in targets.items()}
load(mode="enforce", default_internet="allow", categories={"voice-and-audio": "block"})
out["enforce_default_allow"] = {k: probe(*v) for k, v in targets.items()}
j = json.loads(sh("nft", "-j", "list", "set", "inet", "robosec", "flows4"))
out["flows"] = {f["addr"]: f["bytes"] for f in parse_flows(j)}
print("RESULT=" + json.dumps(out))
'''


@unittest.skipUnless(shutil.which("nft") and shutil.which("unshare") and shutil.which("ip"), "nft/unshare/ip not available")
class Functional(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        f = tempfile.mktemp(suffix=".py"); open(f, "w").write(INNER % {"root": os.path.abspath(ROOT)})
        r = subprocess.run(["unshare", "-Urn", sys.executable, f], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            if "unshare" in r.stderr or "Operation not permitted" in r.stderr and "unshare" in r.stderr:
                raise unittest.SkipTest("user namespaces unavailable: " + r.stderr[:200])
            raise AssertionError(r.stdout + r.stderr)
        cls.res = json.loads([l for l in r.stdout.splitlines() if l.startswith("RESULT=")][0][7:])

    def test_observe_mode_blocks_nothing(self):
        self.assertNotIn("dropped", self.res["observe"].values(), self.res["observe"])

    def test_enforce_default_block(self):
        r = self.res["enforce_default_block"]
        self.assertEqual(r["blockcidr"], "dropped")      # explicit block list
        self.assertEqual(r["voice"], "dropped")          # blocked category
        self.assertEqual(r["unknown"], "dropped")        # never-seen destination, default block
        self.assertEqual(r["udp-other"], "dropped")
        self.assertEqual(r["dns"], "tx")             # allowed category
        self.assertEqual(r["udp53"], "tx")           # always-allow port
        self.assertEqual(r["robot"], "tx")           # robot-internal is never judged
        self.assertEqual(r["lan"], "tx")             # trusted LAN is never judged

    def test_enforce_default_allow_blocks_only_the_blocked_category(self):
        r = self.res["enforce_default_allow"]
        self.assertEqual(r["voice"], "dropped")
        self.assertEqual([k for k, v in r.items() if v == "dropped"], ["voice"])

    def test_bytes_are_counted_per_destination_even_for_dropped_traffic(self):
        flows = self.res["flows"]
        self.assertIn("8.8.8.8", flows); self.assertGreater(flows["8.8.8.8"], 0)
        self.assertNotIn("10.0.1.40", flows)           # internal traffic is never counted
        self.assertNotIn("192.168.30.69", flows)

if __name__ == "__main__":
    unittest.main()
