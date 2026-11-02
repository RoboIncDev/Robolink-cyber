import os, socket, struct, tempfile, unittest
from robosec.netscope import Scoper
from robosec.procnet import parse_net_file, _hex_ip, cgroup_unit, read_sockets, inode_owner_map, proc_info
from robosec.agent import Sampler, EdgeTable


def hx4(ip):  # /proc/net/tcp stores IPv4 as one little-endian 32-bit word
    return struct.pack("<I", struct.unpack(">I", socket.inet_aton(ip))[0]).hex().upper() if False else \
        "%08X" % struct.unpack("<I", socket.inet_aton(ip))[0]


def line(sl, laddr, lport, raddr, rport, state, uid, inode):
    return f"{sl:4d}: {hx4(laddr)}:{lport:04X} {hx4(raddr)}:{rport:04X} {state} 00000000:00000000 00:00000000 00000000 {uid:5d}        0 {inode} 1 0000000000000000 100 0 0 10 0"


HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


class Scope(unittest.TestCase):
    def test_classes(self):
        s = Scoper()
        cases = {"10.0.1.40": "robot", "10.0.200.42": "robot", "10.11.1.2": "robot", "127.0.0.1": "local", "::1": "local",
                 "169.254.1.1": "local", "224.0.0.251": "local", "192.168.30.69": "lan", "192.168.88.1": "lan",
                 "100.67.102.59": "vpn", "172.17.0.2": "lan", "10.99.0.1": "lan", "8.8.8.8": "internet",
                 "1.1.1.1": "internet", "fdc7:e2f2:388f:d514::1": "robot", "2001:db8::1": "internet",
                 "::ffff:8.8.8.8": "internet", "::ffff:10.0.1.40": "robot", "not-an-ip": "internet"}
        for addr, want in cases.items():
            self.assertEqual(s.scope(addr), want, addr)

    def test_overrides(self):
        s = Scoper(robot_nets=["172.30.0.0/16"])
        self.assertEqual(s.scope("172.30.4.4"), "robot")
        self.assertEqual(s.scope("10.0.1.40"), "lan")          # no longer robot-internal under the override


class Parse(unittest.TestCase):
    def test_hex_ip(self):
        self.assertEqual(_hex_ip("0100007F"), "127.0.0.1")
        self.assertEqual(_hex_ip("2865A8C0"), "192.168.101.40")
        self.assertEqual(_hex_ip("00000000000000000000000001000000"), "::1")
        self.assertEqual(_hex_ip("B80D01200000000000000000" "01000000"), "2001:db8::1")

    def test_parse_lines(self):
        txt = HEADER + line(0, "0.0.0.0", 22, "0.0.0.0", 0, "0A", 0, 111) + "\n" + line(1, "10.0.1.41", 40000, "8.8.8.8", 443, "01", 1001, 222) + "\n"
        rows = list(parse_net_file(txt, "tcp"))
        self.assertEqual(rows[0]["state"], "0A"); self.assertEqual(rows[0]["lport"], 22)
        self.assertEqual((rows[1]["raddr"], rows[1]["rport"], rows[1]["inode"], rows[1]["uid"]), ("8.8.8.8", 443, 222, 1001))

    def test_garbage_is_skipped(self):
        self.assertEqual(list(parse_net_file(HEADER + "garbage line\nzz:zz zz:zz\n", "tcp")), [])

    def test_cgroup_unit(self):
        self.assertEqual(cgroup_unit("0::/system.slice/robolink-voice.service\n"), "robolink-voice.service")
        self.assertEqual(cgroup_unit("0::/user.slice/user-1001.slice/session-3.scope\n"), "session-3.scope")
        self.assertEqual(cgroup_unit("0::/\n"), "")

    def test_real_proc_does_not_crash(self):
        self.assertIsInstance(read_sockets(), list)
        owners, unreadable = inode_owner_map()
        self.assertIsInstance(owners, dict); self.assertGreaterEqual(unreadable, 0)
        self.assertEqual(proc_info(os.getpid())["pid"], os.getpid())


class FakeProc(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fakeproc-")
        os.makedirs(f"{self.root}/net")
        tcp = HEADER + "\n".join([
            line(0, "0.0.0.0", 22, "0.0.0.0", 0, "0A", 0, 1),                            # sshd listening
            line(1, "10.0.1.41", 22, "192.168.30.69", 50000, "01", 0, 2),                # inbound ssh from the LAN, owner unreadable
            line(2, "10.0.1.41", 40000, "8.8.8.8", 443, "01", 1001, 3),                  # outbound to the internet
            line(3, "10.0.1.41", 40001, "10.0.1.40", 50080, "01", 1001, 4),              # outbound to PC1 (robot-internal)
            line(4, "127.0.0.1", 40002, "127.0.0.1", 8750, "01", 1001, 5),               # loopback: ignored
            line(5, "10.0.1.41", 40003, "1.1.1.1", 443, "06", 1001, 6),                  # TIME_WAIT: ignored
        ]) + "\n"
        open(f"{self.root}/net/tcp", "w").write(tcp)
        for n in ("tcp6", "udp", "udp6"):
            open(f"{self.root}/net/{n}", "w").write(HEADER)
        os.makedirs(f"{self.root}/100/fd")
        for fd, ino in ((3, 3), (4, 4), (5, 5)):
            os.symlink(f"socket:[{ino}]", f"{self.root}/100/fd/{fd}")
        os.symlink("/usr/bin/python3", f"{self.root}/100/exe")
        open(f"{self.root}/100/comm", "w").write("python3\n")
        open(f"{self.root}/100/cmdline", "w").write("python3\x00robolink.py\x00--x\x00")
        open(f"{self.root}/100/cgroup", "w").write("0::/system.slice/robolink-voice.service\n")

    def test_sampler(self):
        obs, stats = Sampler(Scoper(), proc_root=self.root).sample()
        by = {(o["dir"], o["raddr"]): o for o in obs}
        self.assertEqual(set(by), {("in", "192.168.30.69"), ("out", "8.8.8.8"), ("out", "10.0.1.40")})
        o = by[("out", "8.8.8.8")]
        self.assertEqual((o["scope"], o["exe"], o["unit"], o["proto"], o["rport"]), ("internet", "/usr/bin/python3", "robolink-voice.service", "tcp", 443))
        self.assertEqual(o["cmd"], "python3 robolink.py --x")
        self.assertEqual(by[("out", "10.0.1.40")]["scope"], "robot")
        i = by[("in", "192.168.30.69")]
        self.assertEqual((i["exe"], i["scope"]), ("?", "lan"))                  # inode 2 has no readable owner
        self.assertEqual(stats["unattributed"], 1)

    def test_edge_table(self):
        s = Sampler(Scoper(), proc_root=self.root)
        t = EdgeTable()
        obs, _ = s.sample(); t.update(obs, 100.0); t.update(obs, 102.0)
        first = t.drain(100)
        self.assertEqual(len(first), 3); self.assertEqual(t.pending(), 0)
        e = [x for x in first if x["raddr"] == "8.8.8.8"][0]
        self.assertEqual((e["n"], e["first"], e["last"]), (2, 100.0, 102.0))
        t.update(obs, 104.0)
        again = t.drain(100)
        self.assertEqual(len(again), 3)
        self.assertEqual([x for x in again if x["raddr"] == "8.8.8.8"][0]["n"], 3)

if __name__ == "__main__":
    unittest.main()
