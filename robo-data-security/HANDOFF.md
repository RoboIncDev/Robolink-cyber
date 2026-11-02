# Robosec: robot data-security for the AgiBot X2 "Cadet"

**Handoff document for the next agent.** Read section 0 first, then section 4 (hard rules) before touching anything.
Written 2026-11-02. Everything marked **[verified]** was observed on the real robot or tested here; everything marked
**[unverified]** is a guess or inference and must be checked in Phase 0.

---

## 0. Start here

**The goal.** A security tool for a robot with several computers, in the spirit of OpenSnitch (Linux per-process outbound
firewall): *see all data leaving every computer, analyse it, and let the user enable or disable categories of data going to other
parties.* The owner calls it "robo-data security software".

**State of the work.** A working first version exists in this directory (`/home/ubuntu/cyber/robo-data-security/`):
a per-computer agent, a central server with API and dashboard, and a gateway daemon that renders and applies an nftables
egress ruleset. **108 automated tests pass** (section 5), including a functional test that loads the ruleset into the real
kernel and checks that blocked destinations are refused. It has **not been installed on the robot**: the robot was off the
network when this was written, so nothing about the real computers has been measured yet.

**Do these, in order:**
1. `cd /home/ubuntu/cyber/robo-data-security && python3 -W ignore -m unittest discover -s tests -t .` must print `OK` (108 tests).
2. Read sections 2 to 4 of this file.
3. Wait for / ask the human to power the robot, then run **Phase 0**: `tools/collect_phase0.sh` (read-only). Write `phase0/REPORT.md`.
4. Ask the human the decisions in section 11 (D1 to D5) *before* installing anything.
5. Phase 1 (observe only) on PC2, then PC3, then PC1. Never skip to enforcement.

**What you must not do without the human:** type any password, install anything as root, stop any robot service, restart or reboot
a computer, or change a firewall table other than our own `inet robosec`. See section 4.

---

## 1. Goal, scope, non-goals

**In scope**
- Per-process visibility of network connections on each computer (PC1, PC2, PC3).
- A central view: who talked to whom, how often, how many bytes (bytes only at the gateway).
- Plain-language categories (cloud, telemetry, voice, camera, OTA, remote access, ...) that the owner can allow or block.
- Enforcement at the **egress gateway** (PC2) for traffic leaving the robot to the internet; alerts for new destinations.
- Safe by construction: passive on the robot's internal network, fail-open, one reversible table, no vendor files modified.

**Out of scope for v1** (see backlog, section 13): payload inspection or TLS interception, per-process *blocking* on PC1/PC3,
DNS-name attribution, inbound-exposure policy, mTLS, packaging as a vendor "EM" app, any change to robot control software.

**Non-goals.** Making the robot "unhackable"; replacing ROS 2 security (SROS2) or a command firewall such as RoboShield
(they complement this tool: this one watches *data leaving*, those protect *commands entering*).

---

## 2. Ground truth about the robot

### 2.1 The three computers (all **[verified]** unless marked)

| | PC1 (SoC 0) | PC2 (SoC 1) | PC3 (SoC 2) |
|---|---|---|---|
| Role | motion controller, EtherCAT master, vendor cloud apps | developer computer; Wi-Fi, 5G modem, Bluetooth, depth camera; **egress gateway** | head: face display, speaker/mic, cameras, agent |
| Hardware | aarch64 | Jetson Orin NX, 8 cores, 15.6 GB | Rockchip RK3588 |
| Kernel | `6.1.99-rt36` **PREEMPT_RT** | `5.15.148-tegra` | `6.1.99` |
| OS | vendor image | Ubuntu 22.04.5, system `python3` = 3.10 | Ubuntu 22.04.5 |
| Internal addr (`develop0`) | 10.0.1.40 | 10.0.1.41 | 10.0.1.42 |
| Management addr (`ssh0`) | 10.0.200.40 | 10.0.200.41 | 10.0.200.42 |
| Other addrs | `hotspot0` 192.168.88.88 (an access point); `ethercat0` (L2 only) | `wifi0` DHCP on 192.168.30.0/24 (**changes often**); `sensor0` 10.11.1.1 (no carrier when checked) | none |
| Default route | via 10.0.1.41 (PC2) | `wifi0` via 192.168.30.1 | via 10.0.1.41 (PC2) |
| Login that works | `run@10.0.1.40` with PC2's key (flags below) | `agi@<wifi addr>` with the workstation key | `run@10.0.1.42` with PC2's key (flags below) |

PC2's Wi-Fi MAC is `bc:d2:2c:20:f9:68`; its Tailscale name is `cadet-x2` (100.67.102.59, rootless userspace networking).
The operator workstation is `ubuntu-G450` (192.168.30.69).

**Key consequence [verified, routes only]:** PC1 and PC3 both route their default traffic through PC2, so **PC2 is the natural single
enforcement point for everything that leaves the robot.** *Not yet verified:* that PC2 actually forwards and NATs for them
(`ip_forward`, masquerade) and that PC1/PC3 reach the internet at all. Phase 0 task P0-4.

### 2.2 What runs where (inventory by name; **real executable paths are [unverified]**)
- **PC1 EM apps** (from the app manager on :50080): `app_proxy atop cloud_proxy data_exporter dc_slave dit_bridge dit_qt drp hal_485 hal_ethercat hal_imu
  hal_imu_calibration hal_imu_ros hal_pmu hds_slave housekeeper mc mqtt_broker ota poweroff0 rc reboot0 sm task_manager teleop_bridge`.
  Listening: 22, 111, 1883 and 8883 (MQTT), 5000, 50080 (EM HTTP API), 50091, DDS multicast 239.255.0.1:7400.
- **PC3 EM apps:** `agent atop dit_bridge dit_qt drp face_ui face_ui_proxy hal_audio hal_sensor hds_slave housekeeper interaction_slave
  mono_perception ota poweroff2 reboot2`. Audio codecs ES8388 (speaker) and ES7210 (mic array), DSI face display, MIPI cameras.
- **PC2:** our own tools, `robolink-voice-device`, `robolink-cadet-helper`, `x2_tts.py`, `x2_mute_keeper.py`, `tailscaled`, `bluetoothd`, a ROS
  component container, and **other developers' services** (`kamil-testing/dashboard/bridge.py`, `kamil-testing/guard/guard.py`). PC2 had a
  load average of 26 on 8 cores 4 minutes after a reboot. Do not stop those services; budget CPU around them.
- **Inter-computer traffic [verified]:** ROS 2 / FastDDS (UDP, multicast discovery), EM HTTP :50080 (PC1 and PC3), SSH, sshfs of `/agibot/data`
  (PC3 mounts PC1 and PC2 under `/agibot/nfs/socN`, user `nfs`), PTP time sync (`ptp4l` on `develop0`), MQTT broker on PC1.

### 2.3 Real-time hazards [verified from config files]
- PC1's `hal_ethercat` thread binds CPU 7, its poll thread CPU 6, the motion controller's RL actions CPUs 5 and 6. **Our agent on PC1 must stay on
  CPUs 0-3** (`CPUAffinity=0 1 2 3` in the unit, commented line provided).
- The joints are on **EtherCAT (`ethercat0` on PC1), a layer-2 bus**: it is not IP and our tool must never touch it. 1 ms cycle.
- The deploy node on PC2 publishes joint commands at about 500 Hz and trips a watchdog if its pose input is stale for >1.25 s. A monitoring tool
  that stalls PC2 can therefore affect the robot. Hence the CPU caps in the units and the "passive on the internal network" rule.

### 2.4 Access recipes [verified]
```bash
# workstation -> PC2   (PC2's Wi-Fi address changes; find it by MAC:)
ip neigh | grep -i bc:d2:2c:20:f9:68        # after pinging the /24; tools/collect_phase0.sh automates this
ssh agi@<PC2 wifi address>                  # may need -o StrictHostKeyChecking=accept-new the first time

# PC2 -> PC1 / PC3. PC2's /etc/ssh/ssh_config.d/run.conf forces another default key for 10.0.1.4x, so ALWAYS pass the key:
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes run@10.0.1.40 '<cmd>'
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes run@10.0.1.42 '<cmd>'
```
Never use passwords. If key login stops working, **ask the human** to run `ssh-copy-id -i ~/.ssh/id_ed25519 run@10.0.1.40` on PC2 themselves.
`agi`'s sudo on PC2 is restricted by sudoers. `run` is in the `sudo` group but its sudo password is **[unverified]** and is the human's to enter.

### 2.5 Not yet known (Phase 0 must answer)
Q1 kernel eBPF/nftables/conntrack support on each computer (PC1 is PREEMPT_RT). Q2 does PC2 forward and NAT? Q3 do PC1/PC3 reach the
internet, and through which interface? Q4 what vendor `nft`/`iptables` tables already exist (we must not collide)? Q5 real executable paths of the vendor apps
(to fix `config/categories.json`). Q6 what destinations the robot contacts at idle (the baseline). Q7 how root is obtained for installs. Q8 does a vendor
OTA or reset wipe `/opt` and `/etc` (persistence). Q9 is the 5G modem ever the default route? Q10 DNS resolvers in use.

---

## 3. Architecture

```
 PC1 (motion)             PC3 (head)               PC2 (dev + egress gateway)                      workstation
 ┌────────────┐          ┌────────────┐           ┌──────────────────────────────────────┐        ┌───────────┐
 │ robosec-   │          │ robosec-   │           │ robosec-agent   robosec-server       │  ssh   │ browser   │
 │ agent      │─ report ─┤ agent      │─ report ──┤  (reads /proc)   (SQLite, API, UI)   │◄─tunnel┤ dashboard │
 │ read-only  │  HTTP    │ read-only  │  HTTP     │ robosec-gatewayd (root, CAP_NET_ADMIN)│        └───────────┘
 └────────────┘ + token  └────────────┘ + token   │   pulls ruleset ─► nft table inet robosec
      │ default route via PC2         │            │   pushes per-destination byte counters │
      └───────────────────────────────┴───────────►│  forward chain (PC1/PC3 traffic)       │──► Wi-Fi / 5G / internet
                                                   │  output  chain (PC2's own traffic)     │
                                                   └──────────────────────────────────────┘
```

**Why two layers.** A gateway sees *packets* but not *which program* sent them (NAT erases it). An agent sees *which program* but cannot
count bytes per socket from `/proc`. Together: the agent says "process X on PC3 talks to 203.0.113.9:443", the gateway counts bytes to
203.0.113.9 and can drop them, and the server joins the two by destination address.

**Data flow.** Agent samples `/proc/net/{tcp,tcp6,udp,udp6}` and `/proc/<pid>/fd` every 2 s, builds *edges* `(dir, exe, proto, raddr, rport)`, reports
changed edges every 10 s (spooling to disk if the server is down). The server classifies scope (robot/lan/vpn/local/internet), assigns a category
by rule, stores edges, raises alerts for new internet destinations after the learning window, and owns the policy. `robosec-gatewayd` polls
`/api/v1/gateway/ruleset`, validates with `nft -c`, applies atomically, verifies it can still reach the server, rolls back otherwise, and
pushes `flows4/flows6` counters to `/api/v1/gateway/flows`.

**Scopes** (server-side, `robosec/netscope.py`): `local` (loopback, link-local, multicast), `robot` (10.0.1.0/24, 10.0.200.0/24, 10.11.1.0/24,
fdc7:e2f2:388f:d514::/64), `vpn` (100.64.0.0/10 and Tailscale ULA), `lan` (other RFC 1918 / ULA, including the Wi-Fi 192.168.30.0/24 and the
hotspot 192.168.88.0/24, which are **outside** the robot), `internet` (everything else, including documentation and reserved space). **Policy acts only on `internet`.**

**What it cannot see (be honest in the UI):** flows shorter than the sampling interval (the gateway counters are the cross-check); payload
contents; DNS names (reverse-DNS is not attempted); inbound traffic policy; anything on EtherCAT; traffic that leaves via a path that bypasses
PC2 (PC1's hotspot clients, PC2's own Tailscale tunnel appears as one encrypted flow to Tailscale).

---

## 4. Hard rules for any agent working on this

1. **Never type a password**, and never put one in a script. If a login needs one, stop and ask the human to run the command in their own terminal.
2. **Never stop, restart or reconfigure robot services:** `mc`, `rc`, `sm`, `hal_*`, `app_proxy`, `teleop_bridge`, EM itself, anything under
   `/agibot/software`. Never edit `/agibot/software/mc_param`. Never reboot a computer.
3. **Firewall hygiene:** only ever create, replace or delete `table inet robosec`. Never `nft flush ruleset`, never `iptables -F`, never touch vendor tables.
4. **Internal traffic is sacred.** Rules must accept `robot`, `lan`, `vpn`, `local` destinations *before* anything that counts, logs or drops.
5. **Fail open.** Any error, failed health check or stopped service must leave the robot reachable, never cut off. (A future `fail_closed` option is a human decision.)
6. **Observe before enforce.** No `mode: enforce` anywhere until Phase 1 and 2 acceptance are met and the human approves, in chat, per category.
7. **CPU discipline:** agent `CPUQuota=15%`, `Nice=10`; PC1 agent pinned to CPUs 0-3. Re-measure after every change.
8. **No data leaves the robot because of us.** The server binds to the internal interface only; logs and databases stay local; no telemetry, no cloud.
9. **Do not stop other developers' services** on PC2 (`kamil-testing/*`) or kill processes you did not start.
10. **Ask the human** before: installing as root, enabling a service, turning on enforcement, changing categories' verdicts, any action that could interrupt the
    robot's Wi-Fi or the operator's SSH session.
11. **Robot motion is out of scope.** If the robot is being tested for motion (gantry, e-stop), do not run installs or restarts at that time.

---

## 5. What exists now

### 5.1 File map
```
robosec/
  netscope.py     scope classifier (robot/lan/vpn/local/internet)             stdlib
  procnet.py      /proc/net + /proc/<pid>/fd parsing, process info             stdlib
  agent.py        Sampler, EdgeTable, Reporter (spool + replay), CLI           stdlib
  categorize.py   rule matcher (first match wins; AND inside a match)          stdlib
  nftrender.py    policy validation + nftables ruleset renderer (pure)         stdlib
  server.py       SQLite store, ingest, alerts, policy, API, dashboard         stdlib
  gatewayd.py     fetch/check/apply/verify/rollback, flow counters, --remove   stdlib
  geodb.py        offline IP -> country / network owner (DB-IP Lite), range tables  stdlib
config/           categories.json (FIRST GUESS), *.example.json
dashboard/index.html      single-file UI (no external libraries), light/dark
deploy/           install.sh, uninstall.sh, 3 systemd units
tools/            probe.sh, collect_phase0.sh (Phase 0); build_geodb.py (DB-IP CSV -> geo/); build_map.py (Natural Earth -> dashboard/map/world.json)
dashboard/        index.html (Signal System UI), fonts/ (bundled Poppins + IBM Plex Mono), map/world.json (73 KB, 174 shapes + 65 markers)
geo/              built geo database (NOT in git: third-party data, rebuilt with tools/build_geodb.py)
tests/            108 tests (below)
```
Python target is **3.10** (PC2). Dev machine runs 3.13; avoid 3.11+ only features.

### 5.2 Tests (run: `python3 -W ignore -m unittest discover -s tests -t .`)
| File | Covers |
|---|---|
| `test_netscope_procnet.py` | scope table, hex IP decoding (v4/v6 little-endian), /proc parsing, fake-`/proc` sampler, direction heuristic, unattributed handling |
| `test_categorize.py` | shipped rules, first-match, AND semantics, CIDR match, bad rules rejected |
| `test_server.py` | auth matrix (agent/gateway/admin), placeholder tokens refused, ingest, alerts (and none while learning), policy validation and versioning, ruleset content, byte counters across a counter reset, dashboard served |
| `test_nftrender.py` | observe never drops, enforce drops exactly the blocked set, internal accepted first, only our table, collapse of overlapping CIDRs, digest, `nft -c` accepts the output |
| `test_nft_integration.py` | **functional, real kernel** in a throwaway user+net namespace (no root): see 5.3 |
| `test_gatewayd.py` | apply, no-op when up to date, check failure applies nothing, rollback, fail-open, dry-run, flow parsing |
| `test_reporter.py` | bearer auth, spool, in-order replay, bounded spool, corrupt line dropped, unwritable spool dir |
| `test_end_to_end.py` | fake `/proc` -> sampler -> reporter -> real HTTP server -> ruleset |

### 5.3 Functional ruleset results (real kernel; `tx` = the packet left the interface, `dropped` = it did not)
| target | observe | enforce, default block | enforce, default allow |
|---|---|---|---|
| explicit block CIDR | tx | **dropped** | tx |
| blocked category (learned IP) | tx | **dropped** | **dropped** |
| allowed category | tx | tx | tx |
| never-seen internet address | tx | **dropped** | tx |
| robot-internal (10.0.1.40) | tx | tx | tx |
| trusted LAN (192.168.30.x) | tx | tx | tx |
| UDP 53 (always-allow) | tx | tx | tx |
| other UDP, unclassified | tx | **dropped** | tx |
Byte counters appeared for internet destinations (including dropped ones) and **never** for robot/LAN destinations.
Lesson recorded: a TCP connection dropped in the OUTPUT hook raises **no error** (it just times out); only UDP gets `EPERM`. Test with interface
counters, not exceptions.

### 5.4 Live smoke (workstation, not the robot)
Real `robosec.server` and `robosec.agent` processes: 289 sockets sampled in 51-73 ms, 58 observations, per-process attribution worked, 38
internet destinations classified as `unclassified` (expected: the categories are robot-specific), alerts raised, ruleset served only to the gateway
token, unauthenticated request got 401. Agent CPU measured **0.48 CPU-seconds over about 9 s at a 1 s interval** on the workstation
(about 5% of one core; about half that at the default 2 s). **Not measured on the robot.** The dashboard was loaded in a real browser: tables populated, policy saved through the UI (version bumped, mode changed).


### 5.6 Dashboard redesign and geography (added 2026-11-02)
**Design.** `dashboard/index.html` implements the Robo Inc. *Signal System* (Draft 0.3, https://claude.ai/artifact/3PSQWtNKvom3YFnHcnBG2d): tokens copied verbatim
(palette, type scale 12-32, spacing, radius, motion), dark by default with a Dark / Light / Device switch, Poppins for text and IBM Plex Mono for readings, state shown
as a word plus a dot, 44 px hit targets, 16 px text floor (12 px mono labels only beside larger text), em dash for missing values (so "bytes sent" shows a dash until the gateway
reports, never a fake 0), no gradients or glow. The STOP red is reserved for robot STOP and is **not** used for "Blocked". `tests/test_dashboard.py` locks these rules in.
**No external requests.** Fonts and the map are served by the server from `/static/fonts` and `/static/map` (whitelisted, no path tricks). A test fails if the page references any external URL.
**Geography.** `tools/build_geodb.py` turns DB-IP Lite country and ASN CSVs (CC BY 4.0; credit "IP Geolocation by DB-IP" with a link, shown in the footer) into compact range files in `geo/`; the server
looks every internet destination up locally at ingest and stores `cc`, `asn`, `org` on each edge (old databases are migrated automatically). `GET /api/v1/geo/summary` aggregates by country with the
owners behind each country, processes, and bytes (null, not 0, when the gateway has not reported). Country is approximate and a CDN address is placed where it is registered (1.1.1.1 shows Australia), so the owner is always shown with it.
Update monthly **on the workstation**: download the two CSVs from https://download.db-ip.com/free/ , run `tools/build_geodb.py`, copy `geo/` to the server, then `POST /api/v1/regeocode`. Set `"home": {"lat":..,"lon":..,"label":".."}` in `server.json` for the map arcs.
**Built so far:** D0 tokens + theme + bundled fonts; D1 header / readings / category switches with enforce confirmation / computers / alerts / connections table; M0 geo build + lookup;
M1 server integration + API (`/api/v1/geo/summary`, `cc` filter on `/api/v1/edges`, `/api/v1/regeocode`); M2 map asset; **M3 the map**: "Where data goes" with a 1 hour / 24 hours / all-time window and a destinations / bytes switch
(bytes is disabled until the gateway reports), world map in Equal Earth with grey shading and direct labels (blue is used only for selection), arcs from the configured home, a country panel (owners, programs, "Show these connections"),
and a table beneath that carries the same numbers for keyboard and screen-reader use. The page's projection is a copy of the build tool's; a test runs both in node and Python and requires agreement to 9 decimals.
**Not built yet:** D2 activity chart, D3 detail drawer and richer empty states, alert grouping ("Acknowledge all"; a desktop produces hundreds of alerts), hourly timeline endpoint, the owner's real **home location** (set `"home"` in `server.json`; nothing is drawn from a guess).


### 5.7 Live install on the robot (2026-11-02, trial mode, nothing persistent, no firewall changes)
| Computer | What runs | How | Visibility |
|---|---|---|---|
| PC2 | server (internal address `10.0.1.41:8750` only) + agent `pc2` | as user `agi` from `~/robosec` with `start.sh` / `stop.sh` (no root) | partial: 12 of about 15 sockets unattributed, 302 processes unreadable |
| PC3 | agent `pc3` | **temporary** systemd unit `robosec-agent` (via `sudo systemd-run`, user `run`, capabilities `CAP_SYS_PTRACE`+`CAP_DAC_READ_SEARCH` only, `CPUQuota=15%`, `Nice=10`), files in `/home/run/robosec` | full: 0 unattributed |
| PC1 | agent `pc1` | same as PC3 plus `CPUAffinity=0 1 2 3` (never the real-time cores 5 to 7) | full: 0 unattributed |
**Not installed:** the gateway (needs root on PC2 and the `nft` tool, which no robot computer has; see `docs/PHASE0_REPORT.md`). Nothing under `/etc`, no new user, no vendor service touched; `mc`, `rc`, `sm` and the EtherCAT app were checked running before and after.
**Measured (steady state, robot idle, PC2 load average about 30 from other developers' services):** PC1 agent 2.8% of one core (a sample takes about 390 ms because PC1 has about 800 processes to scan), PC3 0.6%, PC2 about 1%; about 18 MB each. **Not measured:** any effect on a running deploy (P1-3 is still open and needs a supervised idle run).
**Persistence:** the PC1/PC3 units are transient and the PC2 processes are not services, so **all three stop at a reboot** (PC2 rebooted three times on this day). Restart: PC2 `~/robosec/start.sh`; PC1/PC3 repeat the `systemd-run` command in section 8 (or install the persistent units with `deploy/install.sh`).
**View it:** `ssh -L 8760:10.0.1.41:8750 agi@<PC2 wifi address>` then open http://127.0.0.1:8760/ (the workstation's own dev copy uses 8750). Admin token on PC2: `python3 -c "import json;print(json.load(open('/home/agi/robosec/server.json'))['admin_token'])"`.
**Undo:** PC1 and PC3: `sudo systemctl stop robosec-agent; rm -rf /home/run/robosec`. PC2: `~/robosec/stop.sh; rm -rf ~/robosec`.
**First real findings:** PC1 `aima-cloud_proxy-app` holds a connection to Beijing Volcano Engine (14.103.92.63:8885); PC3 `aima-agent-app` holds connections to Tencent Cloud Shenzhen (124.223.144.198:1443, 43.153.127.148:1883) and Volcano Engine (180.184.178.142:443); all classified `robot-vendor-cloud` by the shipped rules. What is sent is not known: bytes need the gateway.

### 5.5 Known weaknesses in what exists (fix in the phases)
- No retention: `edges`, `flows`, `audit`, `alerts` grow without bound (add a pruning job, P2-6).
- Ingest does one SELECT then INSERT/UPDATE per edge (fine for 3 hosts; unmeasured on PC2).
- Transport is plain HTTP with bearer tokens on the internal network; the gateway trusts whatever ruleset the server returns (add HMAC, P4-1).
- Learned destination sets are IP-based: CDN address rotation will make an allowlist (`default_internet: block`) brittle (add domain sets, P3-3).
- `categories.json` globs are guesses; most robot traffic will start as `unclassified`.
- The agent assumes `/proc/net` direction heuristics (local port in the listening set => inbound); UDP unconnected sockets are invisible.
- `gatewayd` reloads the whole table on any change, which resets byte counters (the server compensates, but a reload mid-interval loses at most one interval).

---

## 6. Component specifications

### 6.1 Agent (`python3 -m robosec.agent --config /etc/robosec/agent.json`)
- Read-only; opens no listening socket; sends only to `server`. `--once` prints one sample as JSON (no server, no spool).
- Needs `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH` (or root) to read other users' `/proc/<pid>/fd`; without them processes show `exe: "?"` and `unreadable_procs` is high.
- Config keys: `host` (logical name: use `pc1`/`pc2`/`pc3`), `server`, `token`, `interval_s` 2.0, `flush_s` 10, `ignore_local` true, `spool_dir`, `spool_max_bytes` 20 MB, `max_edges_per_report` 500, `nice` 10, `networks` (override `robot_nets`/`lan_nets`/`vpn_nets`).
- Report payload (POST `/api/v1/report`, `Authorization: Bearer <agent_token>`):
```json
{"host":"pc3","agent_version":"0.1.0","ts":1762000000.0,"seq":12,
 "edges":[{"dir":"out","exe":"/opt/x/face_ui","comm":"face_ui","unit":"face_ui.service","uid":1000,"cmd":"face_ui --x",
           "proto":"tcp","raddr":"203.0.113.9","rport":443,"scope":"internet","n":5,"first":1762000000.0,"last":1762000010.0}],
 "stats":{"sample_ms":12.4,"sockets":210,"observations":14,"unattributed":0,"unreadable_procs":0,"cpu_s":1.2,"interval_s":2.0}}
```
Edge identity is `(host, dir, exe, proto, raddr, rport)`; `n` is the number of samples the edge was alive in, not a connection count.

### 6.2 Server (`python3 -m robosec.server --config /etc/robosec/server.json`)
Three bearer tokens (must differ; `CHANGE-ME*` is refused): `agent_token` (reports), `gateway_token` (ruleset, ack, flows), `admin_token` (everything; admin also satisfies the other two).
Binds to `listen:port` (default 127.0.0.1:8750). **On the robot set `listen` to `10.0.1.41` (the internal address), never `0.0.0.0`**: PC2 is also on Wi-Fi.

| Method + path | Role | Purpose |
|---|---|---|
| `GET /healthz` | none | liveness |
| `GET /` | none | dashboard (needs the admin token to load data) |
| `POST /api/v1/report` | agent | ingest edges + stats |
| `GET /api/v1/summary` | admin | hosts, scope counts, internet categories with bytes, open alerts, learning state, policy, gateway acks |
| `GET /api/v1/edges?host=&scope=&category=&dir=&q=&limit=` | admin | connection list with `bytes_to_dest` |
| `GET /api/v1/alerts`, `POST /api/v1/alerts/{id}/ack` | admin | alerts |
| `GET /api/v1/policy`, `PUT /api/v1/policy` | admin | read / patch policy (validated, version bump, audited) |
| `GET /api/v1/categories`, `POST /api/v1/recategorize` | admin | rules; re-run classification after editing `categories.json` (restart server to reload the file) |
| `POST /api/v1/learning/restart` | admin | restart the alert-free learning window |
| `GET /api/v1/audit` | admin | who changed what |
| `GET /api/v1/gateway/ruleset` | gateway | nft text; headers `X-Robosec-Version`, `X-Robosec-Digest`, `X-Robosec-Mode` |
| `POST /api/v1/gateway/ack`, `POST /api/v1/gateway/flows` | gateway | apply result; `[{"addr","bytes","packets"}]` counters |

Examples:
```bash
AD=$(python3 -c "import json;print(json.load(open('/etc/robosec/server.json'))['admin_token'])")
curl -s -H "Authorization: Bearer $AD" http://10.0.1.41:8750/api/v1/summary | python3 -m json.tool | head -40
curl -s -X PUT -H "Authorization: Bearer $AD" -H 'Content-Type: application/json' \
     -d '{"mode":"observe","categories":{"voice-and-audio":"block"}}' http://10.0.1.41:8750/api/v1/policy
```
Tables: `hosts, edges (UNIQUE host,dir,exe,proto,raddr,rport), alerts, policy (single row), audit, meta, flows (host,addr; bytes are cumulative across counter resets), gateway`.
Alerts: `new_internet_destination` (new outbound edge with scope internet) and `inbound_from_internet`, **only after** the learning window (default 24 h) has ended.

### 6.3 Policy semantics (`robosec/nftrender.py`)
```json
{"mode":"observe|enforce","default_internet":"allow|block","categories":{"<id>":"allow|block"},
 "allow_cidrs":[],"block_cidrs":[],"always_allow":{"udp_ports":[53,123],"tcp_ports":[]}}
```
Evaluation for a NEW connection to an internet destination (chain `decide`), first hit wins: `block_cidrs` -> `allow_cidrs` -> the per-category sets (each
category's verdict) -> `default_internet`. In `observe` every verdict is rendered `accept`. A destination learned under two categories (shared CDN address)
lands in both sets; the first category in alphabetical order wins: **flag these conflicts in the UI (backlog B3)**. "Learned" means: addresses of
`dir=out, scope=internet` edges, grouped by category, capped at 4096 per category.
Rule order inside `chain screen` (**do not reorder**): robot/trusted/local destinations accepted, then byte counters (`add @flows4 { ip daddr counter }`),
then established/related accepted, then non-new accepted, then always-allow ports, then `jump decide`. Base chains `forward` and `output` run at priority -5 with
`policy accept`; an `accept` there ends only our chain, so vendor chains still run, and a `drop` is final.

### 6.4 Gateway daemon (`python3 -m robosec.gatewayd --config /etc/robosec/gatewayd.json [--once] [--dry-run] [--remove]`)
Loop every `poll_s` (15 s): fetch -> if digest unchanged and table present: nothing -> `nft -c -f` -> remember the old table -> `nft -f` (single transaction
via `add table; delete table; table {...}`) -> wait up to `verify_s` for `GET /healthz` on the server -> on failure restore the old table, or delete ours (fail-open).
Every `flows_s` (30 s) read `nft -j list set inet robosec flows4|flows6` and POST counters. The systemd unit runs `--remove` on stop.
Requires root / `CAP_NET_ADMIN`. `--dry-run` only runs `nft -c`.

### 6.5 Categories (`config/categories.json`)
Fields: `id` (letters, digits, `-`, `_`), `label`, `risk` (`low|medium|high`), `match` (list; any may match). Match keys: `exe_glob, comm_glob, unit_glob, cmd_glob`
(fnmatch on the process), `rport, proto, scope, dir` (exact), `cidr` (destination). Shipped categories: `robot-vendor-cloud, robot-telemetry-export,
firmware-updates, voice-and-audio, face-and-display, camera-and-perception, remote-access, robot-teleop, dns, time-sync, package-and-dev-tools,
wireless-and-modem`, plus implicit `unclassified`. **All globs are guesses from app names; Phase 1 replaces them with real paths.**

---

## 7. Phased plan

Each task has an ID, an acceptance test, and a human gate where needed. Effort: S under half a day, M 1-2 days, L several days.

### Phase 0: measure (S) **no installs, read-only**
| ID | Task | Acceptance |
|---|---|---|
| P0-1 | Get the robot powered and PC2 reachable. | `tools/collect_phase0.sh` finds PC2. |
| P0-2 | Run `tools/collect_phase0.sh`; save `phase0/<timestamp>/{pc1,pc2,pc3,pc2_forwarding,egress}.txt`. | files exist, no errors. |
| P0-3 | Write `phase0/REPORT.md` answering Q1 to Q10 (section 2.5), one line each, with the evidence line. | every Q answered or marked "needs human". |
| P0-4 | Confirm PC2 is the egress gateway: `ip_forward=1`, a masquerade rule, and PC1/PC3 `curl https://example.com` succeeding (or failing: then the real egress path is different and **the architecture must change**). | REPORT states yes/no with output. |
| P0-5 | List vendor `nft`/`iptables` tables on each computer. | confirm no table named `robosec`; list names we must not touch. |
| P0-6 | Copy the package (`scp -r robo-data-security agi@<PC2>:/tmp/robosec-pkg`) and run once as the normal user: `cd /tmp/robosec-pkg && python3 -m robosec.agent --once --host pc2`. | JSON prints; note `unreadable_procs`. |
**Gate:** human reads the report and answers section 11.

### Phase 1: observe only (M)
| ID | Task | Acceptance |
|---|---|---|
| P1-1 | Human (root) installs **server + agent on PC2**: `./deploy/install.sh --role all`, edit `/etc/robosec/*.json` (three distinct random tokens; `server.listen=10.0.1.41`), then `systemctl enable --now robosec-server robosec-agent`. **Do not enable gatewayd.** | `curl http://10.0.1.41:8750/healthz` ok from PC2; dashboard shows `pc2` via `ssh -L 8750:10.0.1.41:8750 agi@PC2`. |
| P1-2 | Measure overhead: `systemctl show robosec-agent -p CPUUsageNSec`, `uptime` load before/after, agent `sample_ms` in the dashboard. | agent below 3% of one core at steady state; no sample over 500 ms. |
| P1-3 | Human-gated timing check: with the agent on, run a short **idle** deploy session on the gantry and compare the deploy's own tick/`pose_ref_age` logs against a run with the agent stopped. | no measurable difference (record numbers). Skip if the human declines. |
| P1-4 | Install the **agent only** on PC3, then PC1 (PC1 with `CPUAffinity=0 1 2 3`; reports go to `http://10.0.1.41:8750`). | three hosts show in the dashboard. |
| P1-5 | Let it run 24-48 h through a normal session (idle, voice, teleop, an OTA check if possible). | `unattributed` below 5% of observations; list of every internet destination with owner process. |
| P1-6 | Rewrite `config/categories.json` from real paths; `POST /api/v1/recategorize`. | `unclassified` internet edges below 10%. |
**Gate:** human reviews the destination list: anything unexpected is a finding, not a bug.

### Phase 2: analyse (M)
| ID | Task | Acceptance |
|---|---|---|
| P2-1 | Enable **gatewayd in observe mode** on PC2 (`mode: observe` is the default policy). | table `inet robosec` present; `flows4` counters rising; dashboard "bytes sent" non-zero; vendor traffic unaffected (PC1/PC3 still reach the internet). |
| P2-2 | Verify counters against ground truth: `curl` a 10 MB file from PC3 and compare. | dashboard within 5% of 10 MB. |
| P2-3 | Baseline report: per computer, per category, per destination: bytes, first/last seen. Export CSV from the API. | report generated by a script in `tools/`. |
| P2-4 | Tune alerts: end the learning window; list alert noise; add `ack` workflow. | fewer than 5 unexplained alerts per day. |
| P2-5 | Add reverse-DNS or resolver-log name enrichment (backlog B1). | dashboard shows names for 80% of destinations. |
| P2-6 | Retention job (prune edges unseen for N days, flows, audit) + DB backup. | DB size stable over a week. |

### Phase 3: control (L) **human approves every enforced category, in chat**
| ID | Task | Acceptance |
|---|---|---|
| P3-1 | Choose ONE low-risk category with the human (for example `package-and-dev-tools` or one specific vendor destination). Set `mode: enforce`, `default_internet: allow`, that category `block`. | `nft` shows drop rules; traffic to that destination stops (counters, `curl`); **robot still stands, teleop and SSH unaffected**. |
| P3-2 | Rollback drill: `systemctl stop robosec-gatewayd` and `python3 -m robosec.gatewayd --remove`. | table gone within 2 s; traffic flows. |
| P3-3 | Domain-based sets: a resolver step that turns allow/deny **domains** into IP sets (`robosec/resolve_sets.py`, new) refreshed every few minutes, or `dnsmasq nftset=`. Needed before `default_internet: block`. | CDN rotation does not break an allowed domain over 24 h. |
| P3-4 | Per-category UI toggles in plain language with the documented side effect of each ("Voice features stop working"). | human can switch a category and see the result within one poll interval. |
| P3-5 | Optional: per-computer egress control by systemd unit (`socket cgroupv2`) for PC1/PC3 local traffic (kernel support to be confirmed in P0). | blocks one unit's egress without touching others. |
| P3-6 | Staged default-deny trial (only after P3-3), on the gantry, with a time limit and the rollback command ready. | robot fully functional for a 1 h session. |

### Phase 4: harden (M)
P4-1 HMAC-sign rulesets (shared secret in `/etc/robosec`, header `X-Robosec-Sig`; gatewayd rejects unsigned). P4-2 TLS or at least an
authenticated tunnel for agent/gateway to server traffic. P4-3 Tamper alerts: an agent silent for more than 60 s raises `agent_silent`; gatewayd
state mismatch raises `gateway_drift`. P4-4 Persistence: confirm survival across reboot and a vendor OTA (Q8); otherwise move the install under a
path the vendor keeps, or package as an EM app (ask the vendor path owner). P4-5 Uninstall drill (`deploy/uninstall.sh`) leaves no table and no service.
P4-6 Token rotation procedure documented and tested. P4-7 Secrets: tokens only in files mode 600.

### Phase 5: productise (L)
Dashboard as a tab in the RoboInc Teleop hub (it already serves a FastAPI panel at :7791; the API here is plain JSON so it can be proxied), end-user language
and onboarding, packaged install, docs, optional OpenSnitch "tier B" (backlog B5), optional SROS2 / RoboShield evaluation (B6).

---

## 8. Deployment runbook

```bash
# 0. on the workstation: copy the package to PC2 (host from tools/collect_phase0.sh output)
scp -r /home/ubuntu/cyber/robo-data-security agi@<PC2>:/tmp/robosec-pkg
# 1. HUMAN, as root on PC2 (agi cannot): install and generate tokens
sudo /tmp/robosec-pkg/deploy/install.sh --role all          # installs units, starts nothing
for i in 1 2 3; do python3 -c 'import secrets;print(secrets.token_urlsafe(32))'; done   # agent, gateway, admin
#    edit /etc/robosec/server.json  : the three tokens, "listen":"10.0.1.41"
#    edit /etc/robosec/agent.json   : "host":"pc2","server":"http://10.0.1.41:8750","token":<agent token>
sudo systemctl enable --now robosec-server robosec-agent
# 2. verify
curl -s http://10.0.1.41:8750/healthz
journalctl -u robosec-agent -n 20 --no-pager
# 3. dashboard from the workstation
ssh -L 8750:10.0.1.41:8750 agi@<PC2>      # then open http://127.0.0.1:8750/ and paste the admin token
# 4. other computers: copy the package, install --role agent, set "host":"pc3"/"pc1", same agent token, server http://10.0.1.41:8750
#    On PC1 uncomment CPUAffinity=0 1 2 3 in /etc/systemd/system/robosec-agent.service, then systemctl daemon-reload && restart.
# 5. gateway (Phase 2 only): edit /etc/robosec/gatewayd.json (gateway token, server http://10.0.1.41:8750), then
sudo systemctl enable --now robosec-gatewayd ; sudo nft list table inet robosec | head
# rollback at any time
sudo systemctl stop robosec-gatewayd && sudo nft list tables | grep robosec || echo "enforcement is off"
sudo /tmp/robosec-pkg/deploy/uninstall.sh                      # full removal (run it from the package copy, not from /opt/robosec)
```
If `sudo` is not available to the human either, the agent can run unprivileged with partial visibility (only the user's own processes), which is enough
for a first look but **not** for Phase 1 acceptance.

---

## 9. Test plan

Automated: section 5.2 (108 tests, about 30 s). Add a test for every new rule or behaviour; nothing here may be merged without a green run.
Functional: extend `tests/test_nft_integration.py` (it already builds a dummy interface in a user+net namespace; use `/proc/net/dev`, not `/sys`, because
`/sys` still shows host interfaces inside the namespace). For the forward chain add a two-namespace veth topology.
On the robot (Phase gates): see each phase's acceptance column. Record numbers in `phase0/` and `phase1/` reports; do not assert "no impact" without a measurement.

---

## 10. Security of the tool itself

| Threat | Today | Planned |
|---|---|---|
| Someone on the internal network posts fake reports | agent token required | per-host tokens, TLS (P4-2) |
| Someone pushes a malicious ruleset to the gateway | gateway trusts the server over plain HTTP | HMAC-signed rulesets (P4-1), listen on the internal address only |
| Attacker with the admin token turns on enforcement | audited, but no second factor | human confirmation step for `enforce` (P3), token rotation |
| The security tool leaks data | local only, no outbound calls | keep it that way; document |
| Agent as root-ish helper | capabilities limited to ptrace + read; `NoNewPrivileges`, read-only filesystem except `/var/lib/robosec` | seccomp profile |
| Logs contain sensitive info (process command lines) | stored in SQLite on PC2 | command-line redaction option, retention |

---

## 11. Decisions needed from the human (ask before Phase 1)

| ID | Question | Recommended default |
|---|---|---|
| D1 | Where should the server and dashboard live: PC2, the workstation, or inside the RoboInc Teleop hub? | PC2 internal address, viewed through an SSH tunnel; hub tab in Phase 5. |
| D2 | May agents run on PC1 and PC3 (vendor-managed computers)? | Yes, agent only, PC1 pinned to CPUs 0-3; enforcement only at PC2. |
| D3 | Who provides root for installs, and is a persistent install acceptable given vendor resets/OTA? | Human installs as root; accept re-install after resets. |
| D4 | Stance when the tool fails: fail open (never cut the robot off) or fail closed for internet egress? | Fail open. |
| D5 | Retention: how long to keep connection history, and is a daily DB backup wanted? | 30 days of edges, 90 days of audit, daily local backup. |
| D6 | Which first category will you let us block in Phase 3? | the owner's choice; suggest a developer-tool category first. |

---

## 12. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Agent or gateway steals CPU from control loops | joint control glitches, watchdog trips | caps, nice, PC1 affinity, P1-2/P1-3 measurements, observe-only first |
| A blocked destination breaks a vendor safety or remote-support feature | loss of function | category side-effect text, one category at a time, rollback drill, fail-open |
| CDN IP rotation breaks allowlists | random outages | domain sets (P3-3) before any default-deny |
| PC2 is not actually the egress path | the gateway sees nothing | P0-4; if false, re-architect (agent-side nft per computer, or gateway on the real path) |
| Vendor OTA or factory reset removes the install | silent loss of protection | P4-3 tamper alerts, P4-4 persistence |
| Wrong ruleset locks out SSH or the operator | access loss | LAN/VPN accepted first, atomic apply with rollback, fail-open |
| PREEMPT_RT kernel lacks needed nft/eBPF features | features unavailable | the design uses only nft + /proc (no eBPF) in v1; eBPF is optional tier B |
| Sensitive data in our own database | privacy | local only, 600 permissions, retention, redaction |

---

## 13. Backlog (prioritised)

B1 DNS name attribution: resolver query log or an nflog listener to map destination IP to the name that produced it. (M)
B2 `resolve_sets.py`: domain allow/deny lists to nft sets (P3-3). (M)
B3 Conflict view: addresses learned under several categories; choose precedence per category. (S)
B4 Inbound exposure report from `dir=in` edges and listening ports, plus a policy for it. (M)
B5 Tier B: OpenSnitch daemons per computer where the kernel supports eBPF, gRPC node management, sharing the same category rules. (L) OpenSnitch is GPL-3.0; deriving from it makes our code GPL-3.0.
B6 Evaluate SROS2 and RoboShield for the *command* side (separate project). (M)
B7 TLS SNI extraction (Suricata or NFQUEUE) for encrypted-traffic hostnames. (L)
B8 Per-unit enforcement on PC1/PC3 with `socket cgroupv2`. (M)
B9 Alert delivery (local only by default; opt-in push). (S)
B10 Packaging as a vendor EM app or `.deb`. (M)
B11 `fail_closed` option for internet egress. (S, needs D4)
B12 Hub tab and plain-language policy wizard. (L)

---

## 14. Quick reference for the next agent

```bash
# run everything locally for development
cd /home/ubuntu/cyber/robo-data-security
python3 -W ignore -m unittest discover -s tests -t .                       # 108 tests
python3 -m robosec.agent --once --host dev | python3 -m json.tool | head   # one sample from this machine
python3 -c 'import secrets;print(secrets.token_urlsafe(32))'               # a token
# render a ruleset by hand and syntax-check it in a throwaway namespace (no root, no effect on the host)
python3 - <<'EOF' > /tmp/r.nft
from robosec.nftrender import render, DEFAULT_POLICY
from robosec.netscope import Scoper
print(render(DEFAULT_POLICY, Scoper(), {"dns": ["1.1.1.1"]}))
EOF
unshare -Urn nft -c -f /tmp/r.nft && echo SYNTAX_OK
```
Conventions: stdlib only; Python 3.10-compatible; every new behaviour gets a test; ruleset changes get a functional test; keep `chain screen` order; never
weaken sections 4 and 6.3.

## 15. References
- OpenSnitch (GPL-3.0, daemon + Qt UI over gRPC, multi-node GUI): https://github.com/evilsocket/opensnitch
- Portmaster (GPL-3.0; Windows/Linux desktop; no multi-machine management found): https://github.com/safing/portmaster
- Suricata for ROS 2 traffic (DDS on UDP 7400-7600): https://dev.to/sebos/securing-ros-2-robots-network-intrusion-detection-with-suricata-ipb
- RoboShield v2 (inline ROS 2 command firewall, Rust): https://discourse.openrobotics.org/t/roboshield-v2-an-inline-command-firewall-gateway-for-ros-2-rust-rclrs-two-domain-bridge-sros2/58826 , repo https://github.com/Amin-Ahmed-G/robotshield
- Tetragon (eBPF runtime enforcement): https://docsnext.isovalent.com/project/tetragon/index.html
- Aztarna (robot exposure scanner): https://securityaffairs.com/80395/security/aztarna-scanning-vulnerable-robots.html
- Alias Robotics CAI: https://github.com/aliasrobotics/cai
- nftables wiki (sets, dynamic sets with counters, atomic replace): https://wiki.nftables.org/
