# Phase 0 report: first survey of the Cadet (2026-11-02)

Read-only survey with `tools/collect_phase0.sh` (PC2 at 192.168.30.119, key login, no passwords). Raw output: `phase0/20261102_101259/` (git-ignored).
Answers use the question numbers from `HANDOFF.md` section 2.5. **verified** = seen in the output; **inferred** = follows from verified facts; **open** = needs root.

| Q | Question | Answer |
|---|---|---|
| Q1 | Kernel support | PC2 `5.15.148-tegra`: BPF, BPF_JIT, nf_tables **as a module**, conntrack; `NFT_CT`, `NFT_COUNTER`, `NFT_DYNSET` are **not visible in its config** and there is no BTF (**open**: check `lsmod`/`modinfo` as root). PC1 `6.1.99-rt36`: nf_tables, `NFT_CT` and conntrack built in; BPF syscall not shown. PC3 `6.1.99`: conntrack yes, **nf_tables not found in the config**. |
| Q2 | Does PC2 forward and NAT? | **Forwards: yes** (`ip_forward=1` on PC2, 0 on PC1 and PC3). NAT rules cannot be read without root, but PC1 and PC3 have live outside connections with default route via 10.0.1.41, so **PC2 is the egress gateway (inferred, strongly)**. |
| Q3 | Do PC1/PC3 reach the internet? | **Yes, both**, through PC2 (see "Outside connections" below). |
| Q4 | Existing nft/iptables tables | **Unreadable without root.** `iptables` is v1.8.7 with the nf_tables backend on all three. **`nft` is not installed on any of the three computers**, which the gateway design needs (see "Design consequences"). |
| Q5 | Real executable paths of vendor apps | **Open**: needs per-process attribution, which needs root (PC2 agent as `agi` saw 12 of 15 sockets unattributed). |
| Q6 | Baseline of outside destinations | Partial, below. A 24 to 48 h run is still needed. |
| Q7 | How do we get root? | **PC1 and PC3: user `run` has passwordless sudo** (`sudo_without_password=yes`). **PC2: `agi` needs a password** for sudo (`sudo -n` refused). |
| Q8 | Does an OTA or reset wipe our install? | **Open.** The repo code comments say PC2 is reset by other developers; PC2 rebooted 3 times on 2026-11-02 alone. |
| Q9 | Is the 5G modem the default route? | **No**: PC2's default route is `wifi0` via 192.168.30.1. |
| Q10 | DNS | PC2: systemd-resolved, upstream 192.168.30.1, fallbacks 223.5.5.5, 8.8.8.8, 8.8.4.4. **PC1 and PC3 use 10.0.1.41 (PC2) as their DNS server.** |

## Outside connections seen during the survey (owner and country from the offline DB-IP lookup)
| Computer | Destination | Country | Owner |
|---|---|---|---|
| PC1 (motion) | 14.103.92.63:8885 | CN | Beijing Volcano Engine Technology Co., Ltd. |
| PC3 (head) | 124.223.144.198:1443 (four connections) | CN | Shenzhen Tencent Computer Systems |
| PC3 (head) | 43.153.127.148:1883 (MQTT port) | US | Shenzhen Tencent Computer Systems |
| PC3 (head) | 180.184.178.142:443 | CN | Beijing Volcano Engine Technology Co., Ltd. |
| PC2 (dev) | Tailscale relays on 443 | CA, GB, US | Amazon, NetActuate |
These are facts about *who the robot connects to*. What is sent, and whether it is the vendor's normal cloud service, is **not** known from this survey: Phase 1 attribution and the gateway byte counters are meant to answer that. The owners are registry data, not proof of the service behind them.

## Other findings
- **PC2's app manager answers the Wi-Fi network.** `GET http://192.168.30.119:50080/json/get_all_apps_info` from the workstation returned HTTP 200 with 27 apps. The same API starts and stops apps (POST). PC2 listens on 22, 111, 1667 to 1672, 8899, 50000, 50001, 50080, 50099, 51000 and 51001 on all interfaces, which includes `wifi0`. Whether stop/start is accepted from the LAN without authentication was **not tested**.
- PC1 listens on 1883 and 8883 (MQTT), 5000, 50080, 50091; PC3 on 18080, 50002, 50080.
- PC2's load average was 27 to 33 for at least 9 minutes after each boot (services of other developers and a ROS component container). Anything we run there starts at the lowest priority.

## Design consequences (change the plan)
1. **The gateway (nftables) cannot be installed as designed**: no `nft` binary on any computer, and PC2's kernel config does not show the nftables conntrack, counter and dynamic-set modules. Options, all needing root: install the `nftables` package (needs internet and apt), or port `nftrender.py` to `iptables-restore`/`ipset` (iptables-nft is present), or confirm the modules with `lsmod`. **Decide after a root-level check on PC2.**
2. **Per-process visibility needs root on PC2.** On PC1 and PC3 `run` already has passwordless sudo, so installing the agent there needs only the human's go-ahead.
3. The exposure of PC2's app manager on the Wi-Fi is a finding for the owner independent of this tool.

## State after this survey
Agents run on PC1, PC2 and PC3 and report to a server on PC2's internal address (trial mode: PC2 as user `agi`, PC1/PC3 as temporary systemd units; no firewall changes, no gateway). See `HANDOFF.md` section 5.7. With full visibility on PC1 and PC3 the owners above are now tied to processes: PC1 `aima-cloud_proxy-app`, PC3 `aima-agent-app`.
