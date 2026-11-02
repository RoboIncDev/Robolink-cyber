# robo-data-security (robosec)

Per-process outbound visibility and egress control for a multi-computer robot (AgiBot X2 "Cadet"), in the spirit of OpenSnitch.

**The dashboard, every part explained with screenshots: [`docs/DASHBOARD.md`](docs/DASHBOARD.md).**

**Read `HANDOFF.md` first.** It has the verified facts about the robot, the architecture, the hard safety rules, the phased plan with acceptance tests, the
deployment runbook and the decisions to ask the human.

```bash
python3 -W ignore -m unittest discover -s tests -t .     # 174 tests, about 30 s, no root needed
tools/collect_phase0.sh                                   # Phase 0: read-only survey of the three robot computers
./deploy/install.sh --role all --dry-run                  # what the installer would do
```

Status: running on the Cadet (agents on PC1, PC2, PC3; server on PC2; enforcer on PC3 in counting-only mode; units are temporary and stop at a reboot, see `HANDOFF.md` 5.7). Stdlib-only Python 3.10+.
