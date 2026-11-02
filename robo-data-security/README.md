# robo-data-security (robosec)

Per-process outbound visibility and egress control for a multi-computer robot (AgiBot X2 "Cadet"), in the spirit of OpenSnitch.

**Read `HANDOFF.md` first.** It has the verified facts about the robot, the architecture, the hard safety rules, the phased plan with acceptance tests, the
deployment runbook and the decisions to ask the human.

```bash
python3 -W ignore -m unittest discover -s tests -t .     # 62 tests, about 20 s, no root needed
tools/collect_phase0.sh                                   # Phase 0: read-only survey of the three robot computers
./deploy/install.sh --role all --dry-run                  # what the installer would do
```

Status: first version built and tested offline. Not installed on the robot. Stdlib-only Python 3.10+.
