# Installing the Secure data enforcer (needs root, run by a human or after a clear go)

Nothing here runs by itself. Do one computer at a time, **robot idle and standing on its stand or sitting**, and start with the read-only checks.
The enforcer only ever touches its own chain `ROBOSEC_SECURE` and one `-j ROBOSEC_SECURE` rule at the top of OUTPUT. It refuses to block anything that is
not a public internet address, fails open after 120 s without the server, and `--remove` deletes everything it made. Rules do not survive a reboot.

## 0. Read-only checks (change nothing)
Run on the computer (PC3 or PC1, user `run` has passwordless sudo):
```bash
sudo iptables -w 5 -S | head -20          # must work; if it errors, STOP: this kernel cannot run the enforcer (PC3's config showed no nf_tables)
sudo ip6tables -w 5 -S | head -5          # optional; an error here is tolerated
ls /home/run/robosec/robosec/enforcer.py  # the package must be there (it is, from the agent install)
```

**PC3 specifics (verified 2026-11-02):** the nf_tables iptables fails there ("Could not fetch rule set generation id"); use `iptables-legacy`, and add `"iptables": "iptables-legacy", "ip6tables": "ip6tables-legacy"` to `enforcer.json`. PC3 has no IPv6 firewall module, so IPv6 destinations cannot be blocked there.

## 1. Copy the new code and write the config (user `run`, no root)
```bash
# from PC2 (agi), where the up-to-date package lives:
scp -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -r ~/robosec/robosec run@10.0.1.42:/home/run/robosec/
# on PC3, create the config. GATEWAY_TOKEN is "gateway_token" in PC2's ~/robosec/server.json:
umask 077; cat > /home/run/robosec/enforcer.json <<JSON
{"host": "pc3", "server": "http://10.0.1.41:8750", "token": "GATEWAY_TOKEN"}
JSON
```

## 2. Dry run (shows the rules it WOULD install, installs nothing)
```bash
cd /home/run/robosec && sudo PYTHONPATH=. python3 -m robosec.enforcer --config enforcer.json --dry-run
```

## 3. Start it (root, limited to CAP_NET_ADMIN, removes its rules when stopped)
```bash
# CAP_NET_RAW: iptables needs it. CAP_DAC_READ_SEARCH: root without it cannot read files under /home/run.
sudo systemd-run --unit=robosec-enforcer --property=WorkingDirectory=/home/run/robosec --property=Environment=PYTHONPATH=/home/run/robosec \
  --property=Restart=on-failure --property=RestartSec=5 "--property=CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH" "--property=AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH" \
  --property=ExecStopPost="/usr/bin/python3 -m robosec.enforcer --remove" \
  /usr/bin/python3 -m robosec.enforcer --config /home/run/robosec/enforcer.json
sudo journalctl -u robosec-enforcer -n 20 --no-pager
```
At this point the dashboard shows the computer as "counting only": it counts bytes per destination but blocks nothing until Secure data is switched on.

## 4. Undo (any time)
```bash
sudo systemctl stop robosec-enforcer                                   # ExecStopPost removes the chain and hook
sudo PYTHONPATH=/home/run/robosec python3 -m robosec.enforcer --remove # belt and braces; safe to repeat
sudo iptables-legacy -S | grep -c ROBOSEC                                      # must print 0
```

## 5. First real test
Switch Secure data on for **1 hour** in the dashboard, then check that the robot's local functions still work (voice, display, remote app). The vendor cloud is in
the foreign list, so the vendor's own cloud features may stop: that is what the switch is for. Use "Keep these working" to exempt a category, or press Reopen.
Repeat for PC1 only after PC3 is understood. PC2 needs `agi`'s sudo password and is the gateway, so do it last.
