#!/usr/bin/env python3
"""Build the offline geo database from DB-IP Lite CSVs. Run this on the WORKSTATION, never on a robot computer.

  1. Download (needs internet, you accept DB-IP's CC BY 4.0 terms at https://db-ip.com/db/lite.php):
       dbip-country-lite-YYYY-MM.csv.gz   and   dbip-asn-lite-YYYY-MM.csv.gz     from https://download.db-ip.com/free/
  2. python3 tools/build_geodb.py --country dbip-country-lite-2026-11.csv.gz --asn dbip-asn-lite-2026-11.csv.gz --out geo/
  3. Copy the geo/ directory to wherever the server runs; set "geodb": "<path>" in server.json. DB-IP updates monthly.
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from robosec.geodb import build  # noqa: E402

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--country"); ap.add_argument("--asn"); ap.add_argument("--out", required=True)
a = ap.parse_args()
if not (a.country or a.asn):
    ap.error("give --country and/or --asn")
m = re.search(r"(\d{4}-\d{2})", os.path.basename(a.country or a.asn))
meta = build(a.country, a.asn, a.out, release=m.group(1) if m else "")
print("built", a.out, meta)
