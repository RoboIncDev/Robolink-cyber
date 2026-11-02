"""Map an edge (process + destination) to a human category, from config/categories.json.

Rule format (first category whose any `match` entry matches wins; all keys inside one match AND together):
  exe_glob, comm_glob, unit_glob, cmd_glob   fnmatch-style patterns against the process
  rport, proto, scope, dir                   exact values
  cidr                                       destination address inside this network
The ids and globs shipped in config/categories.json are a FIRST GUESS derived from process and app
names seen on the robot. Phase 1 exists to replace them with what really runs.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json

UNCLASSIFIED = "unclassified"


def load_rules(path: str) -> list[dict]:
    with open(path) as fh:
        data = json.load(fh)
    cats = data["categories"] if isinstance(data, dict) else data
    ids = [c["id"] for c in cats]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate category id")
    for c in cats:
        if not c["id"].replace("-", "").replace("_", "").isalnum():
            raise ValueError(f"bad category id {c['id']!r}")
    return cats


def _glob(value: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(value or "", pattern)


def _match_one(edge: dict, m: dict) -> bool:
    for key, want in m.items():
        if key == "exe_glob" and not _glob(edge.get("exe", ""), want):
            return False
        if key == "comm_glob" and not _glob(edge.get("comm", ""), want):
            return False
        if key == "unit_glob" and not _glob(edge.get("unit", ""), want):
            return False
        if key == "cmd_glob" and not _glob(edge.get("cmd", ""), want):
            return False
        if key == "rport" and int(edge.get("rport", -1)) != int(want):
            return False
        if key in ("proto", "scope", "dir") and edge.get(key) != want:
            return False
        if key == "cidr":
            try:
                if ipaddress.ip_address(edge.get("raddr", "")) not in ipaddress.ip_network(want, strict=False):
                    return False
            except ValueError:
                return False
    return True


def categorize(edge: dict, rules: list[dict]) -> str:
    for cat in rules:
        for m in cat.get("match", []):
            if _match_one(edge, m):
                return cat["id"]
    return UNCLASSIFIED
