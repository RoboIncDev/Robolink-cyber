"""Offline IP -> country / network owner lookup. No network access, ever.

Source data: DB-IP "Lite" country and ASN CSVs (CC BY 4.0, https://db-ip.com : the dashboard footer must credit
"IP Geolocation by DB-IP"). `build()` turns them into compact sorted-range files; `GeoDB` bisects them.

File format (one file per table, big-endian):
    magic "RSGEO1" | width(1) | value_width(1) | count(4) | records...
    record = start(width) end(width) value(value_width)         width 4 = IPv4, 16 = IPv6
Country value = 2 ASCII letters. ASN value = asn(4) + index into orgs.txt (4).
Ranges are sorted by start and do not overlap, so a lookup is: last record with start <= ip, then ip <= end.

Locations are approximate and a CDN / anycast address is placed where it is REGISTERED, not where the server is.
That is why the owner (ASN organisation) is returned alongside the country.
"""
from __future__ import annotations

import csv
import functools
import gzip
import io
import ipaddress
import json
import os
import re
import struct
import time

MAGIC = b"RSGEO1"
HEADER = struct.Struct(">6sBBI")
ATTRIBUTION = "IP Geolocation by DB-IP (CC BY 4.0)"
ATTRIBUTION_URL = "https://db-ip.com"
UNKNOWN_CC = "ZZ"


def _packed(ip: str) -> bytes | None:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    return a.packed


class RangeTable:
    def __init__(self, data: bytes = b"") -> None:
        self.count = 0
        self.width = 0
        self.vw = 0
        self.rs = 0
        self.body = b""
        if data:
            try:
                magic, w, vw, n = HEADER.unpack_from(data, 0)
            except struct.error as exc:                      # a file shorter than the header
                raise ValueError("geo table is truncated or corrupt") from exc
            if magic != MAGIC or w not in (4, 16):
                raise ValueError("not a robosec geo table")
            self.width, self.vw, self.count = w, vw, n
            self.rs = 2 * w + vw
            self.body = memoryview(data)[HEADER.size:]
            if len(self.body) != n * self.rs:
                raise ValueError("geo table is truncated or corrupt")

    def find(self, ip: bytes) -> bytes | None:
        if not self.count or len(ip) != self.width:
            return None
        w, rs, body = self.width, self.rs, self.body
        lo, hi = 0, self.count - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if bytes(body[mid * rs: mid * rs + w]) <= ip:
                lo = mid + 1
            else:
                hi = mid - 1
        if hi < 0:
            return None
        rec = bytes(body[hi * rs: (hi + 1) * rs])
        return rec[2 * w:] if ip <= rec[w: 2 * w] else None


def _write_table(path: str, width: int, vw: int, rows: list[tuple[bytes, bytes, bytes]]) -> None:
    rows.sort(key=lambda r: r[0])
    with open(path, "wb") as fh:
        fh.write(HEADER.pack(MAGIC, width, vw, len(rows)))
        for s, e, v in rows:
            fh.write(s + e + v)


def _open(path: str):
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace", newline="")
    return open(path, "r", encoding="utf-8", errors="replace", newline="")


def build(country_csv: str | None, asn_csv: str | None, out_dir: str, release: str = "") -> dict:
    """Build `out_dir` from DB-IP CSVs (gzip allowed). Either CSV may be omitted. Returns the metadata written."""
    os.makedirs(out_dir, exist_ok=True)
    meta: dict = {"built": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "release": release, "attribution": ATTRIBUTION,
                  "attribution_url": ATTRIBUTION_URL, "license": "CC BY 4.0", "skipped_rows": 0}
    skipped = 0
    if country_csv:
        rows = {4: [], 16: []}
        with _open(country_csv) as fh:
            for rec in csv.reader(fh):
                try:
                    s, e, cc = _packed(rec[0]), _packed(rec[1]), rec[2].strip().upper()
                    if s is None or e is None or len(s) != len(e) or len(cc) != 2 or cc == UNKNOWN_CC:
                        raise ValueError
                    rows[len(s)].append((s, e, cc.encode("ascii")))
                except (ValueError, IndexError, UnicodeEncodeError):
                    skipped += 1
        _write_table(os.path.join(out_dir, "country4.bin"), 4, 2, rows[4])
        _write_table(os.path.join(out_dir, "country6.bin"), 16, 2, rows[16])
        meta["country_ranges"] = {"ipv4": len(rows[4]), "ipv6": len(rows[16])}
    if asn_csv:
        orgs: dict[str, int] = {}
        rows = {4: [], 16: []}
        with _open(asn_csv) as fh:
            for rec in csv.reader(fh):
                try:
                    s, e, asn, org = _packed(rec[0]), _packed(rec[1]), int(rec[2]), re.sub(r"\s+", " ", rec[3]).strip()[:120]
                    if s is None or e is None or len(s) != len(e) or asn <= 0:
                        raise ValueError
                    idx = orgs.setdefault(org, len(orgs))
                    rows[len(s)].append((s, e, struct.pack(">II", asn, idx)))
                except (ValueError, IndexError):
                    skipped += 1
        _write_table(os.path.join(out_dir, "asn4.bin"), 4, 8, rows[4])
        _write_table(os.path.join(out_dir, "asn6.bin"), 16, 8, rows[16])
        with open(os.path.join(out_dir, "orgs.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(orgs, key=orgs.get)))
        meta["asn_ranges"] = {"ipv4": len(rows[4]), "ipv6": len(rows[16]), "organisations": len(orgs)}
    meta["skipped_rows"] = skipped
    with open(os.path.join(out_dir, "meta.json"), "w") as fh:
        json.dump(meta, fh, indent=1)
    return meta


class GeoDB:
    """Lookup object. `available` is False when no database is installed: callers must treat that as 'unknown', not an error."""

    def __init__(self) -> None:
        self.available = False
        self.meta: dict = {}
        self._c = {4: RangeTable(), 16: RangeTable()}
        self._a = {4: RangeTable(), 16: RangeTable()}
        self._orgs: list[str] = []

    @classmethod
    def load(cls, directory: str | None) -> "GeoDB":
        g = cls()
        if not directory or not os.path.isdir(directory):
            return g
        def table(name: str) -> RangeTable:
            p = os.path.join(directory, name)
            if not os.path.exists(p):
                return RangeTable()
            with open(p, "rb") as fh:
                return RangeTable(fh.read())
        g._c = {4: table("country4.bin"), 16: table("country6.bin")}
        g._a = {4: table("asn4.bin"), 16: table("asn6.bin")}
        p = os.path.join(directory, "orgs.txt")
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                g._orgs = fh.read().split("\n")
        try:
            with open(os.path.join(directory, "meta.json")) as fh:
                g.meta = json.load(fh)
        except (OSError, ValueError):
            g.meta = {}
        g.available = any(t.count for t in (*g._c.values(), *g._a.values()))
        return g

    def lookup(self, ip: str) -> dict:
        return dict(self._cached(ip))

    @functools.lru_cache(maxsize=8192)
    def _cached(self, ip: str) -> dict:
        """Always returns {"cc": str|None, "asn": int, "org": str}. Unknown / private / unparseable addresses give empty values."""
        out = {"cc": None, "asn": 0, "org": ""}
        pk = _packed(ip)
        if pk is None or not self.available:
            return out
        v = self._c[len(pk)].find(pk)
        if v:
            out["cc"] = v.decode("ascii")
        v = self._a[len(pk)].find(pk)
        if v:
            asn, idx = struct.unpack(">II", v)
            out["asn"] = asn
            out["org"] = self._orgs[idx] if idx < len(self._orgs) else ""
        return out
