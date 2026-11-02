#!/usr/bin/env python3
"""Build dashboard/map/world.json from Natural Earth 110m countries (public domain). Stdlib only.

  curl -L -o ne_110m_admin_0_countries.geojson \
    https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson
  python3 tools/build_map.py --geojson ne_110m_admin_0_countries.geojson --out dashboard/map/world.json

Projection: Equal Earth (Savric, Patterson, Jenny 2018). The dashboard re-implements the same forward formula to place the
robot's home location, so `scale`, `tx`, `ty` are stored: px = tx + scale * x ; py = ty - scale * y.
Countries too small for the 110m outlines are emitted as `points` (approximate centre) so their traffic still gets a marker.
"""
import argparse
import json
import math
import os
import re

A1, A2, A3, A4 = 1.340264, -0.081106, 0.000893, 0.003796
WIDTH = 1000.0
PREC = 10            # coordinates are stored as integers in tenths of a unit

# Natural Earth leaves ISO_A2_EH = -99 for a few entries; map by ADM0_A3 where a real code exists.
FIX_A3 = {"KOS": "XK", "FRA": "FR", "NOR": "NO", "CYN": None, "SOL": None, "ATA": None}
# Small states and territories that have no polygon at 110m: (name, lat, lon), approximate centres.
SMALL = {
    "SG": ("Singapore", 1.35, 103.82), "HK": ("Hong Kong", 22.32, 114.17), "MO": ("Macao", 22.2, 113.55),
    "MT": ("Malta", 35.9, 14.4), "MC": ("Monaco", 43.74, 7.42), "LI": ("Liechtenstein", 47.14, 9.55),
    "AD": ("Andorra", 42.55, 1.58), "SM": ("San Marino", 43.94, 12.46), "VA": ("Vatican City", 41.9, 12.45),
    "BH": ("Bahrain", 26.0, 50.55), "MV": ("Maldives", 3.2, 73.22), "MU": ("Mauritius", -20.3, 57.58),
    "SC": ("Seychelles", -4.68, 55.49), "KM": ("Comoros", -11.9, 43.87), "ST": ("Sao Tome and Principe", 0.19, 6.61),
    "CV": ("Cabo Verde", 16.0, -24.0), "BB": ("Barbados", 13.19, -59.54), "LC": ("Saint Lucia", 13.91, -60.98),
    "VC": ("Saint Vincent", 13.25, -61.2), "GD": ("Grenada", 12.12, -61.68), "AG": ("Antigua and Barbuda", 17.06, -61.8),
    "KN": ("Saint Kitts and Nevis", 17.36, -62.78), "DM": ("Dominica", 15.41, -61.37), "BM": ("Bermuda", 32.3, -64.75),
    "KY": ("Cayman Islands", 19.31, -81.25), "VG": ("British Virgin Islands", 18.42, -64.64), "AW": ("Aruba", 12.52, -69.97),
    "CW": ("Curacao", 12.17, -68.99), "PR": ("Puerto Rico", 18.22, -66.59), "GU": ("Guam", 13.44, 144.79),
    "WS": ("Samoa", -13.76, -172.1), "TO": ("Tonga", -21.18, -175.2), "KI": ("Kiribati", 1.87, -157.4),
    "FM": ("Micronesia", 6.9, 158.2), "MH": ("Marshall Islands", 7.1, 171.4), "PW": ("Palau", 7.5, 134.6),
    "NR": ("Nauru", -0.53, 166.93), "TV": ("Tuvalu", -7.1, 177.65), "CK": ("Cook Islands", -21.2, -159.8),
    "PF": ("French Polynesia", -17.68, -149.4), "FO": ("Faroe Islands", 62.0, -6.8), "GI": ("Gibraltar", 36.14, -5.35),
    "IM": ("Isle of Man", 54.23, -4.55), "JE": ("Jersey", 49.21, -2.13), "GG": ("Guernsey", 49.46, -2.58),
    "AX": ("Aland Islands", 60.2, 20.0), "BN": ("Brunei", 4.5, 114.7), "BS": ("Bahamas", 24.25, -76.0),
    "TL": ("Timor-Leste", -8.87, 125.73), "RE": ("Reunion", -21.1, 55.5), "MQ": ("Martinique", 14.64, -61.02),
    "GP": ("Guadeloupe", 16.25, -61.58), "GF": ("French Guiana", 3.93, -53.13), "YT": ("Mayotte", -12.8, 45.17),
    "MS": ("Montserrat", 16.74, -62.19), "AI": ("Anguilla", 18.22, -63.06), "TC": ("Turks and Caicos", 21.69, -71.8),
    "SX": ("Sint Maarten", 18.04, -63.06), "MF": ("Saint Martin", 18.08, -63.05), "BL": ("Saint Barthelemy", 17.9, -62.83),
    "PM": ("Saint Pierre and Miquelon", 46.83, -56.33), "SH": ("Saint Helena", -15.96, -5.7), "AS": ("American Samoa", -14.3, -170.7),
    "MP": ("Northern Mariana Islands", 15.2, 145.75), "NU": ("Niue", -19.05, -169.87), "TK": ("Tokelau", -9.2, -171.85),
    "WF": ("Wallis and Futuna", -13.77, -177.15), "VI": ("US Virgin Islands", 18.34, -64.9), "SJ": ("Svalbard", 78.0, 16.0),
    "EH": ("Western Sahara", 24.2, -12.9), "XK": ("Kosovo", 42.6, 20.9),
}


def ee(lon_deg, lat_deg):
    lam, phi = math.radians(lon_deg), math.radians(lat_deg)
    th = math.asin(math.sqrt(3) / 2 * math.sin(phi))
    t2, t6 = th * th, th ** 6
    x = 2 * math.sqrt(3) * lam * math.cos(th) / (3 * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2)))
    y = th * (A1 + A2 * t2 + t6 * (A3 + A4 * t2))
    return x, y


def ring_area_centroid(ring):
    a = cx = cy = 0.0
    for (x0, y0), (x1, y1) in zip(ring, ring[1:] + ring[:1]):
        cr = x0 * y1 - x1 * y0
        a += cr; cx += (x0 + x1) * cr; cy += (y0 + y1) * cr
    if abs(a) < 1e-12:
        return 0.0, ring[0][0], ring[0][1]
    return a / 2, cx / (3 * a), cy / (3 * a)


def build(geojson_path, out_path):
    gj = json.load(open(geojson_path))
    ymax = ee(0, 90)[1]
    xmax = ee(180, 0)[0]
    scale = (WIDTH / 2) / xmax
    height = round(2 * ymax * scale, 1)
    tx, ty = WIDTH / 2, ymax * scale

    def px(lon, lat):
        x, y = ee(lon, lat)
        return tx + scale * x, ty - scale * y

    countries, seen = [], set()
    for f in gj["features"]:
        p = f["properties"]
        cc = p.get("ISO_A2_EH") or p.get("ISO_A2") or ""
        if not re.fullmatch(r"[A-Z]{2}", cc):
            cc = FIX_A3.get(p.get("ADM0_A3"), None) or ""
        if not cc or cc in ("AQ",) or cc in seen:
            continue
        seen.add(cc)
        geom = f["geometry"]
        polys = geom["coordinates"] if geom["type"] == "MultiPolygon" else [geom["coordinates"]]
        d, best = [], (0.0, None)
        for poly in polys:
            for ri, ring in enumerate(poly):
                pts, last = [], None
                for lon, lat in ring[:-1] if ring[0] == ring[-1] else ring:
                    x, y = px(lon, lat)
                    q = (round(x * PREC), round(y * PREC))
                    if q != last:
                        pts.append(q); last = q
                if len(pts) < 3:
                    continue
                s = f"M{pts[0][0]} {pts[0][1]}l" + " ".join(f"{b[0]-a[0]} {b[1]-a[1]}" for a, b in zip(pts, pts[1:])) + "z"
                d.append(s)
                if ri == 0:
                    area, clon, clat = ring_area_centroid([(lo, la) for lo, la in ring[:-1]])
                    if abs(area) > best[0]:
                        best = (abs(area), (clon, clat))
        if not d:
            continue
        clon, clat = best[1]
        cx, cy = px(clon, clat)
        countries.append({"cc": cc, "name": p.get("NAME_LONG") or p.get("NAME") or cc, "d": "".join(d),
                          "cx": round(cx, 1), "cy": round(cy, 1)})
    points = []
    for cc, (name, lat, lon) in sorted(SMALL.items()):
        if cc in seen:
            continue
        x, y = px(lon, lat)
        points.append({"cc": cc, "name": name, "cx": round(x, 1), "cy": round(y, 1)})
    out = {"projection": "equal-earth", "width": WIDTH, "height": height, "scale": scale, "tx": tx, "ty": ty,
           "precision": PREC, "source": "Natural Earth 110m admin-0 countries (public domain)",
           "countries": sorted(countries, key=lambda c: c["cc"]), "points": points}
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as fh:
        json.dump(out, fh, separators=(",", ":"))
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--geojson", required=True); ap.add_argument("--out", required=True)
    a = ap.parse_args()
    o = build(a.geojson, a.out)
    print(f"{len(o['countries'])} country shapes, {len(o['points'])} point markers, {os.path.getsize(a.out)/1024:.0f} KB, viewBox 0 0 {o['width']:.0f} {o['height']}")
