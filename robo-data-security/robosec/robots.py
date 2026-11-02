"""Which robot this installation protects. A small catalog plus the saved choice (server meta). Only facts we can state are listed:
the computers are known for the Cadet (X2 Ultra); for the others the list stays empty until an agent reports, never guessed."""
from __future__ import annotations

CATALOG = {
    "x2-ultra": {"id": "x2-ultra", "maker": "AgiBot", "name": "X2 Ultra", "image": "x2-ultra.png", "license": "Mulan PSL v2",
                 "computers": ["pc1", "pc2", "pc3"], "roles": {"pc1": "motion", "pc2": "dev and gateway", "pc3": "head"}},
    "a3": {"id": "a3", "maker": "AgiBot", "name": "A3", "image": "a3.png", "license": "Mulan PSL v2", "computers": [], "roles": {}},
    "g1": {"id": "g1", "maker": "Unitree", "name": "G1", "image": "g1.png", "license": "BSD-3-Clause", "computers": [], "roles": {}},
}
DEFAULT = "x2-ultra"


def profile(model: str, name: str = "", serial: str = "") -> dict:
    base = CATALOG.get(model) or CATALOG[DEFAULT]
    return {**base, "label": name, "serial": serial}


def validate(body: dict) -> dict:
    if not isinstance(body, dict):
        raise ValueError("body must be an object")
    model = body.get("model")
    if model not in CATALOG:
        raise ValueError("model must be one of " + ", ".join(sorted(CATALOG)))
    out = {"model": model}
    for k, limit in (("label", 40), ("serial", 40)):
        v = body.get(k, "")
        if not isinstance(v, str) or len(v) > limit or any(ord(c) < 32 for c in v):
            raise ValueError(f"{k} must be text of at most {limit} characters")
        out[k] = v.strip()
    return out
