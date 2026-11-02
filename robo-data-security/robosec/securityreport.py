"""The security report: everything the dashboard knows, said in plain words, with a short list of what to do and in what order.

Pure functions: `build()` takes the facts (already read from the store) and returns a structure; `markdown()` turns it into text.
Nothing here guesses. Where a fact is unknown (bytes before an enforcer counts them, a computer that is not reporting) the report says so.
"""
from __future__ import annotations

import time

THE = {"United States", "United Kingdom", "Netherlands", "Philippines", "Bahamas", "Gambia", "United Arab Emirates", "Czechia"}
LEVELS = {"good": "In good shape", "review": "Needs a look", "act": "Act now"}


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _join(items: list[str], limit: int = 4) -> str:
    items = [i for i in items if i]
    if len(items) > limit:
        return ", ".join(items[:limit]) + f" and {len(items) - limit} more"
    return ", ".join(items[:-1]) + (" and " if len(items) > 1 else "") + items[-1] if items else ""


def build(robot: dict, findings: list[dict], secure: dict, abroad: dict, hosts: list[dict], now: float, learning: bool) -> dict:
    open_f = [f for f in findings if not f["accepted"]]
    accepted = len(findings) - len(open_f)
    silent = [h["host"] for h in hosts if now - h["last_seen"] > 120]
    cov = secure.get("coverage", {"active": 0, "total": len(hosts), "missing": []})
    label = secure.get("label", "")
    foreign = secure.get("foreign", {})
    home = abroad.get("home_name") or secure.get("home_cc") or ""
    home = ("the " + home) if home in THE else home
    countries = abroad.get("countries", []) if not abroad.get("needs_home") else []
    name = " ".join(x for x in (robot.get("maker"), robot.get("name")) if x) or "the robot"

    # --- how bad is it ---
    level = "good"
    if any(f["severity"] == "fault" for f in open_f):
        level = "act"
    elif any(f["severity"] == "caution" for f in open_f) or silent or label in ("open",) or cov["missing"]:
        level = "review"
    headline = {"good": f"Nothing needs a decision right now on {name}.",
                "review": f"{name} is working, but some things deserve a look.",
                "act": f"{name} has a problem that should be fixed first."}[level]

    # --- sections ---
    sections = []

    # 1. data leaving
    body = []
    if abroad.get("needs_home"):
        body.append("No home country is set, so the report cannot tell home from abroad. Set one in the server settings.")
        v = "review"
    elif countries:
        t = abroad["totals"]
        body.append(f"In the period covered, {name} connected to {_plural(t['destinations'], 'address', 'addresses')} outside {home}, "
                    f"in {_plural(t['countries'], 'country', 'countries')}, from {_plural(t['computers'], 'computer')} and {_plural(t['programs'], 'program')}.")
        for c in countries[:5]:
            owners = _join([o["org"] for o in c["owners"][:3]], 3)
            progs = _join(sorted({p["program"] for p in c["programs"]}), 3)
            body.append(f"{c.get('name') or c['cc']}: {_plural(c['destinations'], 'address', 'addresses')}, owned by {owners or 'unknown owners'}; programs: {progs or 'unknown'}.")
        body.append("This shows who the robot connected to and where those addresses are registered. It does not show what was sent."
                    + (" Bytes are unknown until an enforcer or the gateway counts them." if t.get("bytes_sent") is None else ""))
        v = "review" if label == "open" else "good"
    else:
        body.append(f"Nothing outside {home or 'the home country'} was seen in this period.")
        v = "good"
    if abroad.get("unlocated"):
        body.append(f"{_plural(abroad['unlocated']['destinations'], 'address', 'addresses')} could not be placed on a map. They are never counted as abroad and never blocked.")
    sections.append({"id": "abroad", "title": f"Data leaving {home or 'home'}", "level": v, "body": body})

    # 2. protection
    body = []
    if label == "secured":
        body.append("Secure data is on and every computer is enforcing it. Foreign destinations are blocked, except the exempt categories.")
        v = "good"
    elif label == "open":
        body.append(f"Secure data is off. All {_plural(foreign.get('destinations', 0), 'foreign address', 'foreign addresses')} can still be reached; "
                    f"{foreign.get('would_block', 0)} would be blocked if it were on.")
        v = "review"
    elif label == "partial":
        body.append(f"Secure data is on, but it only protects {cov['active']} of {cov['total']} computers. {_join(cov['missing'])} can still send data abroad.")
        v = "review"
    elif label == "waiting":
        body.append("Secure data is on but no computer is enforcing it yet, so nothing is blocked.")
        v = "review"
    elif label == "quiet":
        body.append("Secure data is off and nothing foreign has been seen, so there is nothing to block.")
        v = "good"
    else:
        body.append("Secure data cannot be used until a home country is set.")
        v = "review"
    body.append(f"Enforcers are running on {cov['active']} of {cov['total']} computers" + (f" (missing: {_join(cov['missing'])})." if cov["missing"] else "."))
    if silent:
        body.append(f"{_join(silent)} stopped reporting, so nothing is known about {'it' if len(silent) == 1 else 'them'} right now.")
        v = "review"
    if learning:
        body.append("The system is still learning what normal looks like. Alerts for new destinations start after the learning window ends.")
    sections.append({"id": "protection", "title": "Protection", "level": v, "body": body})

    # 3. open doors
    doors = [f for f in open_f if f["id"].startswith(("listen:", "ports:"))]
    body = [f"{f['title']}." + (f" {f['fix']}" if f["fix"] and f["severity"] != "info" else "") for f in doors] or \
           ["No computer shows a port that reaches beyond the robot's own network."]
    sections.append({"id": "doors", "title": "Open ports", "level": "review" if any(f["severity"] != "info" for f in doors) else "good", "body": body})

    # 4. wireless and access
    acc = [f for f in open_f if f["id"].startswith(("bt-", "session:"))]
    body = [f"{f['title']}. {f['detail']}" for f in acc] or ["No Bluetooth or login setting needs attention."]
    sections.append({"id": "access", "title": "Bluetooth and who is logged in", "level": "review" if any(f["severity"] == "caution" for f in acc) else "good", "body": body})

    # --- recommendations, most important first ---
    recs: list[dict] = []

    def rec(prio: str, title: str, why: str, how: str) -> None:
        recs.append({"n": len(recs) + 1, "priority": prio, "title": title, "why": why, "how": how})

    for f in open_f:
        if f["severity"] == "fault":
            rec("high", f["title"], f["detail"], f["fix"] or "See the Findings panel.")
    if abroad.get("needs_home"):
        rec("high", "Set the home country", "Without it, nothing can be called foreign and Secure data cannot be turned on.", "Add a home country to the server settings and restart the server.")
    if cov["missing"]:
        rec("high" if label in ("partial", "waiting") else "medium", f"Install the enforcer on {_join(cov['missing'])}",
            "Without it that computer cannot block anything and its sent bytes are not counted.", "Follow deploy/ENFORCER.md. Start in counting-only mode, which blocks nothing.")
    if label == "open" and foreign.get("would_block", 0) > 0 and cov["active"] > 0:
        rec("medium", "Try Secure data for one hour",
            f"{foreign['would_block']} foreign addresses would be blocked, including the vendor cloud the robot may rely on for voice, the phone app and updates.",
            "Pick 1 hour in Secure data, with the robot idle and someone watching. Switch it off at once if something stops working, then note what stopped.")
    for f in open_f:
        if f["severity"] == "caution" and not f["id"].startswith("agent:"):
            rec("medium", f["title"], f["detail"], f["fix"] or "See the Findings panel.")
    for h in silent:
        rec("medium", f"Get {h} reporting again", "A computer that is not reporting cannot be checked.", "Check that the robosec agent is running there. After a reboot it must be started again.")
    for f in open_f:
        if f["severity"] == "info" and f["id"].startswith(("bt-pairable", "ports:")):
            rec("low", f["title"], f["detail"], f["fix"])
    if accepted:
        rec("low", "Review the findings you marked as known", f"{_plural(accepted, 'finding')} {'is' if accepted == 1 else 'are'} hidden from this list.", "Reopen any that are no longer true.")
    if not recs:
        rec("low", "Keep it this way", "Nothing needs a decision right now.", "Check the dashboard after any software update, a new Bluetooth pairing, or a change to the network.")

    return {"generated": now, "robot": {"name": name, "serial": robot.get("serial", ""), "label": robot.get("label", "")},
            "level": level, "level_word": LEVELS[level], "headline": headline, "sections": sections, "recommendations": recs,
            "counts": {"open_findings": len(open_f), "accepted_findings": accepted, "computers": len(hosts), "silent": len(silent)}}


def markdown(r: dict) -> str:
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["generated"]))
    out = [f"# Security report: {r['robot']['name']}" + (f" ({r['robot']['serial']})" if r["robot"]["serial"] else ""), "",
           f"Generated {when}. **{r['level_word']}.** {r['headline']}", "", "## What to do, in order", ""]
    for x in r["recommendations"]:
        out += [f"{x['n']}. **{x['title']}** ({x['priority']} priority)", f"   - Why: {x['why']}", f"   - How: {x['how']}"]
    out += [""]
    for s in r["sections"]:
        out += [f"## {s['title']} ({LEVELS[s['level']].lower()})", ""] + [f"- {line}" for line in s["body"]] + [""]
    out.append("Locations come from a registry database and are approximate. This report shows who the robot connected to, not what was sent.")
    return "\n".join(out) + "\n"
