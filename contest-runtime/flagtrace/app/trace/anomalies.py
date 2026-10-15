"""Suspicious steps (P2.4b, B8): requests that differ from what the checker sends.

The checker exercises the service the way it is meant to be used, so its recent
requests (the baseline, rebuilt each tick from checker traffic) say which
endpoints, fields, value lengths and characters are normal. A step that calls
an endpoint the checker never calls, sends a field it never sends, or a value
far longer or with characters it never uses, is marked with what differed and
the baseline figures it was compared with.

This is a lead, not a verdict. A baseline with few samples, or none at all,
cannot show that a request is abnormal: below MIN_SAMPLES a finding is weak,
and without a baseline nothing is marked and the result says why. The figures
used are stored with the run, so a later rebuild never changes an old result.
"""
import json

from ..background import ALL_VALUES
from ..parsing import path_template
from ..tokens import extract

MIN_SAMPLES = 20
STRONG, WEAK = "strong", "weak"
BASELINE_ROWS = 20000
# Characters reported per finding; the stored evidence stays small.
MAX_CHARS = 12
SKIPPED_CATEGORIES = ("body",)


def _kind(char):
    return "digit" if char.isdigit() else ("upper" if char.isupper() else "lower")


def new_characters(value, charset):
    """Characters of a kind the checker never sends in this field.

    A letter where the checker already sends letters is not news: its sample is
    small and random values (a username, a password) never cover an alphabet,
    so reporting those would mark every step and bury the real ones.
    Punctuation it never sends here is news, and so is a whole class it never
    uses, e.g. letters in a field it only ever fills with digits.
    """
    kinds = {_kind(c) for c in charset if c.isalnum()}
    out = []
    for char in sorted(set(value) - set(charset)):
        if char.isalnum() and _kind(char) in kinds:
            continue
        out.append(char)
    return out


def field_key(location):
    """Header positions differ between clients; the header name is the field."""
    location = list(location)
    if len(location) > 3 and location[1] == "header":
        location = location[:3]
    return json.dumps(location, separators=(",", ":"))


def load_baseline(reader, game_id, service):
    endpoints, updated, window_end = {}, None, None
    for row in reader.db.execute("""SELECT method,path_template,field,stats,updated FROM baseline
            WHERE game_id=? AND service=? LIMIT ?""", (game_id, service, BASELINE_ROWS)):
        stats = json.loads(row["stats"])
        ep = endpoints.setdefault((row["method"] or "", row["path_template"] or ""),
                                  {"fields": {}, "samples": 0, "content_types": set()})
        key = field_key(json.loads(row["field"]))
        if stats["samples"] > ep["fields"].get(key, {}).get("samples", 0):
            ep["fields"][key] = stats
        ep["samples"] = max(ep["samples"], stats["samples"])
        ep["content_types"].update(stats.get("content_types", []))
        updated = max(updated or 0, row["updated"] or 0)
        window_end = stats.get("window_end_tick", window_end)
    return endpoints, updated, window_end


def strength(samples):
    return STRONG if samples >= MIN_SAMPLES else WEAK


def compare(row, parsed, endpoints, service_samples):
    """Findings for one HTTP request against the baseline of its service."""
    endpoint = (row["method"] or "", path_template(row["path"] or ""))
    ep = endpoints.get(endpoint)
    if ep is None:
        return [{"kind": "endpoint_unseen", "field": None, "strength": strength(service_samples),
                 "detail": f"the checker never called {endpoint[0]} {endpoint[1]}",
                 "baseline": {"service_samples": service_samples, "endpoints": len(endpoints)}}]
    findings = []
    content_type = parsed.get("content_type") or ""
    if content_type and ep["content_types"] and content_type not in ep["content_types"]:
        findings.append({"kind": "content_type_unseen", "field": None, "strength": strength(ep["samples"]),
                         "detail": f"content type {content_type} never sent by the checker here",
                         "baseline": {"samples": ep["samples"], "content_types": sorted(ep["content_types"])}})
    tokens, _ = extract(parsed, b"", "req", ALL_VALUES)
    for token in tokens:
        location = token["location"]
        if token["parent"] is not None or location[1] in SKIPPED_CATEGORIES:
            continue
        key, value = field_key(location), token["value"]
        stats = ep["fields"].get(key)
        if stats is None:
            if location[1] == "path":
                continue  # the endpoint template already covers its segments
            findings.append({"kind": "field_unseen", "field": location, "strength": strength(ep["samples"]),
                             "detail": "field never sent by the checker to this endpoint",
                             "baseline": {"samples": ep["samples"]}})
            continue
        figures = {"samples": stats["samples"], "len_p50": stats["len_p50"], "len_p99": stats["len_p99"]}
        if len(value) > max(2 * stats["len_p99"], stats["len_p99"] + 16):
            findings.append({"kind": "length", "field": location, "strength": strength(stats["samples"]),
                             "detail": f"{len(value)} characters, checker p99 {stats['len_p99']}",
                             "baseline": figures})
        new = new_characters(value, stats["charset"])
        if new:
            findings.append({"kind": "charset", "field": location, "strength": strength(stats["samples"]),
                             "detail": "characters the checker never sends here: " + "".join(new[:MAX_CHARS]),
                             "chars": "".join(new[:MAX_CHARS]), "baseline": figures})
    return findings


def check(reader, game_id, service, nodes, order):
    """(summary, flagged steps) for one run, in the run's read snapshot."""
    endpoints, updated, window_end = load_baseline(reader, game_id, service)
    service_samples = sum(ep["samples"] for ep in endpoints.values())
    summary = {"state": "computed", "min_samples": MIN_SAMPLES,
               "baseline": {"endpoints": len(endpoints), "service_samples": service_samples,
                            "window_end_tick": window_end, "updated": updated}}
    if not endpoints:
        # Nothing to compare with: no step is called normal or abnormal.
        summary.update(state="no_baseline", steps_flagged=0, strong=0, weak=0, raw_skipped=0,
                       note="no checker traffic for this service in the baseline window")
        return summary, []
    ids = list(order)
    parsed = {r["id"]: r["req_parsed"] for r in reader.db.execute(
        f"SELECT id,req_parsed FROM transactions WHERE id IN ({','.join('?' * len(ids))})", ids)}
    flagged, raw = [], 0
    for position, tx in enumerate(ids, start=1):
        row = nodes[tx]["row"]
        if row["proto"] != "http":
            raw += 1
            continue
        findings = compare(row, json.loads(parsed.get(tx) or "{}"), endpoints, service_samples)
        if findings:
            flagged.append({"transaction_id": tx, "position": position, "findings": findings,
                            "strength": STRONG if any(f["strength"] == STRONG for f in findings) else WEAK})
    summary.update(steps_flagged=len(flagged), strong=sum(f["strength"] == STRONG for f in flagged),
                   weak=sum(f["strength"] == WEAK for f in flagged), raw_skipped=raw)
    return summary, flagged
