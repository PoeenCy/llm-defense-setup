"""Chain group and suspicious-step routes (P2.4b), served by the internal API.

Counts are taken over profiles through their latest run, so asking for a new
analysis never counts a flag-out twice, and a profile whose re-analysis found
a different chain moves to that chain's group. Field variation across a group
is what a single chain cannot tell: a short value that is the same in every
chain was chosen by the attacker (an admin ID), one that differs every time
was produced per run.
"""
import json

from ..background import ALL_VALUES
from ..parsing import path_template
from ..tokens import extract
from . import contracts
from .grouping import field_name
from .routes import API_VERSION, NotFound, _id, _int, display_state

MEMBER_RUNS = 2000     # latest runs listed per group
VARIATION_CHAINS = 200  # chains whose requests are read for field variation
MAX_DISTINCT = 50       # distinct values tracked per field
SAMPLES = 3             # example values shown per field
# Free text has byte offsets for names, so it has no field to compare. Path
# segments do have one, and whether the ID in a path changes per chain is
# exactly what this table is for, so unlike the group shape they are kept.
SKIPPED_CATEGORIES = ("body",)

MEMBERS = """FROM trace_profiles p
        JOIN trace_runs r ON r.id=p.latest_run_id
        JOIN transactions t ON t.id=p.anchor_transaction_id
        LEFT JOIN trace_jobs j ON j.trace_id=p.id AND j.request_sequence=p.last_requested_sequence"""


def _group_stats(db, game_id, where, args):
    return db.execute(f"""SELECT r.group_id,count(*) AS profiles,count(DISTINCT t.source_key) AS sources,
            min(t.ts_request) AS first_ts,max(t.ts_request) AS last_ts,
            sum(EXISTS(SELECT 1 FROM trace_suspects s WHERE s.run_id=r.id AND s.strength='strong')) AS suspect_profiles
            {MEMBERS} WHERE p.game_id=? AND r.group_id IS NOT NULL{where} GROUP BY r.group_id""",
                      (game_id, *args))


def list_groups(db, game_id, params):
    limit = _int(params, "limit", 50, 1, 200)
    offset = _int(params, "offset", 0, 0, 1_000_000)
    where, args = "", []
    for name in ("service", "source_key"):
        if params.get(name):
            where += f" AND t.{name}=?"
            args.append(params[name])
    stats = sorted(_group_stats(db, game_id, where, args), key=lambda r: (-(r["last_ts"] or 0), r["group_id"]))
    page = stats[offset:offset + limit]
    meta = {r["id"]: r for r in db.execute(
        f"SELECT * FROM trace_groups WHERE id IN ({','.join('?' * len(page))})", [r["group_id"] for r in page])} if page else {}
    items = [{"group_id": r["group_id"], "service": meta[r["group_id"]]["service"],
              "description": meta[r["group_id"]]["description"],
              "steps": len(json.loads(meta[r["group_id"]]["signature"])),
              "profiles": r["profiles"], "sources": r["sources"], "first_ts": r["first_ts"], "last_ts": r["last_ts"],
              "suspect_profiles": r["suspect_profiles"]} for r in page if r["group_id"] in meta]
    return {"api_version": API_VERSION, "items": items, "total": len(stats), "limit": limit, "offset": offset,
            "next_offset": offset + limit if offset + limit < len(stats) else None}


def group_detail(db, game_id, group_id, params):
    limit = _int(params, "limit", 50, 1, 500)
    offset = _int(params, "offset", 0, 0, 1_000_000)
    group = db.execute("SELECT * FROM trace_groups WHERE id=? AND game_id=?", (group_id, game_id)).fetchone()
    if group is None:
        raise NotFound()
    members = db.execute(f"""SELECT p.id AS trace_id,p.latest_run_id,p.latest_run_sequence,r.state AS run_state,
            t.ts_request,t.tick,t.source_key,t.team_id,t.flags_found,
            j.status AS job_status,j.request_sequence AS job_sequence,
            (SELECT strength FROM trace_suspects s WHERE s.run_id=r.id ORDER BY strength='strong' DESC LIMIT 1) AS suspect
            {MEMBERS} WHERE p.game_id=? AND r.group_id=? ORDER BY t.ts_request DESC,p.id DESC""",
                         (game_id, group_id)).fetchall()
    sources = {}
    for m in members:
        s = sources.setdefault(m["source_key"], {"source_key": m["source_key"], "team_id": m["team_id"],
                                                  "profiles": 0, "last_ts": m["ts_request"]})
        s["profiles"] += 1
    page = [{"trace_id": m["trace_id"], "run_id": m["latest_run_id"], "ts_request": m["ts_request"], "tick": m["tick"],
             "source_key": m["source_key"], "team_id": m["team_id"],
             "flag_count": len(json.loads(m["flags_found"] or "[]")), "display_state": display_state(m),
             "suspect": m["suspect"]} for m in members[offset:offset + limit]]
    return {"api_version": API_VERSION, "group_id": group_id, "service": group["service"],
            "description": group["description"], "normalizer_version": group["normalizer_version"],
            "shape": json.loads(group["signature"]), "profiles": len(members),
            "sources": sorted(sources.values(), key=lambda s: (-s["profiles"], s["source_key"])),
            "fields": field_variation(db, [m["latest_run_id"] for m in members[:MEMBER_RUNS]]),
            "fields_chains": min(len(members), VARIATION_CHAINS),
            "members": page, "limit": limit, "offset": offset,
            "next_offset": offset + limit if offset + limit < len(members) else None}


def field_variation(db, run_ids):
    """Per step position and field: how many of the sampled chains sent it, and
    how many different values it had.

    Read from the requests themselves, not from the per-run value roles. A
    group must not inherit what single-chain inference concluded, and a value
    every chain sends verbatim is classified constant, which means it is not
    stored at all — exactly the case this table exists to name. The roles are
    attached alongside as what single-chain analysis made of the field.
    """
    sample = run_ids[:VARIATION_CHAINS]
    if not sample:
        return []
    marks = ",".join("?" * len(sample))
    fields = {}
    for r in db.execute(f"""SELECT s.run_id,s.position,t.req_parsed FROM trace_steps s
            JOIN transactions t ON t.id=s.transaction_id
            WHERE s.run_id IN ({marks}) AND s.role<>'context' AND t.proto='http'""", sample):
        tokens, _ = extract(json.loads(r["req_parsed"] or "{}"), b"", "req", ALL_VALUES)
        for token in tokens:
            if token["parent"] is not None or token["location"][1] in SKIPPED_CATEGORIES:
                continue
            # An endpoint word in the path is the same in every chain of the
            # group by construction: the path template is part of the group.
            if token["location"][1] == "path" and path_template(token["value"]) == token["value"]:
                continue
            f = fields.setdefault((r["position"], field_name(token["location"])),
                                  {"runs": set(), "values": {}, "capped": False, "roles": {}, "ambiguous": 0})
            f["runs"].add(r["run_id"])
            if len(f["values"]) < MAX_DISTINCT:
                f["values"].setdefault(token["value"], len(f["values"]))
            elif token["value"] not in f["values"]:
                f["capped"] = True
    for r in db.execute(f"""SELECT s.position,v.location,v.role,v.ambiguous FROM trace_values v
            JOIN trace_steps s ON s.run_id=v.run_id AND s.transaction_id=v.transaction_id
            WHERE v.run_id IN ({marks})""", sample):
        f = fields.get((r["position"], field_name(json.loads(r["location"]))))
        if f is not None:
            f["roles"][r["role"]] = f["roles"].get(r["role"], 0) + 1
            f["ambiguous"] += r["ambiguous"]
    out = []
    for (position, name), f in sorted(fields.items()):
        listed, distinct = len(f["runs"]), len(f["values"])
        if listed < 2:
            verdict = "single_chain"
        elif f["capped"] or distinct >= listed:
            verdict = "differs_each_time"
        elif distinct == 1:
            verdict = "same_in_all"       # the attacker sends this one verbatim
        else:
            verdict = "mixed"
        # Roles are per listed entry, so a field counted as constant has none.
        roles = dict(f["roles"])
        if sum(roles.values()) < listed:
            roles[contracts.VALUE_CONSTANT] = listed - sum(roles.values())
        out.append({"position": position, "field": name, "chains": len(sample), "sent_by": listed,
                    "distinct": distinct, "distinct_capped": f["capped"],
                    "samples": sorted(f["values"])[:SAMPLES], "roles": roles,
                    "ambiguous": f["ambiguous"], "verdict": verdict})
    return out


def run_grouping(db, run, analysis):
    """The run's own group, plus how many profiles are in it now."""
    summary = analysis.get("grouping")
    if not summary or not run["group_id"]:
        return dict(contracts.NOT_COMPUTED)
    now = db.execute("""SELECT count(*) AS profiles,count(DISTINCT t.source_key) AS sources
        FROM trace_profiles p JOIN trace_runs r ON r.id=p.latest_run_id
        JOIN transactions t ON t.id=p.anchor_transaction_id WHERE r.group_id=?""", (run["group_id"],)).fetchone()
    return {**summary, "group_id": run["group_id"], "now": {"profiles": now["profiles"], "sources": now["sources"]}}


def run_suspects(db, run_id, analysis):
    summary = analysis.get("suspects")
    if not summary:
        return dict(contracts.NOT_COMPUTED)
    steps = [{"transaction_id": s["transaction_id"], "position": s["position"], "strength": s["strength"],
              "findings": json.loads(s["findings"])}
             for s in db.execute("SELECT * FROM trace_suspects WHERE run_id=? ORDER BY position", (run_id,))]
    return {**summary, "steps": steps}


def handle(db, game_id, path, params):
    """(status, body) for a chain-group route, or None for any other path."""
    parts = path.strip("/").split("/")
    try:
        if parts == ["chain-groups"]:
            return 200, list_groups(db, game_id, params)
        if len(parts) == 2 and parts[0] == "chain-groups":
            return 200, group_detail(db, game_id, _id(parts[1]), params)
    except NotFound:
        return 404, {"error": "not found in this game"}
    return None
