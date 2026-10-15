"""Identical flag-outs, listed once.

An attacker who replays the same request reads the same flag again and again.
Every one of those transactions is a flag-out with a profile of its own, so the
plain list repeats one row with different timestamps. A group is the profiles
with the same source, service, flag(s) and anchor request line (method and
path, not the query). It is only a view: nothing is merged or dropped, and each
member keeps its own analysis and history.

A group shows the member whose analysis linked the most earlier steps (the
newest one on a tie), so a longer chain found once is not hidden behind its
one-step repeats.
"""
import json

from ..analysis import uid
from .routes import API_VERSION, NotFound, _id, _int, display_state

# Members read per group to count states and pick the one shown. A group larger
# than this is still counted exactly; only the breakdown says it is sampled.
MEMBER_SAMPLE = 2000
KEY = ("source_key", "service", "flags_found", "method", "path")

JOINS = """FROM trace_profiles p
        JOIN transactions t ON t.id=p.anchor_transaction_id
        LEFT JOIN trace_runs r ON r.id=p.latest_run_id
        LEFT JOIN trace_jobs j ON j.trace_id=p.id AND j.request_sequence=p.last_requested_sequence"""
MEMBER_COLUMNS = """p.id AS trace_id,p.latest_run_id,p.latest_run_sequence,t.ts_request,t.tick,t.team_id,
        t.source_key,t.service,t.method,t.path,t.proto,t.flags_found,
        r.state AS run_state,r.warnings AS run_warnings,
        (SELECT count(*) FROM trace_steps s WHERE s.run_id=r.id AND s.role<>'context') AS step_count,
        (SELECT count(*) FROM trace_steps s WHERE s.run_id=r.id AND s.role='data_linked') AS linked_count,
        (SELECT count(*) FROM trace_edges e WHERE e.run_id=r.id) AS edge_count,
        j.status AS job_status,j.request_sequence AS job_sequence,j.attempts AS job_attempts,j.error AS job_error"""


def group_id(game_id, row):
    return uid("flagout-group", game_id, *(row[k] or "" for k in KEY))


def _filters(game_id, params):
    where, args = ["p.game_id=?"], [game_id]
    for name in ("source_key", "service", "team_id"):
        if params.get(name) not in (None, ""):
            where.append(f"t.{name}=?")
            args.append(params[name])
    if params.get("state"):
        where.append("(j.status=? OR r.state=?)")
        args += [params["state"], params["state"]]
    return where, args


def summary(row):
    """The fields the list renders, named as in the profile list."""
    flags = json.loads(row["flags_found"] or "[]")
    out = {"trace_id": row["trace_id"], "ts_request": row["ts_request"], "tick": row["tick"],
           "team_id": row["team_id"], "source_key": row["source_key"], "service": row["service"],
           "method": row["method"], "path": row["path"], "proto": row["proto"], "flags_found": flags,
           "flag_count": len(flags), "display_state": display_state(row), "latest_run": None, "latest_request": None}
    if row["latest_run_id"]:
        out["latest_run"] = {"run_id": row["latest_run_id"], "state": row["run_state"],
                             "step_count": row["step_count"], "linked_count": row["linked_count"],
                             "edge_count": row["edge_count"],
                             "warning_count": len(json.loads(row["run_warnings"] or "[]"))}
    if row["job_status"]:
        out["latest_request"] = {"request_sequence": row["job_sequence"], "status": row["job_status"],
                                 "attempts": row["job_attempts"], "error": row["job_error"]}
    return out


def _members(db, where, args, key_row, limit, offset=0):
    clause = " AND ".join(where + ["t.source_key IS ?", "t.service IS ?", "t.flags_found IS ?",
                                   "t.method IS ?", "t.path IS ?"])
    return db.execute(f"SELECT {MEMBER_COLUMNS} {JOINS} WHERE {clause} ORDER BY t.ts_request DESC,p.id DESC "
                      "LIMIT ? OFFSET ?", (*args, *(key_row[k] for k in KEY), limit, offset)).fetchall()


def list_groups(db, game_id, params):
    limit = _int(params, "limit", 50, 1, 200)
    offset = _int(params, "offset", 0, 0, 1_000_000)
    where, args = _filters(game_id, params)
    clause = " AND ".join(where)
    grouped = f"""SELECT t.source_key,t.service,t.flags_found,t.method,t.path,count(*) AS n,
                  min(t.ts_request) AS first_ts,max(t.ts_request) AS last_ts,min(t.tick) AS tick_min,
                  max(t.tick) AS tick_max
                  {JOINS} WHERE {clause} GROUP BY t.source_key,t.service,t.flags_found,t.method,t.path"""
    totals = db.execute(f"SELECT count(*),coalesce(sum(n),0) FROM ({grouped})", args).fetchone()
    rows = db.execute(grouped + " ORDER BY last_ts DESC,source_key,service,flags_found,method,path LIMIT ? OFFSET ?",
                      (*args, limit + 1, offset)).fetchall()
    items = []
    for g in rows[:limit]:
        members = _members(db, where, args, g, MEMBER_SAMPLE)
        states, results = {}, {}
        for m in members:
            state = display_state(m)
            states[state] = states.get(state, 0) + 1
            if m["latest_run_id"]:
                shape = (m["step_count"], m["edge_count"])
                results[shape] = results.get(shape, 0) + 1
        shown = max(members, key=lambda m: (m["linked_count"] or 0, m["ts_request"] or 0, m["trace_id"]))
        items.append({"group_id": group_id(game_id, g), "count": g["n"], "first_ts": g["first_ts"],
                      "last_ts": g["last_ts"], "tick_min": g["tick_min"], "tick_max": g["tick_max"],
                      "states": states, "sampled": len(members) < g["n"],
                      "results": [{"step_count": s, "edge_count": e, "count": n}
                                  for (s, e), n in sorted(results.items(), key=lambda x: -x[1])],
                      "shown": summary(shown)})
    more = len(rows) > limit
    return {"api_version": API_VERSION, "items": items, "total_groups": totals[0], "total_profiles": totals[1],
            "limit": limit, "offset": offset, "next_offset": offset + limit if more else None}


def group_members(db, game_id, trace_id, params):
    """The group a profile belongs to, newest first."""
    limit = _int(params, "limit", 100, 1, 500)
    offset = _int(params, "offset", 0, 0, 1_000_000)
    key_row = db.execute("""SELECT t.source_key,t.service,t.flags_found,t.method,t.path FROM trace_profiles p
        JOIN transactions t ON t.id=p.anchor_transaction_id WHERE p.id=? AND p.game_id=?""",
                         (trace_id, game_id)).fetchone()
    if key_row is None:
        raise NotFound()
    where, args = _filters(game_id, params)
    rows = _members(db, where, args, key_row, limit + 1, offset)
    return {"api_version": API_VERSION, "group_id": group_id(game_id, key_row),
            "items": [summary(r) for r in rows[:limit]], "limit": limit, "offset": offset,
            "next_offset": offset + limit if len(rows) > limit else None}


def handle(db, game_id, path, params):
    """(status, body) for a group route, or None for any other path."""
    parts = path.strip("/").split("/")
    try:
        if parts == ["trace-groups"]:
            return 200, list_groups(db, game_id, params)
        if len(parts) == 3 and parts[0] == "trace-groups" and parts[2] == "members":
            return 200, group_members(db, game_id, _id(parts[1]), params)
    except NotFound:
        return 404, {"error": "not found in this game"}
    return None
