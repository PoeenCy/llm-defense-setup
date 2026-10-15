"""Phase 2 routes, served by the existing internal API.

Reads run on the API's read-only connection and never touch schema or config
rows. Every lookup is scoped to the current game and checks how the IDs relate
(run → trace, transaction → run), not only that they look valid. Payloads are
bounded on the server: lists carry metadata, and full request/response bytes
come only from the evidence route, cut to a fixed size per side.

The single write is the retrace request. It only enqueues an analysis job on
its own short-lived connection; it never runs an exploit, a rule or SSH.
"""
import base64
import json
import re
import time

from . import contracts
from .repository import Reader, Repository

API_VERSION = 2
HEX64 = re.compile(r"[0-9a-f]{64}")
IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
EVIDENCE_BYTES_PER_SIDE = 256 * 1024
EVIDENCE_TOKENS = 500
STEP_LIMIT = 500
EDGE_LIMIT = 1000
VALUE_LIMIT = 1000
WORKER_STALE_SECONDS = 60
TX_FIELDS = ("id", "game_id", "conn_id", "seq_in_conn", "team_id", "source_key", "is_checker", "service", "tick",
             "ts_request", "ts_response", "ts_end", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "method",
             "path", "status", "classification", "flag_out")


class NotFound(Exception):
    pass


def _json(value, default=None):
    if value is None:
        return default
    return json.loads(value) if isinstance(value, str) else value


def _id(value):
    if not HEX64.fullmatch(value or ""):
        raise NotFound()
    return value


def _int(params, name, default, low, high):
    try:
        value = int(params.get(name, default))
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer")
    return max(low, min(value, high))


def handle(db, game_id, path, params, trace_enabled):
    """Return (status, body) for a Phase 2 route, or None when the path is not
    one, so the caller falls through to the Phase 1 routes."""
    parts = path.strip("/").split("/")
    reader = Reader(db, game_id)
    try:
        if parts == ["trace-status"]:
            return 200, trace_status(reader, trace_enabled)
        if parts == ["traces"]:
            return 200, list_traces(reader, params)
        if len(parts) == 2 and parts[0] == "traces":
            return 200, trace_detail(reader, _id(parts[1]), trace_enabled)
        if len(parts) == 3 and parts[0] == "traces" and parts[2] == "runs":
            return 200, run_history(reader, _id(parts[1]), params)
        if len(parts) == 4 and parts[0] == "traces" and parts[2] == "runs":
            return 200, run_detail(reader, _id(parts[1]), _id(parts[3]))
        if len(parts) == 6 and parts[0] == "traces" and parts[2] == "runs" and parts[4] == "scripts":
            return 200, script_artifact(reader, _id(parts[1]), _id(parts[3]), _id(parts[5]))
        if len(parts) == 3 and parts[0] == "transactions" and parts[2] == "evidence":
            run = params.get("run_id")
            return 200, evidence(reader, _id(parts[1]), _id(run) if run else None)
    except NotFound:
        return 404, {"error": "not found in this game", "api_version": API_VERSION}
    return None


# ── list and detail ─────────────────────────────────────────────────────
def display_state(row):
    """What the profile shows first. A newer request still waiting, running or
    failed is shown over the older result it may replace; that older result
    stays available in the history."""
    job, run_seq = row["job_status"], row["latest_run_sequence"]
    newer = run_seq is None or (row["job_sequence"] or 0) > run_seq
    if job in (contracts.JOB_PENDING, contracts.JOB_RUNNING, contracts.JOB_FAILED) and newer:
        return job
    return row["run_state"] or job or contracts.JOB_PENDING


def profile_summary(row):
    flags = _json(row["flags_found"], [])
    out = {"trace_id": row["trace_id"], "anchor_transaction_id": row["anchor_transaction_id"],
           "created": row["created"], "source_key": row["source_key"], "team_id": row["team_id"],
           "service": row["service"], "tick": row["tick"], "ts_request": row["ts_request"],
           "method": row["method"], "path": row["path"], "status": row["status"], "proto": row["proto"],
           "flags_found": flags, "flag_count": len(flags), "quality": _json(row["quality"], []),
           "classification": row["classification"], "display_state": display_state(row),
           "latest_run": None, "latest_request": None}
    if row["latest_run_id"]:
        out["latest_run"] = {"run_id": row["latest_run_id"], "state": row["run_state"],
                             "request_sequence": row["latest_run_sequence"], "created": row["run_created"],
                             "engine_version": row["engine_version"], "step_count": row["step_count"],
                             "linked_count": row["linked_count"],
                             "edge_count": row["edge_count"], "warning_count": len(_json(row["run_warnings"], []))}
    if row["job_status"]:
        out["latest_request"] = {"request_sequence": row["job_sequence"], "status": row["job_status"],
                                 "attempts": row["job_attempts"], "error": row["job_error"]}
    return out


def list_traces(reader, params):
    limit = _int(params, "limit", 50, 1, 200)
    cursor = None
    if params.get("cursor"):
        ts, _, trace = params["cursor"].partition(":")
        try:
            cursor = (int(ts), _id(trace))
        except (ValueError, NotFound):
            raise ValueError("cursor must be <ts_request>:<trace_id>")
    filters = {k: params.get(k) for k in ("source_key", "service", "team_id", "tick", "src_ip", "state")}
    if filters["tick"] not in (None, ""):
        filters["tick"] = _int(params, "tick", 0, -2**31, 2**31)
    rows, total = reader.list_profiles(filters, limit + 1, cursor)
    more = len(rows) > limit
    rows = rows[:limit]
    following = f"{rows[-1]['ts_request']}:{rows[-1]['trace_id']}" if more and rows else None
    return {"api_version": API_VERSION, "items": [profile_summary(r) for r in rows], "total": total,
            "limit": limit, "next_cursor": following}


def trace_detail(reader, trace_id, trace_enabled):
    profile = reader.profile(trace_id)
    if not profile:
        raise NotFound()
    jobs = [dict(j) for j in reader.jobs_for(trace_id, limit=20)]
    latest = None
    if profile["latest_run_id"]:
        run = reader.run(trace_id, profile["latest_run_id"])
        latest = run_header(run, profile)
    newest = jobs[0] if jobs else None
    summary = {"job_status": newest["status"] if newest else None,
               "job_sequence": newest["request_sequence"] if newest else None,
               "latest_run_sequence": profile["latest_run_sequence"],
               "run_state": latest["state"] if latest else None}
    return {"api_version": API_VERSION, "trace_id": trace_id, "trace_enabled": trace_enabled,
            "display_state": display_state(summary),
            "anchor": {"transaction_id": profile["anchor_transaction_id"], "source_key": profile["source_key"],
                       "team_id": profile["team_id"], "service": profile["service"], "tick": profile["tick"],
                       "ts_request": profile["ts_request"], "ts_response": profile["ts_response"],
                       "method": profile["method"], "path": profile["path"], "status": profile["status"],
                       "proto": profile["proto"], "conn_id": profile["conn_id"],
                       "seq_in_conn": profile["seq_in_conn"], "flags_found": _json(profile["flags_found"], []),
                       "quality": _json(profile["quality"], []), "classification": profile["classification"]},
            "created": profile["created"], "last_requested_sequence": profile["last_requested_sequence"],
            "latest_run": latest, "jobs": jobs}


def run_header(run, profile=None):
    metrics = _json(run["metrics"], {})
    coverage = _json(run["coverage"], {})
    return {"run_id": run["id"], "job_id": run["job_id"], "request_sequence": run["request_sequence"],
            "trigger_key": run["trigger_key"], "state": run["state"], "engine_version": run["engine_version"],
            "algorithm_hash": run["algorithm_hash"], "snapshot_wall": run["snapshot_wall"],
            "created": run["created"], "warnings": _json(run["warnings"], []),
            "limits_hit": coverage.get("limits_hit", []), "duration_ms": metrics.get("duration_ms"),
            "steps": metrics.get("steps"), "edges": metrics.get("edges"),
            "is_latest": bool(profile and profile["latest_run_id"] == run["id"])}


def run_history(reader, trace_id, params):
    profile = reader.profile(trace_id)
    if not profile:
        raise NotFound()
    limit, offset = _int(params, "limit", 20, 1, 100), _int(params, "offset", 0, 0, 1_000_000)
    rows, total = reader.runs_for(trace_id, limit, offset)
    items = []
    for row in rows:
        metrics = _json(row["metrics"], {})
        items.append({"run_id": row["id"], "job_id": row["job_id"], "request_sequence": row["request_sequence"],
                      "trigger_key": row["trigger_key"], "state": row["state"],
                      "engine_version": row["engine_version"], "algorithm_hash": row["algorithm_hash"],
                      "snapshot_wall": row["snapshot_wall"], "created": row["created"],
                      "step_count": row["step_count"], "edge_count": row["edge_count"],
                      "duration_ms": metrics.get("duration_ms"),
                      "is_latest": profile["latest_run_id"] == row["id"]})
    return {"api_version": API_VERSION, "trace_id": trace_id, "items": items, "total": total,
            "limit": limit, "offset": offset}


def run_detail(reader, trace_id, run_id):
    from . import chains  # chains builds on this module's helpers
    profile = reader.profile(trace_id)
    run = reader.run(trace_id, run_id) if profile else None
    if not run:
        raise NotFound()
    steps = [{"transaction_id": s["transaction_id"], "position": s["position"], "role": s["role"],
              "reasons": _json(s["reasons"], []), "quality": _json(s["quality"], []),
              "summary": _json(s["summary"], {}),
              # Enough to find the same exchange in Tulip; the dashboard does
              # the lookup, so no flow ID is ever stored as if it were ours.
              "network": {"src_ip": s["src_ip"], "src_port": s["src_port"], "dst_ip": s["dst_ip"],
                          "dst_port": s["dst_port"], "ts_request": s["tx_ts_request"]}}
             for s in reader.steps(run_id, STEP_LIMIT + 1)]
    edges = []
    for e in reader.edges(run_id, EDGE_LIMIT + 1):
        edges.append({"evidence_key": e["evidence_key"], "kind": e["kind"],
                      "dst_transaction_id": e["dst_transaction_id"], "dst_token_id": e["dst_token_id"],
                      "dst_location": _json(e["dst_location"]), "dst_representation_id": e["dst_representation_id"],
                      "dst_observed_ts": e["dst_observed_ts"], "src_transaction_id": e["src_transaction_id"],
                      "src_token_id": e["src_token_id"], "src_location": _json(e["src_location"]),
                      "src_representation_id": e["src_representation_id"], "src_observed_ts": e["src_observed_ts"],
                      "value_preview": e["value_preview"], "value_length": e["value_length"],
                      "transform": _json(e["transform"], []), "ambiguous": bool(e["ambiguous"]),
                      "alternatives": _json(e["alternatives"], []), "note": e["note"]})
    analysis = _json(run["analysis"], {})
    return {"api_version": API_VERSION, "trace_id": trace_id, **run_header(run, profile),
            "anchor": _json(run["anchor"], {}), "coverage": _json(run["coverage"], {}),
            "metrics": _json(run["metrics"], {}), "analysis": analysis,
            "steps": steps[:STEP_LIMIT], "edges": edges[:EDGE_LIMIT],
            "steps_truncated": len(steps) > STEP_LIMIT, "edges_truncated": len(edges) > EDGE_LIMIT,
            "job": {"status": run["job_status"], "attempts": run["attempts"], "error": run["job_error"]},
            # Declared and explicitly not run yet (P2.4/P2.5), never an empty result.
            **{name: dict(contracts.NOT_COMPUTED) for name in contracts.EXTENSION_SECTIONS},
            "value_roles": value_roles(reader, run_id, analysis),
            "scripts": scripts(reader, run_id, analysis),
            "grouping": chains.run_grouping(reader.db, run, analysis),
            "suspects": chains.run_suspects(reader.db, run_id, analysis)}


def value_roles(reader, run_id, analysis):
    """A run classified by engine p2.4.0 or later carries its summary in the
    analysis; an older run never had value roles and says so."""
    summary = analysis.get("value_roles")
    if not summary:
        return dict(contracts.NOT_COMPUTED)
    rows = reader.values(run_id, VALUE_LIMIT + 1)
    items = [{"value_key": v["value_key"], "transaction_id": v["transaction_id"], "token_id": v["token_id"],
              "location": _json(v["location"]), "role": v["role"], "var": v["var"],
              "value_preview": v["value_preview"], "value_length": v["value_length"], "template": v["template"],
              "parts": _json(v["parts"], []), "transform": _json(v["transform"], []), "unresolved": v["unresolved"],
              "session_cookie": bool(v["session_cookie"]), "ambiguous": bool(v["ambiguous"]),
              "evidence": _json(v["evidence"], {})} for v in rows[:VALUE_LIMIT]]
    return {**summary, "values": items, "values_listed_truncated": len(rows) > VALUE_LIMIT}


def scripts(reader, run_id, analysis):
    """Artifact metadata only. Contents have a separate scoped endpoint so a
    normal run detail remains small even for binary or multipart requests."""
    summary = analysis.get("scripts")
    if not summary:
        return dict(contracts.NOT_COMPUTED)
    rows = reader.script_artifacts(run_id)
    verifications = reader.replay_verifications([r["id"] for r in rows])
    items = []
    for row in rows:
        verification = verifications.get(row["id"])
        items.append({"artifact_id": row["id"], "kind": row["kind"],
                      "transaction_id": row["transaction_id"], "position": row["position"],
                      "format": row["format"], "filename": row["filename"],
                      "exporter_version": row["exporter_version"], "content_hash": row["content_hash"],
                      "support": row["support"], "warnings": _json(row["warnings"], []),
                      "size": row["size"], "created": row["created"],
                      "verification": ({"status": verification["status"], "fixture": verification["fixture"],
                                        "target": verification["target"], "artifact_hash": verification["artifact_hash"],
                                        "flags": _json(verification["flags"], []), "error": verification["error"],
                                        "finished": verification["finished"]} if verification else
                                       {"status": contracts.VERIFY_NOT_RUN})})
    chain = next((a for a in items if a["kind"] == "chain"), None)
    verification = chain["verification"]["status"] if chain else contracts.VERIFY_NOT_RUN
    return {**summary, "verification": verification, "artifacts": items}


def script_artifact(reader, trace_id, run_id, artifact_id):
    row = reader.script_artifact(trace_id, run_id, artifact_id)
    if not row:
        raise NotFound()
    content = row["content"] or b""
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    return {"api_version": API_VERSION, "trace_id": trace_id, "run_id": run_id,
            "artifact_id": row["id"], "kind": row["kind"], "transaction_id": row["transaction_id"],
            "position": row["position"], "format": row["format"], "filename": row["filename"],
            "exporter_version": row["exporter_version"], "content_hash": row["content_hash"],
            "support": row["support"], "warnings": _json(row["warnings"], []), "content": content}


# ── evidence ────────────────────────────────────────────────────────────
def evidence(reader, transaction_id, run_id=None):
    db = reader.db
    row = db.execute(f"SELECT {','.join(TX_FIELDS)},req_parsed,resp_parsed,turns,quality,flags_found"
                     " FROM transactions WHERE id=? AND game_id=?", (transaction_id, reader.game_id)).fetchone()
    if not row:
        raise NotFound()
    if run_id:
        # Asked in the context of a run: the transaction has to be one of its
        # steps, and the run has to belong to this game. Legacy 'context' rows
        # are not steps of the flow and are not served as such.
        if not db.execute("""SELECT 1 FROM trace_steps s JOIN trace_runs r ON r.id=s.run_id
                             WHERE s.run_id=? AND s.transaction_id=? AND r.game_id=? AND s.role<>'context'""",
                          (run_id, transaction_id, reader.game_id)).fetchone():
            raise NotFound()
    reps, budget = [], {"req": EVIDENCE_BYTES_PER_SIDE, "resp": EVIDENCE_BYTES_PER_SIDE}
    for rep in db.execute("""SELECT id,side,kind,parent_id,transform,data,original_size,truncated,spans
                             FROM representations WHERE transaction_id=? ORDER BY rowid""", (transaction_id,)):
        data = rep["data"] or b""
        side = rep["side"] if rep["side"] in budget else "req"
        shown = data[:max(0, budget[side])]
        budget[side] -= len(shown)
        reps.append({"id": rep["id"], "side": rep["side"], "kind": rep["kind"], "parent_id": rep["parent_id"],
                     "transform": _json(rep["transform"], []), "spans": _json(rep["spans"], []),
                     "original_size": rep["original_size"], "stored_size": len(data),
                     # Cut when Phase 1 stored it, versus cut for this response.
                     "storage_truncated": bool(rep["truncated"]), "api_truncated": len(shown) < len(data),
                     "data_base64": base64.b64encode(shown).decode()})
    tokens = [{"id": t["id"], "representation_id": t["representation_id"], "role": t["role"],
               "side": "resp" if t["role"] == "produced" else "req", "location": _json(t["location"]),
               "value": t["value"], "normalized_value": t["normalized_value"], "parent_id": t["parent_id"],
               "transform": _json(t["transform"], []), "span": _json(t["span"]), "observed_ts": t["observed_ts"]}
              for t in db.execute("""SELECT id,representation_id,role,location,value,normalized_value,parent_id,
                                     transform,span,observed_ts FROM tokens WHERE transaction_id=? ORDER BY rowid
                                     LIMIT ?""", (transaction_id, EVIDENCE_TOKENS + 1))]
    token_total = db.execute("SELECT count(*) FROM tokens WHERE transaction_id=?", (transaction_id,)).fetchone()[0]
    sightings = [dict(s) for s in db.execute("""SELECT representation_id,value,side,start,end FROM flag_sightings
                                                WHERE transaction_id=? ORDER BY side,start LIMIT 200""",
                                             (transaction_id,))]
    pcaps = [dict(p) for p in db.execute("""SELECT p.path,f.hash,f.status FROM transaction_pcaps x
                JOIN pcap_files f ON f.id=x.file_id JOIN pcap_paths p ON p.file_id=f.id
                WHERE x.transaction_id=? LIMIT 20""", (transaction_id,))]
    tx = {k: row[k] for k in TX_FIELDS}
    return {"api_version": API_VERSION, "transaction": tx, "quality": _json(row["quality"], []),
            "flags_found": _json(row["flags_found"], []),
            "request": {"available": True, "parsed": _json(row["req_parsed"], {})},
            "response": {"available": row["ts_response"] is not None, "parsed": _json(row["resp_parsed"], {})},
            "turns": _json(row["turns"]), "representations": reps, "sightings": sightings,
            "tokens": tokens[:EVIDENCE_TOKENS], "tokens_total": token_total,
            "tokens_truncated": token_total > EVIDENCE_TOKENS, "pcaps": pcaps,
            "limits": {"bytes_per_side": EVIDENCE_BYTES_PER_SIDE, "tokens": EVIDENCE_TOKENS}}


# ── worker status ───────────────────────────────────────────────────────
def trace_status(reader, trace_enabled):
    now = time.time()
    workers = []
    for row in reader.worker_status():
        data = _json(row["data"], {})
        # A worker publishes between jobs, and one job may run for up to its
        # lease, so a long lease must not make a busy worker look dead.
        quiet = max(WORKER_STALE_SECONDS, 3 * (data.get("poll_seconds") or 1), 2 * (data.get("lease_seconds") or 0))
        workers.append({"worker_id": row["worker_id"], "updated": row["updated"],
                        "stale": now - row["updated"] > quiet,
                        **{k: data.get(k) for k in ("state", "error", "last_error", "jobs_done", "jobs_failed",
                                                    "current_job", "engine_version", "algorithm_hash")}})
    live = [w for w in workers if not w["stale"]]
    if not trace_enabled:
        state = "disabled"
    elif not live:
        state = "no_worker"
    elif any(w["state"] == "degraded" for w in live):
        state = "degraded"
    else:
        state = live[0]["state"] or "unknown"
    return {"api_version": API_VERSION, "enabled": trace_enabled, "state": state, "workers": workers,
            "backlog": reader.queue_backlog(), "checked": now}


# ── retrace (the one write) ─────────────────────────────────────────────
def retrace(db_path, cfg, trace_id, body):
    if not HEX64.fullmatch(trace_id or ""):
        return 404, {"error": "not found in this game"}
    key = body.get("idempotency_key") if isinstance(body, dict) else None
    if not isinstance(key, str) or not IDEMPOTENCY_KEY.fullmatch(key):
        return 400, {"error": "idempotency_key must be 1-128 characters of [A-Za-z0-9_.:-]"}
    if not cfg.options["trace"]["enabled"]:
        # A job enqueued while no worker runs would sit unseen; say so instead.
        return 409, {"error": "trace worker disabled (flagtrace.trace.enabled=false)"}
    try:
        repo = Repository.open(db_path, cfg, worker_id="api", timeout=3)
    except ValueError as exc:  # schema not migrated to this build yet
        return 503, {"error": str(exc)}
    try:
        job = repo.enqueue_retrace(trace_id, key)
    finally:
        repo.close()
    if job is None:
        return 404, {"error": "not found in this game"}
    return 202, {"api_version": API_VERSION, "trace_id": trace_id, **job}
