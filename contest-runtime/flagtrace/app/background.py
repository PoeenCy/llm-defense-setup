"""Optional flag-ID intake and bounded checker baseline rebuilds."""
import json
import math
import time
import urllib.request
from pathlib import Path

from .parsing import path_template
from .store import dumps
from .tokens import extract

# Checker traffic is analysed field by field, so even one-character values count.
ALL_VALUES = {"min_len": 1, "struct_min_len": 1, "sub_min_len": 1, "max_tokens": 2000, "stoplist": []}
# Session material, not values an attacker would be handed as a flag ID.
CREDENTIAL_LOCATIONS = ("cookie", "header")


def import_flagids(store, rows, source="file"):
    clean = []
    for r in rows:
        if not isinstance(r["tick"], int) or len(str(r["value"])) > 4096:
            raise ValueError("invalid flag-ID record")
        clean.append((store.cfg.game_id, r["tick"], str(r["service"]), str(r["owner_team_id"]), str(r["value"]), source))
    with store.db:
        store.db.executemany("INSERT OR IGNORE INTO flag_ids(game_id,tick,service,owner_team_id,value,source) VALUES(?,?,?,?,?,?)", clean)
    return len(clean)


def fetch_flagids(store):
    url = store.cfg.options.get("flag_ids_url")
    if not url:
        return 0
    if not url.startswith(("http://", "https://")):
        raise ValueError("flag_ids_url must use HTTP(S)")
    with urllib.request.urlopen(url, timeout=5) as response:
        data = response.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("flag-ID response too large")
    rows = json.loads(data)
    if not isinstance(rows, list):
        raise ValueError("flag-ID adapter expects a list of normalized records")
    return import_flagids(store, rows, "configured_http")


def rebuild_baseline(store):
    db, cfg = store.db, store.cfg
    tick = db.execute("SELECT max(tick) FROM transactions WHERE game_id=?", (cfg.game_id,)).fetchone()[0]
    if tick is None:
        return
    rows = db.execute("""SELECT service,method,path,req_parsed FROM transactions
        WHERE game_id=? AND is_checker=1 AND tick>=? AND proto='http'
        ORDER BY ts_request DESC LIMIT 10000""", (cfg.game_id, tick - cfg.options["baseline_ticks"] + 1)).fetchall()
    groups = {}
    for r in rows:
        parsed = json.loads(r["req_parsed"])
        ts, _ = extract(parsed, b"", "req", ALL_VALUES)
        for token in ts:
            if token["parent"] is not None:
                continue
            key = (r["service"], r["method"], path_template(r["path"] or ""), dumps(token["location"]))
            group = groups.setdefault(key, {"lengths": [], "charset": set(), "types": set()})
            group["lengths"].append(len(token["value"]))
            group["charset"].update(token["value"])
            group["types"].add(parsed.get("content_type", ""))
    with db:
        db.execute("DELETE FROM baseline WHERE game_id=?", (cfg.game_id,))
        for key, group in groups.items():
            lengths = sorted(group["lengths"])
            stats = {"samples": len(lengths), "len_p50": lengths[len(lengths)//2], "len_p99": lengths[max(0, math.ceil(len(lengths)*.99)-1)],
                     "charset": "".join(sorted(group["charset"])), "content_types": sorted(group["types"]),
                     "window_end_tick": tick, "sample_limit_reached": len(rows) == 10000}
            db.execute("INSERT INTO baseline VALUES(?,?,?,?,?,?,?)", (cfg.game_id, *key, dumps(stats), time.time()))


def collect_checker_flagids(store):
    """Flag-ID candidates from the checker's own putflag sessions.

    A putflag is a checker transaction whose request carries a flag (flags_in).
    Candidates are the values in that connection up to and including it, from
    requests and responses alike, because a server-generated ID only shows up
    in a response. A location is kept only if its value changes between ticks,
    so constants such as path names never become targets. Phase 2 (B6) matches
    these at query time; ingest tokenization does not depend on this table.
    Rebuilt from scratch each time: the rows are derived from transactions.
    """
    db, cfg = store.db, store.cfg
    owner = str(cfg.raw.get("team_id") or "")
    puts = db.execute("""SELECT DISTINCT t.id,t.conn_id,t.seq_in_conn,t.tick,t.service FROM flags_in f
        JOIN transactions t ON t.id=f.transaction_id WHERE f.game_id=? AND t.is_checker=1""", (cfg.game_id,)).fetchall()
    candidates = []
    seen = {}
    for put in puts:
        rows = db.execute("""SELECT id,method,path,req_parsed,resp_parsed FROM transactions
            WHERE conn_id=? AND seq_in_conn<=? ORDER BY seq_in_conn""", (put["conn_id"], put["seq_in_conn"])).fetchall()
        for r in rows:
            for side, column in (("req", "req_parsed"), ("resp", "resp_parsed")):
                ts, _ = extract(json.loads(r[column]), b"", side, ALL_VALUES)
                # Drop flags and every fragment split out of a flag-bearing value.
                flagged = {i for i, t in enumerate(ts) if cfg.regex.search(t["value"].encode("utf-8", "replace"))}
                for i, token in enumerate(ts):
                    value = token["value"]
                    if i in flagged or token["parent"] in flagged or token["location"][1] in CREDENTIAL_LOCATIONS:
                        continue
                    key = (put["service"], r["method"], path_template(r["path"] or ""), dumps(token["location"]))
                    seen.setdefault(key, {}).setdefault(put["tick"], set()).add(value)
                    candidates.append((key, put["tick"], put["service"], value, r["id"]))
    varying = {key for key, ticks in seen.items()
               if len(ticks) >= 2 and len(set().union(*ticks.values())) >= 2}
    with db:
        db.execute("DELETE FROM flag_ids WHERE game_id=? AND source='checker_put'", (cfg.game_id,))
        db.executemany("""INSERT OR IGNORE INTO flag_ids(game_id,tick,service,owner_team_id,value,source,location,transaction_id)
            VALUES(?,?,?,?,?,'checker_put',?,?)""",
            [(cfg.game_id, tick, service, owner, value, key[3], tid) for key, tick, service, value, tid in candidates if key in varying])
    return len(varying)
