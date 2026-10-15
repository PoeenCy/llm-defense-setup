"""Internal HTTP API. The existing dashboard proxies these routes.

Everything is read-only except two writes: POST /traces/<id>/retrace, which only
enqueues a Phase 2 analysis job (see trace/routes.py), and POST /decoder, which
stores the decoder mode ingest reads before each capture (see settings.py)."""
import base64
from contextlib import closing
import json
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import migrations, settings
from .config import DECODER_MODES
from .trace import chains, dedup
from .trace import routes as trace_routes

MAX_POST_BYTES = 4096


def query(path, game_id, url, trace_enabled=False, cfg=None):
    parsed = urlsplit(url)
    params = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=3)) as db:
        db.row_factory = sqlite3.Row
        # Phase 2 first: /transactions/<id>/evidence must not fall into the
        # Phase 1 /transactions/<id> branch below.
        routed = trace_routes.handle(db, game_id, parsed.path, params, trace_enabled)
        if routed is None:
            routed = dedup.handle(db, game_id, parsed.path, params)
        if routed is None:
            routed = chains.handle(db, game_id, parsed.path, params)
        if routed is not None:
            return routed
        if parsed.path in ("/health", "/status"):
            row = db.execute("SELECT data,updated FROM runtime_status WHERE game_id=?", (game_id,)).fetchone()
            data = json.loads(row["data"]) if row else {"state": "starting"}
            data["stale"] = not row or time.time() - row["updated"] > 60
            data["updated"] = row["updated"] if row else None
            return (503 if parsed.path == "/health" and (data["stale"] or data.get("state") != "running") else 200), data
        if parsed.path == "/decoder":
            return 200, decoder_state(db, game_id, cfg)
        if parsed.path in ("/transactions", "/flagouts"):
            limit = max(1, min(int(params.get("limit", 100)), 500))
            offset = max(0, min(int(params.get("offset", 0)), 1_000_000))
            where, values = ["game_id=?"], [game_id]
            for name in ("team_id", "service", "source_key", "tick", "src_ip"):
                if name in params:
                    where.append(name + "=?")
                    values.append(params[name])
            if parsed.path == "/flagouts":
                where.append("flag_out=1")
            cols = "id,conn_id,seq_in_conn,team_id,source_key,is_checker,service,tick,ts_request,ts_response,src_ip,src_port,dst_ip,dst_port,proto,method,path,status,quality,flags_found,flag_out,classification"
            rows = db.execute(f"SELECT {cols} FROM transactions WHERE {' AND '.join(where)} ORDER BY ts_request,id LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
            return 200, {"items": [dict(r) for r in rows], "limit": limit, "offset": offset}
        if parsed.path.startswith("/transactions/"):
            tid = parsed.path.removeprefix("/transactions/")
            row = db.execute("SELECT * FROM transactions WHERE id=? AND game_id=?", (tid, game_id)).fetchone()
            if not row:
                return 404, {"error": "unknown transaction"}
            result = dict(row)
            for k in ("req_parsed", "resp_parsed", "quality", "flags_found", "turns"):
                result[k] = json.loads(result[k])
            result["representations"] = []
            remaining = 2 * 1024 * 1024
            for r in db.execute("SELECT * FROM representations WHERE transaction_id=? ORDER BY rowid", (tid,)):
                rep = dict(r)
                data = rep.pop("data")
                shown = data[:remaining]
                remaining -= len(shown)
                rep["data_base64"] = base64.b64encode(shown).decode()
                rep["api_truncated"] = len(shown) < len(data)
                for k in ("transform", "spans"):
                    rep[k] = json.loads(rep[k])
                result["representations"].append(rep)
            result["tokens"] = [dict(r) for r in db.execute("SELECT * FROM tokens WHERE transaction_id=? ORDER BY rowid", (tid,))]
            result["pcaps"] = [dict(r) for r in db.execute("SELECT p.path,f.hash,f.status FROM transaction_pcaps x JOIN pcap_files f ON f.id=x.file_id JOIN pcap_paths p ON p.file_id=f.id WHERE x.transaction_id=?", (tid,))]
            return 200, result
        return 404, {"error": "unknown endpoint"}


def decoder_state(db, game_id, cfg):
    """The stored mode and the ingest's own report of the last capture. Without
    the config (health checks) the default is not known here, only stored."""
    row = db.execute("SELECT data FROM runtime_status WHERE game_id=?", (game_id,)).fetchone()
    reported = (json.loads(row["data"]) if row else {}).get("decoder") or {}
    if cfg is not None:
        stored = settings.decoder_mode(db, cfg)
    else:
        stored = {k: reported.get(k) for k in ("mode", "source", "default", "since")}
    return {**reported, **stored, "modes": list(DECODER_MODES)}


def command(path, cfg, url, body):
    """The write routes. Anything else posted here is refused."""
    parts = urlsplit(url).path.strip("/").split("/")
    if len(parts) == 3 and parts[0] == "traces" and parts[2] == "retrace":
        return trace_routes.retrace(path, cfg, parts[1], body)
    if parts == ["decoder"]:
        mode = body.get("mode") if isinstance(body, dict) else None
        if mode not in DECODER_MODES + ("default",):
            return 400, {"error": "mode must be one of " + ", ".join(DECODER_MODES + ("default",))}
        try:
            db = migrations.open_initialized(path, timeout=3)
        except ValueError as exc:  # schema not migrated to this build yet
            return 503, {"error": str(exc)}
        try:
            settings.set_decoder_mode(db, cfg, mode)
            return 200, decoder_state(db, cfg.game_id, cfg)
        finally:
            db.close()
    return 404, {"error": "unknown endpoint"}


def make_server(path, game_id, host="0.0.0.0", port=8095, cfg=None):
    trace_enabled = bool(cfg and cfg.options["trace"]["enabled"])

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                status, data = query(path, game_id, self.path, trace_enabled, cfg)
            except ValueError as exc:
                status, data = 400, {"error": str(exc)}
            except sqlite3.Error:
                status, data = 503, {"error": "database not ready"}
            self.reply(status, data)

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if cfg is None:
                    status, data = 404, {"error": "unknown endpoint"}
                elif not 0 < length <= MAX_POST_BYTES:
                    status, data = 400, {"error": "JSON body required (at most 4 KiB)"}
                else:
                    status, data = command(path, cfg, self.path, json.loads(self.rfile.read(length)))
            except ValueError as exc:
                status, data = 400, {"error": str(exc)}
            except sqlite3.Error:
                # Busy or not migrated: the caller may retry with the same key.
                status, data = 503, {"error": "database busy or not ready; retry with the same idempotency_key"}
            self.reply(status, data)

        def reply(self, status, data):
            payload = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass
    return ThreadingHTTPServer((host, port), Handler)
