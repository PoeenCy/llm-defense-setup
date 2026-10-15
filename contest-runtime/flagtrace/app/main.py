"""Commands:

  run         ingest loop plus the read API (owns the schema: migrates on open)
  trace       the Phase 2 worker: dispatch, claim, analyse, commit
  migrate     upgrade the database alone, with both writers stopped
              (--check: exit 3 when an upgrade is pending; backs up first)
  trace-once  one dispatch/claim/analyse pass, same engine as the worker
  worker-health  exit 0 while this worker's heartbeat is fresh (Compose)
  ingest      offline ingest of a directory, then exit
  status      print the stored runtime status

Example: python -m flagtrace.app.main --config services.json ingest --traffic DIR --db FILE --finalize
"""
import argparse
import json
import logging
import os
import shutil
import signal
import threading
import time
from pathlib import Path

from . import migrations
from .api import make_server, query
from .background import collect_checker_flagids, fetch_flagids, import_flagids, rebuild_baseline
from .config import Config
from .ingest import Ingestor
from .store import Store
from .trace import worker as trace_worker
from .trace.replay import verify as verify_replay

log = logging.getLogger("flagtrace")


def publish_status(status):
    if not os.environ.get("REDIS_HOST"):
        return
    try:
        import redis
        with redis.Redis(host=os.environ["REDIS_HOST"], port=int(os.environ.get("REDIS_PORT", "6379")), socket_timeout=1, socket_connect_timeout=1) as r:
            r.set("flagtrace_status", json.dumps({**status, "updated": time.time()}), ex=60)
    except Exception as exc:
        log.debug("status publish failed: %s", exc)


def run(args, cfg):
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    store = Store(args.db, cfg)
    ingestor = Ingestor(store, args.traffic)
    server = make_server(args.db, cfg.game_id, args.host, args.port, cfg=cfg)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    background_at = 0
    try:
        while not stop.is_set():
            status = {}
            try:
                if shutil.disk_usage(store.path.parent).free < cfg.options["min_free_gb"] * 1024**3:
                    raise RuntimeError("disk below flagtrace.min_free_gb; ingest paused")
                # Live readers only consume explicitly closed/published captures.
                paths = [p for p in Path(args.traffic).glob("*.pcap") if p.with_suffix(p.suffix + ".ready").is_file()]
                status = ingestor.run(paths)
                if time.monotonic() >= background_at:
                    rebuild_baseline(store)
                    collect_checker_flagids(store)
                    try:
                        fetch_flagids(store)
                    except Exception as exc:
                        status["flag_ids_error"] = str(exc)
                    background_at = time.monotonic() + cfg.tick_us / 1_000_000
                late = store.db.execute("SELECT count(*) FROM pcap_files WHERE game_id=? AND status='late'", (cfg.game_id,)).fetchone()[0]
                if late:
                    status.update(state="degraded", late_files=late)
                status = store.status(**status)
            except Exception as exc:
                log.exception("ingest cycle failed")
                status = store.status(state="degraded", error=str(exc))
            publish_status(status)
            stop.wait(cfg.options["poll_seconds"])
    finally:
        # Do not finalize open TCP on service restart: replay its pinned PCAPs.
        ingestor.close()
        store.status(state="stopped")
        store.close()
        server.shutdown()
        server.server_close()


def worker_health(db_path, cfg):
    """Compose healthcheck for the trace worker: its own heartbeat row must be
    fresh. 'disabled' is healthy on purpose: the container idles by config."""
    worker_id = os.environ.get("FLAGTRACE_WORKER_ID")
    try:
        code, data = query(db_path, cfg.game_id, "/trace-status", cfg.options["trace"]["enabled"])
    except Exception as exc:
        print(f"unhealthy: {exc}")
        return 1
    mine = [w for w in data["workers"] if not worker_id or w["worker_id"] == worker_id]
    fresh = [w for w in mine if not w["stale"] and w["state"] in ("running", "disabled")]
    print(json.dumps({"state": data["state"], "workers": mine, "backlog": data["backlog"]}, default=str))
    return 0 if fresh else 1


def main():
    parser = argparse.ArgumentParser(description="Flag-trace Phase 1")
    parser.add_argument("--config", default=os.environ.get("CONFIG", "/runtime/config/services.json"))
    sub = parser.add_subparsers(dest="command", required=True)
    for cmd in ("run", "ingest", "status", "import-flagids", "migrate", "trace", "trace-once", "worker-health",
                "verify-script"):
        p = sub.add_parser(cmd)
        p.add_argument("--db", default=os.environ.get("FLAGTRACE_DB", "/data/flagtrace.sqlite3"))
        if cmd in ("run", "ingest"):
            p.add_argument("--traffic", default=os.environ.get("TRAFFIC_DIR", "/traffic"))
        if cmd == "ingest":
            p.add_argument("--finalize", action="store_true", help="close incomplete connections at end of an offline dataset")
        if cmd == "run":
            p.add_argument("--host", default="0.0.0.0")
            p.add_argument("--port", type=int, default=8095)
        if cmd in ("trace", "trace-once"):
            # 'seed' stores the anchor and marks linking not computed; it is the
            # P2.1 behaviour, kept for comparing against the full engine.
            p.add_argument("--mode", choices=("full", "seed"), default="full")
        if cmd == "migrate":
            p.add_argument("--check", action="store_true", help="report only; exit 3 if an upgrade is pending")
            p.add_argument("--backup-dir", default=os.environ.get("FLAGTRACE_BACKUP_DIR", "/data/backups"))
        if cmd == "import-flagids":
            p.add_argument("file")
        if cmd == "verify-script":
            p.add_argument("artifact_id")
            p.add_argument("--fixture", required=True, help="stable name/version of the local fixture")
            p.add_argument("--target", default="127.0.0.1", help="localhost or a literal loopback IP")
            p.add_argument("--port", type=int, help="local fixture port override; captured ports remain the default")
            p.add_argument("--flag-id")
            p.add_argument("--expect")
            p.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [flagtrace] %(message)s")
    cfg = Config.load(args.config)
    if args.command == "run":
        run(args, cfg)
    elif args.command == "migrate":
        # Schema work alone: no game/config rows are written, so this is safe
        # to run before either writer starts.
        at, target, needed = migrations.pending(args.db)
        if args.check:
            print(json.dumps({"at": at, "target": target, "needed": needed}))
            raise SystemExit(3 if needed else 0)
        db = migrations.connect(args.db)
        try:
            saved = migrations.backup(db, args.backup_dir, at) if needed else None
            print(json.dumps({**migrations.upgrade(db), "backup": saved}, indent=2))
        finally:
            db.close()
    elif args.command == "worker-health":
        raise SystemExit(worker_health(args.db, cfg))
    elif args.command == "trace":
        trace_worker.serve(args.db, cfg, mode=args.mode)
    elif args.command == "trace-once":
        print(json.dumps(trace_worker.run_once(args.db, cfg, mode=args.mode), indent=2, default=str))
    elif args.command == "verify-script":
        print(json.dumps(verify_replay(args.db, cfg, args.artifact_id, args.fixture, args.target,
                                       args.flag_id, args.expect, args.timeout, args.port), indent=2, default=str))
    elif args.command == "status":
        print(json.dumps({**query(args.db, cfg.game_id, "/status")[1],
                          "trace": query(args.db, cfg.game_id, "/trace-status",
                                         cfg.options["trace"]["enabled"])[1]}, indent=2))
    else:
        store = Store(args.db, cfg)
        try:
            if args.command == "import-flagids":
                print(import_flagids(store, json.loads(Path(args.file).read_text())))
            else:
                ingestor = Ingestor(store, args.traffic)
                try:
                    ingestor.run(Path(args.traffic).glob("*.pcap"), finalize=args.finalize)
                    rebuild_baseline(store)
                    collect_checker_flagids(store)
                    print(json.dumps(store.status(state="complete"), indent=2))
                finally:
                    ingestor.close()
        finally:
            store.close()


if __name__ == "__main__":
    main()
