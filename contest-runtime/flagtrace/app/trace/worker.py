"""The trace worker: dispatch, claim, analyse, commit, heartbeat.

One job at a time by default. Correctness does not depend on that: the unique
constraints on (trace, trigger) and (trace, sequence), plus the lease token
checked at commit time, are what prevent a second worker — or a worker that
came back after a pause — from producing a duplicate or stale result.

Read and write transactions are kept apart. The analysis runs inside a deferred
read snapshot which is released before the result is written, so the single
SQLite write lock is never held across the graph search.
"""
import json
import logging
import os
import signal
import threading
import time

from . import contracts
from .engine import Engine
from .repository import Repository

log = logging.getLogger("flagtrace.trace")

# Longest run of back-to-back jobs before the worker goes back to its loop to
# publish a heartbeat, adopt new flag-outs and reclaim dead leases. A backlog is
# worked through in slices, not in one silent pass that makes the worker look
# dead. Checked between jobs, so one job can overrun it by its own budget.
SLICE_SECONDS = 5.0
# Queue rows adopted per poll; a full batch means more may be waiting.
DISPATCH_BATCH = 50
SCRIPT_BACKFILL_BATCH = 50


class Worker:
    def __init__(self, repo, cfg, mode="full", stop=None, slice_seconds=SLICE_SECONDS):
        self.repo, self.cfg, self.mode = repo, cfg, mode
        self.trace = cfg.options["trace"]
        self.stop = stop or threading.Event()
        self.slice_seconds = slice_seconds
        self.state = {"worker_id": repo.worker_id, "state": "starting", "jobs_done": 0,
                      "jobs_failed": 0, "last_error": None, "current_job": None}

    # ── one unit of work ────────────────────────────────────────────────
    def process_one(self):
        """Claim and finish one job. Returns a short outcome dict, or None when
        there was nothing due."""
        job = self.repo.claim()
        if not job:
            return None
        self.state["current_job"] = job["id"]
        try:
            engine = Engine(self.repo, self.cfg, mode=self.mode, algorithm=json.loads(job["algorithm_config"]))
            anchor = self.repo.db.execute("SELECT anchor_transaction_id FROM trace_profiles WHERE id=?",
                                          (job["trace_id"],)).fetchone()
            if anchor is None:
                self.repo.release(job, "trace profile vanished", retry=False)
                return {"job_id": job["id"], "status": "failed", "error": "profile missing"}
            # The snapshot is only open for the analysis itself.
            with self.repo.snapshot():
                result = engine.analyse(anchor["anchor_transaction_id"])
            outcome = self.repo.commit_result(job, result)
            if not outcome["committed"]:
                # Lease lost: another worker owns this job now. Do not retry or
                # count it; whoever holds the lease will finish it.
                log.warning("job %s not committed: %s", job["id"], outcome["reason"])
                self.state["last_error"] = outcome["reason"]
                return {"job_id": job["id"], "status": "abandoned", "error": outcome["reason"]}
            self.state["jobs_done"] += 1
            return {"job_id": job["id"], "status": "done", "run_id": outcome["run_id"],
                    "state": result.state, "duplicate": outcome["duplicate"],
                    "duration_ms": result.metrics["duration_ms"]}
        except LookupError as exc:
            # The anchor is not in this game's data: retrying cannot fix it.
            self.repo.release(job, str(exc), retry=False)
            self.state["jobs_failed"] += 1
            self.state["last_error"] = str(exc)
            return {"job_id": job["id"], "status": "failed", "error": str(exc)}
        except Exception as exc:
            log.exception("trace job %s failed", job["id"])
            status = self.repo.release(job, f"{type(exc).__name__}: {exc}", retry=True)
            if status == "lost":
                return {"job_id": job["id"], "status": "abandoned", "error": "lease lost"}
            if status == "failed":
                self.state["jobs_failed"] += 1
            self.state["last_error"] = str(exc)
            return {"job_id": job["id"], "status": status, "error": str(exc)}
        finally:
            self.state["current_job"] = None

    def tick(self):
        """One poll: adopt new flag-outs, reclaim dead leases, then work due jobs
        for at most one slice. `more` means work was left over, so the caller
        polls again at once instead of sleeping."""
        dispatched = self.repo.dispatch_pending(limit=DISPATCH_BATCH)
        backfilled = self.repo.enqueue_missing_scripts(limit=SCRIPT_BACKFILL_BATCH)
        regrouped = self.repo.enqueue_missing_grouping(limit=SCRIPT_BACKFILL_BATCH)
        reclaimed = self.repo.reclaim_expired()
        done = []
        more = (dispatched["examined"] >= DISPATCH_BATCH or
                backfilled["examined"] >= SCRIPT_BACKFILL_BATCH or
                regrouped["examined"] >= SCRIPT_BACKFILL_BATCH)
        until = time.monotonic() + self.slice_seconds
        while not self.stop.is_set():
            # At least one job per poll, so a slow dispatch cannot starve work.
            if done and time.monotonic() >= until:
                more = True
                break
            outcome = self.process_one()
            if outcome is None:
                break
            done.append(outcome)
        return {"dispatched": dispatched, "script_backfill": backfilled, "grouping_backfill": regrouped,
                "reclaimed": reclaimed, "processed": done, "more": more}

    # ── service loop ────────────────────────────────────────────────────
    def serve(self):
        self.state["state"] = "running"
        self.publish()
        while not self.stop.is_set():
            more = False
            try:
                summary = self.tick()
                more = summary["more"]
                self.state.update(state="running", backlog=self.repo.queue_backlog(), error=None)
                if summary["processed"]:
                    log.info("trace: %d job(s) processed, %d dispatched, %d script backfill, %d lease(s) reclaimed",
                             len(summary["processed"]), summary["dispatched"]["jobs_created"],
                             summary["script_backfill"]["jobs_created"], summary["reclaimed"])
            except Exception as exc:
                # A failing poll must not kill the worker: the next poll retries
                # and the status says the module is degraded meanwhile.
                log.exception("trace poll failed")
                self.state.update(state="degraded", error=str(exc))
            self.publish()
            if not more:
                self.stop.wait(self.trace["poll_seconds"])
        self.state.update(state="stopped")
        self.publish()

    def publish(self):
        try:
            self.repo.publish_worker_status({**self.state, "engine_version": contracts.ENGINE_VERSION,
                                             "algorithm_hash": self.cfg.algorithm_hash(),
                                             "poll_seconds": self.trace["poll_seconds"],
                                             "lease_seconds": self.trace["lease_seconds"]})
        except Exception as exc:
            log.debug("worker status not published: %s", exc)


def _open_with_wait(db_path, cfg, stop, wait_seconds):
    """The ingest writer owns the schema, so on a cold start the database may
    not exist or may not be migrated yet. Wait for it instead of crash-looping,
    but give up loudly rather than wait forever on a real version mismatch."""
    deadline = time.monotonic() + wait_seconds
    last = None
    while not stop.is_set():
        try:
            return Repository.open(db_path, cfg, worker_id=os.environ.get("FLAGTRACE_WORKER_ID"))
        except Exception as exc:
            if str(exc) != last:
                log.warning("waiting for an initialized Flag-trace database: %s", exc)
                last = str(exc)
            if time.monotonic() > deadline:
                raise
            stop.wait(min(5, max(1, cfg.options["trace"]["poll_seconds"])))
    return None


def serve(db_path, cfg, mode="full", wait_seconds=300):
    """Entry point for the `trace` command."""
    if not cfg.options["trace"]["enabled"]:
        log.info("flagtrace.trace.enabled is false; worker idle by configuration")
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    repo = _open_with_wait(db_path, cfg, stop, wait_seconds)
    if repo is None:
        return
    worker = Worker(repo, cfg, mode=mode, stop=stop)
    try:
        if not cfg.options["trace"]["enabled"]:
            # Stay up and report the disabled state instead of crash-looping in
            # Compose; enabling the block then needs only a restart.
            worker.state.update(state="disabled")
            while not stop.is_set():
                worker.publish()
                stop.wait(min(30, max(1, worker.trace["poll_seconds"] * 10)))
            return
        worker.serve()
    finally:
        repo.close()


def run_once(db_path, cfg, mode="full", drain=True):
    """`trace-once`: the same engine and persistence path as the live worker,
    used by fixtures and health checks. There is no test-only code path."""
    repo = Repository.open(db_path, cfg)
    worker = Worker(repo, cfg, mode=mode)
    try:
        if drain:
            # Dispatch is bounded per poll; keep polling until nothing new was
            # adopted and nothing due was left, as the live loop would.
            total = {"dispatched": {"examined": 0, "jobs_created": 0},
                     "script_backfill": {"examined": 0, "jobs_created": 0,
                                         "exporter_version": None},
                     "grouping_backfill": {"examined": 0, "jobs_created": 0, "normalizer_version": None},
                     "reclaimed": 0, "processed": []}
            while True:
                out = worker.tick()
                for key in ("examined", "jobs_created"):
                    total["dispatched"][key] += out["dispatched"][key]
                    total["script_backfill"][key] += out["script_backfill"][key]
                    total["grouping_backfill"][key] += out["grouping_backfill"][key]
                total["script_backfill"]["exporter_version"] = out["script_backfill"]["exporter_version"]
                total["grouping_backfill"]["normalizer_version"] = out["grouping_backfill"]["normalizer_version"]
                total["reclaimed"] += out["reclaimed"]
                total["processed"] += out["processed"]
                if (not out["dispatched"]["examined"] and not out["script_backfill"]["examined"]
                        and not out["grouping_backfill"]["examined"] and not out["processed"] and not out["more"]):
                    return total
        return worker.tick()
    finally:
        repo.close()
