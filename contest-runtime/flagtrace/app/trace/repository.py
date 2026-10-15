"""Every Phase 2 query and write, so the engine stays pure logic.

Reads are scoped (game, source, service) and bounded (per-query LIMIT plus a
per-job row budget) because a token lookup may legitimately reach back to the
start of the game. Writes are short transactions: claiming, committing a result
and enqueueing never stay open across the analysis itself, which is what keeps
one SQLite writer from blocking ingest.
"""
import json
import os
import secrets
import time
from contextlib import contextmanager

from .. import migrations
from ..store import dumps
from . import contracts
from .export import EXPORTER_VERSION
from .grouping import NORMALIZER_VERSION, backfill_trigger

# Structured locations are tried before free-text body matches: a value in a
# cookie/path/form field is a far better link than the same bytes seen inside
# an HTML page. Order is also the tie-break, so output stays stable.
CATEGORY_RANK = {"cookie": 0, "header": 1, "path": 2, "query": 3, "form": 4, "json": 5, "multipart": 6, "body": 9}
BODY_CATEGORY = "body"
TX_COLUMNS = ("id,game_id,conn_id,seq_in_conn,team_id,source_key,is_checker,service,tick,ts_request,"
              "ts_response,ts_end,src_ip,src_port,dst_ip,dst_port,proto,method,path,status,quality,"
              "flags_found,flag_out,classification,config_version")


class RowBudget:
    """Total rows a single job may read, not a per-query limit."""

    def __init__(self, limit):
        self.limit, self.used, self.exceeded = limit, 0, False

    def take(self, n):
        self.used += n
        if self.used > self.limit:
            self.exceeded = True
        return self.exceeded

    def left(self):
        return max(0, self.limit - self.used)


class Reader:
    def __init__(self, db, game_id, budget=None):
        self.db, self.game_id, self.budget = db, game_id, budget

    def _rows(self, sql, params, limit):
        if self.budget:
            limit = min(limit, self.budget.left())
            if limit <= 0:
                self.budget.exceeded = True
                return []
        rows = self.db.execute(sql + " LIMIT ?", (*params, limit)).fetchall()
        if self.budget:
            self.budget.take(len(rows))
        return rows

    @contextmanager
    def snapshot(self):
        """A deferred read transaction: every query in the block sees one
        consistent view, and it is released before any result is written."""
        self.db.execute("BEGIN DEFERRED")
        try:
            yield self
        finally:
            self.db.rollback()

    # ── transactions ────────────────────────────────────────────────────
    def transaction(self, transaction_id):
        return self.db.execute(f"SELECT {TX_COLUMNS} FROM transactions WHERE id=? AND game_id=?",
                               (transaction_id, self.game_id)).fetchone()

    def transactions_by_id(self, ids):
        out = {}
        ids = list(ids)
        for i in range(0, len(ids), 100):
            chunk = ids[i:i + 100]
            placeholders = ",".join("?" for _ in chunk)
            for row in self.db.execute(f"SELECT {TX_COLUMNS} FROM transactions WHERE game_id=? AND id IN ({placeholders})",
                                       (self.game_id, *chunk)):
                out[row["id"]] = row
            if self.budget:
                self.budget.take(len(chunk))
        return out

    def flag_sightings(self, transaction_id, limit=200):
        return self._rows("SELECT representation_id,value,side,start,end FROM flag_sightings WHERE transaction_id=?"
                          " ORDER BY side,start", (transaction_id,), limit)

    # ── tokens ──────────────────────────────────────────────────────────
    def consumed_tokens(self, transaction_id, limit):
        """Request-side values of one transaction, structured fields first."""
        rows = self._rows("SELECT rowid AS seq,id,transaction_id,representation_id,observed_ts,value,"
                          "normalized_value,role,location,parent_id,transform,span FROM tokens"
                          " WHERE transaction_id=? AND role='consumed' ORDER BY rowid", (transaction_id,), limit)
        return sorted(rows, key=lambda r: (CATEGORY_RANK.get(category(r["location"]), 8), r["seq"]))

    def produced_candidates(self, value, service, source_key, before_us, exclude_tx, limit):
        """Responses that carried this value, nearest before the use first."""
        return self._token_candidates(value, service, source_key, before_us, exclude_tx, limit, "produced", "DESC")

    def consumed_candidates(self, value, service, source_key, before_us, exclude_tx, limit):
        """Earliest request that used this value: the request-reuse fallback,
        which is how register → login is linked when nothing produced it."""
        return self._token_candidates(value, service, source_key, before_us, exclude_tx, limit, "consumed", "ASC")

    def _token_candidates(self, value, service, source_key, before_us, exclude_tx, limit, role, order):
        # The checker is excluded here, not filtered later: its traffic shares
        # flag IDs with every team and would otherwise link all of them.
        sql = ("SELECT t.id,t.transaction_id,t.representation_id,t.observed_ts,t.value,t.normalized_value,"
               "t.role,t.location,t.parent_id,t.transform,t.span,x.conn_id,x.seq_in_conn,x.ts_request,"
               "x.method,x.path,x.status,x.service,x.proto,x.quality FROM tokens t"
               " JOIN transactions x ON x.id=t.transaction_id"
               " WHERE t.game_id=? AND t.source_key=? AND t.normalized_value=? AND t.role=?"
               " AND t.observed_ts<=? AND t.transaction_id<>? AND x.is_checker=0")
        params = [self.game_id, source_key, value, role, before_us, exclude_tx]
        if service is not None:
            sql += " AND t.service=?"
            params.append(service)
        return self._rows(sql + f" ORDER BY t.observed_ts {order},t.id", params, limit)

    # ── value roles (P2.4) ──────────────────────────────────────────────
    # Bounded by their own limits, not the job's row budget: they run after the
    # search, over the steps it found, so a run the budget cut short still gets
    # the steps it did examine classified.
    def request_fields(self, transaction_id, body_limit):
        """Parsed request, plus the stored body when it has no structure."""
        row = self.db.execute("SELECT proto,req_parsed FROM transactions WHERE id=? AND game_id=?",
                              (transaction_id, self.game_id)).fetchone()
        if row is None:
            return {}, b""
        parsed = json.loads(row["req_parsed"]) if row["req_parsed"] else {}
        body = b""
        if row["proto"] != "http" or parsed.get("body_type", "raw") == "raw":
            rep = self.db.execute("SELECT substr(data,1,?) AS data FROM representations WHERE transaction_id=?"
                                  " AND side='req' AND kind='body' LIMIT 1", (body_limit, transaction_id)).fetchone()
            if rep and rep["data"] is not None:
                body = bytes(rep["data"]) if not isinstance(rep["data"], str) else rep["data"].encode("latin-1")
        return parsed, body

    def export_transaction(self, transaction_id):
        """Complete evidence needed by the pure P2.5 exporter.

        Unlike the UI evidence route this is not presentation-truncated.  The
        stored representation still says when Phase 1 itself truncated it, in
        which case the exporter refuses to claim byte-faithful support.
        """
        row = self.db.execute(f"SELECT {TX_COLUMNS},req_parsed,resp_parsed FROM transactions"
                              " WHERE id=? AND game_id=?", (transaction_id, self.game_id)).fetchone()
        if row is None:
            return None
        out = dict(row)
        out["req_parsed"] = json.loads(row["req_parsed"]) if row["req_parsed"] else {}
        out["resp_parsed"] = json.loads(row["resp_parsed"]) if row["resp_parsed"] else {}
        for side in ("req", "resp"):
            raw = self.db.execute("SELECT data,original_size,truncated FROM representations WHERE"
                                  " transaction_id=? AND side=? AND kind='raw' ORDER BY rowid LIMIT 1",
                                  (transaction_id, side)).fetchone()
            body = self.db.execute("SELECT data,original_size,truncated FROM representations WHERE"
                                   " transaction_id=? AND side=? AND kind='body' ORDER BY rowid LIMIT 1",
                                   (transaction_id, side)).fetchone()
            out[side + "_raw"] = bytes(raw["data"]) if raw and raw["data"] is not None else None
            out[side + "_raw_truncated"] = bool(raw and raw["truncated"])
            out[side + "_body"] = bytes(body["data"]) if body and body["data"] is not None else None
            out[side + "_body_truncated"] = bool(body and body["truncated"])
        out["token_values"] = {r["id"]: r["normalized_value"] for r in self.db.execute(
            "SELECT id,normalized_value FROM tokens WHERE transaction_id=?", (transaction_id,))}
        return out

    def flag_ids_matching(self, service, owner, values, limit):
        """Flag-ID records whose value is one of `values`, newest tick first.
        `owner` None means every team's flag IDs are considered."""
        out, values = [], sorted(set(values))
        for i in range(0, len(values), 500):
            chunk = values[i:i + 500]
            sql = (f"SELECT f.tick,f.owner_team_id,f.value,f.source,f.location,f.transaction_id,t.conn_id"
                   f" FROM flag_ids f LEFT JOIN transactions t ON t.id=f.transaction_id"
                   f" WHERE f.game_id=? AND f.service=? AND f.value IN ({','.join('?' for _ in chunk)})")
            params = [self.game_id, service, *chunk]
            if owner is not None:
                sql += " AND f.owner_team_id=?"
                params.append(owner)
            out += self.db.execute(sql + " ORDER BY f.tick DESC,f.value LIMIT ?", (*params, limit - len(out))).fetchall()
            if len(out) >= limit:
                break
        return out

    def flag_id_counts(self, service, owner):
        """How many flag-ID records exist in the game, and in this scope by source."""
        game = self.db.execute("SELECT count(*) FROM flag_ids WHERE game_id=?", (self.game_id,)).fetchone()[0]
        sql, params = "SELECT source,count(*) FROM flag_ids WHERE game_id=? AND service=?", [self.game_id, service]
        if owner is not None:
            sql += " AND owner_team_id=?"
            params.append(owner)
        return game, dict(self.db.execute(sql + " GROUP BY source", params).fetchall())

    def flag_puts(self, flags, limit=50):
        """Checker transactions that stored these flags: when, and in which session."""
        flags = sorted(set(flags))
        if not flags:
            return []
        return self.db.execute(f"""SELECT DISTINCT f.flag,f.tick,t.id AS transaction_id,t.conn_id FROM flags_in f
            JOIN transactions t ON t.id=f.transaction_id WHERE f.game_id=? AND t.is_checker=1
            AND f.flag IN ({','.join('?' for _ in flags)}) ORDER BY f.tick,t.id LIMIT ?""",
                               (self.game_id, *flags, limit)).fetchall()

    def ingest_gaps(self):
        """Captures this game could not fully ingest. A trace built on top of a
        gap may be missing steps, so the result records what was known."""
        files = dict(self.db.execute("SELECT status,count(*) FROM pcap_files WHERE game_id=? AND status IN"
                                     " ('error','late') GROUP BY status", (self.game_id,)).fetchall())
        rejected = self.db.execute("SELECT count(*) FROM pcap_rejects WHERE game_id=?",
                                   (self.game_id,)).fetchone()[0]
        checkpoint = self.db.execute("SELECT last_ts FROM ingest_checkpoints WHERE game_id=?",
                                     (self.game_id,)).fetchone()
        return {"error_files": files.get("error", 0), "late_files": files.get("late", 0),
                "rejected_files": rejected,
                # Recorded for reference only: it is how far packet time has
                # been read, not a promise every transaction before it exists.
                "checkpoint_packet_ts": checkpoint[0] if checkpoint else None}

    def document_frequency(self, service, value):
        row = self.db.execute("SELECT n FROM token_df WHERE game_id=? AND service=? AND value=?",
                              (self.game_id, service, value)).fetchone()
        return row["n"] if row else 0

    def service_samples(self, service):
        row = self.db.execute("SELECT n FROM service_stats WHERE game_id=? AND service=?",
                              (self.game_id, service)).fetchone()
        return row["n"] if row else 0

    # ── profiles, jobs and runs (API reads) ─────────────────────────────
    # Runs committed by engines before p2.3.2 may hold 'context' steps (traffic
    # that was only near the flag-out). They are not part of the flow, so every
    # read below leaves them out of steps and counts.
    def list_profiles(self, filters, limit, cursor=None):
        """Newest anchor first. The cursor is the (ts_request, trace_id) of the
        last row already shown, so pages stay stable while new profiles land."""
        where, params = ["p.game_id=?"], [self.game_id]
        for name, column in (("source_key", "t.source_key"), ("service", "t.service"), ("team_id", "t.team_id"),
                             ("tick", "t.tick"), ("src_ip", "t.src_ip")):
            if filters.get(name) not in (None, ""):
                where.append(f"{column}=?")
                params.append(filters[name])
        if filters.get("state"):
            # Either what the newest request is doing or what the shown result is.
            where.append("(j.status=? OR r.state=?)")
            params += [filters["state"], filters["state"]]
        joins = """FROM trace_profiles p
                JOIN transactions t ON t.id=p.anchor_transaction_id
                LEFT JOIN trace_runs r ON r.id=p.latest_run_id
                LEFT JOIN trace_jobs j ON j.trace_id=p.id AND j.request_sequence=p.last_requested_sequence"""
        total = self.db.execute(f"SELECT count(*) {joins} WHERE {' AND '.join(where)}", params).fetchone()[0]
        if cursor:
            where.append("(t.ts_request<? OR (t.ts_request=? AND p.id<?))")
            params += [cursor[0], cursor[0], cursor[1]]
        rows = self.db.execute(
            f"""SELECT p.id AS trace_id,p.anchor_transaction_id,p.created,p.last_requested_sequence,
                       p.latest_run_id,p.latest_run_sequence,
                       t.source_key,t.team_id,t.service,t.tick,t.ts_request,t.src_ip,t.method,t.path,t.status,
                       t.proto,t.flags_found,t.quality,t.classification,
                       r.state AS run_state,r.created AS run_created,r.engine_version,r.warnings AS run_warnings,
                       (SELECT count(*) FROM trace_steps s WHERE s.run_id=r.id AND s.role<>'context') AS step_count,
                       (SELECT count(*) FROM trace_steps s WHERE s.run_id=r.id AND s.role='data_linked') AS linked_count,
                       (SELECT count(*) FROM trace_edges e WHERE e.run_id=r.id) AS edge_count,
                       j.status AS job_status,j.error AS job_error,j.attempts AS job_attempts,
                       j.request_sequence AS job_sequence
                {joins} WHERE {' AND '.join(where)}
                ORDER BY t.ts_request DESC,p.id DESC LIMIT ?""", (*params, limit)).fetchall()
        return rows, total

    def profile(self, trace_id):
        return self.db.execute(
            """SELECT p.*,t.source_key,t.team_id,t.service,t.tick,t.ts_request,t.ts_response,t.method,t.path,
                      t.status,t.proto,t.conn_id,t.seq_in_conn,t.flags_found,t.quality,t.classification
               FROM trace_profiles p JOIN transactions t ON t.id=p.anchor_transaction_id
               WHERE p.id=? AND p.game_id=?""", (trace_id, self.game_id)).fetchone()

    def jobs_for(self, trace_id, limit=50):
        return self.db.execute("""SELECT id,request_sequence,trigger_key,status,attempts,error,engine_version,
                   algorithm_hash,created,updated,available_at,lease_until FROM trace_jobs
                   WHERE trace_id=? AND game_id=? ORDER BY request_sequence DESC LIMIT ?""",
                               (trace_id, self.game_id, limit)).fetchall()

    def runs_for(self, trace_id, limit, offset):
        rows = self.db.execute("""SELECT r.id,r.job_id,r.request_sequence,r.state,r.engine_version,r.algorithm_hash,
                   r.snapshot_wall,r.created,r.metrics,j.status AS job_status,j.trigger_key,
                   (SELECT count(*) FROM trace_steps s WHERE s.run_id=r.id AND s.role<>'context') AS step_count,
                   (SELECT count(*) FROM trace_edges e WHERE e.run_id=r.id) AS edge_count
                   FROM trace_runs r JOIN trace_jobs j ON j.id=r.job_id
                   WHERE r.trace_id=? AND r.game_id=? ORDER BY r.request_sequence DESC LIMIT ? OFFSET ?""",
                               (trace_id, self.game_id, limit, offset)).fetchall()
        total = self.db.execute("SELECT count(*) FROM trace_runs WHERE trace_id=? AND game_id=?",
                                (trace_id, self.game_id)).fetchone()[0]
        return rows, total

    def run(self, trace_id, run_id):
        return self.db.execute("""SELECT r.*,j.trigger_key,j.status AS job_status,j.attempts,j.error AS job_error
               FROM trace_runs r JOIN trace_jobs j ON j.id=r.job_id
               WHERE r.id=? AND r.trace_id=? AND r.game_id=?""", (run_id, trace_id, self.game_id)).fetchone()

    def steps(self, run_id, limit=500):
        # The network tuple is read from the transaction, not from the stored
        # summary, so results committed before it was served still carry it.
        return self.db.execute("""SELECT s.*,t.src_ip,t.src_port,t.dst_ip,t.dst_port,t.ts_request AS tx_ts_request
                               FROM trace_steps s LEFT JOIN transactions t ON t.id=s.transaction_id
                               WHERE s.run_id=? AND s.role<>'context' ORDER BY s.position LIMIT ?""",
                               (run_id, limit)).fetchall()

    def edges(self, run_id, limit=1000):
        return self.db.execute("SELECT * FROM trace_edges WHERE run_id=? ORDER BY rowid LIMIT ?",
                               (run_id, limit)).fetchall()

    def values(self, run_id, limit=1000):
        return self.db.execute("SELECT * FROM trace_values WHERE run_id=? ORDER BY rowid LIMIT ?",
                               (run_id, limit)).fetchall()

    def script_artifacts(self, run_id):
        return self.db.execute("""SELECT id,run_id,kind,transaction_id,position,format,filename,
                   exporter_version,content_hash,support,warnings,length(content) AS size,created
                   FROM trace_script_artifacts WHERE run_id=? ORDER BY
                   CASE kind WHEN 'request' THEN 0 ELSE 1 END,position,id""", (run_id,)).fetchall()

    def script_artifact(self, trace_id, run_id, artifact_id):
        return self.db.execute("""SELECT a.* FROM trace_script_artifacts a
                   JOIN trace_runs r ON r.id=a.run_id
                   WHERE a.id=? AND a.run_id=? AND r.trace_id=? AND r.game_id=?""",
                               (artifact_id, run_id, trace_id, self.game_id)).fetchone()

    def replay_verifications(self, artifact_ids):
        if not artifact_ids:
            return {}
        marks = ",".join("?" for _ in artifact_ids)
        rows = self.db.execute(f"""SELECT v.* FROM trace_replay_verifications v
                    JOIN (SELECT artifact_id,max(finished) AS finished FROM trace_replay_verifications
                          WHERE artifact_id IN ({marks}) GROUP BY artifact_id) latest
                    ON latest.artifact_id=v.artifact_id AND latest.finished=v.finished""", tuple(artifact_ids)).fetchall()
        return {r["artifact_id"]: r for r in rows}

    def artifact_for_verification(self, artifact_id):
        return self.db.execute("""SELECT a.* FROM trace_script_artifacts a JOIN trace_runs r ON r.id=a.run_id
                   WHERE a.id=? AND r.game_id=?""", (artifact_id, self.game_id)).fetchone()

    def worker_status(self):
        return self.db.execute("SELECT worker_id,data,updated FROM trace_runtime_status WHERE game_id=?"
                               " ORDER BY updated DESC LIMIT 10", (self.game_id,)).fetchall()

    def queue_backlog(self):
        jobs = dict(self.db.execute("SELECT status,count(*) FROM trace_jobs WHERE game_id=? GROUP BY status",
                                    (self.game_id,)))
        pending_dispatch = self.db.execute("SELECT count(*) FROM trace_queue WHERE game_id=? AND status='pending'",
                                           (self.game_id,)).fetchone()[0]
        oldest = self.db.execute("SELECT min(created) FROM trace_jobs WHERE game_id=? AND status='pending'",
                                 (self.game_id,)).fetchone()[0]
        return {"pending_dispatch": pending_dispatch,
                "jobs": {k: jobs.get(k, 0) for k in contracts.JOB_STATUSES},
                "oldest_pending_age": (time.time() - oldest) if oldest else None,
                "profiles": self.db.execute("SELECT count(*) FROM trace_profiles WHERE game_id=?",
                                            (self.game_id,)).fetchone()[0]}


class Repository(Reader):
    """Writer-side operations. One instance owns one connection."""

    def __init__(self, db, cfg, worker_id=None):
        super().__init__(db, cfg.game_id)
        self.cfg = cfg
        self.trace_cfg = cfg.options["trace"]
        self.worker_id = worker_id or f"{os.uname().nodename}:{os.getpid()}"
        self.db.isolation_level = None  # every transaction is explicit here

    @classmethod
    def open(cls, path, cfg, worker_id=None, timeout=10):
        return cls(migrations.open_initialized(path, timeout=timeout), cfg, worker_id)

    @contextmanager
    def write(self):
        """BEGIN IMMEDIATE so two writers conflict at the start of the
        transaction, not half-way through it."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self.db
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def close(self):
        self.db.close()

    # ── dispatch ────────────────────────────────────────────────────────
    def dispatch_pending(self, limit=50):
        """Turn Phase 1 flag-out queue rows into profiles plus an initial job.

        The trigger key is derived from the anchor, so re-ingesting the same
        PCAP (which cannot create a second queue row anyway) and a replayed
        dispatch both land on the same job. The queue row flips to dispatched
        in the same commit, so a crash here repeats the work, not doubles it.
        """
        rows = self.db.execute("""SELECT q.transaction_id FROM trace_queue q
            WHERE q.game_id=? AND q.status='pending' ORDER BY q.created LIMIT ?""",
                               (self.game_id, limit)).fetchall()
        created = 0
        for row in rows:
            anchor = row["transaction_id"]
            trace = contracts.trace_id(self.game_id, anchor)
            with self.write() as db:
                now = time.time()
                db.execute("""INSERT OR IGNORE INTO trace_profiles(id,game_id,anchor_transaction_id,created,
                              last_requested_sequence) VALUES(?,?,?,?,0)""", (trace, self.game_id, anchor, now))
                if self._insert_job(db, trace, "ingest:" + anchor, now):
                    created += 1
                db.execute("UPDATE trace_queue SET status='dispatched' WHERE transaction_id=? AND game_id=?",
                           (anchor, self.game_id))
        return {"examined": len(rows), "jobs_created": created}

    def enqueue_missing_scripts(self, limit=50):
        """Backfill linked profiles whose latest immutable run predates P2.5.

        A new analysis is requested instead of adding artifacts to the old run:
        runs are immutable snapshots, and the exporter must see the same trace
        and value-role result it is recording.  The versioned trigger makes the
        operation idempotent across worker polls and restarts.
        """
        trigger = "auto:scripts:" + EXPORTER_VERSION
        # Read first: an idle poll must not take SQLite's single write lock.
        rows = self.db.execute("""SELECT p.id FROM trace_profiles p
            JOIN trace_runs r ON r.id=p.latest_run_id
            WHERE p.game_id=? AND r.state=?
              AND NOT EXISTS (SELECT 1 FROM trace_script_artifacts a
                              WHERE a.run_id=r.id AND a.kind='chain' AND a.exporter_version=?)
              AND NOT EXISTS (SELECT 1 FROM trace_jobs done
                              WHERE done.trace_id=p.id AND done.trigger_key=?)
              AND NOT EXISTS (SELECT 1 FROM trace_jobs active
                              WHERE active.trace_id=p.id AND active.status IN (?,?))
            ORDER BY r.created,p.id LIMIT ?""",
            (self.game_id, contracts.RUN_LINKED, EXPORTER_VERSION, trigger,
             contracts.JOB_PENDING, contracts.JOB_RUNNING, limit)).fetchall()
        now, created = time.time(), 0
        for row in rows:
            with self.write() as db:
                if self._insert_job(db, row["id"], trigger, now):
                    created += 1
        return {"examined": len(rows), "jobs_created": created,
                "exporter_version": EXPORTER_VERSION}

    def enqueue_missing_grouping(self, limit=50):
        """Re-analyse profiles whose latest run has no chain group: runs from
        before P2.4b, or grouped under an older normalizer. Same rules as the
        script backfill: a new immutable run, one versioned trigger per
        profile, and never beside a request that is already waiting."""
        trigger = backfill_trigger()
        rows = self.db.execute("""SELECT p.id FROM trace_profiles p
            JOIN trace_runs r ON r.id=p.latest_run_id
            LEFT JOIN trace_groups g ON g.id=r.group_id
            WHERE p.game_id=? AND r.state<>? AND (r.group_id IS NULL OR g.normalizer_version<>?)
              AND NOT EXISTS (SELECT 1 FROM trace_jobs done
                              WHERE done.trace_id=p.id AND done.trigger_key=?)
              AND NOT EXISTS (SELECT 1 FROM trace_jobs active
                              WHERE active.trace_id=p.id AND active.status IN (?,?))
            ORDER BY r.created,p.id LIMIT ?""",
            (self.game_id, contracts.RUN_SEED_ONLY, NORMALIZER_VERSION, trigger,
             contracts.JOB_PENDING, contracts.JOB_RUNNING, limit)).fetchall()
        now, created = time.time(), 0
        for row in rows:
            with self.write() as db:
                if self._insert_job(db, row["id"], trigger, now):
                    created += 1
        return {"examined": len(rows), "jobs_created": created, "normalizer_version": NORMALIZER_VERSION}

    def _insert_job(self, db, trace, trigger_key, now):
        """Allocate the next request sequence from the profile counter inside
        the caller's transaction. The counter never reuses a number, so a job
        finishing late can be told from a newer one."""
        existing = db.execute("SELECT id FROM trace_jobs WHERE trace_id=? AND trigger_key=?",
                              (trace, trigger_key)).fetchone()
        if existing:
            return None
        sequence = db.execute("SELECT last_requested_sequence FROM trace_profiles WHERE id=?",
                              (trace,)).fetchone()[0] + 1
        job = contracts.job_id(trace, trigger_key)
        db.execute("""INSERT INTO trace_jobs(id,trace_id,game_id,request_sequence,trigger_key,engine_version,
                      algorithm_hash,algorithm_config,status,available_at,attempts,created,updated)
                      VALUES(?,?,?,?,?,?,?,?,?,?,0,?,?)""",
                   (job, trace, self.game_id, sequence, trigger_key, contracts.ENGINE_VERSION,
                    self.cfg.algorithm_hash(), dumps(self.cfg.algorithm_config()), contracts.JOB_PENDING,
                    now, now, now))
        db.execute("UPDATE trace_profiles SET last_requested_sequence=? WHERE id=?", (sequence, trace))
        return job

    def enqueue_retrace(self, trace_id, idempotency_key):
        """Manual re-analysis. Resending the same key returns the same job;
        a new key creates a new sequence and keeps the previous result."""
        trigger = "retrace:" + str(idempotency_key)
        with self.write() as db:
            profile = db.execute("SELECT id FROM trace_profiles WHERE id=? AND game_id=?",
                                 (trace_id, self.game_id)).fetchone()
            if not profile:
                return None
            existing = db.execute("SELECT id,request_sequence,status FROM trace_jobs WHERE trace_id=? AND trigger_key=?",
                                  (trace_id, trigger)).fetchone()
            if existing:
                return {"job_id": existing["id"], "request_sequence": existing["request_sequence"],
                        "status": existing["status"], "created": False}
            job = self._insert_job(db, trace_id, trigger, time.time())
            sequence = db.execute("SELECT last_requested_sequence FROM trace_profiles WHERE id=?",
                                  (trace_id,)).fetchone()[0]
        return {"job_id": job, "request_sequence": sequence, "status": contracts.JOB_PENDING, "created": True}

    # ── lease lifecycle ─────────────────────────────────────────────────
    def reclaim_expired(self, limit=50):
        with self.write() as db:
            rows = db.execute("""SELECT id FROM trace_jobs WHERE game_id=? AND status=? AND lease_until<?
                                 LIMIT ?""", (self.game_id, contracts.JOB_RUNNING, time.time(), limit)).fetchall()
            for row in rows:
                # The lease token is dropped, which is what stops the previous
                # holder from committing after a new worker takes the job.
                db.execute("""UPDATE trace_jobs SET status=?,lease_owner=NULL,lease_token=NULL,lease_until=NULL,
                              available_at=?,updated=? WHERE id=?""",
                           (contracts.JOB_PENDING, time.time(), time.time(), row["id"]))
        return len(rows)

    def claim(self):
        """Take one due job. Returns a dict with the fencing token, or None."""
        max_attempts = self.trace_cfg["max_attempts"]
        while True:
            with self.write() as db:
                now = time.time()
                row = db.execute("""SELECT * FROM trace_jobs WHERE game_id=? AND status=? AND available_at<=?
                                    ORDER BY available_at,created LIMIT 1""",
                                 (self.game_id, contracts.JOB_PENDING, now)).fetchone()
                if not row:
                    return None
                if row["attempts"] >= max_attempts:
                    db.execute("UPDATE trace_jobs SET status=?,error=?,updated=? WHERE id=?",
                               (contracts.JOB_FAILED, (row["error"] or "") + " | max_attempts exceeded", now, row["id"]))
                    continue
                token = secrets.token_hex(8)
                db.execute("""UPDATE trace_jobs SET status=?,attempts=attempts+1,lease_owner=?,lease_token=?,
                              lease_until=?,updated=? WHERE id=?""",
                           (contracts.JOB_RUNNING, self.worker_id, token, now + self.trace_cfg["lease_seconds"],
                            now, row["id"]))
                job = dict(row)
                job.update(status=contracts.JOB_RUNNING, attempts=row["attempts"] + 1, lease_token=token,
                           lease_until=now + self.trace_cfg["lease_seconds"])
                return job

    def extend_lease(self, job):
        with self.write() as db:
            now = time.time()
            changed = db.execute("""UPDATE trace_jobs SET lease_until=?,updated=? WHERE id=? AND lease_token=?
                                    AND status=?""",
                                 (now + self.trace_cfg["lease_seconds"], now, job["id"], job["lease_token"],
                                  contracts.JOB_RUNNING)).rowcount
        return changed == 1

    def release(self, job, error=None, retry=True):
        """Give a job back. Keeps attempts, so a crash loop still terminates.
        Returns 'lost' when another worker already holds the job: then nothing
        is changed, and the failure is not this worker's to report."""
        with self.write() as db:
            now = time.time()
            attempts = db.execute("SELECT attempts FROM trace_jobs WHERE id=?", (job["id"],)).fetchone()["attempts"]
            final = not retry or attempts >= self.trace_cfg["max_attempts"]
            backoff = min(60.0, 2.0 ** min(attempts, 6))
            changed = db.execute("""UPDATE trace_jobs SET status=?,error=?,available_at=?,lease_owner=NULL,
                          lease_token=NULL,lease_until=NULL,updated=? WHERE id=? AND lease_token=? AND status=?""",
                       (contracts.JOB_FAILED if final else contracts.JOB_PENDING, error,
                        now if final else now + backoff, now, job["id"], job["lease_token"],
                        contracts.JOB_RUNNING)).rowcount
        if not changed:
            return "lost"
        return "failed" if final else "pending"

    # ── result persistence ──────────────────────────────────────────────
    def commit_result(self, job, result):
        """Run, steps, edges and the job's completion in one transaction.

        Refused unless the lease token still matches: a worker that lost its
        lease must not overwrite the work of the one that took over. The latest
        pointer only moves forward by request sequence, so a slow old job
        cannot replace a newer result.
        """
        run = contracts.run_id(job["id"])
        dto = result.dto()
        with self.write() as db:
            current = db.execute("SELECT status,lease_token,request_sequence FROM trace_jobs WHERE id=?",
                                 (job["id"],)).fetchone()
            if not current or current["lease_token"] != job["lease_token"] or current["status"] != contracts.JOB_RUNNING:
                return {"committed": False, "reason": "lease lost"}
            if db.execute("SELECT 1 FROM trace_runs WHERE id=?", (run,)).fetchone():
                # A crash between commit and acknowledgement replays this call;
                # the run already exists, so only the job status is finished.
                db.execute("UPDATE trace_jobs SET status=?,error=NULL,lease_token=NULL,lease_owner=NULL,"
                           "lease_until=NULL,updated=? WHERE id=?", (contracts.JOB_DONE, time.time(), job["id"]))
                return {"committed": True, "run_id": run, "duplicate": True}
            now = time.time()
            db.execute("""INSERT INTO trace_runs(id,job_id,trace_id,game_id,request_sequence,engine_version,
                          algorithm_hash,state,anchor,coverage,warnings,metrics,analysis,snapshot_wall,created)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (run, job["id"], job["trace_id"], self.game_id, job["request_sequence"],
                        contracts.ENGINE_VERSION, job["algorithm_hash"], dto["state"], dumps(dto["anchor"]),
                        dumps(dto["coverage"]), dumps(dto["warnings"]), dumps(dto["metrics"]),
                        dumps(dto["analysis"]), dto["coverage"].get("snapshot_wall") or now, now))
            for step in dto["steps"]:
                db.execute("""INSERT INTO trace_steps(run_id,transaction_id,position,role,reasons,quality,summary)
                              VALUES(?,?,?,?,?,?,?)""",
                           (run, step["transaction_id"], step["position"], step["role"], dumps(step["reasons"]),
                            dumps(step["quality"]), dumps(step["summary"])))
            for edge in dto["edges"]:
                db.execute("""INSERT OR IGNORE INTO trace_edges(run_id,evidence_key,kind,dst_transaction_id,
                              dst_token_id,dst_location,dst_representation_id,dst_observed_ts,src_transaction_id,
                              src_token_id,src_location,src_representation_id,src_observed_ts,value_preview,
                              value_length,transform,ambiguous,alternatives,note)
                              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                           (run, contracts.evidence_key(edge["kind"], edge["dst_token_id"], edge["dst_location"],
                                                        edge["src_token_id"]),
                            edge["kind"], edge["dst_transaction_id"], edge["dst_token_id"], dumps(edge["dst_location"]),
                            edge["dst_representation_id"], edge["dst_observed_ts"], edge["src_transaction_id"],
                            edge["src_token_id"], dumps(edge["src_location"]), edge["src_representation_id"],
                            edge["src_observed_ts"], edge["value_preview"], edge["value_length"],
                            dumps(edge["transform"]), int(edge["ambiguous"]), dumps(edge["alternatives"]),
                            edge["note"]))
            roles = dto["value_roles"]
            for value in roles.get("values", []) if roles.get("state") != contracts.NOT_COMPUTED["state"] else []:
                db.execute("""INSERT OR IGNORE INTO trace_values(run_id,value_key,transaction_id,token_id,location,
                              role,var,value_preview,value_length,template,parts,transform,unresolved,session_cookie,
                              ambiguous,evidence) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                           (run, value["value_key"], value["transaction_id"], value["token_id"],
                            dumps(value["location"]), value["role"], value["var"], value["value_preview"],
                            value["value_length"], value["template"], dumps(value["parts"]),
                            dumps(value["transform"]), value["unresolved"], int(value["session_cookie"]),
                            int(value["ambiguous"]), dumps(value["evidence"])))
            scripts = dto["scripts"]
            if scripts.get("state") != contracts.NOT_COMPUTED["state"]:
                for artifact in scripts.get("artifacts", []):
                    aid = contracts.artifact_id(run, artifact["kind"], artifact.get("transaction_id"),
                                                artifact["exporter_version"], artifact["content_hash"])
                    db.execute("""INSERT INTO trace_script_artifacts(id,run_id,kind,transaction_id,position,
                                  format,filename,exporter_version,content_hash,support,warnings,content,created)
                                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                               (aid, run, artifact["kind"], artifact.get("transaction_id"),
                                artifact.get("position"), artifact["format"], artifact["filename"],
                                artifact["exporter_version"], artifact["content_hash"], artifact["support"],
                                dumps(artifact.get("warnings", [])), artifact["content"], now))
            grouped = dto["grouping"]
            if grouped.get("state") == "computed":
                db.execute("""INSERT OR IGNORE INTO trace_groups(id,game_id,service,normalizer_version,description,
                              signature,created) VALUES(?,?,?,?,?,?,?)""",
                           (grouped["group_id"], self.game_id, grouped["service"], grouped["normalizer_version"],
                            grouped["description"], dumps(grouped["shape"]), now))
                db.execute("UPDATE trace_runs SET group_id=? WHERE id=?", (grouped["group_id"], run))
            for step in dto["suspects"].get("steps", []):
                db.execute("""INSERT OR IGNORE INTO trace_suspects(run_id,transaction_id,position,strength,findings)
                              VALUES(?,?,?,?,?)""", (run, step["transaction_id"], step["position"],
                                                     step["strength"], dumps(step["findings"])))
            db.execute("""UPDATE trace_jobs SET status=?,error=NULL,lease_owner=NULL,lease_token=NULL,
                          lease_until=NULL,updated=? WHERE id=?""", (contracts.JOB_DONE, now, job["id"]))
            db.execute("""UPDATE trace_profiles SET latest_run_id=?,latest_run_sequence=? WHERE id=?
                          AND (latest_run_sequence IS NULL OR latest_run_sequence<=?)""",
                       (run, job["request_sequence"], job["trace_id"], job["request_sequence"]))
        return {"committed": True, "run_id": run, "duplicate": False}

    def publish_worker_status(self, data):
        with self.write() as db:
            db.execute("INSERT OR REPLACE INTO trace_runtime_status VALUES(?,?,?,?)",
                       (self.worker_id, self.game_id, dumps(data), time.time()))

    def record_verification(self, artifact, fixture, target, status, flags, output, error, started, finished):
        vid = contracts.verification_id(artifact["id"], artifact["content_hash"], fixture, started)
        with self.write() as db:
            # Bind the attestation to the content hash read before execution.
            current = db.execute("SELECT content_hash FROM trace_script_artifacts WHERE id=?",
                                 (artifact["id"],)).fetchone()
            if current is None or current["content_hash"] != artifact["content_hash"]:
                raise ValueError("artifact changed before verification could be recorded")
            db.execute("""INSERT INTO trace_replay_verifications(id,artifact_id,artifact_hash,fixture,target,
                          status,flags,output,error,started,finished) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                       (vid, artifact["id"], artifact["content_hash"], fixture, target, status,
                        dumps(flags), output[:4096], error, started, finished))
        return vid


def category(location):
    """Second element of a typed location path: cookie/header/path/.../body."""
    if isinstance(location, str):
        try:
            location = json.loads(location)
        except ValueError:
            return BODY_CATEGORY
    return location[1] if isinstance(location, list) and len(location) > 1 else BODY_CATEGORY


def location_of(row):
    value = row["location"]
    return json.loads(value) if isinstance(value, str) else value
