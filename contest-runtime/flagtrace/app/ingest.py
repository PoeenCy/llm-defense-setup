"""Ordered PCAP commands to a long-lived Go helper, with replay on restart."""
import base64
import hashlib
import json
import os
import select
import shutil
import struct
import subprocess
import time
from pathlib import Path

from . import settings
from .analysis import Decoder, enrich, transaction_id, uid
from .ledger import ledger_lock


def pcap_metadata(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as f:
        prefix = f.read(40)
        digest.update(prefix)
        for data in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(data)
    if len(prefix) < 24:
        raise ValueError("short PCAP header")
    magic = prefix[:4]
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
    if not endian:
        raise ValueError("unsupported capture format; classic PCAP required")
    ts = 0
    if len(prefix) >= 40:
        sec, fraction = struct.unpack(endian + "II", prefix[24:32])
        ts = sec * 1_000_000 + (fraction // 1000 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else fraction)
    return digest.hexdigest(), ts


class FileIngestError(Exception):
    """The helper rejected one capture but is still healthy. The file is marked
    and the remaining captures keep going; any other failure means the helper
    itself is suspect and the cycle is aborted so the next one replays."""


class Transport:
    def __init__(self, cfg):
        binary = os.environ.get("FLAGTRACE_TRANSPORT", "flagtrace-transport")
        self.proc = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        self.buffer = b""
        self.limit = cfg.options["max_connection_bytes"] * 10 + 1024 * 1024
        self.send(cfg.transport())

    def send(self, command):
        self.proc.stdin.write(json.dumps(command).encode() + b"\n")
        self.proc.stdin.flush()

    def command(self, command):
        self.send(command)
        deadline = time.monotonic() + 300
        while True:
            while b"\n" not in self.buffer:
                if time.monotonic() > deadline:
                    raise TimeoutError("transport made no progress for 300 seconds")
                if not select.select([self.proc.stdout], [], [], 1)[0]:
                    continue
                data = os.read(self.proc.stdout.fileno(), 65536)
                if not data:
                    raise RuntimeError(f"transport exited ({self.proc.poll()})")
                self.buffer += data
                if len(self.buffer) > self.limit:
                    raise ValueError("transport record exceeds configured limit")
            line, self.buffer = self.buffer.split(b"\n", 1)
            record = json.loads(line)
            if record.get("schema_version") != 1:
                raise ValueError("unsupported transport schema")
            yield record
            deadline = time.monotonic() + 300
            if record["type"] == "checkpoint":
                return

    def close(self):
        if self.proc.poll() is None:
            self.proc.stdin.close()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc.stdout.close()


class Ingestor:
    def __init__(self, store, traffic):
        self.store, self.cfg, self.traffic = store, store.cfg, Path(traffic)
        self.helper = None
        self.session_done = set()
        self.counters = {}
        self.metadata_cache = {}
        # One decoder for the life of the process, so its result cache spans
        # files; its mode is set from the database before each file.
        self.decoder = Decoder(self.cfg)
        self.duplicates_skipped = 0

    def metadata(self, path):
        st = path.stat()
        key = (str(path), st.st_size, st.st_mtime_ns)
        if key not in self.metadata_cache:
            self.metadata_cache[key] = pcap_metadata(path)
        return self.metadata_cache[key]

    def discover(self, paths):
        """Register readable captures; quarantine the unreadable ones.

        A file that cannot be parsed at all (truncated header, foreign format,
        unreadable) is recorded in pcap_rejects by name *and* identity, so the
        files around it are still ingested, the same broken file is not reopened
        on every poll, and a repaired or replaced file is picked up again.
        """
        db, cfg = self.store.db, self.cfg
        found = []
        errors = []
        known = {(r["path"], r["size"], r["mtime_ns"]) for r in
                 db.execute("SELECT path,size,mtime_ns FROM pcap_rejects WHERE game_id=?", (cfg.game_id,))}
        for path in paths:
            path = Path(path)
            try:
                st = path.stat()
                identity = (path.name, st.st_size, st.st_mtime_ns)
            except OSError as exc:
                errors.append(f"{path.name}: {exc}")
                continue
            if identity in known:
                errors.append(f"{path.name}: skipped, already rejected")
                continue
            try:
                sha, ts = self.metadata(path)
                found.append((ts, path.name, sha))
            except (OSError, ValueError) as exc:
                errors.append(f"{path.name}: {exc}")
                now = time.time()
                with db:
                    db.execute("""INSERT INTO pcap_rejects(game_id,path,size,mtime_ns,error,first_seen,last_seen)
                        VALUES(?,?,?,?,?,?,?) ON CONFLICT(game_id,path,size,mtime_ns)
                        DO UPDATE SET last_seen=excluded.last_seen,error=excluded.error""",
                               (cfg.game_id, identity[0], identity[1], identity[2], str(exc), now, now))
        with db:
            ordinal = db.execute("SELECT coalesce(max(ordinal),0) FROM pcap_files WHERE game_id=?", (cfg.game_id,)).fetchone()[0]
            last = db.execute("SELECT last_ts FROM ingest_checkpoints WHERE game_id=?", (cfg.game_id,)).fetchone()
            for ts, name, sha in sorted(found):
                fid = uid(cfg.game_id, cfg.options["capture_source"], sha)
                previous = db.execute("SELECT file_id FROM pcap_paths WHERE path=?", (name,)).fetchone()
                if previous and previous[0] != fid:
                    raise ValueError(f"capture filename reused with different content or game: {name}")
                if not db.execute("SELECT 1 FROM pcap_files WHERE id=?", (fid,)).fetchone():
                    ordinal += 1
                    status = "late" if ts and last and ts < last[0] else "queued"
                    db.execute("INSERT INTO pcap_files(id,game_id,ordinal,hash,first_ts,status,received_at) VALUES(?,?,?,?,?,?,?)", (fid, cfg.game_id, ordinal, sha, ts, status, time.time()))
                db.execute("INSERT OR IGNORE INTO pcap_paths VALUES(?,?)", (name, fid))
        return errors

    def _start(self):
        if self.helper is None:
            self.helper = Transport(self.cfg)
            self.session_done.clear()

    def _records(self, command, fid=None, ordinal=None):
        db, cfg = self.store.db, self.cfg
        error = None
        for record in self.helper.command(command):
            kind = record["type"]
            if kind == "transaction":
                # A replay after a restart re-reads the pinned tail: whatever
                # was already stored is dropped before parsing and decoding,
                # which is where nearly all of the ingest CPU goes.
                if db.execute("SELECT 1 FROM transactions WHERE id=?", (transaction_id(cfg, record),)).fetchone():
                    self.duplicates_skipped += 1
                    continue
                self.store.insert(enrich(record, cfg, self.decoder))
            elif kind in ("error", "warning"):
                error = record.get("error") or record.get("reason")
            elif kind == "checkpoint":
                self.counters = {k: record[k] for k in ("packets", "ignored", "unsupported", "packet_time")}
                maximum = db.execute("SELECT coalesce(max(ordinal),0)+1 FROM pcap_files WHERE game_id=?", (cfg.game_id,)).fetchone()[0]
                floor = (ordinal + 1) if ordinal is not None else maximum
                for active in record["active_files"]:
                    row = db.execute("SELECT ordinal FROM pcap_files WHERE id=?", (active,)).fetchone()
                    if row:
                        floor = min(floor, row[0])
                if error and ordinal is not None:
                    floor = min(floor, ordinal)
                with db:
                    if fid:
                        db.execute("UPDATE pcap_files SET status=?,error=?,processed_at=? WHERE id=?", ("error" if error else "done", error, time.time(), fid))
                    db.execute("""INSERT INTO ingest_checkpoints VALUES(?,?,?,?) ON CONFLICT(game_id)
                        DO UPDATE SET replay_from=excluded.replay_from,last_ts=max(last_ts,excluded.last_ts),updated=excluded.updated""", (cfg.game_id, floor, record["packet_time"], time.time()))
        if error:
            raise FileIngestError(error)

    def run(self, paths, finalize=False):
        # The same lock is held by retention through deletion. Before opening a
        # file the ledger has already pinned the complete recovery tail.
        with ledger_lock(self.store.path.parent):
            rejected = self.discover(paths)
            self._start()
            db, cfg = self.store.db, self.cfg
            # Also covers transactions flushed with no file (finalize).
            self.decoder.mode = settings.decoder_mode(db, cfg)["mode"]
            attempt_limit = cfg.options["max_file_attempts"]
            checkpoint = db.execute("SELECT replay_from FROM ingest_checkpoints WHERE game_id=?", (cfg.game_id,)).fetchone()
            floor = checkpoint[0] if checkpoint else 1
            rows = db.execute("""SELECT f.*,min(p.path) AS path FROM pcap_files f JOIN pcap_paths p ON p.file_id=f.id
                WHERE f.game_id=? AND (f.ordinal>=? OR f.status IN ('queued','processing','error')) AND f.status!='late'
                AND NOT (f.status='error' AND f.attempts>=?)
                GROUP BY f.id ORDER BY f.ordinal""", (cfg.game_id, floor, attempt_limit)).fetchall()
            failed = []
            try:
                for row in rows:
                    if row["id"] in self.session_done:
                        continue
                    path = self.traffic / row["path"]
                    sha, _ = self.metadata(path)
                    if sha != row["hash"]:
                        raise ValueError(f"PCAP content changed: {path.name}")
                    # Read per file: a mode changed from the dashboard applies
                    # from the next capture on, and each capture records the
                    # mode it was read under.
                    self.decoder.mode = settings.decoder_mode(db, cfg)["mode"]
                    with db:
                        db.execute("UPDATE pcap_files SET status='processing',attempts=attempts+1,decoder_mode=? WHERE id=?",
                                   (self.decoder.mode, row["id"]))
                        db.execute("INSERT OR IGNORE INTO ingest_checkpoints VALUES(?,?,0,?)", (cfg.game_id, min(floor, row["ordinal"]), time.time()))
                    try:
                        self._records({"path": str(path.resolve()), "id": row["id"], "source": cfg.options["capture_source"]}, row["id"], row["ordinal"])
                    except FileIngestError as exc:
                        # The helper stayed healthy and already recorded the
                        # reason on this file. Keep ingesting the other files;
                        # once the retry budget is spent, move the recovery
                        # floor past this file so it stops blocking the tail.
                        # Data that crossed the broken file is never claimed to
                        # be complete: the gap is reported in the status.
                        failed.append(f"{path.name}: {exc}")
                        if row["attempts"] + 1 >= attempt_limit:
                            with db:
                                db.execute("""UPDATE ingest_checkpoints SET replay_from=max(replay_from,?),updated=?
                                    WHERE game_id=?""", (row["ordinal"] + 1, time.time(), cfg.game_id))
                        self.session_done.add(row["id"])
                        continue
                    self.session_done.add(row["id"])
                if finalize:
                    self._records({"finalize": True})
            except Exception:
                self.close()
                raise
            state = {}
            if rejected or failed:
                state = {"state": "degraded", "rejected_captures": rejected, "failed_captures": failed}
            return self.store.status(**{"state": "running", **self.counters, **state,
                                        "decoder": self.decoder_status(), "duplicates_skipped": self.duplicates_skipped})

    def decoder_status(self):
        """The mode the next capture will be read under, the mode the last one
        was read under, and what the decoder did since this process started."""
        db, cfg = self.store.db, self.cfg
        last = db.execute("""SELECT decoder_mode FROM pcap_files WHERE game_id=? AND decoder_mode IS NOT NULL
            ORDER BY ordinal DESC LIMIT 1""", (cfg.game_id,)).fetchone()
        return {**settings.decoder_mode(db, cfg), "last_file_mode": last[0] if last else None, **self.decoder.status()}

    def close(self):
        if self.helper:
            self.helper.close()
            self.helper = None
