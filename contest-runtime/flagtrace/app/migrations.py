"""Schema ownership, split out of Store.

Only an explicit migration (the `migrate` command, or the ingest writer opening
the database) may run DDL or bump the version. The trace worker and the API
open the same file without DDL and without rewriting game/config/team rows:
they check that the schema they were built for is the schema on disk and fail
loudly otherwise. That keeps "upgrade the binaries" and "upgrade the data" two
separate, ordered operations, as the rollout in the plan requires.
"""
import sqlite3
import time
from pathlib import Path

SCHEMA_VERSION = 7
SCHEMA_SQL = Path(__file__).with_name("schema.sql")


def connect(path, readonly=False, timeout=10):
    path = Path(path)
    if readonly:
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=timeout)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(path, timeout=timeout)
    db.row_factory = sqlite3.Row
    if not readonly:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=%d" % int(timeout * 1000))
    return db


def version(db):
    try:
        return db.execute("SELECT max(version) FROM schema_version").fetchone()[0]
    except sqlite3.OperationalError:
        return None


def _v2(db):
    # flag_ids records where a checker-derived candidate was seen.
    db.execute("ALTER TABLE flag_ids ADD COLUMN location TEXT")
    db.execute("ALTER TABLE flag_ids ADD COLUMN transaction_id TEXT")


def _v3(db):
    # Phase 2 tables and the capture-reject ledger are plain additions, already
    # created by schema.sql above. The per-file attempt counter is what stops a
    # capture the helper keeps rejecting from being retried on every poll, so
    # existing rows need the column added.
    columns = {r["name"] for r in db.execute("PRAGMA table_info(pcap_files)")}
    if "attempts" not in columns:
        db.execute("ALTER TABLE pcap_files ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")


def _v4(db):
    # P2.4: trace_values and the flag-ID value index are plain additions,
    # already created by schema.sql above. Runs committed before this version
    # have no value roles and are served as not computed.
    pass


def _v5(db):
    # P2.6: runtime_settings is a plain addition. Each capture records the
    # decoder mode it was ingested under; files ingested before this version
    # were all decoded in full and keep NULL.
    columns = {r["name"] for r in db.execute("PRAGMA table_info(pcap_files)")}
    if "decoder_mode" not in columns:
        db.execute("ALTER TABLE pcap_files ADD COLUMN decoder_mode TEXT")


def _v6(db):
    # P2.5 script artifacts and their local replay attestations are plain
    # additions, already created by schema.sql. Existing runs deliberately
    # remain without artifacts and are served as not_computed.
    pass


def _v7(db):
    # P2.4b: trace_groups and trace_suspects are plain additions. Runs record
    # their group; runs committed before this version have none and the worker
    # re-analyses those profiles (grouping.backfill_trigger).
    columns = {r["name"] for r in db.execute("PRAGMA table_info(trace_runs)")}
    if "group_id" not in columns:
        db.execute("ALTER TABLE trace_runs ADD COLUMN group_id TEXT")


MIGRATIONS = ((2, _v2), (3, _v3), (4, _v4), (5, _v5), (6, _v6), (7, _v7))


def upgrade(db):
    """Create missing objects and run pending steps. Each step commits with its
    own version bump, so a crash never leaves a half-applied version behind."""
    db.executescript(SCHEMA_SQL.read_text())
    at = version(db)
    if at is None:
        # schema.sql just created the current layout for an empty database.
        with db:
            db.execute("INSERT INTO schema_version VALUES(?)", (SCHEMA_VERSION,))
        return {"from": None, "to": SCHEMA_VERSION, "applied": []}
    if at > SCHEMA_VERSION:
        raise ValueError(f"Flag-trace database is newer (v{at}) than this build (v{SCHEMA_VERSION})")
    applied = []
    for target, step in MIGRATIONS:
        if at >= target:
            continue
        db.execute("BEGIN IMMEDIATE")
        try:
            step(db)
            db.execute("INSERT INTO schema_version VALUES(?)", (target,))
            db.commit()
        except BaseException:
            db.rollback()
            raise
        applied.append(target)
        at = target
    if at != SCHEMA_VERSION:
        raise ValueError("unsupported Flag-trace database version")
    return {"from": applied[0] - 1 if applied else at, "to": at, "applied": applied}


def pending(path):
    """(on-disk version, this build's version, whether an upgrade is needed).
    A missing database needs nothing: the ingest writer creates it current."""
    path = Path(path)
    if not path.exists():
        return None, SCHEMA_VERSION, False
    db = connect(path, readonly=True)
    try:
        at = version(db)
    finally:
        db.close()
    if at is not None and at > SCHEMA_VERSION:
        raise ValueError(f"Flag-trace database is newer (v{at}) than this build (v{SCHEMA_VERSION})")
    return at, SCHEMA_VERSION, at is not None and at < SCHEMA_VERSION


def backup(db, directory, at):
    """Consistent online copy (SQLite backup API, safe under WAL) taken before
    an upgrade. The image of the previous phase cannot read an upgraded file,
    so this copy is the way back."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"flagtrace-v{at}-{time.strftime('%Y%m%dT%H%M%S')}.sqlite3"
    copy = sqlite3.connect(target)
    try:
        db.backup(copy)
    finally:
        copy.close()
    return str(target)


def open_initialized(path, readonly=False, timeout=10):
    """Open an existing database for reading or for trace writes, with no DDL."""
    db = connect(path, readonly=readonly, timeout=timeout)
    at = version(db)
    if at != SCHEMA_VERSION:
        db.close()
        raise ValueError(f"Flag-trace schema v{at} on disk, this build needs v{SCHEMA_VERSION}: run `migrate` first")
    return db
