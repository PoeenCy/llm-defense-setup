"""Shared lock for ingest/recovery versus host retention. Fail closed on errors."""
import contextlib
import fcntl
import sqlite3
from pathlib import Path


@contextlib.contextmanager
def ledger_lock(directory, shared=False, blocking=True):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "retention.lock").open("a") as handle:
        op = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        if not blocking:
            op |= fcntl.LOCK_NB
        fcntl.flock(handle, op)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def may_delete(db_path, filename):
    """Call only while holding exclusive ledger_lock, including through unlink.

    Any unresolved generation pins its files; active replay floors pin the tail.
    A missing/corrupt ledger or unseen file never grants deletion permission.
    """
    try:
        with contextlib.closing(sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro", uri=True)) as db:
            rows = db.execute("""SELECT f.status, f.ordinal, c.replay_from FROM pcap_paths p
                JOIN pcap_files f ON f.id=p.file_id LEFT JOIN ingest_checkpoints c ON c.game_id=f.game_id
                WHERE p.path=?""", (filename,)).fetchall()
            return bool(rows) and all(status == "done" and floor is not None and ordinal < floor for status, ordinal, floor in rows)
    except sqlite3.Error:
        return False
