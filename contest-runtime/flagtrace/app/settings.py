"""Runtime overrides set from the dashboard, kept in the database.

The decoder mode is the only one. services.json holds the default; a row in
runtime_settings overrides it until it is reset, across restarts, so a mode
lowered under load stays lowered until someone raises it again. The status
always says which of the two is in force, so a lowered mode cannot go unnoticed.
"""
import time

from .config import DECODER_MODES

DECODER_KEY = "decoder_mode"


def decoder_mode(db, cfg):
    """The mode in force and where it comes from."""
    default = cfg.options["decoder_mode"]
    row = db.execute("SELECT value,source,updated FROM runtime_settings WHERE game_id=? AND key=?",
                     (cfg.game_id, DECODER_KEY)).fetchone()
    if row is None or row["value"] not in DECODER_MODES:
        return {"mode": default, "source": "config", "default": default, "since": None}
    return {"mode": row["value"], "source": row["source"], "default": default, "since": row["updated"]}


def set_decoder_mode(db, cfg, mode, source="dashboard"):
    """Store an override, or drop it when `mode` is "default"."""
    if mode != "default" and mode not in DECODER_MODES:
        raise ValueError("mode must be one of " + ", ".join(DECODER_MODES + ("default",)))
    with db:
        if mode == "default":
            db.execute("DELETE FROM runtime_settings WHERE game_id=? AND key=?", (cfg.game_id, DECODER_KEY))
        else:
            db.execute("""INSERT INTO runtime_settings(game_id,key,value,source,updated) VALUES(?,?,?,?,?)
                ON CONFLICT(game_id,key) DO UPDATE SET source=excluded.source,
                updated=CASE WHEN value=excluded.value THEN updated ELSE excluded.updated END,
                value=excluded.value""", (cfg.game_id, DECODER_KEY, mode, source, time.time()))
    return decoder_mode(db, cfg)
