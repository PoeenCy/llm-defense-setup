"""Durable ingestion ledger and Phase 2 outbox. All writes use short commits."""
import json
import time
from pathlib import Path

from . import migrations
from .analysis import uid

# Kept as a module attribute for callers that imported it from here.
SCHEMA_VERSION = migrations.SCHEMA_VERSION


def dumps(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


class Store:
    def __init__(self, path, cfg, migrate=True):
        self.path, self.cfg = Path(path), cfg
        self.db = migrations.connect(self.path) if migrate else migrations.open_initialized(self.path)
        if migrate:
            migrations.upgrade(self.db)
        with self.db:
            previous = self.db.execute("SELECT * FROM games WHERE id=?", (cfg.game_id,)).fetchone()
            if previous and (previous["start_us"], previous["tick_us"]) != (cfg.start_us, cfg.tick_us):
                raise ValueError("game timing changed: use a new game.id for reimport")
            self.db.execute("INSERT OR IGNORE INTO games VALUES(?,?,?)", (cfg.game_id, cfg.start_us, cfg.tick_us))
            self.db.execute("INSERT OR IGNORE INTO config_versions VALUES(?,?,?)", (cfg.version, cfg.game_id, dumps(cfg.raw)))
            for team in cfg.raw.get("teams", []):
                self.db.execute("INSERT OR REPLACE INTO teams VALUES(?,?,?,?)", (cfg.game_id, str(team["id"]), team.get("name", ""), dumps(team["ips"])))

    def insert(self, item):
        r, tag, p, tx = item["record"], item["tag"], item["parsed"], item["id"]
        conn = uid(self.cfg.game_id, r["conn_id"])
        with self.db:
            if self.db.execute("SELECT 1 FROM transactions WHERE id=?", (tx,)).fetchone():
                return False
            self.db.execute("INSERT OR IGNORE INTO connections VALUES(?,?,?,?,?,?,?,?)", (conn, self.cfg.game_id, r["conn_id"], r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"], r["start_ts"]))
            values = dict(id=tx, game_id=self.cfg.game_id, config_version=self.cfg.version, conn_id=conn, seq_in_conn=r["seq"],
                          **tag, ts_request=r["request"]["ts"], ts_response=r["response"].get("ts") or None,
                          ts_end=max(r["response"].get("end_ts", 0), r["request"].get("end_ts", 0)),
                          src_ip=r["src_ip"], src_port=r["src_port"], dst_ip=r["dst_ip"], dst_port=r["dst_port"], proto=r["proto"],
                          method=p["req"].get("method"), path=p["req"].get("path"), status=p["resp"].get("status"),
                          req_parsed=dumps(p["req"]), resp_parsed=dumps(p["resp"]), turns=dumps(r.get("turns")),
                          quality=dumps(item["quality"]), flags_found=dumps(item["flags_found"]), flag_out=int(item["flag_out"]),
                          classification=item["classification"], created=time.time())
            self.db.execute(f"INSERT INTO transactions ({','.join(values)}) VALUES ({','.join('?' for _ in values)})", tuple(values.values()))
            for fid in r["pcaps"]:
                self.db.execute("INSERT OR IGNORE INTO transaction_pcaps VALUES(?,?)", (tx, fid))
            for rep in item["representations"]:
                self.db.execute("INSERT INTO representations VALUES(?,?,?,?,?,?,?,?,?,?)", (rep["id"], tx, rep["side"], rep["kind"], rep["parent_id"], dumps(rep["transform"]), rep["data"], rep["original_size"], rep["truncated"], dumps(rep["spans"])))
            for token in item["tokens"]:
                self.db.execute("INSERT INTO tokens VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (token["id"], tx, token["representation_id"], self.cfg.game_id,
                    tag["team_id"], tag["source_key"], tag["service"], token["observed_ts"], token["value"], token["normalized_value"], token["role"],
                    dumps(token["location"]), token["parent_id"], dumps(token["transform"]), dumps(token["span"])))
            for value in {x["normalized_value"] for x in item["tokens"]}:
                self.db.execute("INSERT INTO token_df VALUES(?,?,?,1) ON CONFLICT(game_id,service,value) DO UPDATE SET n=n+1", (self.cfg.game_id, tag["service"], value))
            self.db.execute("INSERT INTO service_stats VALUES(?,?,1) ON CONFLICT(game_id,service) DO UPDATE SET n=n+1", (self.cfg.game_id, tag["service"]))
            for sighting in item["sightings"]:
                self.db.execute("INSERT OR IGNORE INTO flag_sightings VALUES(?,?,?,?,?,?)", (tx, sighting["representation_id"], sighting["value"], sighting["side"], sighting["start"], sighting["end"]))
                if tag["is_checker"] and sighting["side"] == "req":
                    self.db.execute("INSERT OR IGNORE INTO flags_in VALUES(?,?,?,?)", (self.cfg.game_id, sighting["value"], tx, tag["tick"]))
            if item["flag_out"]:
                self.db.execute("INSERT INTO trace_queue(transaction_id,game_id,created) VALUES(?,?,?)", (tx, self.cfg.game_id, time.time()))
        return True

    def status(self, **extra):
        game = (self.cfg.game_id,)
        # Dispatch backlog and analysis backlog are different queues: a flag-out
        # that has been turned into a job is no longer pending dispatch, but its
        # analysis has not run yet. Reporting one number for both would show an
        # empty backlog as soon as the dispatcher kept up.
        jobs = dict(self.db.execute("SELECT status,count(*) FROM trace_jobs WHERE game_id=? GROUP BY status", game))
        data = {"game_id": self.cfg.game_id, "config_version": self.cfg.version,
                "transactions": self.db.execute("SELECT count(*) FROM transactions WHERE game_id=?", game).fetchone()[0],
                "pending_trace_jobs": self.db.execute("SELECT count(*) FROM trace_queue WHERE game_id=? AND status='pending'", game).fetchone()[0],
                "trace_profiles": self.db.execute("SELECT count(*) FROM trace_profiles WHERE game_id=?", game).fetchone()[0],
                "trace_jobs": {k: jobs.get(k, 0) for k in ("pending", "running", "done", "failed")},
                "files": dict(self.db.execute("SELECT status,count(*) FROM pcap_files WHERE game_id=? GROUP BY status", game)),
                "rejected_files": self.db.execute("SELECT count(*) FROM pcap_rejects WHERE game_id=?", game).fetchone()[0], **extra}
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO runtime_status VALUES(?,?,?)", (self.cfg.game_id, dumps(data), time.time()))
        return data

    def close(self):
        self.db.close()
