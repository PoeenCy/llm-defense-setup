PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS games(id TEXT PRIMARY KEY, start_us INTEGER NOT NULL, tick_us INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS config_versions(id TEXT PRIMARY KEY, game_id TEXT REFERENCES games, config TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS teams(game_id TEXT, id TEXT, name TEXT, networks TEXT, PRIMARY KEY(game_id,id));
CREATE TABLE IF NOT EXISTS pcap_files(
 id TEXT PRIMARY KEY, game_id TEXT NOT NULL, ordinal INTEGER NOT NULL, hash TEXT NOT NULL,
 first_ts INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'queued', error TEXT,
 received_at REAL NOT NULL, processed_at REAL, attempts INTEGER NOT NULL DEFAULT 0,
 decoder_mode TEXT,
 UNIQUE(game_id,ordinal), UNIQUE(game_id,hash)
);
CREATE TABLE IF NOT EXISTS pcap_paths(path TEXT PRIMARY KEY, file_id TEXT NOT NULL REFERENCES pcap_files);
CREATE TABLE IF NOT EXISTS connections(
 id TEXT PRIMARY KEY, game_id TEXT, transport_id TEXT, src_ip TEXT, src_port INTEGER,
 dst_ip TEXT, dst_port INTEGER, start_ts INTEGER
);
CREATE TABLE IF NOT EXISTS transactions(
 id TEXT PRIMARY KEY, game_id TEXT NOT NULL, config_version TEXT REFERENCES config_versions,
 conn_id TEXT REFERENCES connections, seq_in_conn INTEGER NOT NULL,
 team_id TEXT, source_key TEXT NOT NULL, is_checker INTEGER NOT NULL, service TEXT NOT NULL,
 tick INTEGER, ts_request INTEGER NOT NULL, ts_response INTEGER, ts_end INTEGER,
 src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, proto TEXT,
 method TEXT, path TEXT, status INTEGER, req_parsed TEXT, resp_parsed TEXT, turns TEXT,
 quality TEXT NOT NULL, flags_found TEXT NOT NULL, flag_out INTEGER NOT NULL,
 classification TEXT NOT NULL, created REAL NOT NULL,
 UNIQUE(game_id,conn_id,seq_in_conn)
);
CREATE INDEX IF NOT EXISTS tx_source ON transactions(game_id,source_key,service,ts_request);
CREATE INDEX IF NOT EXISTS tx_team ON transactions(game_id,team_id,service,ts_request);
CREATE INDEX IF NOT EXISTS tx_checker ON transactions(game_id,is_checker,tick);
CREATE INDEX IF NOT EXISTS tx_flag ON transactions(game_id,flag_out,ts_request);
CREATE TABLE IF NOT EXISTS transaction_pcaps(
 transaction_id TEXT REFERENCES transactions, file_id TEXT REFERENCES pcap_files,
 PRIMARY KEY(transaction_id,file_id)
);
CREATE TABLE IF NOT EXISTS representations(
 id TEXT PRIMARY KEY, transaction_id TEXT REFERENCES transactions, side TEXT, kind TEXT,
 parent_id TEXT, transform TEXT, data BLOB, original_size INTEGER, truncated INTEGER, spans TEXT
);
CREATE TABLE IF NOT EXISTS tokens(
 id TEXT PRIMARY KEY, transaction_id TEXT REFERENCES transactions, representation_id TEXT REFERENCES representations,
 game_id TEXT, team_id TEXT, source_key TEXT, service TEXT, observed_ts INTEGER,
 value TEXT, normalized_value TEXT, role TEXT, location TEXT, parent_id TEXT,
 transform TEXT, span TEXT
);
CREATE INDEX IF NOT EXISTS token_lookup ON tokens(game_id,source_key,service,normalized_value,observed_ts);
CREATE INDEX IF NOT EXISTS token_tx ON tokens(transaction_id);
CREATE TABLE IF NOT EXISTS token_df(game_id TEXT,service TEXT,value TEXT,n INTEGER NOT NULL,
 PRIMARY KEY(game_id,service,value));
CREATE TABLE IF NOT EXISTS service_stats(game_id TEXT,service TEXT,n INTEGER NOT NULL,
 PRIMARY KEY(game_id,service));
CREATE TABLE IF NOT EXISTS flag_sightings(
 transaction_id TEXT REFERENCES transactions,representation_id TEXT REFERENCES representations,
 value TEXT,side TEXT,start INTEGER,end INTEGER,
 PRIMARY KEY(transaction_id,representation_id,value,start)
);
CREATE TABLE IF NOT EXISTS flags_in(game_id TEXT,flag TEXT,transaction_id TEXT,tick INTEGER,
 PRIMARY KEY(game_id,flag,transaction_id));
CREATE TABLE IF NOT EXISTS trace_queue(
 transaction_id TEXT PRIMARY KEY REFERENCES transactions,game_id TEXT NOT NULL,
 schema_version INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'pending',
 created REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, lease_until REAL, error TEXT
);
CREATE TABLE IF NOT EXISTS ingest_checkpoints(game_id TEXT PRIMARY KEY, replay_from INTEGER NOT NULL,
 last_ts INTEGER NOT NULL DEFAULT 0, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS flag_ids(game_id TEXT,tick INTEGER,service TEXT,owner_team_id TEXT,
 value TEXT,source TEXT,location TEXT,transaction_id TEXT,PRIMARY KEY(game_id,tick,service,owner_team_id,value));
CREATE TABLE IF NOT EXISTS baseline(game_id TEXT,service TEXT,method TEXT,path_template TEXT,field TEXT,
 stats TEXT,updated REAL,PRIMARY KEY(game_id,service,method,path_template,field));
CREATE TABLE IF NOT EXISTS runtime_status(game_id TEXT PRIMARY KEY,data TEXT,updated REAL);
-- Operator overrides set from the dashboard, kept across restarts. A missing
-- row means the value from services.json applies.
CREATE TABLE IF NOT EXISTS runtime_settings(game_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
 source TEXT NOT NULL, updated REAL NOT NULL, PRIMARY KEY(game_id,key));
-- Captures that could not be read at all (truncated/foreign format). Keyed by
-- identity, not just name, so a repaired or replaced file is retried once and
-- a permanently broken one stops blocking the files around it.
CREATE TABLE IF NOT EXISTS pcap_rejects(
 game_id TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
 error TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
 PRIMARY KEY(game_id,path,size,mtime_ns)
);
-- Phase 2. One profile per anchor transaction; jobs and runs carry the history.
CREATE TABLE IF NOT EXISTS trace_profiles(
 id TEXT PRIMARY KEY, game_id TEXT NOT NULL, anchor_transaction_id TEXT NOT NULL REFERENCES transactions,
 created REAL NOT NULL, last_requested_sequence INTEGER NOT NULL DEFAULT 0,
 latest_run_id TEXT, latest_run_sequence INTEGER,
 UNIQUE(game_id,anchor_transaction_id)
);
CREATE TABLE IF NOT EXISTS trace_jobs(
 id TEXT PRIMARY KEY, trace_id TEXT NOT NULL REFERENCES trace_profiles, game_id TEXT NOT NULL,
 request_sequence INTEGER NOT NULL, trigger_key TEXT NOT NULL,
 engine_version TEXT NOT NULL, algorithm_hash TEXT NOT NULL, algorithm_config TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', available_at REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
 lease_owner TEXT, lease_token TEXT, lease_until REAL, error TEXT,
 created REAL NOT NULL, updated REAL NOT NULL,
 UNIQUE(trace_id,trigger_key), UNIQUE(trace_id,request_sequence)
);
CREATE INDEX IF NOT EXISTS trace_jobs_ready ON trace_jobs(game_id,status,available_at);
CREATE TABLE IF NOT EXISTS trace_runs(
 id TEXT PRIMARY KEY, job_id TEXT NOT NULL UNIQUE REFERENCES trace_jobs,
 trace_id TEXT NOT NULL REFERENCES trace_profiles, game_id TEXT NOT NULL,
 request_sequence INTEGER NOT NULL, engine_version TEXT NOT NULL, algorithm_hash TEXT NOT NULL,
 state TEXT NOT NULL, anchor TEXT NOT NULL, coverage TEXT NOT NULL, warnings TEXT NOT NULL,
 metrics TEXT NOT NULL, analysis TEXT NOT NULL, snapshot_wall REAL NOT NULL, created REAL NOT NULL,
 group_id TEXT
);
CREATE INDEX IF NOT EXISTS trace_runs_trace ON trace_runs(trace_id,request_sequence);
CREATE TABLE IF NOT EXISTS trace_steps(
 run_id TEXT NOT NULL REFERENCES trace_runs, transaction_id TEXT NOT NULL REFERENCES transactions,
 position INTEGER NOT NULL, role TEXT NOT NULL, reasons TEXT NOT NULL, quality TEXT NOT NULL,
 summary TEXT NOT NULL, PRIMARY KEY(run_id,transaction_id)
);
CREATE INDEX IF NOT EXISTS trace_steps_tx ON trace_steps(transaction_id);
CREATE TABLE IF NOT EXISTS trace_edges(
 run_id TEXT NOT NULL REFERENCES trace_runs, evidence_key TEXT NOT NULL, kind TEXT NOT NULL,
 dst_transaction_id TEXT NOT NULL, dst_token_id TEXT, dst_location TEXT, dst_representation_id TEXT,
 dst_observed_ts INTEGER, src_transaction_id TEXT, src_token_id TEXT, src_location TEXT,
 src_representation_id TEXT, src_observed_ts INTEGER, value_preview TEXT, value_length INTEGER,
 transform TEXT, ambiguous INTEGER NOT NULL DEFAULT 0, alternatives TEXT, note TEXT,
 PRIMARY KEY(run_id,evidence_key)
);
-- P2.4 value roles, one row per listed (non-constant) request field of a run.
-- The run's analysis holds the summary; a run without one was not classified.
CREATE TABLE IF NOT EXISTS trace_values(
 run_id TEXT NOT NULL REFERENCES trace_runs, value_key TEXT NOT NULL, transaction_id TEXT NOT NULL,
 token_id TEXT, location TEXT NOT NULL, role TEXT NOT NULL, var TEXT, value_preview TEXT, value_length INTEGER,
 template TEXT, parts TEXT, transform TEXT, unresolved TEXT, session_cookie INTEGER NOT NULL DEFAULT 0,
 ambiguous INTEGER NOT NULL DEFAULT 0, evidence TEXT, PRIMARY KEY(run_id,value_key)
);
-- P2.5 immutable replay artifacts. Script contents are separate from the run
-- JSON so opening a profile does not pull every captured request into memory.
CREATE TABLE IF NOT EXISTS trace_script_artifacts(
 id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES trace_runs,
 kind TEXT NOT NULL, transaction_id TEXT REFERENCES transactions, position INTEGER,
 format TEXT NOT NULL, filename TEXT NOT NULL, exporter_version TEXT NOT NULL,
 content_hash TEXT NOT NULL, support TEXT NOT NULL, warnings TEXT NOT NULL,
 content BLOB NOT NULL, created REAL NOT NULL,
 UNIQUE(run_id,kind,transaction_id,exporter_version)
);
CREATE INDEX IF NOT EXISTS trace_script_artifacts_run ON trace_script_artifacts(run_id,position);
CREATE TABLE IF NOT EXISTS trace_replay_verifications(
 id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES trace_script_artifacts,
 artifact_hash TEXT NOT NULL, fixture TEXT NOT NULL, target TEXT NOT NULL,
 status TEXT NOT NULL, flags TEXT NOT NULL, output TEXT NOT NULL, error TEXT,
 started REAL NOT NULL, finished REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS trace_replay_artifact ON trace_replay_verifications(artifact_id,finished);
-- P2.4b. A group is a chain shape (grouping.py); a profile belongs to the
-- group of its latest run, so a re-analysis never counts twice. Runs record
-- their own group in trace_runs.group_id (added by migration v7).
CREATE TABLE IF NOT EXISTS trace_groups(
 id TEXT PRIMARY KEY, game_id TEXT NOT NULL, service TEXT NOT NULL, normalizer_version TEXT NOT NULL,
 description TEXT NOT NULL, signature TEXT NOT NULL, created REAL NOT NULL
);
-- Steps that differ from the checker baseline, with the figures compared.
CREATE TABLE IF NOT EXISTS trace_suspects(
 run_id TEXT NOT NULL REFERENCES trace_runs, transaction_id TEXT NOT NULL REFERENCES transactions,
 position INTEGER NOT NULL, strength TEXT NOT NULL, findings TEXT NOT NULL,
 PRIMARY KEY(run_id,transaction_id)
);
-- Flag IDs are looked up by the values a chain sent, not scanned by tick.
CREATE INDEX IF NOT EXISTS flag_ids_value ON flag_ids(game_id,service,value);
CREATE TABLE IF NOT EXISTS trace_runtime_status(worker_id TEXT PRIMARY KEY, game_id TEXT NOT NULL,
 data TEXT, updated REAL);
