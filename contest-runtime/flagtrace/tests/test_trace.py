"""Phase 2: trace profiles, the worker lifecycle and the evidence engine.

Expectations are written as request meaning (method, path, field category) and
values, never as row IDs. Crash and concurrency cases act on real processes and
real connections against a temporary database instead of mocked calls.
"""
import base64
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

RUNTIME = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RUNTIME))
import fixtures as F
from flagtrace.app import migrations
from flagtrace.app.api import make_server
from flagtrace.app.background import collect_checker_flagids, import_flagids
from flagtrace.app.config import Config, validate_optional
from flagtrace.app.ingest import Ingestor
from flagtrace.app.settings import set_decoder_mode
from flagtrace.app.store import Store
from flagtrace.app.trace import contracts, routes, worker
from flagtrace.app.trace.engine import Engine
from flagtrace.app.trace.export import EXPORTER_VERSION
from flagtrace.app.trace.repository import Reader, Repository, category

TICK_US = 120_000_000

# Runs the real worker in a child process and kills it around the commit.
CRASH_CHILD = r'''
import json, os, sys
sys.path.insert(0, sys.argv[1])
from flagtrace.app.config import Config
from flagtrace.app.trace import worker
from flagtrace.app.trace.repository import Repository
original = Repository.commit_result
def crash(self, job, result):
    if sys.argv[4] == "after":
        original(self, job, result)
    os._exit(3)
Repository.commit_result = crash
worker.run_once(sys.argv[2], Config(json.loads(sys.argv[3])))
'''


def raw_config(**trace):
    raw = F.config()
    raw["flagtrace"]["trace"].update(trace)
    return raw


class TraceBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "db.sqlite3"
        self.raw = raw_config()
        self.cfg = Config(self.raw)
        self.store = Store(self.db_path, self.cfg)
        self.ingestor = Ingestor(self.store, self.root)

    def tearDown(self):
        self.ingestor.close()
        self.store.close()
        self.tmp.cleanup()

    def ingest(self, packets, name="a.pcap", finalize=True):
        if packets is not None:
            F.write_pcap(self.root / name, packets)
        return self.ingestor.run(sorted(self.root.glob("*.pcap")), finalize=finalize)

    def trace(self, mode="full"):
        return worker.run_once(self.db_path, self.cfg, mode=mode)

    def repo(self, cfg=None, **kw):
        repo = Repository.open(self.db_path, cfg or self.cfg, **kw)
        self.addCleanup(repo.close)
        return repo

    def q(self, sql, *args):
        return self.store.db.execute(sql, args).fetchall()

    def one(self, sql, *args):
        return self.store.db.execute(sql, args).fetchone()[0]

    def profile(self, path):
        rows = self.q("""SELECT p.* FROM trace_profiles p JOIN transactions t ON t.id=p.anchor_transaction_id
                         WHERE t.path=?""", path)
        self.assertEqual(len(rows), 1, f"expected one profile anchored at {path}")
        return rows[0]

    def view(self, run_id):
        """A run as meaning: steps by (method, path), edges by category."""
        steps = []
        for r in self.q("""SELECT s.role,s.reasons,s.quality,t.method,t.path,t.source_key,t.conn_id,t.src_port
                           FROM trace_steps s JOIN transactions t ON t.id=s.transaction_id
                           WHERE s.run_id=? ORDER BY s.position""", run_id):
            steps.append({"step": (r["method"], r["path"]), "role": r["role"], "reasons": json.loads(r["reasons"]),
                          "quality": json.loads(r["quality"]), "source_key": r["source_key"],
                          "conn_id": r["conn_id"], "src_port": r["src_port"]})
        edges = []
        for r in self.q("""SELECT e.*,s.method AS sm,s.path AS sp,s.src_port AS sport,d.method AS dm,d.path AS dp
                           FROM trace_edges e JOIN transactions s ON s.id=e.src_transaction_id
                           JOIN transactions d ON d.id=e.dst_transaction_id WHERE e.run_id=?""", run_id):
            edges.append({"meaning": ((r["sm"], r["sp"]), category(r["src_location"]), (r["dm"], r["dp"]),
                                      category(r["dst_location"]), r["kind"]),
                          "value": r["value_preview"], "ambiguous": bool(r["ambiguous"]),
                          "alternatives": json.loads(r["alternatives"]), "src_port": r["sport"],
                          "key": r["evidence_key"]})
        run = dict(self.q("SELECT * FROM trace_runs WHERE id=?", run_id)[0])
        for key in ("anchor", "coverage", "warnings", "metrics", "analysis"):
            run[key] = json.loads(run[key])
        return steps, edges, run

    def latest(self, path):
        profile = self.profile(path)
        self.assertIsNotNone(profile["latest_run_id"], f"no run for {path}")
        return self.view(profile["latest_run_id"])

    @staticmethod
    def core(steps):
        return {s["step"] for s in steps}

    @staticmethod
    def meanings(edges):
        return {e["meaning"] for e in edges}

    @staticmethod
    def unexplained(run):
        return {u["value_preview"]: u["reason"] for u in run["coverage"]["unexplained"]}


class ChainTests(TraceBase):
    """Acceptance matrix A1–A6 and A9–A11: what the engine links, and why."""

    def assert_notes_chain(self, path="/files/f93a1c"):
        steps, edges, run = self.latest(path)
        self.assertEqual(run["state"], contracts.RUN_LINKED)
        # Exactly the flow: register, login, upload, read. Nothing else.
        self.assertEqual([s["step"] for s in steps], F.NOTES_STEPS)
        self.assertEqual({s["role"] for s in steps}, {contracts.ROLE_ANCHOR, contracts.ROLE_DATA_LINKED})
        self.assertEqual(self.meanings(edges), set(F.NOTES_EDGES))
        self.assertTrue(set(F.NOTES_UNEXPLAINED) <= set(self.unexplained(run)))
        self.assertEqual([s["role"] for s in steps if s["step"] == ("GET", path)], [contracts.ROLE_ANCHOR])
        return steps, edges, run

    def test_a1_same_connection(self):
        self.ingest(F.notes_packets())
        self.trace()
        steps, _, _ = self.assert_notes_chain()
        self.assertEqual(len({s["conn_id"] for s in steps}), 1)

    def test_a1_one_connection_per_step(self):
        # Linked by data alone: no two steps share a TCP connection, so the
        # result cannot be explained by connection proximity.
        self.ingest(F.notes_split_packets())
        self.trace()
        steps, _, _ = self.assert_notes_chain()
        self.assertEqual(len({s["conn_id"] for s in steps}), 4)
        self.assertTrue(all(contracts.REASON_TOKEN_LINK in s["reasons"] for s in steps if s["role"] != "anchor"))

    def test_a2_noise_and_future_are_excluded(self):
        self.ingest(sorted(F.notes_split_packets() + F.noise_packets() + F.after_anchor_packets()))
        self.trace()
        steps, edges, _ = self.assert_notes_chain()
        by_step = {s["step"]: s for s in steps}
        # Before the anchor but sharing no value with the chain: not a step.
        self.assertNotIn(("GET", "/static/app.js"), by_step)
        # After the anchor: never part of it, even though it reuses the cookie.
        self.assertNotIn(("GET", "/healthz"), by_step)
        self.assertEqual(sum(1 for s in steps if s["step"] == ("GET", "/files/f93a1c")), 1)
        self.assertFalse(any(("GET", "/static/app.js") in (e["meaning"][0], e["meaning"][2]) for e in edges))

    def test_a3_interleaved_scripts_stay_apart(self):
        self.ingest(F.two_scripts_packets())
        self.trace()
        self.assertEqual(self.one("SELECT count(*) FROM trace_profiles"), 2)
        own = {"/files/f1aaaa": {"s1aa11bb", "f1aaaa", "u1xxxxx", "p1yyyyy"},
               "/files/f2bbbb": {"s2cc22dd", "f2bbbb", "u2xxxxx", "p2yyyyy"}}
        for path, values in own.items():
            with self.subTest(anchor=path):
                steps, edges, run = self.latest(path)
                self.assertEqual({e["value"] for e in edges}, values)
                self.assertEqual(self.meanings(edges), set(F.NOTES_EDGES) - {
                    (("POST", "/upload"), "json", ("GET", "/files/f93a1c"), "path", "response_to_request"),
                    (("POST", "/login"), "cookie", ("GET", "/files/f93a1c"), "cookie", "response_to_request")} | {
                    (("POST", "/upload"), "json", ("GET", path), "path", "response_to_request"),
                    (("POST", "/login"), "cookie", ("GET", path), "cookie", "response_to_request")})
                self.assertEqual(sum(1 for s in steps if s["role"] == contracts.ROLE_DATA_LINKED), 3)
        # The second script sends the same traversal payload as the first. That
        # is the step repeated, not a value handed over, and must not merge them.
        _, _, run = self.latest("/files/f2bbbb")
        self.assertEqual(self.unexplained(run)["../../notes/7731.txt"], "repeated_in_same_step")

    def test_a4_sources_do_not_cross(self):
        self.ingest(F.shared_token_packets())
        self.trace()
        profiles = self.q("""SELECT p.latest_run_id,t.source_key FROM trace_profiles p
                             JOIN transactions t ON t.id=p.anchor_transaction_id""")
        self.assertEqual({p["source_key"] for p in profiles},
                         {"team:team-05", "team:team-09", "ip:10.60.88.1", "ip:10.60.89.1"})
        for profile in profiles:
            with self.subTest(source=profile["source_key"]):
                steps, edges, run = self.view(profile["latest_run_id"])
                self.assertEqual({s["source_key"] for s in steps}, {profile["source_key"]})
                self.assertEqual(self.meanings(edges), {(("POST", "/login"), "cookie", ("GET", "/files/shared01"),
                                                         "cookie", "response_to_request")})
                self.assertEqual(run["coverage"]["scope"]["source_key"], profile["source_key"])

    def test_a5_old_account_and_nearest_source(self):
        self.ingest(F.old_account_packets())
        self.trace()
        steps, edges, run = self.latest("/files/oa0123ff")
        self.assertEqual(run["state"], contracts.RUN_LINKED)
        cookie = [e for e in edges if e["meaning"][1] == "cookie"]
        self.assertEqual(len(cookie), 1)
        # Nearest login before the read wins; the older one is an alternative,
        # and having one is not the same as being ambiguous.
        self.assertEqual(cookie[0]["src_port"], 52121)
        self.assertFalse(cookie[0]["ambiguous"])
        self.assertEqual(len(cookie[0]["alternatives"]), 1)
        # Registration ticks earlier is found through the index, not skipped
        # in favour of the repeated login of the same account.
        reuse = {e["meaning"] for e in edges if e["meaning"][4] == contracts.EDGE_REQUEST_REUSE}
        self.assertEqual(reuse, {(("POST", "/register"), "form", ("POST", "/login"), "form", "request_reuse")})
        self.assertIn(("POST", "/register"), self.core(steps))
        self.assertGreaterEqual(run["metrics"]["queries"], 1)

    def test_a5_equal_sources_are_ambiguous_and_stable(self):
        self.ingest(F.old_account_packets())
        self.trace()
        first_key = {e["key"] for e in self.latest("/files/oa0123ff")[1] if e["meaning"][1] == "cookie"}
        # Make both logins indistinguishable: same field, same observed time.
        self.store.db.execute("UPDATE tokens SET observed_ts=? WHERE role='produced' AND normalized_value='oa11bb22'",
                              (F.BASE * 1_000_000,))
        self.store.db.commit()
        trace = self.profile("/files/oa0123ff")["id"]
        chosen = []
        for key in ("tie-1", "tie-2"):
            self.repo().enqueue_retrace(trace, key)
            self.trace()
            cookie = [e for e in self.latest("/files/oa0123ff")[1] if e["meaning"][1] == "cookie"]
            self.assertEqual(len(cookie), 1)
            self.assertTrue(cookie[0]["ambiguous"])
            self.assertEqual(len(cookie[0]["alternatives"]), 1)
            chosen.append(cookie[0]["key"])
        self.assertEqual(chosen[0], chosen[1])
        self.assertTrue(first_key)

    def test_a5_equal_time_across_connections_is_not_ordered(self):
        self.ingest(F.old_account_packets())
        read_ts = self.one("SELECT ts_request FROM transactions WHERE path='/files/oa0123ff'")
        self.store.db.execute("UPDATE tokens SET observed_ts=? WHERE role='produced' AND normalized_value='oa11bb22'",
                              (read_ts,))
        self.store.db.commit()
        self.trace()
        _, edges, run = self.latest("/files/oa0123ff")
        self.assertFalse([e for e in edges if e["meaning"][1] == "cookie"])
        self.assertEqual(self.unexplained(run)["oa11bb22"], "equal_timestamp_order_unknown")

    def test_a6_multiple_flags_one_profile_per_anchor(self):
        self.ingest(F.multi_flag_packets())
        self.trace()
        self.assertEqual(self.one("SELECT count(*) FROM trace_profiles"), 2)
        _, _, run = self.latest("/files/both")
        self.assertEqual(run["anchor"]["flags_found"], ["FLAG{first_of_two}", "FLAG{second_of_two}"])
        steps, _, run = self.latest("/files/third")
        self.assertEqual(run["anchor"]["flags_found"], ["FLAG{third_one}"])
        # The first anchor shares the session but is a different profile: the
        # cookie came from the login, so the earlier read is not a step here.
        self.assertEqual(self.core(steps), {("POST", "/login"), ("GET", "/files/third")})

    def test_lowered_decoder_is_warned_on_the_run(self):
        set_decoder_mode(self.store.db, self.cfg, "off")
        self.ingest(F.notes_packets())
        self.trace()
        steps, _, run = self.latest("/files/f93a1c")
        self.assertEqual(len(steps), 4)
        self.assertIn("resp:decoder_off", run["coverage"]["ingest_quality"])
        self.assertTrue(any("decoder lowered (decoder_off)" in w for w in run["warnings"]))
        script = self.one("SELECT support FROM trace_script_artifacts WHERE run_id=? AND kind='chain'",
                          self.profile("/files/f93a1c")["latest_run_id"])
        self.assertEqual(script, contracts.SCRIPT_NEEDS_EDIT)

    def test_a9_incomplete_evidence_is_visible(self):
        self.ingest(F.degraded_chain_packets())
        self.trace()
        steps, edges, run = self.latest("/files/dgfile")
        self.assertEqual(run["anchor"]["flags_found"], ["FLAG{after_decode}"])
        # Seen in the content-decoded body, not in the gzip bytes on the wire.
        kinds = {r[0] for r in self.q("""SELECT r.kind FROM flag_sightings s JOIN representations r
                                         ON r.id=s.representation_id JOIN transactions t ON t.id=s.transaction_id
                                         WHERE t.path='/files/dgfile' AND s.side='resp'""")}
        self.assertEqual(kinds, {"body"})
        upload = next(s for s in steps if s["step"] == ("POST", "/upload"))
        self.assertIn("resp:incomplete_body", upload["quality"])
        self.assertTrue(any("incompletely" in w for w in run["warnings"]))
        self.assertIn("resp:incomplete_body", run["coverage"]["ingest_quality"])
        # The cut response still names the file, so the link is kept and the
        # step's quality says what the evidence is worth.
        self.assertIn((("POST", "/upload"), "json", ("GET", "/files/dgfile"), "path", "response_to_request"),
                      self.meanings(edges))

    def test_a11_repeated_fields_and_captured_markup(self):
        self.ingest(F.html_payload_packets())
        self.trace()
        steps, edges, run = self.latest("/files/hxfile01")
        self.assertEqual(self.core(steps), {("POST", "/login"), ("POST", "/render"), ("GET", "/files/hxfile01")})
        # A word-like file ID is still linked once a structured response named it.
        self.assertIn((("POST", "/render"), "json", ("GET", "/files/hxfile01"), "path", "response_to_request"),
                      self.meanings(edges))
        locations = [json.loads(r[0]) for r in self.q("""SELECT location FROM tokens k JOIN transactions t
                     ON t.id=k.transaction_id WHERE t.path LIKE '/login%' AND k.value IN ('first1234','second123')
                     ORDER BY k.value""")]
        self.assertEqual(locations, [["resp", "json", "a.b", 0], ["resp", "json", "a.b", 1]])
        users = sorted(u for u in self.unexplained(run) if u.startswith("hxuser"))
        self.assertEqual(users, ["hxuser001", "hxuser002"])

    def test_word_fragments_and_constant_parameters_do_not_link(self):
        # Regression from dataset A: "image" split out of "/image-sharing/" was
        # linked to the word in an HTML page and in "image/png", chaining every
        # file read to the one before it.
        self.ingest(F.image_sharing_packets())
        self.trace()
        self.assertEqual(self.one("SELECT count(*) FROM trace_profiles"), 2)
        for n, row in enumerate(self.q("""SELECT p.latest_run_id FROM trace_profiles p JOIN transactions t
                                          ON t.id=p.anchor_transaction_id ORDER BY t.ts_request""")):
            with self.subTest(read=n):
                steps, edges, run = self.view(row["latest_run_id"])
                self.assertEqual(edges, [])
                self.assertEqual(self.core(steps), {("GET", "/image-sharing/")})
                self.assertEqual(run["state"], contracts.RUN_LINKED)
                skipped = run["coverage"]["counters"]["tokens_skipped"]
                self.assertGreater(skipped.get("endpoint_literal", 0), 0)
                self.assertGreater(skipped.get("literal_fragment", 0), 0)
                # The first read has nothing before it; the second repeats it.
                self.assertEqual(self.unexplained(run)["L2ZsYWcvZmxhZw=="],
                                 "no_source_in_scope" if n == 0 else "repeated_in_same_step")

    def test_one_request_flag_out_is_one_step(self):
        # Dataset A: a file read needing no login showed up to 64 steps because
        # same-source traffic just before it was listed as "context". The
        # result is the flow only, so it is the anchor alone.
        cut = F.Connection(port=52401, clock=5_000)
        cut.send(F.request("/static/big.js"))
        cut.send(b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\npartial", server=True)
        cut.close()
        self.ingest(sorted(F.image_sharing_packets(reads=5) + cut.packets))
        self.trace()
        runs = self.q("SELECT latest_run_id FROM trace_profiles")
        self.assertEqual(len(runs), 5)
        for row in runs:
            steps, edges, run = self.view(row["latest_run_id"])
            with self.subTest(run=row["latest_run_id"]):
                self.assertEqual([(s["step"], s["role"]) for s in steps],
                                 [(("GET", "/image-sharing/"), contracts.ROLE_ANCHOR)])
                self.assertEqual(edges, [])
                self.assertEqual(run["state"], contracts.RUN_LINKED)
                self.assertEqual(run["coverage"]["limits_hit"], [])
                # An unrelated, cut response nearby does not taint the result.
                self.assertNotIn("resp:incomplete_body", run["coverage"]["ingest_quality"])
                self.assertFalse(any("incompletely" in w for w in run["warnings"]))

    def test_bearer_token_links_whole_token_to_login(self):
        # Real-capture finding (DTFC live): a login access_token sent back as
        # `Authorization: Bearer <token>` must link as the whole token, not only
        # via JWT-claim fragments. The scheme word is stripped before matching.
        self.ingest(F.bearer_token_packets())
        self.trace()
        steps, edges, run = self.latest("/vault")
        self.assertEqual(run["state"], contracts.RUN_LINKED)
        self.assertEqual(self.core(steps), {("POST", "/login"), ("GET", "/vault")})
        tok = [e for e in edges if e["meaning"][3] == "header"]
        self.assertEqual(len(tok), 1)
        self.assertEqual(tok[0]["meaning"],
                         (("POST", "/login"), "json", ("GET", "/vault"), "header", "response_to_request"))
        self.assertEqual(tok[0]["value"], "tok7fa3c9e1b55d4e2a8c0f16229adb3e77")
        # The "Bearer " scheme is not left dangling as an unexplained value.
        self.assertNotIn("Bearer", json.dumps(self.unexplained(run)))

    def test_checker_traffic_never_links(self):
        self.ingest(sorted(F.checker_putflag_packets() + F.notes_split_packets(clock=2_000_000)))
        self.trace()
        steps, _, run = self.latest("/files/f93a1c")
        self.assertNotIn("ip:10.60.0.1", {s["source_key"] for s in steps})
        self.assertTrue(run["coverage"]["scope"]["exclude_checker"])


class ValueRoleTests(TraceBase):
    """P2.4a (B6): every value a chain sends gets a role a script can act on.
    Flag IDs come from the checker's own putflag sessions or an import; the
    local lab has neither, which is exactly the case where nothing may be
    called a target."""

    TICK1 = 121_000_000   # one tick after the game started

    def roles(self, path, run=None):
        """(values keyed by (step path, (category, name)), summary) of a run."""
        run = run or self.profile(path)["latest_run_id"]
        out = {}
        for r in self.q("""SELECT v.*,t.path AS step FROM trace_values v JOIN transactions t ON t.id=v.transaction_id
                           WHERE v.run_id=?""", run):
            loc = json.loads(r["location"])
            out[(r["step"].split("?")[0], tuple(loc[1:3]))] = {
                **dict(r), "location": loc, "parts": json.loads(r["parts"]), "evidence": json.loads(r["evidence"]),
                "transform": json.loads(r["transform"])}
        summary = json.loads(self.one("SELECT analysis FROM trace_runs WHERE id=?", run))["value_roles"]
        return out, summary

    def reconfigure(self, raw):
        self.ingestor.close()
        self.store.close()
        self.raw, self.cfg = raw, Config(raw)
        self.store = Store(self.db_path, self.cfg)
        self.ingestor = Ingestor(self.store, self.root)

    def flag_ids(self, *rows):
        import_flagids(self.store, [{"service": "notes", "owner_team_id": "team-01", **r} for r in rows])

    def test_notes_chain_with_checker_flag_ids(self):
        # The checker stored the stolen flag at tick 0 and got note 7731 back;
        # at tick 1 it stored another flag as 7732. The attacker reads 7731.
        self.ingest(sorted(F.checker_notes_packets([(0, "7731", b"FLAG{stolen_from_notes}"),
                                                    (1, "7732", b"FLAG{next_tick_flag}")])
                           + F.notes_split_packets(clock=self.TICK1)))
        collect_checker_flagids(self.store)
        self.trace()
        values, summary = self.roles("/files/f93a1c")
        role = {k: (v["role"], v["var"]) for k, v in values.items()}
        self.assertEqual(role, {
            ("/register", ("form", "user")): ("generated", "user"),
            ("/register", ("form", "pass")): ("generated", "pass"),
            ("/login", ("form", "user")): ("generated", "user"),
            ("/login", ("form", "pass")): ("generated", "pass"),
            ("/upload", ("cookie", "session")): ("linked", "session"),
            ("/upload", ("form", "name")): ("target", None),
            ("/files/f93a1c", ("cookie", "session")): ("linked", "session"),
            ("/files/f93a1c", ("path", 1)): ("linked", "id")})
        name = values[("/upload", ("form", "name"))]
        self.assertEqual(name["template"], "../../notes/{flag_id}.txt")
        self.assertEqual([(p["var"], p["role"]) for p in name["parts"]], [("flag_id", "target")])
        # Tied to the very session that stored the flag this anchor leaked.
        self.assertEqual(name["parts"][0]["evidence"]["basis"], contracts.BASIS_SAME_PUT)
        self.assertEqual({f["tick"] for f in name["parts"][0]["evidence"]["flag_ids"]}, {0})
        self.assertTrue(values[("/upload", ("cookie", "session"))]["session_cookie"])
        self.assertEqual(values[("/login", ("form", "user"))]["evidence"]["kind"], contracts.EDGE_REQUEST_REUSE)
        self.assertEqual(summary["flag_ids"]["status"], "available")
        self.assertEqual([p["tick"] for p in summary["flag_ids"]["leaked_flag_puts"]], [0])
        self.assertEqual(summary["flag_ids"]["matched_values"], 1)
        self.assertEqual(summary["state"], "computed")
        self.assertEqual({k: summary["counts"][k] for k in ("target", "linked", "generated", "unknown")},
                         {"target": 1, "linked": 3, "generated": 4, "unknown": 0})
        # The flag ID is a parameter, not a link: nothing reaches the checker.
        steps, _, _ = self.latest("/files/f93a1c")
        self.assertNotIn("ip:10.60.0.1", {s["source_key"] for s in steps})

    def test_without_flag_ids_nothing_is_a_target(self):
        self.ingest(F.notes_split_packets(clock=self.TICK1))
        self.trace()
        values, summary = self.roles("/files/f93a1c")
        self.assertNotIn("target", {v["role"] for v in values.values()})
        name = values[("/upload", ("form", "name"))]
        self.assertEqual((name["role"], name["template"]), ("unknown", "../../notes/{unknown}.txt"))
        self.assertEqual(summary["flag_ids"]["status"], "none")
        self.assertTrue(any("no flag-ID source" in n for n in summary["flag_ids"]["notes"]))
        self.assertEqual(values[("/register", ("form", "user"))]["role"], "generated")

    def test_imported_flag_ids_and_validity_window(self):
        self.ingest(F.notes_split_packets(clock=self.TICK1))
        self.flag_ids({"tick": 0, "value": "7731"})
        self.trace()
        values, summary = self.roles("/files/f93a1c")
        part = values[("/upload", ("form", "name"))]["parts"][0]
        # No checker session to tie it to, no validity rule: weakest basis, said so.
        self.assertEqual((part["role"], part["evidence"]["basis"]), ("target", contracts.BASIS_EARLIER))
        self.assertEqual(part["evidence"]["flag_ids"][0]["source"], "file")
        self.assertTrue(any("flag_validity_ticks" in n for n in summary["flag_ids"]["notes"]))

        trace = self.profile("/files/f93a1c")["id"]
        for validity, expected in ((1, None), (2, contracts.BASIS_WINDOW)):
            with self.subTest(validity=validity):
                raw = raw_config()
                raw["game"]["flag_validity_ticks"] = validity
                cfg = Config(raw)
                self.repo(cfg).enqueue_retrace(trace, f"validity-{validity}")
                worker.run_once(self.db_path, cfg)
                values, summary = self.roles("/files/f93a1c")
                name = values[("/upload", ("form", "name"))]
                if expected is None:
                    # Tick 0's flag ID is no longer valid in tick 1: not a target,
                    # and the refusal is visible.
                    self.assertEqual(name["role"], "unknown")
                    self.assertEqual(summary["flag_ids"]["refused"],
                                     [{"value_preview": "7731", "reasons": ["flag_id_outside_validity_window"]}])
                else:
                    self.assertEqual(name["parts"][0]["evidence"]["basis"], expected)

    def test_other_teams_flag_ids_are_not_this_teams_targets(self):
        self.ingest(F.notes_split_packets(clock=self.TICK1))
        self.flag_ids({"tick": 0, "value": "7731", "owner_team_id": "team-05"})
        self.trace()
        values, summary = self.roles("/files/f93a1c")
        self.assertEqual(values[("/upload", ("form", "name"))]["role"], "unknown")
        self.assertEqual(summary["flag_ids"]["status"], "none_for_scope")

    def test_short_flag_id_from_parsed_fields(self):
        # One character is below every token threshold, so it is not in the
        # token table at all; it is matched on the parsed request.
        self.ingest(F.step_chain(53201, self.TICK1, [(F.request("/note?id=7"), F.response(b"FLAG{short_id}"))]))
        self.flag_ids({"tick": 1, "value": "7"})
        self.trace()
        values, _ = self.roles("/note")
        short = values[("/note", ("query", "id"))]
        self.assertEqual((short["role"], short["var"], short["token_id"]), ("target", "flag_id", None))
        self.assertTrue(short["ambiguous"])
        self.assertTrue(short["evidence"]["short"])

    def test_flag_id_inside_base64_and_jwt(self):
        self.ingest(F.encoded_target_packets(clock=self.TICK1))
        self.flag_ids({"tick": 1, "value": "7731"})
        self.trace()
        values, _ = self.roles("/read")
        b64 = values[("/read", ("query", "f"))]
        self.assertEqual((b64["role"], b64["template"], b64["transform"]),
                         ("target", "/notes/{flag_id}.txt", ["base64"]))
        values, _ = self.roles("/jwtread")
        jwt = values[("/jwtread", ("header", "authorization"))]
        self.assertEqual((jwt["role"], jwt["unresolved"], jwt["template"]), ("target", "jwt_unverified", None))
        self.assertEqual(jwt["evidence"]["claim"], "note")

    def test_flag_id_in_raw_tcp_payload(self):
        raw = raw_config()
        raw["services"].append({"name": "vault", "port": 9000, "proto": "tcp", "layer": "l4-raw"})
        self.reconfigure(raw)
        c = F.Connection(port=53401, clock=self.TICK1, service=9000)
        c.send(b"GET_NOTE 7731\n")
        c.send(b"FLAG{raw_vault}\n", server=True)
        c.close()
        self.ingest(c.packets)
        import_flagids(self.store, [{"tick": 1, "service": "vault", "owner_team_id": "team-01", "value": "7731"}])
        self.trace()
        run = self.one("SELECT latest_run_id FROM trace_profiles")
        rows = self.q("SELECT role,var,location FROM trace_values WHERE run_id=?", run)
        self.assertEqual([(r["role"], r["var"], json.loads(r["location"])) for r in rows],
                         [("target", "flag_id", ["req", "body", 9, 13])])

    def test_constant_payloads_are_not_listed(self):
        # Dataset A shape: a base64 path read with no login. The parameter is
        # an encoding of words, sent the same way every time: a constant.
        self.ingest(F.image_sharing_packets(reads=2))
        self.trace()
        for run in [r[0] for r in self.q("SELECT latest_run_id FROM trace_profiles")]:
            with self.subTest(run=run):
                self.assertEqual(self.one("SELECT count(*) FROM trace_values WHERE run_id=?", run), 0)
                summary = json.loads(self.one("SELECT analysis FROM trace_runs WHERE id=?", run))["value_roles"]
                self.assertGreater(summary["counts"]["constant"], 0)

    def test_graphql_echo_and_query_text(self):
        # Seen on the real dataset B: query texts read as "unknown" identifiers,
        # and the username echoed by signup made login look linked while the
        # signup's own username had no role at all.
        self.ingest(F.graphql_echo_packets())
        self.trace()
        run = self.one("SELECT latest_run_id FROM trace_profiles")
        rows = self.q("""SELECT v.role,v.var,v.location,v.evidence,t.ts_request FROM trace_values v
                         JOIN transactions t ON t.id=v.transaction_id WHERE v.run_id=? ORDER BY t.ts_request""", run)
        got = [(r["role"], r["var"], json.loads(r["location"])[1:]) for r in rows]
        self.assertEqual(got, [
            ("generated", "name", ["json", "variables", 0, "user", 0, "name", 0]),
            ("generated", "password", ["json", "variables", 0, "user", 0, "password", 0]),
            ("generated", "name", ["json", "variables", 0, "key", 0]),
            ("generated", "password", ["json", "variables", 0, "password", 0]),
            ("linked", "token", ["header", "authorization", 3])])
        self.assertTrue(json.loads(rows[2]["evidence"])["echoed_by_response"])
        # No query text is listed: each is a constant sent verbatim.
        self.assertFalse(any("query" in json.loads(r["location"]) for r in rows))

    def test_endpoint_words_are_not_echoed_values(self):
        # Seen on the real dataset A/B: a response field "image" was taken for
        # an echo of the word "image" in the request path /image-sharing/...,
        # which turned the anchor's own path into a template.
        self.ingest(F.step_chain(53601, 1000, [
            (F.request("/image-sharing/upload", "POST", b'{"name":"pic1a2b3c"}', F.JSON_CT),
             F.response(b'{"kind":"image","id":"pic1a2b3c"}', F.JSON_CT)),
            (F.request("/image-sharing/view", "POST", b'{"kind":"image","id":"pic1a2b3c"}', F.JSON_CT),
             F.response(b"FLAG{word_echo}")),
        ]))
        self.trace()
        values, _ = self.roles("/image-sharing/view")
        self.assertEqual({k: (v["role"], v["var"]) for k, v in values.items()}, {
            ("/image-sharing/upload", ("json", "name")): ("generated", "name"),
            ("/image-sharing/view", ("json", "kind")): ("linked", "kind"),
            ("/image-sharing/view", ("json", "id")): ("generated", "name")})

    def test_late_flag_ids_change_only_a_new_run(self):
        self.ingest(F.notes_split_packets(clock=self.TICK1))
        self.trace()
        first = self.profile("/files/f93a1c")["latest_run_id"]
        self.flag_ids({"tick": 0, "value": "7731"})
        self.repo().enqueue_retrace(self.profile("/files/f93a1c")["id"], "flag-ids-arrived")
        self.trace()
        second = self.profile("/files/f93a1c")["latest_run_id"]
        self.assertNotEqual(first, second)
        self.assertEqual(self.roles("/files/f93a1c", first)[0][("/upload", ("form", "name"))]["role"], "unknown")
        self.assertEqual(self.roles("/files/f93a1c", second)[0][("/upload", ("form", "name"))]["role"], "target")

    def test_runs_before_value_roles_are_not_computed(self):
        self.ingest(F.notes_split_packets())
        self.trace()
        profile = self.profile("/files/f93a1c")
        reader = Reader(self.store.db, self.cfg.game_id)
        body = routes.run_detail(reader, profile["id"], profile["latest_run_id"])
        self.assertEqual(body["value_roles"]["state"], "computed")
        self.assertTrue(body["value_roles"]["values"])
        # What an engine before p2.4.0 committed: no summary, no rows.
        run = profile["latest_run_id"]
        analysis = json.loads(self.one("SELECT analysis FROM trace_runs WHERE id=?", run))
        del analysis["value_roles"]
        with self.store.db:
            self.store.db.execute("UPDATE trace_runs SET analysis=? WHERE id=?", (json.dumps(analysis), run))
            self.store.db.execute("DELETE FROM trace_values WHERE run_id=?", (run,))
        body = routes.run_detail(reader, profile["id"], run)
        self.assertEqual(body["value_roles"], contracts.NOT_COMPUTED)


class LifecycleTests(TraceBase):
    """A7, A8, A10 and A12: identity, leases, crashes, retrace and budgets."""

    def counts(self):
        return tuple(self.one(f"SELECT count(*) FROM {t}") for t in ("trace_profiles", "trace_jobs", "trace_runs"))

    def test_seed_mode_says_linking_was_not_computed(self):
        self.ingest(F.notes_split_packets())
        self.trace(mode="seed")
        steps, edges, run = self.latest("/files/f93a1c")
        self.assertEqual(run["state"], contracts.RUN_SEED_ONLY)
        self.assertEqual([s["role"] for s in steps], [contracts.ROLE_ANCHOR])
        self.assertEqual(edges, [])
        self.assertEqual(run["analysis"]["linking"], contracts.NOT_COMPUTED)

    def test_a7_replayed_capture_and_retrace_identity(self):
        self.ingest(F.notes_split_packets())
        self.trace()
        self.assertEqual(self.counts(), (1, 1, 1))
        first = self.profile("/files/f93a1c")
        old = self.view(first["latest_run_id"])
        # Replay the same capture: nothing new to dispatch or run.
        self.ingestor.close()
        self.ingest(None)
        self.trace()
        self.assertEqual(self.counts(), (1, 1, 1))
        repo = self.repo()
        a = repo.enqueue_retrace(first["id"], "k1")
        again = repo.enqueue_retrace(first["id"], "k1")
        self.assertEqual((a["job_id"], a["request_sequence"], a["created"]), (again["job_id"], 2, True))
        self.assertFalse(again["created"])
        b = repo.enqueue_retrace(first["id"], "k2")
        self.assertEqual(b["request_sequence"], 3)
        self.assertIsNone(repo.enqueue_retrace("0" * 64, "k3"))
        self.trace()
        self.assertEqual(self.counts(), (1, 3, 3))
        profile = self.profile("/files/f93a1c")
        self.assertEqual(profile["latest_run_sequence"], 3)
        # The earlier result is untouched by the new runs.
        self.assertEqual(self.view(first["latest_run_id"]), old)

    def test_linked_run_without_scripts_is_backfilled_once(self):
        self.ingest(F.notes_split_packets())
        self.trace()
        first = self.profile("/files/f93a1c")
        old_run = first["latest_run_id"]
        self.assertEqual(self.one("SELECT count(*) FROM trace_script_artifacts WHERE run_id=?", old_run), 5)

        # Model a linked run created before P2.5. It stays immutable; the
        # automatic backfill creates a new analysis result with artifacts.
        self.store.db.execute("DELETE FROM trace_script_artifacts WHERE run_id=?", (old_run,))
        self.store.db.commit()
        out = self.trace()
        self.assertEqual(out["script_backfill"]["jobs_created"], 1)
        current = self.profile("/files/f93a1c")
        self.assertNotEqual(current["latest_run_id"], old_run)
        self.assertEqual(current["latest_run_sequence"], 2)
        self.assertEqual(self.one("SELECT count(*) FROM trace_script_artifacts WHERE run_id=?", old_run), 0)
        self.assertEqual(self.one("SELECT count(*) FROM trace_script_artifacts WHERE run_id=?",
                                  current["latest_run_id"]), 5)
        self.assertEqual(self.one("SELECT trigger_key FROM trace_jobs WHERE request_sequence=2"),
                         "auto:scripts:" + EXPORTER_VERSION)

        # Polling and restart-safe: the versioned trigger cannot enqueue twice.
        again = self.trace()
        self.assertEqual(again["script_backfill"]["jobs_created"], 0)
        self.assertEqual(self.counts(), (1, 2, 2))

    def run_child(self, when):
        result = subprocess.run([sys.executable, "-c", CRASH_CHILD, str(RUNTIME), str(self.db_path),
                                 json.dumps(self.raw), when], capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 3, result.stderr.decode()[-2000:])

    def test_a7_crash_before_commit(self):
        self.ingest(F.notes_split_packets())
        self.run_child("before")
        job = self.q("SELECT * FROM trace_jobs")[0]
        self.assertEqual((job["status"], job["attempts"]), (contracts.JOB_RUNNING, 1))
        self.assertEqual(self.one("SELECT count(*) FROM trace_runs"), 0)
        # Before the lease runs out nobody may take the job over.
        self.assertEqual(self.trace()["processed"], [])
        self.store.db.execute("UPDATE trace_jobs SET lease_until=0")
        self.store.db.commit()
        out = self.trace()
        self.assertEqual(out["reclaimed"], 1)
        self.assertEqual([p["status"] for p in out["processed"]], ["done"])
        self.assertEqual(self.counts(), (1, 1, 1))
        self.assertEqual(self.one("SELECT attempts FROM trace_jobs"), 2)

    def test_a7_crash_after_commit(self):
        self.ingest(F.notes_split_packets())
        self.run_child("after")
        self.assertEqual(self.one("SELECT status FROM trace_jobs"), contracts.JOB_DONE)
        self.assertEqual(self.trace()["processed"], [])
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_a8_stale_lease_cannot_commit(self):
        self.ingest(F.notes_split_packets())
        a, b = self.repo(worker_id="a"), self.repo(worker_id="b")
        a.dispatch_pending()
        job_a = a.claim()
        with a.snapshot():
            result_a = Engine(a, self.cfg).analyse(self.profile("/files/f93a1c")["anchor_transaction_id"])
        # A pauses past its lease; B reclaims and finishes the job.
        self.store.db.execute("UPDATE trace_jobs SET lease_until=0")
        self.store.db.commit()
        self.assertEqual(b.reclaim_expired(), 1)
        self.assertEqual(worker.Worker(b, self.cfg).process_one()["status"], "done")
        self.assertEqual(a.commit_result(job_a, result_a), {"committed": False, "reason": "lease lost"})
        self.assertEqual(a.release(job_a, "late failure"), "lost")
        self.assertEqual(self.counts(), (1, 1, 1))
        job = self.q("SELECT * FROM trace_jobs")[0]
        self.assertEqual((job["status"], job["error"], job["attempts"]), (contracts.JOB_DONE, None, 2))

    def test_a8_latest_pointer_never_moves_back(self):
        self.ingest(F.notes_split_packets())
        self.trace()
        trace = self.profile("/files/f93a1c")["id"]
        repo = self.repo()
        older = repo.enqueue_retrace(trace, "older")
        newer = repo.enqueue_retrace(trace, "newer")
        # The older request is held back and finishes last.
        self.store.db.execute("UPDATE trace_jobs SET available_at=? WHERE id=?", (time.time() + 3600, older["job_id"]))
        self.store.db.commit()
        self.trace()
        self.assertEqual(self.profile("/files/f93a1c")["latest_run_sequence"], newer["request_sequence"])
        self.store.db.execute("UPDATE trace_jobs SET available_at=0 WHERE id=?", (older["job_id"],))
        self.store.db.commit()
        self.trace()
        profile = self.profile("/files/f93a1c")
        self.assertEqual(profile["latest_run_sequence"], newer["request_sequence"])
        self.assertEqual(profile["latest_run_id"], contracts.run_id(newer["job_id"]))
        self.assertEqual(self.counts(), (1, 3, 3))

    def test_a8_failing_job_is_bounded_and_others_continue(self):
        self.ingest(F.multi_flag_packets())
        bad = self.one("SELECT id FROM transactions WHERE path='/files/both'")
        original = Engine.analyse

        def analyse(engine, anchor_id):
            if anchor_id == bad:
                raise RuntimeError("injected")
            return original(engine, anchor_id)

        with mock.patch.object(Engine, "analyse", analyse):
            for _ in range(5):
                self.trace()
                self.store.db.execute("UPDATE trace_jobs SET available_at=0 WHERE status='pending'")
                self.store.db.commit()
        jobs = {r["path"]: r for r in self.q("""SELECT t.path,j.status,j.attempts,j.error FROM trace_jobs j
                   JOIN trace_profiles p ON p.id=j.trace_id JOIN transactions t ON t.id=p.anchor_transaction_id""")}
        self.assertEqual(jobs["/files/third"]["status"], contracts.JOB_DONE)
        self.assertEqual((jobs["/files/both"]["status"], jobs["/files/both"]["attempts"]),
                         (contracts.JOB_FAILED, self.cfg.options["trace"]["max_attempts"]))
        self.assertIn("injected", jobs["/files/both"]["error"])
        # A failed request keeps no result; a new one can still succeed.
        self.repo().enqueue_retrace(self.profile("/files/both")["id"], "after-fix")
        self.trace()
        self.assertIsNotNone(self.profile("/files/both")["latest_run_id"])

    def test_a8_busy_database_degrades_then_recovers(self):
        self.ingest(F.notes_split_packets())
        repo = self.repo(timeout=0.2)
        blocker = sqlite3.connect(self.db_path, timeout=0.2, isolation_level=None)
        self.addCleanup(blocker.close)
        blocker.execute("BEGIN IMMEDIATE")
        with self.assertRaises(sqlite3.OperationalError):
            worker.Worker(repo, self.cfg).tick()
        # The serving loop owns its connection, as in the `trace` command.
        stop, holder = threading.Event(), {}

        def serve():
            own = Repository.open(self.db_path, self.cfg, timeout=0.2)
            holder["worker"] = worker.Worker(own, self.cfg, stop=stop)
            try:
                holder["worker"].serve()
            finally:
                own.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            self.wait_for(lambda: "worker" in holder and holder["worker"].state["state"] == "degraded")
            blocker.execute("ROLLBACK")
            self.wait_for(lambda: holder["worker"].state["jobs_done"] == 1)
            self.wait_for(lambda: holder["worker"].state["state"] == "running")
        finally:
            stop.set()
            thread.join(10)
        self.assertEqual(self.counts(), (1, 1, 1))

    def wait_for(self, condition, seconds=10):
        deadline = time.monotonic() + seconds
        while not condition():
            self.assertLess(time.monotonic(), deadline, "condition not reached")
            time.sleep(0.05)

    def test_backlog_is_worked_in_slices_with_heartbeats(self):
        # A backlog used to be drained in one pass with no heartbeat in between,
        # so the worker read as dead (stale) exactly while it was busiest, and
        # new flag-outs waited for the whole pass. 10 jobs x 0.2 s = 2 s.
        self.ingest(F.image_sharing_packets(reads=10))
        repo = self.repo()
        beats = []
        publish = repo.publish_worker_status
        repo.publish_worker_status = lambda data: (beats.append(time.monotonic()), publish(data))
        real = Engine.analyse

        def slow(engine, anchor):
            time.sleep(0.2)
            return real(engine, anchor)
        w = worker.Worker(repo, self.cfg, slice_seconds=0.5)
        threading.Timer(3.5, w.stop.set).start()
        with mock.patch.object(Engine, "analyse", slow):
            w.serve()
        self.assertEqual(self.one("SELECT count(*) FROM trace_jobs WHERE status='done'"), 10)
        # Busy slices publish every ~0.5-0.7 s; idle polls every poll_seconds (1 s).
        self.assertLess(max(b - a for a, b in zip(beats, beats[1:])), 1.5)

    def test_a10_late_transaction_needs_a_new_run(self):
        self.ingest(F.stalled_register_packets(), finalize=False)
        self.trace()
        first = self.profile("/files/st0123ff")
        steps, edges, run = self.view(first["latest_run_id"])
        self.assertNotIn(("POST", "/register"), {s["step"] for s in steps})
        self.assertEqual(self.unexplained(run)["stuser001"], "no_source_in_scope")
        before = self.view(first["latest_run_id"])
        # The registration lands once its connection ends. Nothing reruns on
        # its own: the profile still shows the first result until asked.
        self.ingest(None, finalize=True)
        self.trace()
        self.assertEqual(self.profile("/files/st0123ff")["latest_run_id"], first["latest_run_id"])
        self.repo().enqueue_retrace(first["id"], "late-register")
        self.trace()
        steps, edges, run = self.latest("/files/st0123ff")
        self.assertIn((("POST", "/register"), "form", ("POST", "/login"), "form", "request_reuse"),
                      self.meanings(edges))
        self.assertEqual(self.view(first["latest_run_id"]), before)

    def budget_run(self, **limits):
        cfg = Config(raw_config(**limits))
        self.trace()
        trace = self.profile("/files/f93a1c")["id"]
        self.repo(cfg).enqueue_retrace(trace, json.dumps(limits, sort_keys=True))
        # Executed by a worker on the default config: the job's own snapshot
        # decides the limits, and the run records the one it used.
        self.trace()
        steps, edges, run = self.latest("/files/f93a1c")
        self.assertEqual(run["algorithm_hash"], cfg.algorithm_hash())
        self.assertEqual(run["analysis"]["algorithm_config"], cfg.algorithm_config())
        return steps, edges, run

    def test_a12_budgets_cut_results_visibly(self):
        self.ingest(F.notes_split_packets())
        for limits, name in (({"max_query_rows": 5}, contracts.LIMIT_QUERY_ROWS),
                             ({"max_depth": 1}, contracts.LIMIT_DEPTH),
                             ({"max_nodes": 2}, contracts.LIMIT_NODES),
                             ({"max_edges": 1}, contracts.LIMIT_EDGES),
                             ({"max_tokens_per_node": 1}, contracts.LIMIT_TOKENS)):
            with self.subTest(limit=name):
                steps, edges, run = self.budget_run(**limits)
                self.assertEqual(run["state"], contracts.RUN_PARTIAL)
                self.assertIn(name, run["coverage"]["limits_hit"])
                self.assertTrue(any(name in w for w in run["warnings"]))
                self.assertLessEqual(len(steps), max(2, limits.get("max_nodes", 64)))
                # A cut result never holds an edge to a step it does not show.
                shown = {r[0] for r in self.q("SELECT transaction_id FROM trace_steps WHERE run_id=?", run["id"])}
                for edge in self.q("SELECT src_transaction_id,dst_transaction_id FROM trace_edges WHERE run_id=?",
                                   run["id"]):
                    self.assertLessEqual({edge[0], edge[1]}, shown)

    def test_a12_deadline(self):
        self.ingest(F.notes_split_packets())
        clock = iter(range(0, 10**6, 1))
        with mock.patch("flagtrace.app.trace.engine.time.monotonic", side_effect=lambda: next(clock)):
            self.trace()
        _, _, run = self.latest("/files/f93a1c")
        self.assertEqual(run["state"], contracts.RUN_PARTIAL)
        self.assertIn(contracts.LIMIT_DEADLINE, run["coverage"]["limits_hit"])

    def test_a12_analysis_holds_no_write_lock(self):
        self.ingest(F.notes_split_packets())
        writes = []
        original = Repository.consumed_tokens

        def probe(repo, *args, **kw):
            other = sqlite3.connect(self.db_path, timeout=0, isolation_level=None)
            try:
                other.execute("BEGIN IMMEDIATE")
                other.execute("ROLLBACK")
                writes.append(True)
            finally:
                other.close()
            return original(repo, *args, **kw)

        with mock.patch.object(Repository, "consumed_tokens", probe):
            self.trace()
        self.assertTrue(writes)
        self.assertEqual(self.latest("/files/f93a1c")[2]["state"], contracts.RUN_LINKED)


class SchemaConfigTests(TraceBase):
    def test_phase1_database_migrates_and_keeps_queue(self):
        self.ingest(F.notes_split_packets())
        self.ingestor.close()
        self.store.close()
        db = sqlite3.connect(self.db_path)
        for table in ("trace_replay_verifications", "trace_script_artifacts", "trace_values", "trace_edges",
                      "trace_steps", "trace_runs", "trace_jobs", "trace_profiles",
                      "trace_runtime_status", "pcap_rejects", "runtime_settings", "trace_groups", "trace_suspects"):
            db.execute(f"DROP TABLE {table}")
        db.execute("DROP INDEX flag_ids_value")
        db.execute("ALTER TABLE pcap_files DROP COLUMN attempts")
        db.execute("ALTER TABLE pcap_files DROP COLUMN decoder_mode")
        db.execute("DELETE FROM schema_version")
        db.execute("INSERT INTO schema_version VALUES(2)")
        db.commit()
        db.close()
        with self.assertRaisesRegex(ValueError, "migrate"):
            migrations.open_initialized(self.db_path)
        for expected in ([3, 4, 5, 6, 7], []):
            db = migrations.connect(self.db_path)
            try:
                self.assertEqual(migrations.upgrade(db)["applied"], expected)
            finally:
                db.close()
        self.store = Store(self.db_path, self.cfg)
        self.ingestor = Ingestor(self.store, self.root)
        # Captures ingested before v5 were decoded in full and say nothing.
        self.assertEqual(self.one("SELECT count(*) FROM pcap_files WHERE decoder_mode IS NULL"),
                         self.one("SELECT count(*) FROM pcap_files"))
        self.assertEqual(self.one("SELECT count(*) FROM trace_queue WHERE status='pending'"), 1)
        self.assertEqual(self.one("SELECT count(*) FROM transactions"), 4)
        self.trace()
        self.assertEqual(self.one("SELECT count(*) FROM trace_runs"), 1)
        self.assertEqual(self.one("SELECT count(*) FROM trace_queue WHERE status='dispatched'"), 1)

    def test_trace_config_validation(self):
        for trace, message in (({"same_service_only": False}, "same_service_only"),
                               ({"lease_seconds": 1, "algorithm_budget_ms": 1000}, "lease_seconds"),
                               ({"bogus": 1}, "unknown"),
                               ({"max_depth": 0}, "max_depth"),
                               ({"max_context": 8}, "no longer used"),
                               ({"burst_gap_seconds": 3}, "no longer used"),
                               ({"token_max_df": 0}, "token_max_df")):
            with self.subTest(trace=trace), self.assertRaisesRegex(ValueError, message):
                Config(raw_config(**trace))
        raw = F.config()
        raw["flagtrace"]["enabled"] = False
        with self.assertRaisesRegex(ValueError, "requires flagtrace.enabled"):
            validate_optional(raw)
        raw = F.config()
        del raw["flagtrace"]["trace"]
        self.assertFalse(Config(raw).options["trace"]["enabled"])
        # Operational settings do not change what an analysis means.
        base = Config(raw_config()).algorithm_hash()
        self.assertEqual(Config(raw_config(poll_seconds=7, lease_seconds=90, max_attempts=9)).algorithm_hash(), base)
        self.assertNotEqual(Config(raw_config(max_depth=3)).algorithm_hash(), base)

    def cli(self, *args, env=None):
        (self.root / "services.json").write_text(json.dumps(self.raw))
        return subprocess.run([sys.executable, "-m", "flagtrace.app.main", "--config", str(self.root / "services.json"),
                               *args, "--db", str(self.db_path)], cwd=RUNTIME, capture_output=True, timeout=60,
                              env={**os.environ, **(env or {})})

    def test_migrate_command_checks_and_backs_up(self):
        self.ingest(F.notes_split_packets())
        self.ingestor.close()
        self.store.close()
        self.assertEqual(self.cli("migrate", "--check").returncode, 0)
        db = sqlite3.connect(self.db_path)
        db.execute("DROP TABLE trace_profiles")
        db.execute("DELETE FROM schema_version")
        db.execute("INSERT INTO schema_version VALUES(2)")
        db.commit()
        db.close()
        check = self.cli("migrate", "--check")
        self.assertEqual((check.returncode, json.loads(check.stdout)["needed"]), (3, True))
        done = self.cli("migrate", "--backup-dir", str(self.root / "backups"))
        self.assertEqual(done.returncode, 0, done.stderr.decode()[-1000:])
        result = json.loads(done.stdout)
        self.assertEqual(result["applied"], [3, 4, 5, 6, 7])
        copy = sqlite3.connect(result["backup"])
        self.assertEqual(copy.execute("SELECT max(version) FROM schema_version").fetchone()[0], 2)
        self.assertEqual(copy.execute("SELECT count(*) FROM transactions").fetchone()[0], 4)
        copy.close()
        self.assertEqual(self.cli("migrate", "--check").returncode, 0)
        self.store = Store(self.db_path, self.cfg)
        self.ingestor = Ingestor(self.store, self.root)

    def test_worker_health_command(self):
        env = {"FLAGTRACE_WORKER_ID": "w1"}
        self.assertEqual(self.cli("worker-health", env=env).returncode, 1)
        self.repo(worker_id="w2").publish_worker_status({"state": "running", "poll_seconds": 1})
        self.assertEqual(self.cli("worker-health", env=env).returncode, 1)
        self.repo(worker_id="w1").publish_worker_status({"state": "running", "poll_seconds": 1})
        self.assertEqual(self.cli("worker-health", env=env).returncode, 0)
        self.store.db.execute("UPDATE trace_runtime_status SET updated=0 WHERE worker_id='w1'")
        self.store.db.commit()
        self.assertEqual(self.cli("worker-health", env=env).returncode, 1)

    def test_worker_needs_migrated_database(self):
        empty = self.root / "empty.sqlite3"
        with self.assertRaisesRegex(ValueError, "migrate"):
            Repository.open(empty, self.cfg)


class CaptureGapTests(TraceBase):
    def test_unreadable_capture_does_not_block_others(self):
        (self.root / "0-bad.pcap").write_bytes(b"not a capture at all")
        status = self.ingest(F.notes_split_packets(), name="1-good.pcap")
        self.assertEqual(status["state"], "degraded")
        self.assertTrue(any("0-bad.pcap" in x for x in status["rejected_captures"]))
        self.assertEqual(self.one("SELECT count(*) FROM transactions"), 4)
        status = self.ingest(None)
        self.assertTrue(any("already rejected" in x for x in status["rejected_captures"]))
        self.assertEqual(self.one("SELECT count(*) FROM pcap_rejects"), 1)
        self.trace()
        _, _, run = self.latest("/files/f93a1c")
        self.assertEqual(run["coverage"]["ingest_gaps"]["rejected_files"], 1)
        self.assertTrue(any("capture file" in w for w in run["warnings"]))

    def test_broken_records_stop_retrying_and_tail_continues(self):
        F.write_pcap(self.root / "0-cut.pcap", F.noise_packets())
        with (self.root / "0-cut.pcap").open("ab") as f:
            f.write(b"\x00" * 8 + b"\xff\x00\x00\x00" * 2 + b"short")
        limit = self.cfg.options["max_file_attempts"]
        for _ in range(limit + 2):
            status = self.ingest(F.notes_split_packets(clock=2_000_000), name="1-good.pcap")
            self.ingestor.close()
        cut = self.q("SELECT status,attempts FROM pcap_files ORDER BY ordinal")[0]
        self.assertEqual((cut["status"], cut["attempts"]), ("error", limit))
        self.assertEqual(self.one("SELECT count(*) FROM transactions WHERE path='/files/f93a1c'"), 1)
        self.trace()
        _, _, run = self.latest("/files/f93a1c")
        self.assertEqual(run["coverage"]["ingest_gaps"]["error_files"], 1)


class ApiTests(TraceBase):
    """P2.2/P2.3 routes over real HTTP, as the dashboard proxy calls them."""

    def serve(self, cfg=None):
        server = make_server(self.db_path, self.cfg.game_id, "127.0.0.1", 0, cfg=cfg or self.cfg)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def call(self, base, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(base + path, data=data, method="POST" if body is not None else "GET",
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def test_list_detail_runs_and_evidence(self):
        self.ingest(F.two_scripts_packets())
        self.trace()
        base = self.serve()
        status, page = self.call(base, "/traces?limit=1")
        self.assertEqual((status, page["total"], len(page["items"])), (200, 2, 1))
        first = page["items"][0]
        self.assertEqual(first["path"], "/files/f2bbbb")  # newest anchor first
        self.assertEqual(first["display_state"], contracts.RUN_LINKED)
        self.assertEqual(first["flag_count"], 1)
        status, rest = self.call(base, "/traces?limit=1&cursor=" + page["next_cursor"])
        self.assertEqual([i["path"] for i in rest["items"]], ["/files/f1aaaa"])
        self.assertIsNone(rest["next_cursor"])
        self.assertEqual(self.call(base, "/traces?source_key=ip:10.9.9.9")[1]["total"], 0)
        self.assertEqual(self.call(base, "/traces?state=linked")[1]["total"], 2)
        # The flow only: three linked steps plus the anchor.
        run_summary = first["latest_run"]
        self.assertEqual(run_summary["linked_count"], 3)
        self.assertEqual(run_summary["edge_count"], 5)
        self.assertEqual(run_summary["step_count"], 4)

        trace = first["trace_id"]
        status, detail = self.call(base, f"/traces/{trace}")
        self.assertEqual(detail["anchor"]["flags_found"], ["FLAG{second_script}"])
        self.assertTrue(detail["latest_run"]["is_latest"])
        run = detail["latest_run"]["run_id"]
        status, history = self.call(base, f"/traces/{trace}/runs")
        self.assertEqual([r["run_id"] for r in history["items"]], [run])
        status, body = self.call(base, f"/traces/{trace}/runs/{run}")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], contracts.RUN_LINKED)
        self.assertEqual({s["role"] for s in body["steps"]}, {"anchor", "data_linked"})
        for name in set(contracts.EXTENSION_SECTIONS) - {"value_roles", "scripts", "grouping", "suspects"}:
            self.assertEqual(body[name], contracts.NOT_COMPUTED)
        # Every step carries what the dashboard needs to find the same
        # exchange in Tulip. No flow ID is stored: the match is made at
        # display time, so a reimported capture cannot leave a stale one here.
        for step in body["steps"]:
            net = step["network"]
            self.assertEqual(net["dst_port"], 8080)
            self.assertEqual(net["src_ip"], "10.60.5.1")
            self.assertEqual(net["ts_request"], step["summary"]["ts_request"])
            self.assertTrue(net["src_port"] and net["dst_ip"])
        # P2.4b: the two scripts of this fixture have the same shape (new
        # session, user and file ID each), so both profiles share one group.
        self.assertEqual((body["grouping"]["state"], body["grouping"]["now"]["profiles"]), ("computed", 2))
        self.assertEqual((body["suspects"]["state"], body["suspects"]["steps"]), ("no_baseline", []))
        self.assertEqual(body["scripts"]["state"], "computed")
        self.assertEqual(len(body["scripts"]["artifacts"]), len(body["steps"]) + 1)
        chain = next(a for a in body["scripts"]["artifacts"] if a["kind"] == "chain")
        status, artifact = self.call(base, f"/traces/{trace}/runs/{run}/scripts/{chain['artifact_id']}")
        self.assertEqual((status, artifact["content_hash"], artifact["support"]),
                         (200, chain["content_hash"], chain["support"]))
        self.assertIn("def exploit(host, flag_id=None, port=None):", artifact["content"])
        # No flag-ID source in this fixture: classified, and it says so.
        self.assertEqual(body["value_roles"]["state"], "computed")
        self.assertEqual(body["value_roles"]["flag_ids"]["status"], "none")
        self.assertNotIn(contracts.VALUE_TARGET, {v["role"] for v in body["value_roles"]["values"]})
        edge = next(e for e in body["edges"] if e["dst_location"][1] == "path")
        self.assertEqual(edge["src_location"], ["resp", "json", "id", 0])

        # Evidence of the source step, in the context of this run.
        status, ev = self.call(base, f"/transactions/{edge['src_transaction_id']}/evidence?run_id={run}")
        self.assertEqual(status, 200)
        reps = {r["id"]: r for r in ev["representations"]}
        self.assertIn(edge["src_representation_id"], reps)
        self.assertIn(b'"f2bbbb"', base64.b64decode(reps[edge["src_representation_id"]]["data_base64"]))
        token = next(t for t in ev["tokens"] if t["id"] == edge["src_token_id"])
        self.assertEqual(token["location"], edge["src_location"])
        self.assertTrue(ev["response"]["available"])

        # Relations are checked, not just the shape of the IDs.
        other = self.call(base, "/traces")[1]["items"][1]
        self.assertEqual(self.call(base, f"/traces/{other['trace_id']}/runs/{run}")[0], 404)
        # The two scripts share no value, so neither anchor is a step of the
        # other's run.
        other_run = other["latest_run"]["run_id"]
        self.assertEqual(self.call(base, f"/transactions/{first['anchor_transaction_id']}/evidence?run_id={other_run}")[0], 404)
        self.assertEqual(self.call(base, f"/transactions/{other['anchor_transaction_id']}/evidence?run_id={run}")[0], 404)
        self.assertEqual(self.call(base, "/traces/" + "0" * 64)[0], 404)
        self.assertEqual(self.call(base, "/traces/not-an-id")[0], 404)
        self.assertEqual(self.call(base, "/traces?limit=x")[0], 400)
        # The Phase 1 route keeps working next to the new one.
        self.assertEqual(self.call(base, f"/transactions/{other['anchor_transaction_id']}")[0], 200)

    def test_context_rows_of_older_runs_are_hidden(self):
        # Engines before p2.3.2 also stored nearby traffic as 'context' steps.
        # Those runs stay in the history, but are read as the flow only.
        self.ingest(sorted(F.notes_split_packets() + F.noise_packets()))
        self.trace()
        run = self.profile("/files/f93a1c")["latest_run_id"]
        noise = self.one("SELECT id FROM transactions WHERE path='/static/app.js'")
        with self.store.db:
            self.store.db.execute("""INSERT INTO trace_steps(run_id,transaction_id,position,role,reasons,quality,summary)
                                     VALUES(?,?,0,'context','["burst"]','[]','{}')""", (run, noise))
        base = self.serve()
        item = self.call(base, "/traces")[1]["items"][0]
        self.assertEqual(item["latest_run"]["step_count"], 4)
        body = self.call(base, f"/traces/{item['trace_id']}/runs/{run}")[1]
        self.assertNotIn(noise, [s["transaction_id"] for s in body["steps"]])
        self.assertEqual(self.call(base, f"/traces/{item['trace_id']}/runs")[1]["items"][0]["step_count"], 4)
        self.assertEqual(self.call(base, f"/transactions/{noise}/evidence?run_id={run}")[0], 404)

    def test_retrace_route(self):
        self.ingest(F.notes_split_packets())
        self.trace()
        base = self.serve()
        trace = self.call(base, "/traces")[1]["items"][0]["trace_id"]
        status, job = self.call(base, f"/traces/{trace}/retrace", {"idempotency_key": "ui-1"})
        self.assertEqual((status, job["request_sequence"], job["created"]), (202, 2, True))
        status, again = self.call(base, f"/traces/{trace}/retrace", {"idempotency_key": "ui-1"})
        self.assertEqual((status, again["job_id"], again["created"]), (202, job["job_id"], False))
        self.assertEqual(self.call(base, f"/traces/{trace}")[1]["display_state"], contracts.JOB_PENDING)
        self.assertEqual(self.call(base, f"/traces/{trace}/retrace", {"idempotency_key": "a b"})[0], 400)
        self.assertEqual(self.call(base, f"/traces/{trace}/retrace", {})[0], 400)
        self.assertEqual(self.call(base, "/traces/" + "0" * 64 + "/retrace", {"idempotency_key": "x"})[0], 404)
        self.assertEqual(self.call(base, "/transactions", {"idempotency_key": "x"})[0], 404)
        self.trace()
        detail = self.call(base, f"/traces/{trace}")[1]
        self.assertEqual((detail["display_state"], detail["latest_run"]["request_sequence"]), ("linked", 2))
        self.assertEqual(self.call(base, f"/traces/{trace}/runs")[1]["total"], 2)
        # With the worker switched off nothing is enqueued to wait unseen.
        off = Config(raw_config(enabled=False))
        base_off = self.serve(off)
        self.assertEqual(self.call(base_off, f"/traces/{trace}/retrace", {"idempotency_key": "ui-2"})[0], 409)
        self.assertEqual(self.call(base_off, "/trace-status")[1]["state"], "disabled")

    def test_trace_status_and_pending_profiles(self):
        self.ingest(F.multi_flag_packets())
        base = self.serve()
        status, state = self.call(base, "/trace-status")
        self.assertEqual((state["state"], state["backlog"]["pending_dispatch"]), ("no_worker", 2))
        self.repo().dispatch_pending()
        items = self.call(base, "/traces")[1]["items"]
        # Waiting and failed profiles are listed with their state, not hidden.
        self.assertEqual({i["display_state"] for i in items}, {contracts.JOB_PENDING})
        self.assertTrue(all(i["latest_run"] is None for i in items))
        self.store.db.execute("UPDATE trace_jobs SET status='failed',error='boom'")
        self.store.db.commit()
        failed = self.call(base, "/traces?state=failed")[1]["items"]
        self.assertEqual([i["latest_request"]["error"] for i in failed], ["boom", "boom"])
        repo = self.repo()
        repo.publish_worker_status({"state": "running", "poll_seconds": 1})
        status, state = self.call(base, "/trace-status")
        self.assertEqual((state["state"], state["backlog"]["jobs"]["failed"]), ("running", 2))

    def test_captured_markup_is_returned_as_data(self):
        self.ingest(F.html_payload_packets())
        self.trace()
        base = self.serve()
        anchor = self.call(base, "/traces")[1]["items"][0]["anchor_transaction_id"]
        ev = self.call(base, f"/transactions/{anchor}/evidence")[1]
        body = next(r for r in ev["representations"] if r["side"] == "resp" and r["kind"] == "body")
        self.assertIn(b'<script>alert("xss")</script>', base64.b64decode(body["data_base64"]))
        login = self.one("SELECT id FROM transactions WHERE path LIKE '/login%'")
        ev = self.call(base, f"/transactions/{login}/evidence")[1]
        self.assertEqual(ev["request"]["parsed"]["query"], [["next", "/a"], ["next", "/b"]])
        self.assertEqual(ev["request"]["parsed"]["form"][0], ["user", "hxuser001"])
        self.assertEqual(ev["request"]["parsed"]["form"][2], ["user", "hxuser002"])

    def test_missing_response_and_storage_cut(self):
        raw = F.config()
        raw["flagtrace"]["max_body_stored"] = 64
        self.cfg = Config(raw)
        self.ingestor.close()
        self.store.close()
        self.db_path.unlink()
        self.store = Store(self.db_path, self.cfg)
        self.ingestor = Ingestor(self.store, self.root)
        c = F.Connection()
        c.send(F.request("/big"))
        c.send(F.response(b"A" * 500 + b"FLAG{cut_but_seen}"), server=True)
        c.close()
        d = F.Connection(port=51300, clock=100_000)
        d.send(b"POST /p HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort")
        d.close()
        self.ingest(c.packets + d.packets)
        base = self.serve()
        big = self.one("SELECT id FROM transactions WHERE path='/big'")
        ev = self.call(base, f"/transactions/{big}/evidence")[1]
        body = next(r for r in ev["representations"] if r["side"] == "resp" and r["kind"] == "body")
        self.assertTrue(body["storage_truncated"])
        self.assertEqual((body["stored_size"], body["original_size"]), (64, 518))
        self.assertIn("FLAG{cut_but_seen}", ev["flags_found"])
        cut = self.one("SELECT id FROM transactions WHERE path='/p'")
        ev = self.call(base, f"/transactions/{cut}/evidence")[1]
        self.assertFalse(ev["response"]["available"])
        self.assertIn("missing_response", ev["quality"])


class ContractTests(unittest.TestCase):
    def test_identities_are_separate_and_deterministic(self):
        trace = contracts.trace_id("game", "tx")
        job = contracts.job_id(trace, "ingest:tx")
        self.assertEqual(trace, contracts.trace_id("game", "tx"))
        self.assertNotEqual(trace, contracts.trace_id("other", "tx"))
        self.assertEqual(contracts.run_id(job), contracts.run_id(job))
        self.assertEqual(len({trace, job, contracts.run_id(job), "tx"}), 4)

    def test_extension_sections_are_declared_not_computed(self):
        anchor = contracts.Anchor(transaction_id="t", game_id="g", source_key="ip:1.2.3.4", team_id=None,
                                  service="s", tick=0, conn_id=None, seq_in_conn=0, ts_request=1, ts_response=2,
                                  method="GET", path="/", status=200, proto="http")
        dto = contracts.RunResult(state=contracts.RUN_SEED_ONLY, anchor=anchor).dto()
        for name in contracts.EXTENSION_SECTIONS:
            self.assertEqual(dto[name], contracts.NOT_COMPUTED)
        json.dumps(dto)


if __name__ == "__main__":
    unittest.main()
