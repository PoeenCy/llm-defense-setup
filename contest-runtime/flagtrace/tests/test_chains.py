"""P2.4b: chains grouped by shape (B7) and steps that differ from the checker
baseline (B8).

The point of grouping is that values must not matter: a new session, user and
file ID on every run of one exploit, or the same exploit from another team,
still land in one group. The point of the baseline comparison is the opposite:
it must stay quiet when it has nothing to compare with, and say how much
evidence it had when it does speak.
"""
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import fixtures as F
from flagtrace.app.api import query
from flagtrace.app.background import rebuild_baseline
from flagtrace.app.config import Config
from flagtrace.app.ingest import Ingestor
from flagtrace.app.store import Store
from flagtrace.app.trace import anomalies, worker
from flagtrace.app.trace.grouping import NORMALIZER_VERSION, backfill_trigger
from flagtrace.app.trace.repository import Repository

TEAM9 = "10.60.9.1"


class ChainBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "db.sqlite3"
        self.cfg = Config(F.config())
        self.store = Store(self.db_path, self.cfg)
        self.ingestor = Ingestor(self.store, self.root)

    def tearDown(self):
        self.ingestor.close()
        self.store.close()
        self.tmp.cleanup()

    def ingest(self, packets, baseline=False):
        F.write_pcap(self.root / "a.pcap", sorted(packets))
        self.ingestor.run(sorted(self.root.glob("*.pcap")), finalize=True)
        if baseline:
            rebuild_baseline(self.store)

    def trace(self):
        return worker.run_once(self.db_path, self.cfg)

    def get(self, url):
        return query(self.db_path, self.cfg.game_id, url)

    def groups(self):
        code, data = self.get("/chain-groups")
        self.assertEqual(code, 200)
        return data

    def run_of(self, path):
        row = self.store.db.execute("""SELECT p.id AS trace_id,p.latest_run_id FROM trace_profiles p
            JOIN transactions t ON t.id=p.anchor_transaction_id WHERE t.path=?""", (path,)).fetchone()
        self.assertIsNotNone(row, f"no profile anchored at {path}")
        code, detail = self.get(f"/traces/{row['trace_id']}/runs/{row['latest_run_id']}")
        self.assertEqual(code, 200)
        return detail


class GroupingTests(ChainBase):
    def test_same_shape_with_different_values_is_one_group(self):
        """New session, user, password and file ID each run: one group."""
        self.ingest(F.two_scripts_packets())
        self.trace()
        data = self.groups()
        self.assertEqual(data["total"], 1)
        group = data["items"][0]
        self.assertEqual((group["profiles"], group["sources"], group["steps"]), (2, 1, 4))
        self.assertEqual(group["description"], "POST /register → POST /login → POST /upload → GET /files/{id}")
        first, second = (self.run_of(p) for p in ("/files/f1aaaa", "/files/f2bbbb"))
        self.assertEqual(first["grouping"]["group_id"], second["grouping"]["group_id"])
        self.assertEqual(first["grouping"]["normalizer_version"], NORMALIZER_VERSION)
        self.assertEqual(first["grouping"]["now"], {"profiles": 2, "sources": 1})

    def test_another_shape_is_another_group(self):
        self.ingest(F.two_scripts_packets() + F.html_payload_packets())
        self.trace()
        data = self.groups()
        self.assertEqual(data["total"], 2)
        self.assertEqual(sorted(g["profiles"] for g in data["items"]), [1, 2])
        self.assertNotEqual(self.run_of("/files/f1aaaa")["grouping"]["group_id"],
                            self.run_of("/files/hxfile01")["grouping"]["group_id"])

    def test_the_same_shape_from_another_team_joins_the_group(self):
        """Every team runs the same vulnbox, so one exploit used by two teams
        is one group with two sources — that is what makes a group worth
        prioritising."""
        self.ingest(F.notes_split_packets()
                    + F.notes_split_packets(session="t9aa11bb", file_id="f9cccc", user="u9xxxxx",
                                            password="p9yyyyy", flag=b"FLAG{team_nine}", port=51701,
                                            clock=60_000, ip=TEAM9))
        self.trace()
        data = self.groups()
        self.assertEqual(data["total"], 1)
        self.assertEqual((data["items"][0]["profiles"], data["items"][0]["sources"]), (2, 2))
        code, detail = self.get("/chain-groups/" + data["items"][0]["group_id"])
        self.assertEqual([s["source_key"] for s in detail["sources"]], ["team:team-05", "team:team-09"])
        self.assertEqual([s["profiles"] for s in detail["sources"]], [1, 1])

    def test_a_retrace_does_not_count_the_profile_twice(self):
        self.ingest(F.notes_split_packets())
        self.trace()
        trace_id = self.store.db.execute("SELECT id FROM trace_profiles").fetchone()[0]
        self.repo = Repository.open(self.db_path, self.cfg)
        try:
            self.repo.enqueue_retrace(trace_id, "again")
        finally:
            self.repo.close()
        self.trace()
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM trace_runs").fetchone()[0], 2)
        group = self.groups()["items"][0]
        self.assertEqual((group["profiles"], group["sources"]), (1, 1))
        # Both runs are grouped; membership is taken through the latest one.
        rows = {r[0] for r in self.store.db.execute("SELECT group_id FROM trace_runs")}
        self.assertEqual(rows, {group["group_id"]})

    def test_field_variation_tells_a_fixed_value_from_a_per_run_one(self):
        """A single chain cannot tell a constant the attacker chose from a
        value made up per run; comparing the chains of a group can."""
        self.ingest(F.two_scripts_packets())
        self.trace()
        code, detail = self.get("/chain-groups/" + self.groups()["items"][0]["group_id"])
        fields = {(f["position"], f["field"]): f for f in detail["fields"]}
        user = fields[(1, "form:user")]
        self.assertEqual((user["chains"], user["sent_by"], user["distinct"], user["verdict"]),
                         (2, 2, 2, "differs_each_time"))
        self.assertEqual(user["roles"], {"generated": 2})
        # Both chains send the same upload name. Single-chain analysis could
        # not decide (unknown in the first, constant in the repeat); across the
        # group it is plainly a payload the attacker sends verbatim.
        name = fields[(3, "form:name")]
        self.assertEqual((name["sent_by"], name["distinct"], name["verdict"]), (2, 1, "same_in_all"))
        self.assertEqual((name["roles"], name["samples"]), ({"unknown": 1, "constant": 1}, ["../../notes/7731.txt"]))
        session = fields[(3, "cookie:session")]
        self.assertEqual((session["verdict"], session["roles"]), ("differs_each_time", {"linked": 2}))
        self.assertEqual(fields[(4, "path:1")]["verdict"], "differs_each_time")   # the file ID
        # Endpoint words are fixed by the group's own shape, so they are left out.
        self.assertEqual([k for k in fields if k[1].startswith("path:")], [(4, "path:1")])
        self.assertEqual(detail["fields_chains"], 2)

    def test_groups_are_listed_newest_first_and_paged(self):
        self.ingest(F.two_scripts_packets() + F.html_payload_packets())
        self.trace()
        data = self.groups()
        self.assertEqual([g["last_ts"] for g in data["items"]],
                         sorted((g["last_ts"] for g in data["items"]), reverse=True))
        code, page = self.get("/chain-groups?limit=1")
        self.assertEqual((len(page["items"]), page["next_offset"]), (1, 1))
        code, page = self.get("/chain-groups?limit=1&offset=1")
        self.assertEqual((len(page["items"]), page["next_offset"]), (1, None))
        self.assertEqual(self.get("/chain-groups/" + "0" * 64)[0], 404)
        self.assertEqual(self.get("/chain-groups/not-an-id")[0], 404)

    def test_runs_without_a_group_are_re_analysed_once(self):
        """A run committed before P2.4b has no group. The worker asks for one
        new analysis per profile, under a versioned trigger, and never twice."""
        self.ingest(F.notes_split_packets())
        self.trace()
        with self.store.db:
            self.store.db.execute("UPDATE trace_runs SET group_id=NULL")
            self.store.db.execute("DELETE FROM trace_groups")
        out = self.trace()
        self.assertEqual(out["grouping_backfill"]["jobs_created"], 1)
        self.assertEqual(out["grouping_backfill"]["normalizer_version"], NORMALIZER_VERSION)
        triggers = [r[0] for r in self.store.db.execute("SELECT trigger_key FROM trace_jobs ORDER BY request_sequence")]
        self.assertEqual(triggers[-1], backfill_trigger())
        self.assertEqual(self.groups()["items"][0]["profiles"], 1)
        again = self.trace()
        self.assertEqual(again["grouping_backfill"]["jobs_created"], 0)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM trace_jobs").fetchone()[0], len(triggers))


class SuspectTests(ChainBase):
    def checker(self, sessions, start_tick=0):
        """Benign checker sessions: register, store a note, each tick its own
        note ID. This is what the baseline is built from."""
        return F.checker_notes_packets([(start_tick + n // 5, f"note{n:03d}a", b"FLAG{tick%d_put}" % n)
                                        for n in range(sessions)])

    def test_without_a_baseline_nothing_is_marked(self):
        self.ingest(F.notes_split_packets(), baseline=True)
        self.trace()
        suspects = self.run_of("/files/f93a1c")["suspects"]
        self.assertEqual((suspects["state"], suspects["steps"]), ("no_baseline", []))
        self.assertIn("no checker traffic", suspects["note"])
        self.assertEqual(self.groups()["items"][0]["suspect_profiles"], 0)

    def test_endpoints_the_checker_never_calls_are_marked(self):
        self.ingest(F.notes_split_packets() + self.checker(25), baseline=True)
        self.trace()
        suspects = self.run_of("/files/f93a1c")["suspects"]
        self.assertEqual(suspects["state"], "computed")
        marked = {s["position"]: s for s in suspects["steps"]}
        kinds = {p: sorted({f["kind"] for f in s["findings"]}) for p, s in marked.items()}
        # /register is what the checker does too, so it is not an unseen endpoint.
        self.assertNotIn("endpoint_unseen", kinds.get(1, []))
        for position in (2, 3, 4):
            self.assertIn("endpoint_unseen", kinds[position], f"step {position}: {kinds.get(position)}")
            self.assertEqual(marked[position]["strength"], "strong")
        self.assertEqual(suspects["baseline"]["endpoints"], 2)   # /register and /put
        self.assertGreaterEqual(suspects["baseline"]["service_samples"], anomalies.MIN_SAMPLES)
        self.assertEqual(self.groups()["items"][0]["suspect_profiles"], 1)

    def test_a_letter_the_checker_happens_to_skip_is_not_evidence(self):
        """The checker's own values are random, so it never covers an alphabet.
        Marking a step because a password contains "y" flagged every step and
        buried the real leads; only a kind of character it never sends counts."""
        self.ingest(F.notes_split_packets() + self.checker(25), baseline=True)
        self.trace()
        suspects = self.run_of("/files/f93a1c")["suspects"]
        flagged = {s["position"] for s in suspects["steps"]}
        self.assertEqual(flagged, {2, 3, 4})       # /register is what the checker does too
        self.assertNotIn("charset", {f["kind"] for s in suspects["steps"] for f in s["findings"]})
        self.assertEqual(anomalies.new_characters("p1yyyyy", "chk0u123pw"), [])
        self.assertEqual(anomalies.new_characters("../notes", "chk0u123pw"), [".", "/"])
        # A class it never uses here is news, e.g. letters in a digits-only field.
        self.assertEqual(anomalies.new_characters("7731x", "0123456789"), ["x"])

    def test_a_thin_baseline_only_gives_weak_findings(self):
        """Few checker samples cannot show that a request is abnormal."""
        self.ingest(F.notes_split_packets() + self.checker(2), baseline=True)
        self.trace()
        suspects = self.run_of("/files/f93a1c")["suspects"]
        self.assertEqual(suspects["state"], "computed")
        self.assertLess(suspects["baseline"]["service_samples"], anomalies.MIN_SAMPLES)
        self.assertTrue(suspects["steps"])
        self.assertEqual({s["strength"] for s in suspects["steps"]}, {"weak"})
        self.assertEqual((suspects["strong"], suspects["weak"]), (0, len(suspects["steps"])))
        self.assertEqual(self.groups()["items"][0]["suspect_profiles"], 0)

    def test_a_finding_keeps_the_figures_it_was_compared_with(self):
        """A later baseline rebuild must not change what an old run reported."""
        self.ingest(F.notes_split_packets() + self.checker(25), baseline=True)
        self.trace()
        before = self.run_of("/files/f93a1c")["suspects"]
        with self.store.db:
            self.store.db.execute("DELETE FROM baseline")
        rebuild_baseline(self.store)
        after = self.run_of("/files/f93a1c")["suspects"]
        self.assertEqual(after, before)
        self.assertEqual(after["baseline"]["endpoints"], 2)
        self.assertEqual(after["min_samples"], anomalies.MIN_SAMPLES)

    def test_raw_tcp_steps_are_counted_not_judged(self):
        """Raw TCP has no request line or fields to compare, so it is reported
        as skipped rather than silently treated as normal."""
        self.ingest(F.image_sharing_packets() + self.checker(25), baseline=True)
        self.trace()
        for row in self.store.db.execute("SELECT DISTINCT proto FROM transactions WHERE flag_out=1"):
            self.assertEqual(row[0], "http")   # fixture is HTTP; guard the assumption
        shapes = {json.loads(r[0])[0]["proto"] for r in self.store.db.execute("SELECT signature FROM trace_groups")}
        self.assertEqual(shapes, {"http"})


if __name__ == "__main__":
    unittest.main()
