"""Identical flag-outs listed once (trace/dedup.py): grouping is a view over
profiles, never a merge, so counts follow profiles and each keeps its runs."""
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import fixtures as F
from flagtrace.app.api import query
from flagtrace.app.config import Config
from flagtrace.app.ingest import Ingestor
from flagtrace.app.store import Store
from flagtrace.app.trace import worker
from flagtrace.app.trace.repository import Repository

FLAG = b"FLAG{repeated_read}"
TEAM5, TEAM9 = "10.60.5.1", "10.60.9.1"


def read(port, clock, ip=TEAM5, path="/flagfile", flag=FLAG, cookie=None):
    headers = [("Cookie", f"session={cookie}")] if cookie else []
    return F.step_chain(port, clock, [(F.request(path, headers=headers), F.response(flag))], ip=ip)


def login_then_read(port, clock):
    """The same read, once with the login that issued its session: the one
    repeat whose analysis links an earlier step."""
    return F.step_chain(port, clock, [
        (F.request("/login", "POST", b"user=rpuser01&pass=rppass01", F.FORM_CT),
         F.response(b"ok", [("Set-Cookie", "session=zz11yy22aa")])),
        (F.request("/flagfile", headers=[("Cookie", "session=zz11yy22aa")]), F.response(FLAG)),
    ])


class DedupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "db.sqlite3"
        self.cfg = Config(F.config())
        store = Store(self.db, self.cfg)
        ingestor = Ingestor(store, self.root)
        packets = (login_then_read(52001, 1000)               # chain, oldest
                   + read(52101, 100_000) + read(52102, 200_000)  # the same read repeated
                   + read(52201, 300_000, ip=TEAM9)           # same flag, another team
                   + read(52301, 400_000, path="/flagfile2")  # same flag, another request
                   + read(52401, 500_000, flag=b"FLAG{other_tick}"))
        F.write_pcap(self.root / "a.pcap", sorted(packets))
        ingestor.run(self.root.glob("*.pcap"), finalize=True)
        ingestor.close()
        store.close()
        worker.run_once(self.db, self.cfg)
        db = sqlite3.connect(self.db)
        rows = db.execute("""SELECT p.id,t.src_ip,t.path,t.ts_request,t.flags_found FROM trace_profiles p
                             JOIN transactions t ON t.id=p.anchor_transaction_id""").fetchall()
        db.close()
        self.traces = {(ip, path, ts): tid for tid, ip, path, ts, _ in rows}
        reads = sorted((ts, tid) for tid, ip, path, ts, flags in rows
                       if (ip, path) == (TEAM5, "/flagfile") and "repeated_read" in flags)
        self.chain, self.repeat1, self.repeat2 = (tid for _, tid in reads)

    def tearDown(self):
        self.tmp.cleanup()

    def get(self, url):
        return query(self.db, self.cfg.game_id, url)

    def group_of(self, data, trace_id):
        return next(g for g in data["items"] if trace_id in self.members(g["shown"]["trace_id"]))

    def members(self, trace_id, extra=""):
        code, data = self.get(f"/trace-groups/{trace_id}/members?limit=50{extra}")
        self.assertEqual(code, 200)
        return [m["trace_id"] for m in data["items"]]

    def test_repeats_of_one_flag_out_are_one_row(self):
        code, data = self.get("/trace-groups")
        self.assertEqual(code, 200)
        self.assertEqual((data["total_groups"], data["total_profiles"]), (4, 6))
        group = self.group_of(data, self.repeat2)
        self.assertEqual(group["count"], 3)
        self.assertEqual(group["states"], {"linked": 3})
        self.assertEqual(group["tick_min"], group["tick_max"])
        self.assertLess(group["first_ts"], group["last_ts"])
        self.assertEqual(group["shown"]["flags_found"], ["FLAG{repeated_read}"])
        # Another team, another request or another flag is a separate row.
        others = [g for g in data["items"] if g is not group]
        self.assertEqual(sorted(g["count"] for g in others), [1, 1, 1])
        self.assertEqual({(g["shown"]["source_key"], g["shown"]["path"], tuple(g["shown"]["flags_found"])) for g in others},
                         {("team:team-09", "/flagfile", ("FLAG{repeated_read}",)),
                          ("team:team-05", "/flagfile2", ("FLAG{repeated_read}",)),
                          ("team:team-05", "/flagfile", ("FLAG{other_tick}",))})
        # Newest group first.
        self.assertEqual([g["last_ts"] for g in data["items"]], sorted((g["last_ts"] for g in data["items"]), reverse=True))

    def test_the_row_shows_the_longest_chain_not_the_newest_repeat(self):
        group = self.group_of(self.get("/trace-groups")[1], self.chain)
        self.assertEqual(group["shown"]["trace_id"], self.chain)
        self.assertEqual(group["shown"]["latest_run"]["step_count"], 2)
        self.assertEqual(sorted((r["step_count"], r["count"]) for r in group["results"]), [(1, 2), (2, 1)])
        self.assertEqual(group["last_ts"], max(ts for (ip, path, ts), tid in self.traces.items()
                                               if tid in (self.chain, self.repeat1, self.repeat2)))

    def test_members_are_paged_newest_first_from_any_member(self):
        self.assertEqual(self.members(self.chain), [self.repeat2, self.repeat1, self.chain])
        self.assertEqual(self.members(self.repeat1), self.members(self.chain))
        code, page = self.get(f"/trace-groups/{self.chain}/members?limit=2")
        self.assertEqual((len(page["items"]), page["next_offset"]), (2, 2))
        code, page = self.get(f"/trace-groups/{self.chain}/members?limit=2&offset=2")
        self.assertEqual(([m["trace_id"] for m in page["items"]], page["next_offset"]), ([self.chain], None))
        other = self.traces[(TEAM9, "/flagfile", min(ts for (ip, _, ts) in self.traces if ip == TEAM9))]
        self.assertEqual(self.members(other), [other])
        self.assertEqual(self.get("/trace-groups/" + "0" * 64 + "/members")[0], 404)
        self.assertEqual(self.get("/trace-groups/not-an-id/members")[0], 404)

    def test_filters_and_paging_apply_to_groups(self):
        code, data = self.get("/trace-groups?source_key=team:team-09")
        self.assertEqual((data["total_groups"], data["total_profiles"]), (1, 1))
        code, data = self.get("/trace-groups?limit=1")
        self.assertEqual((len(data["items"]), data["next_offset"]), (1, 1))
        code, data = self.get("/trace-groups?limit=1&offset=3")
        self.assertEqual((len(data["items"]), data["next_offset"]), (1, None))
        # The HTTP handler turns this into 400, as for every other route.
        with self.assertRaisesRegex(ValueError, "limit"):
            self.get("/trace-groups?limit=x")

    def test_a_retrace_is_not_a_repeat(self):
        repo = Repository.open(self.db, self.cfg)
        try:
            repo.enqueue_retrace(self.repeat1, "again")
        finally:
            repo.close()
        group = self.group_of(self.get("/trace-groups")[1], self.repeat1)
        self.assertEqual((group["count"], group["states"]), (3, {"linked": 2, "pending": 1}))
        code, data = self.get("/trace-groups?state=pending")
        self.assertEqual((data["total_groups"], data["items"][0]["count"]), (1, 1))
        self.assertEqual(self.members(self.chain, "&state=pending"), [self.repeat1])
        worker.run_once(self.db, self.cfg)
        group = self.group_of(self.get("/trace-groups")[1], self.repeat1)
        self.assertEqual((group["count"], group["states"]), (3, {"linked": 3}))


if __name__ == "__main__":
    unittest.main()
