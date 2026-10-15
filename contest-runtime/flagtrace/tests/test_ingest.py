import base64
import gzip
import json
import os
import sqlite3
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from fixtures import Connection, config, notes_packets, request, response, write_pcap
from common import flag_decoders
from flagtrace.app import ingest as ingest_module
from flagtrace.app.api import command, query
from flagtrace.app.background import collect_checker_flagids, import_flagids, rebuild_baseline
from flagtrace.app.config import Config
from flagtrace.app.ingest import Ingestor
from flagtrace.app.ledger import may_delete
from flagtrace.app.migrations import SCHEMA_VERSION
from flagtrace.app.parsing import dechunk, parse_message
from flagtrace.app.settings import set_decoder_mode
from flagtrace.app.store import Store
from flagtrace.app.tokens import extract

FORM = [("Content-Type", "application/x-www-form-urlencoded")]
JSON = [("Content-Type", "application/json")]


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cfg = Config(config())
        self.store = Store(self.root / "db.sqlite3", self.cfg)
        self.ingestor = Ingestor(self.store, self.root)

    def tearDown(self):
        self.ingestor.close()
        self.store.close()
        self.tmp.cleanup()

    def ingest(self, packets, name="a.pcap", finalize=True):
        path = self.root / name
        write_pcap(path, packets)
        self.ingestor.run(self.root.glob("*.pcap"), finalize=finalize)

    def count(self, table):
        return self.store.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]

    def test_notes_chain_input_and_duplicate(self):
        self.ingest(notes_packets())
        self.assertEqual(self.count("transactions"), 4)
        self.assertEqual(self.count("trace_queue"), 1)
        values = {r[0] for r in self.store.db.execute("SELECT value FROM tokens")}
        self.assertTrue({"k8x2pv", "q91zzr", "ab12cd9f", "f93a1c", "7731"} <= values)
        before = self.store.db.execute("SELECT sum(n) FROM token_df").fetchone()[0]
        self.ingestor.close()
        self.ingestor.run(self.root.glob("*.pcap"), finalize=True)
        self.assertEqual(self.count("transactions"), 4)
        self.assertEqual(self.count("trace_queue"), 1)
        self.assertEqual(before, self.store.db.execute("SELECT sum(n) FROM token_df").fetchone()[0])

    def test_restart_cross_file_and_retention_floor(self):
        packets = notes_packets()
        self.ingest(packets[:8], finalize=False)
        self.assertFalse(may_delete(self.store.path, "a.pcap"))
        self.ingestor.close()
        self.ingest(packets[8:], "b.pcap")
        self.assertEqual(self.count("transactions"), 4)
        self.assertEqual(self.count("trace_queue"), 1)
        self.assertTrue(may_delete(self.store.path, "a.pcap"))
        self.assertFalse(may_delete(self.store.path, "unknown.pcap"))

    def test_pipelining_and_informational(self):
        c = Connection()
        c.send(request("/a") + request("/b"))
        c.send(b"HTTP/1.1 100 Continue\r\n\r\n" + response(b"first") + response(b"FLAG{second}"), server=True)
        c.close()
        self.ingest(c.packets)
        rows = self.store.db.execute("SELECT path,flag_out FROM transactions ORDER BY seq_in_conn").fetchall()
        self.assertEqual([tuple(x) for x in rows], [("/a", 0), ("/b", 1)])

    def test_retransmission_and_out_of_order(self):
        c = Connection()
        q = request("/x")
        a = c.send(q[:12]); b = c.send(q[12:])
        c.packets[-2:] = [b, a, (a[0] + 2, a[1])]
        c.send(response(b"FLAG{once}"), server=True)
        c.close()
        self.ingest(c.packets)
        self.assertEqual(self.count("transactions"), 1)
        raw = self.store.db.execute("SELECT data FROM representations WHERE side='req' AND kind='raw'").fetchone()[0]
        self.assertEqual(raw, q)

    def test_checker_and_unknown_source(self):
        packets = []
        for n, ip in enumerate(("10.60.0.1", "10.60.88.1", "10.60.89.1")):
            c = Connection(ip=ip, port=51000+n, clock=n*100000)
            c.send(request("/flag")); c.send(response(b"FLAG{shared}"), server=True); c.close()
            packets += c.packets
        self.ingest(packets)
        self.assertEqual(self.count("transactions"), 3)
        self.assertEqual(self.count("trace_queue"), 2)
        keys = {r[0] for r in self.store.db.execute("SELECT source_key FROM transactions WHERE flag_out=1")}
        self.assertEqual(keys, {"ip:10.60.88.1", "ip:10.60.89.1"})

    def test_encoded_flags_and_capture_groups(self):
        self.cfg.regex = __import__('re').compile(rb"FLAG\{([A-Za-z0-9_]+)\}")
        c = Connection()
        c.send(request("/gzip"))
        wire = response(gzip.compress(base64.b64encode(b"FLAG{encoded_value}")), [("Content-Encoding", "gzip")])
        c.send(wire, server=True); c.close()
        self.ingest(c.packets)
        row = self.store.db.execute("SELECT flags_found FROM transactions").fetchone()
        self.assertIn("FLAG{encoded_value}", json.loads(row[0]))
        self.assertEqual(wire, self.store.db.execute("SELECT data FROM representations WHERE side='resp' AND kind='raw'").fetchone()[0])

    def test_echo_is_scoped_to_transaction(self):
        c = Connection()
        c.send(request("/store", "POST", b"FLAG{same}")); c.send(response(b"FLAG{same}"), server=True)
        c.send(request("/steal")); c.send(response(b"FLAG{same}"), server=True); c.close()
        self.ingest(c.packets)
        self.assertEqual(self.count("trace_queue"), 1)
        self.assertEqual([r[0] for r in self.store.db.execute("SELECT classification FROM transactions ORDER BY seq_in_conn")], ["echo", "flag_out_candidate"])

    def test_head_and_empty_responses(self):
        c = Connection()
        c.send(request("/head", "HEAD") + request("/empty"))
        c.send(b"HTTP/1.1 200 OK\r\nContent-Length: 9000\r\n\r\nHTTP/1.1 204 OK\r\n\r\n", server=True)
        c.close(); self.ingest(c.packets)
        self.assertEqual(self.count("transactions"), 2)

    def test_api_filter_and_baseline(self):
        c = Connection(ip="10.60.0.1")
        c.send(request("/store", "POST", b"user=checker&note=abc", [("Content-Type", "application/x-www-form-urlencoded")]))
        c.send(response(b"ok"), server=True); c.close(); self.ingest(c.packets)
        rebuild_baseline(self.store)
        self.assertGreater(self.count("baseline"), 0)
        status, data = query(self.store.path, self.cfg.game_id, "/transactions?source_key=ip%3A10.60.0.1")
        self.assertEqual(status, 200); self.assertEqual(len(data["items"]), 1)
        tid = data["items"][0]["id"]
        self.assertEqual(query(self.store.path, self.cfg.game_id, "/transactions/" + tid)[0], 200)
        import_flagids(self.store, [{"tick": 1, "service": "notes", "owner_team_id": "team-01", "value": "7731"}])
        self.assertEqual(self.count("flag_ids"), 1)

    def test_atomic_commit(self):
        self.store.db.execute("CREATE TRIGGER reject_queue BEFORE INSERT ON trace_queue BEGIN SELECT RAISE(ABORT,'fault'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.ingest(notes_packets())
        self.assertEqual(self.count("transactions"), 3)
        self.assertEqual(self.count("trace_queue"), 0)
        self.store.db.execute("DROP TRIGGER reject_queue")
        self.ingestor.run(self.root.glob("*.pcap"), finalize=True)
        self.assertEqual(self.count("transactions"), 4)
        self.assertEqual(self.count("trace_queue"), 1)

    def test_raw_tcp_turns(self):
        self.cfg.endpoints[0]["layer"] = "l4-raw"
        c = Connection(); c.send(b"GETFLAG\n"); c.send(b"FLAG{raw_tcp}\n", server=True); c.close()
        self.ingest(c.packets)
        row = self.store.db.execute("SELECT proto,turns FROM transactions").fetchone()
        self.assertEqual(row[0], "tcp"); self.assertEqual(len(json.loads(row[1])), 2)
        self.assertEqual(self.count("trace_queue"), 1)

    def rows(self):
        return self.store.db.execute("SELECT * FROM transactions ORDER BY conn_id,seq_in_conn").fetchall()

    def test_structured_short_values_are_tokens(self):
        c = Connection()
        c.send(request("/notes/7731?id=42&q=x", "POST", b"fid=99&z=1", FORM))
        c.send(response(b'{"id": 42, "n": 7}', JSON), server=True)
        c.send(request("/plain"))
        c.send(response(b"note 7731 stored abcdefgh"), server=True)
        c.close(); self.ingest(c.packets)
        found = {(r[0], r[1]) for r in self.store.db.execute("SELECT value,json_extract(location,'$[1]') FROM tokens")}
        self.assertTrue({("7731", "path"), ("42", "query"), ("99", "form"), ("42", "json"), ("abcdefgh", "body")} <= found)
        # One-character values and short words in free text stay out.
        self.assertFalse({("x", "query"), ("1", "form"), ("7", "json"), ("7731", "body"), ("note", "body")} & found)

    def test_checker_putflag_flag_ids(self):
        packets = []
        for tick in range(3):
            c = Connection(ip="10.60.0.1", port=52000 + tick, clock=tick * 120_000_000 + 1000)
            c.send(request("/register", "POST", f"user=chk{tick}user&role=writer".encode(), FORM))
            c.send(response(b"ok", [("Set-Cookie", f"session=sess{tick}abc")]), server=True)
            c.send(request("/put", "POST", f"title=static&body=FLAG{{tick{tick}_put}}".encode(), FORM + [("Cookie", f"session=sess{tick}abc")]))
            c.send(response(f'{{"id": {500 + tick}}}'.encode(), JSON), server=True)
            c.close(); packets += c.packets
        import_flagids(self.store, [{"tick": 0, "service": "notes", "owner_team_id": "team-01", "value": "from-api"}])
        self.ingest(packets)
        self.assertEqual(self.count("trace_queue"), 0)
        collect_checker_flagids(self.store)
        rows = self.store.db.execute("SELECT tick,value,owner_team_id,location,transaction_id FROM flag_ids WHERE source='checker_put'").fetchall()
        values = {(r[0], r[1]) for r in rows}
        # The checker-sent username and the server-generated note ID, per tick.
        self.assertTrue({(0, "chk0user"), (1, "chk1user"), (2, "chk2user"), (0, "500"), (1, "501"), (2, "502")} <= values)
        self.assertFalse({v for _, v in values} & {"static", "writer", "register", "put", "sess0abc", "FLAG{tick0_put}", "FLAG{tick0", "put}"})
        self.assertEqual({r[2] for r in rows}, {"team-01"})
        self.assertTrue(all(r[3] and r[4] for r in rows))
        collect_checker_flagids(self.store)
        self.assertEqual(len(rows), self.store.db.execute("SELECT count(*) FROM flag_ids WHERE source='checker_put'").fetchone()[0])
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM flag_ids WHERE source='file'").fetchone()[0], 1)

    def test_cut_response_body_stays_paired(self):
        c = Connection()
        c.send(request("/big"))
        c.send(b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\nFLAG{partial} and more", server=True)
        c.close(); self.ingest(c.packets)
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["proto"], rows[0]["path"], rows[0]["flag_out"]), ("http", "/big", 1))
        self.assertIn("resp:incomplete_body", json.loads(rows[0]["quality"]))
        self.assertNotIn("missing_response", json.loads(rows[0]["quality"]))

    def test_cut_chunked_gzip_response_is_scanned(self):
        co = zlib.compressobj(9, zlib.DEFLATED, 31)
        gz = co.compress(b"FLAG{chunked_cut}" + bytes(range(256)) * 16) + co.flush()
        chunks = b"".join(b"%x\r\n" % len(gz[i:i+500]) + gz[i:i+500] + b"\r\n" for i in range(0, len(gz), 500)) + b"0\r\n\r\n"
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n" + chunks
        c = Connection()
        c.send(request("/z")); c.send(wire[:len(wire) // 2], server=True); c.close()
        self.ingest(c.packets)
        row = self.rows()[0]
        self.assertIn("FLAG{chunked_cut}", json.loads(row["flags_found"]))
        self.assertTrue({"resp:incomplete_body", "resp:decode_incomplete"} <= set(json.loads(row["quality"])))

    def test_cut_header_and_cut_request(self):
        c = Connection()
        c.send(request("/h")); c.send(b"HTTP/1.1 200 OK\r\nContent-Le", server=True); c.close()
        d = Connection(port=51300, clock=100000)
        d.send(b"POST /p HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort"); d.close()
        self.ingest(c.packets + d.packets)
        rows = {r["path"]: r for r in self.rows()}
        self.assertEqual(len(rows), 2)
        self.assertIn("resp:incomplete_header", json.loads(rows["/h"]["quality"]))
        self.assertTrue({"req:incomplete_body", "missing_response"} <= set(json.loads(rows["/p"]["quality"])))
        self.assertIsNone(rows["/p"]["ts_response"])

    def test_schema_v1_migrates(self):
        self.assertEqual(self.store.db.execute("SELECT max(version) FROM schema_version").fetchone()[0], SCHEMA_VERSION)
        path = self.root / "v1.sqlite3"
        old = sqlite3.connect(path)
        old.executescript("""CREATE TABLE schema_version(version INTEGER PRIMARY KEY); INSERT INTO schema_version VALUES(1);
            CREATE TABLE flag_ids(game_id TEXT,tick INTEGER,service TEXT,owner_team_id TEXT,value TEXT,source TEXT,
              PRIMARY KEY(game_id,tick,service,owner_team_id,value));
            INSERT INTO flag_ids VALUES('fixture',1,'notes','team-01','7731','file');""")
        old.close()
        for _ in range(2):  # reopening a migrated database is a no-op
            store = Store(path, self.cfg)
            try:
                self.assertEqual(store.db.execute("SELECT max(version) FROM schema_version").fetchone()[0], SCHEMA_VERSION)
                self.assertEqual([tuple(r) for r in store.db.execute("SELECT value,location FROM flag_ids")], [("7731", None)])
            finally:
                store.close()

    def test_conflicting_networks_rejected(self):
        raw = config(); raw["teams"][1]["ips"] = ["10.60.5.0/24"]
        with self.assertRaises(ValueError):
            Config(raw)


ENCODED = base64.b64encode(b"FLAG{encoded_value}")


def exchange(body, port=51234, clock=0, path="/note"):
    c = Connection(port=port, clock=clock)
    c.send(request(path))
    c.send(response(body), server=True)
    c.close()
    return c.packets


class DecoderTests(unittest.TestCase):
    """Duplicate work dropped before enrichment, and the decoder modes."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        raw = config()
        # The fixture budget (10 ms) is often spent by the time a search ends,
        # and a search that ran out of budget is deliberately not reused.
        raw["flagtrace"]["decode_budget"] = 2
        self.cfg = Config(raw)
        self.open()

    def open(self):
        self.store = Store(self.root / "db.sqlite3", self.cfg)
        self.ingestor = Ingestor(self.store, self.root)

    def close(self):
        self.ingestor.close()
        self.store.close()

    def tearDown(self):
        self.close()
        self.tmp.cleanup()

    def ingest(self, packets, name="a.pcap"):
        write_pcap(self.root / name, packets)
        return self.ingestor.run(sorted(self.root.glob("*.pcap")), finalize=True)

    def rows(self, sql, *args):
        return self.store.db.execute(sql, args).fetchall()

    def test_replay_skips_stored_transactions_before_enrich(self):
        self.ingest(notes_packets())
        df = self.rows("SELECT sum(n) FROM token_df")[0][0]
        # A restart replays every capture from the recovery floor.
        with self.store.db:
            self.store.db.execute("UPDATE ingest_checkpoints SET replay_from=1")
            self.store.db.execute("UPDATE pcap_files SET status='queued'")
        self.ingestor.close()
        self.ingestor = Ingestor(self.store, self.root)
        with mock.patch.object(ingest_module, "enrich", wraps=ingest_module.enrich) as enrich:
            status = self.ingestor.run(sorted(self.root.glob("*.pcap")), finalize=True)
        self.assertEqual(enrich.call_count, 0)
        self.assertEqual(status["duplicates_skipped"], 4)
        self.assertEqual(self.rows("SELECT count(*) FROM transactions")[0][0], 4)
        self.assertEqual(self.rows("SELECT count(*) FROM trace_queue")[0][0], 1)
        self.assertEqual(self.rows("SELECT sum(n) FROM token_df")[0][0], df)

    def test_identical_bodies_are_decoded_once(self):
        status = self.ingest(exchange(ENCODED) + exchange(ENCODED, port=51235, clock=50_000))
        self.assertEqual((status["decoder"]["searched"], status["decoder"]["cache_hits"]), (1, 1))
        rows = self.rows("SELECT id,flags_found,flag_out FROM transactions ORDER BY ts_request")
        self.assertEqual([(json.loads(r["flags_found"]), r["flag_out"]) for r in rows],
                         [(["FLAG{encoded_value}"], 1)] * 2)
        # Each transaction keeps its own decoded evidence; only the work is shared.
        for r in rows:
            decoded = self.rows("SELECT data,transform FROM representations WHERE transaction_id=? AND kind='decoded'", r["id"])
            self.assertEqual([(bytes(d["data"]), json.loads(d["transform"])) for d in decoded],
                             [(b"FLAG{encoded_value}", ["base64"])])

    def test_exhausted_search_is_not_reused(self):
        with mock.patch.object(flag_decoders.Engine, "exhausted", return_value=True):
            status = self.ingest(exchange(ENCODED) + exchange(ENCODED, port=51235, clock=50_000))
        self.assertEqual((status["decoder"]["searched"], status["decoder"]["cache_hits"]), (2, 0))
        for r in self.rows("SELECT quality FROM transactions"):
            self.assertIn("resp:decode_budget_exhausted", json.loads(r["quality"]))

    def test_gated_mode_decodes_only_bodies_that_look_encoded(self):
        set_decoder_mode(self.store.db, self.cfg, "gated")
        status = self.ingest(exchange(ENCODED) + exchange(b"plain page", port=51235, clock=50_000, path="/plain"))
        self.assertEqual((status["decoder"]["searched"], status["decoder"]["skipped_gated"]), (1, 1))
        rows = {r["path"]: r for r in self.rows("SELECT path,flags_found,quality FROM transactions")}
        self.assertEqual(json.loads(rows["/note"]["flags_found"]), ["FLAG{encoded_value}"])
        self.assertNotIn("resp:decoder_gated", json.loads(rows["/note"]["quality"]))
        self.assertIn("resp:decoder_gated", json.loads(rows["/plain"]["quality"]))
        self.assertEqual(self.rows("SELECT decoder_mode FROM pcap_files")[0][0], "gated")

    def test_off_mode_says_so_on_every_body(self):
        set_decoder_mode(self.store.db, self.cfg, "off")
        status = self.ingest(exchange(ENCODED))
        row = self.rows("SELECT flags_found,flag_out,quality FROM transactions")[0]
        self.assertEqual((json.loads(row["flags_found"]), row["flag_out"]), ([], 0))
        self.assertIn("resp:decoder_off", json.loads(row["quality"]))
        self.assertEqual(self.rows("SELECT count(*) FROM trace_queue")[0][0], 0)
        self.assertEqual((status["decoder"]["skipped_off"], status["decoder"]["searched"]), (1, 0))

    def test_mode_is_read_per_file_and_kept_across_restart(self):
        code, state = command(self.store.path, self.cfg, "/decoder", {"mode": "off"})
        self.assertEqual((code, state["mode"], state["source"], state["default"]), (200, "off", "dashboard", "full"))
        self.ingest(exchange(ENCODED), "a.pcap")
        self.close()
        self.open()  # restart: the override is still in force
        code, state = query(self.store.path, self.cfg.game_id, "/decoder", cfg=self.cfg)
        self.assertEqual((code, state["mode"], state["source"], state["last_file_mode"]), (200, "off", "dashboard", "off"))
        code, state = command(self.store.path, self.cfg, "/decoder", {"mode": "default"})
        self.assertEqual((code, state["mode"], state["source"], state["since"]), (200, "full", "config", None))
        status = self.ingest(exchange(ENCODED, port=51235, clock=60_000_000), "b.pcap")
        self.assertEqual(status["decoder"]["last_file_mode"], "full")
        files = [tuple(r) for r in self.rows("SELECT p.path,f.decoder_mode FROM pcap_files f JOIN pcap_paths p ON p.file_id=f.id ORDER BY f.ordinal")]
        self.assertEqual(files, [("a.pcap", "off"), ("b.pcap", "full")])
        found = [json.loads(r[0]) for r in self.rows("SELECT flags_found FROM transactions ORDER BY ts_request")]
        self.assertEqual(found, [[], ["FLAG{encoded_value}"]])

    def test_setting_the_same_mode_keeps_its_start_time(self):
        first = set_decoder_mode(self.store.db, self.cfg, "gated")
        with mock.patch("flagtrace.app.settings.time.time", return_value=first["since"] + 600):
            again = set_decoder_mode(self.store.db, self.cfg, "gated")
            lowered = set_decoder_mode(self.store.db, self.cfg, "off")
        self.assertEqual(again["since"], first["since"])
        self.assertEqual(lowered["since"], first["since"] + 600)

    def test_decoder_mode_is_validated(self):
        for body in ({"mode": "fast"}, {}, {"mode": None}, ["off"]):
            with self.subTest(body=body):
                self.assertEqual(command(self.store.path, self.cfg, "/decoder", body)[0], 400)
        raw = config(); raw["flagtrace"]["decoder_mode"] = "fast"
        with self.assertRaisesRegex(ValueError, "decoder_mode"):
            Config(raw)
        code, state = query(self.store.path, self.cfg.game_id, "/decoder", cfg=self.cfg)
        self.assertEqual((code, state["mode"], state["source"], state["modes"]), (200, "full", "config", ["full", "gated", "off"]))
        # Without the config (the health check's fallback) the ingest's own report is used.
        self.ingest(exchange(ENCODED))
        code, state = query(self.store.path, self.cfg.game_id, "/decoder")
        self.assertEqual((code, state["mode"], state["default"]), (200, "full", "full"))


class ParserTests(unittest.TestCase):
    def test_chunked_and_duplicates(self):
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=abcdef\r\nSet-Cookie: b=ghijkl\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: value\r\n\r\n"
        p, body = parse_message(wire, False, 10000)
        self.assertEqual(body, b"abcde"); self.assertEqual(len(p["cookies"]), 2)

    def test_dechunk_cut_and_malformed(self):
        self.assertEqual(dechunk(b"3\r\nabc\r\n4\r\nde", 100), (b"abcde", "decode_incomplete"))
        self.assertEqual(dechunk(b"3\r\nabc\r\n", 100), (b"abc", "decode_incomplete"))
        self.assertEqual(dechunk(b"3\r\nabc\r\n0\r\n\r\n", 100), (b"abc", None))
        for bad in (b"zz\r\nabc\r\n", b"3\r\nabcX\r\n0\r\n\r\n"):
            with self.assertRaises(ValueError):
                dechunk(bad, 100)

    def test_struct_min_len_validated(self):
        raw = config(); raw["flagtrace"]["token"] = {"struct_min_len": 0}
        with self.assertRaises(ValueError):
            Config(raw)

    def test_nested_duplicate_json_locations(self):
        p, body = parse_message(request("/x", "POST", b'{"a.b":"abcdef","a.b":"ghijkl"}', [("Content-Type", "application/json")]), True, 1000)
        ts, _ = extract(p, body, "req", Config(config()).options["token"])
        values = {t["value"]: t["location"] for t in ts}
        self.assertEqual(values["abcdef"], ["req", "json", "a.b", 0])
        self.assertEqual(values["ghijkl"], ["req", "json", "a.b", 1])


if __name__ == "__main__":
    unittest.main()
