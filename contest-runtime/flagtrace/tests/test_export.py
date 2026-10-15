import json
import sqlite3
import subprocess
import socketserver
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from flagtrace.tests import fixtures as F
from flagtrace.app.background import import_flagids
from flagtrace.app.config import Config
from flagtrace.app.ingest import Ingestor
from flagtrace.app.store import Store
from flagtrace.app.trace import contracts, worker
from flagtrace.app.trace.replay import verify
from flagtrace.app.trace.export import RUNTIME


class NotesFixture(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    session = "fresh-session-52"
    file_id = "fresh-file-91"

    def reply(self, body=b"ok", status=200, headers=()):
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers(); self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        form = parse_qs(body.decode(), keep_blank_values=True)
        if self.path == "/register":
            self.reply(b'{"ok":true}', headers=(("Content-Type", "application/json"),))
        elif self.path == "/login":
            if not form.get("user") or not form.get("pass"):
                self.reply(b"bad login", 400)
            else:
                self.reply(b"ok", headers=(("Set-Cookie", f"session={self.session}; HttpOnly"),))
        elif self.path == "/upload":
            good_cookie = f"session={self.session}" in (self.headers.get("Cookie") or "")
            good_target = form.get("name") == ["../../notes/9917.txt"]
            if not (good_cookie and good_target):
                self.reply(b"bad upload", 400)
            else:
                self.reply(json.dumps({"id": self.file_id}).encode(),
                           headers=(("Content-Type", "application/json"),))
        else:
            self.reply(b"not found", 404)

    def do_GET(self):
        if self.path == "/files/" + self.file_id and f"session={self.session}" in (self.headers.get("Cookie") or ""):
            self.reply(b"FLAG{fixture_reproduced}")
        else:
            self.reply(b"not found", 404)

    def log_message(self, *_):
        pass


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cfg = Config(F.config())
        self.db = self.root / "db.sqlite3"
        self.store = Store(self.db, self.cfg)
        self.ingestor = Ingestor(self.store, self.root)
        packets = sorted(F.notes_split_packets() + F.html_payload_packets() + F.graphql_echo_packets())
        F.write_pcap(self.root / "notes.pcap", packets)
        self.ingestor.run(self.root.glob("*.pcap"), finalize=True)
        import_flagids(self.store, [{"tick": 0, "service": "notes", "owner_team_id": "team-01", "value": "7731"}])
        self.ingestor.close(); self.store.close()
        worker.run_once(self.db, self.cfg)

    def tearDown(self):
        self.tmp.cleanup()

    def row(self, sql, args=()):
        db = sqlite3.connect(self.db); db.row_factory = sqlite3.Row
        try:
            return db.execute(sql, args).fetchone()
        finally:
            db.close()

    def chain(self):
        return self.row("""SELECT a.* FROM trace_script_artifacts a JOIN trace_runs r ON r.id=a.run_id
                           JOIN trace_profiles p ON p.id=r.trace_id JOIN transactions t ON t.id=p.anchor_transaction_id
                           WHERE t.path='/files/f93a1c' AND a.kind='chain'""")

    def notes_run(self):
        return self.row("""SELECT p.latest_run_id FROM trace_profiles p JOIN transactions t
                           ON t.id=p.anchor_transaction_id WHERE t.path='/files/f93a1c'""")[0]

    def test_artifacts_are_immutable_complete_and_compile(self):
        run = (self.notes_run(),)
        db = sqlite3.connect(self.db); db.row_factory = sqlite3.Row
        try:
            artifacts = db.execute("SELECT * FROM trace_script_artifacts WHERE run_id=? ORDER BY kind,position",
                                   (run[0],)).fetchall()
        finally:
            db.close()
        self.assertEqual(len(artifacts), 5)  # four requests plus one chain
        self.assertEqual({a["support"] for a in artifacts}, {contracts.SCRIPT_SUPPORTED})
        for artifact in artifacts:
            compile(bytes(artifact["content"]), artifact["filename"], "exec")
        chain = next(a for a in artifacts if a["kind"] == "chain")
        self.assertEqual(chain["content_hash"], __import__("hashlib").sha256(bytes(chain["content"])).hexdigest())

    def test_graphql_json_and_bearer_chain_compiles(self):
        artifact = self.row("""SELECT a.* FROM trace_script_artifacts a JOIN trace_runs r ON r.id=a.run_id
                            JOIN trace_profiles p ON p.id=r.trace_id JOIN transactions t ON t.id=p.anchor_transaction_id
                            WHERE t.flags_found LIKE '%graphql_vault%' AND a.kind='chain'""")
        self.assertEqual(artifact["support"], contracts.SCRIPT_SUPPORTED, json.loads(artifact["warnings"]))
        compile(bytes(artifact["content"]), "graphql-chain.py", "exec")

    def test_single_request_sends_duplicate_fields_and_encoding_verbatim(self):
        row = self.row("""SELECT a.content,x.data AS raw FROM trace_script_artifacts a
                       JOIN representations x ON x.transaction_id=a.transaction_id AND x.side='req' AND x.kind='raw'
                       JOIN transactions t ON t.id=a.transaction_id
                       WHERE a.kind='request' AND t.req_parsed LIKE '%next=/a%'""")
        received = []

        class Capture(socketserver.BaseRequestHandler):
            def handle(self):
                data = b""
                while b"\r\n\r\n" not in data:
                    data += self.request.recv(4096)
                head, sep, body = data.partition(b"\r\n\r\n")
                match = __import__("re").search(br"(?im)^Content-Length:\s*(\d+)", head)
                length = int(match.group(1)) if match else 0
                while len(body) < length:
                    body += self.request.recv(4096)
                received.append(head + sep + body[:length])
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

        server = socketserver.TCPServer(("127.0.0.1", 0), Capture)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with tempfile.NamedTemporaryFile(suffix=".py") as script:
                script.write(bytes(row["content"])); script.flush()
                run = subprocess.run([sys.executable, script.name, "127.0.0.1", "--port", str(server.server_address[1])],
                                     capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr.decode())
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)
        self.assertEqual(received, [bytes(row["raw"])])

    def test_chain_replays_with_fresh_session_file_id_and_target(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), NotesFixture)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            artifact = self.chain()
            outcome = verify(self.db, self.cfg, artifact["id"], "notes-v1", "127.0.0.1",
                             flag_id="9917", expected="FLAG{fixture_reproduced}", port=server.server_port)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)
        self.assertEqual(outcome["status"], contracts.VERIFY_REPRODUCED, outcome)
        saved = self.row("SELECT artifact_hash,fixture,target,status FROM trace_replay_verifications")
        self.assertEqual((saved["artifact_hash"], saved["fixture"], saved["target"], saved["status"]),
                         (artifact["content_hash"], "notes-v1", f"127.0.0.1:{server.server_port}",
                          contracts.VERIFY_REPRODUCED))

    def test_non_loopback_verification_is_refused(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            verify(self.db, self.cfg, self.chain()["id"], "bad", "10.0.0.2")


class RuntimeHelperTests(unittest.TestCase):
    """The helpers a generated script carries, run on their own."""

    def setUp(self):
        self.ns = {}
        exec(compile(RUNTIME, "runtime", "exec"), self.ns)

    def test_a_missing_value_names_the_response_not_just_the_path(self):
        """A step fails when the one before it did: a login that was refused
        answers with a null, and the script used to die on `KeyError(path)`,
        which says nothing about why. The message has to carry the response."""
        path = ["data", 0, "signIn", 0, "access_token", 0]
        at = self.ns["_json_at"]
        self.assertEqual(at(b'{"data":{"signIn":{"access_token":"tok123"}}}', path), "tok123")
        for body, stopped in ((b'{"data":{"signIn":null}}', ["data", 0, "signIn", 0]),
                              (b'{"errors":[{"message":"email already exists"}],"data":null}', ["data", 0])):
            with self.subTest(body=body):
                with self.assertRaises(ValueError) as raised:
                    at(body, path)
                message = str(raised.exception)
                self.assertIn(repr(stopped), message)
                self.assertIn("probably failed", message)
                self.assertIn(body[:40].decode(), message)
        with self.assertRaisesRegex(ValueError, "this object has"):
            at(b'{"data":{"signUp":{"id":1}}}', path)

    def test_a_missing_header_or_cookie_says_so(self):
        with self.assertRaisesRegex(ValueError, "header 'location'"):
            self.ns["_header"]([("Content-Type", "text/html")], "location")
        with self.assertRaisesRegex(ValueError, "cookie 'session'"):
            self.ns["_cookie"]([("Set-Cookie", "other=1; Path=/")], "session")
        self.assertEqual(self.ns["_cookie"]([("Set-Cookie", "session=abc; Path=/")], "session"), "abc")


if __name__ == "__main__":
    unittest.main()
