"""Browser acceptance for the FLAG TRACE tab, step 1 of 2: build a fixture
database and serve the Flag-trace API on 127.0.0.1:18095.

  FLAGTRACE_TRANSPORT=/tmp/flagtrace-transport python3 serve_fixture.py /tmp/ft-ui
  FLAGTRACE_API_URL=http://127.0.0.1:18095 CONFIG=/tmp/ft-ui/services.json \
    uvicorn app.main:app --host 127.0.0.1 --port 18080      # from dashboard/
  python3 check.py /tmp/ft-ui                                 # step 2

Not part of unittest discovery and never copied into an image (.dockerignore).
"""
import json, sys
from pathlib import Path
RT = str(Path(__file__).resolve().parents[3])
sys.path.insert(0, RT); sys.path.insert(0, RT + "/flagtrace/tests")
import fixtures as F
from flagtrace.app.config import Config
from flagtrace.app.store import Store
from flagtrace.app.ingest import Ingestor
from flagtrace.app.api import make_server
from flagtrace.app.background import import_flagids
from flagtrace.app.trace import worker
from flagtrace.app.trace.repository import Repository
root = Path(sys.argv[1]); root.mkdir(parents=True, exist_ok=True)
for p in root.glob("*"):
    if p.is_file(): p.unlink()
raw = F.config(); (root / "services.json").write_text(json.dumps(raw))
cfg = Config(raw)
F.write_pcap(root / "a.pcap", sorted(F.two_scripts_packets() + F.html_payload_packets() + F.degraded_chain_packets()))
db = root / "db.sqlite3"
store = Store(db, cfg); ing = Ingestor(store, root); ing.run(root.glob("*.pcap"), finalize=True); ing.close()
# The notes chains send ../../notes/7731.txt: with 7731 as this team's flag ID
# the Values table has a target with a template to show.
import_flagids(store, [{"tick": 0, "service": "notes", "owner_team_id": "team-01", "value": "7731"}]); store.close()
print(json.dumps(worker.run_once(db, cfg))[:200])
repo = Repository.open(db, cfg)
traces = {r["path"]: r["id"] for r in repo.db.execute("SELECT p.id,t.path FROM trace_profiles p JOIN transactions t ON t.id=p.anchor_transaction_id")}
repo.enqueue_retrace(traces["/files/f1aaaa"], "second-run"); repo.close()
worker.run_once(db, cfg)                                         # f1aaaa now has 2 runs
repo = Repository.open(db, cfg); repo.enqueue_retrace(traces["/files/dgfile"], "waiting"); repo.close()  # pending request
(root / "traces.json").write_text(json.dumps(traces))
server = make_server(db, cfg.game_id, "127.0.0.1", 18095, cfg=cfg)
print("api ready", flush=True)
server.serve_forever()
