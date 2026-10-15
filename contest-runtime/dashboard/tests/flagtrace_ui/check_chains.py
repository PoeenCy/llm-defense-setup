"""Browser acceptance for P2.4b in the FLAG TRACE tab: the chain group of a
profile, how its fields vary across the group, and the steps that differ from
the checker baseline.

Builds its own fixture (two chains of one shape, plus benign checker sessions
to build a baseline from), serves the Flag-trace API on 127.0.0.1:18097 from a
thread, then drives a dashboard already pointed at that port:

  FLAGTRACE_API_URL=http://127.0.0.1:18097 CONFIG=/tmp/ft-chains/services.json \
    uvicorn app.main:app --host 127.0.0.1 --port 18182        # from dashboard/
  FLAGTRACE_TRANSPORT=/tmp/flagtrace-transport DASHBOARD=http://127.0.0.1:18182 \
    CHROMIUM=<path> python3 check_chains.py /tmp/ft-chains

Not part of unittest discovery and never copied into an image (.dockerignore).
"""
import json, os, sys, threading
from pathlib import Path
RT = str(Path(__file__).resolve().parents[3])
sys.path.insert(0, RT); sys.path.insert(0, RT + "/flagtrace/tests")
import fixtures as F
from flagtrace.app.api import make_server
from flagtrace.app.background import rebuild_baseline
from flagtrace.app.config import Config
from flagtrace.app.ingest import Ingestor
from flagtrace.app.store import Store
from flagtrace.app.trace import worker
from playwright.sync_api import sync_playwright

root = Path(sys.argv[1]); root.mkdir(parents=True, exist_ok=True)
for p in root.glob("*"):
    if p.is_file(): p.unlink()
raw = F.config(); (root / "services.json").write_text(json.dumps(raw))
cfg = Config(raw)
checker = F.checker_notes_packets([(n // 5, f"note{n:03d}a", b"FLAG{tick%d_put}" % n) for n in range(25)])
F.write_pcap(root / "a.pcap", sorted(F.two_scripts_packets() + checker))
db = root / "db.sqlite3"
store = Store(db, cfg); ing = Ingestor(store, root); ing.run(root.glob("*.pcap"), finalize=True); ing.close()
rebuild_baseline(store); store.close()
print(json.dumps(worker.run_once(db, cfg))[:120], flush=True)
server = make_server(db, cfg.game_id, "127.0.0.1", 18097, cfg=cfg)
threading.Thread(target=server.serve_forever, daemon=True).start()

BASE = os.environ.get("DASHBOARD", "http://127.0.0.1:18182")
results, errors = [], []
def ok(name, cond, detail=""):
    results.append((name, bool(cond), detail)); print(("PASS " if cond else "FAIL ") + name, detail, flush=True)
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=os.environ.get("CHROMIUM") or None)
    page = browser.new_page(viewport={"width": 1600, "height": 1100})
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(BASE + "/#flagtrace")
    page.wait_for_selector("#ft-list tr.ft-row")
    page.locator("#ft-list tr.ft-row").first.click()
    page.wait_for_selector("#ft-steps tr.ft-row")

    group = page.inner_text("#ft-chain-group")
    ok("chain shape and group size shown",
       "POST /register → POST /login → POST /upload → GET /files/{id}" in group
       and "2" in group and "flag-out" in group, group[:150].replace("\n", " "))

    suspects = page.inner_text("#ft-suspects-summary")
    ok("baseline size and strength shown", "step(s) differ" in suspects and "checker value(s)" in suspects,
       suspects.replace("\n", " ")[:160])
    rows = page.locator("#ft-suspects tr.ft-row")
    ok("endpoints the checker never calls are listed, and nothing else", rows.count() == 3
       and "endpoint the checker never calls" in page.inner_text("#ft-suspects"), str(rows.count()))
    ok("strong findings are marked on the timeline",
       page.locator("#ft-steps .ft-suspect-mark").count() == rows.count(),
       f'{page.locator("#ft-steps .ft-suspect-mark").count()} marks for {rows.count()} rows')
    rows.first.click()
    page.wait_for_timeout(400)
    ok("a suspicious step opens its evidence",
       "checker baseline" in page.inner_text("#ft-evidence"), page.inner_text("#ft-evidence")[:90].replace("\n", " "))

    page.click("#ft-group-details summary")
    page.wait_for_selector("#ft-group-members tr[data-trace]")
    body = page.inner_text("#ft-group-body")
    ok("field variation tells a fixed value from a per-run one",
       "fixed in every chain" in body and "new in every chain" in body, body[:0])
    ok("the fixed payload is shown with its examples", "../../notes/7731.txt" in body)
    members = page.locator("#ft-group-members tr[data-trace]")
    ok("both chains of the group are listed", members.count() == 2, str(members.count()))
    other = members.nth(1).get_attribute("data-trace")
    members.nth(1).click()
    page.wait_for_function(f"location.hash === '#flagtrace/{other}'")
    ok("a chain of the group opens from here", page.evaluate("FT.trace") == other)
    browser.close()
ok("no page errors", not errors, "; ".join(errors)[:300])
server.shutdown()
sys.exit(0 if all(r[1] for r in results) else 1)
