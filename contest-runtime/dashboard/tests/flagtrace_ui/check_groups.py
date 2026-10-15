"""Browser acceptance for identical flag-outs grouped in the FLAG TRACE list.

Builds its own fixture (one flag-out read three times, plus three look-alikes
that must stay separate), serves the Flag-trace API on 127.0.0.1:18096 from a
thread, then drives a dashboard already pointed at that port:

  FLAGTRACE_API_URL=http://127.0.0.1:18096 CONFIG=/tmp/ft-groups/services.json \
    uvicorn app.main:app --host 127.0.0.1 --port 18181        # from dashboard/
  FLAGTRACE_TRANSPORT=/tmp/flagtrace-transport DASHBOARD=http://127.0.0.1:18181 \
    CHROMIUM=<path> python3 check_groups.py /tmp/ft-groups

Not part of unittest discovery and never copied into an image (.dockerignore).
"""
import json, os, sys, threading
from pathlib import Path
RT = str(Path(__file__).resolve().parents[3])
sys.path.insert(0, RT); sys.path.insert(0, RT + "/flagtrace/tests")
import fixtures as F
from test_dedup import TEAM9, login_then_read, read
from flagtrace.app.api import make_server
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
F.write_pcap(root / "a.pcap", sorted(login_then_read(52001, 1000) + read(52101, 100_000) + read(52102, 200_000)
                                     + read(52201, 300_000, ip=TEAM9) + read(52301, 400_000, path="/flagfile2")
                                     + read(52401, 500_000, flag=b"FLAG{other_tick}")))
db = root / "db.sqlite3"
store = Store(db, cfg); ing = Ingestor(store, root); ing.run(root.glob("*.pcap"), finalize=True); ing.close(); store.close()
worker.run_once(db, cfg)
server = make_server(db, cfg.game_id, "127.0.0.1", 18096, cfg=cfg)
threading.Thread(target=server.serve_forever, daemon=True).start()

BASE = os.environ.get("DASHBOARD", "http://127.0.0.1:18181")
results, errors = [], []
def ok(name, cond, detail=""):
    results.append((name, bool(cond), detail)); print(("PASS " if cond else "FAIL ") + name, detail, flush=True)
GROUP_ROWS = "#ft-list tr.ft-row:not(.ft-member)"
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=os.environ.get("CHROMIUM") or None)
    page = browser.new_page(viewport={"width": 1600, "height": 1000})
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(BASE + "/#flagtrace")
    page.evaluate("localStorage.removeItem('ft-grouped')"); page.reload()
    page.wait_for_selector("#ft-list tr.ft-row")
    rows = page.locator(GROUP_ROWS)
    ok("grouped by default: 6 profiles in 4 rows", rows.count() == 4 and page.inner_text("#ft-count") .lower() == "4 flag-outs · 6 profiles",
       page.inner_text("#ft-count"))
    ok("first column is last seen", page.inner_text("#ft-list >> xpath=../thead/tr/th[1]").lower().startswith("last seen"))
    dup = page.locator("#ft-list button.ft-dup")
    ok("only the repeated flag-out has ×N", dup.count() == 1 and "×3" in dup.inner_text(), dup.inner_text() if dup.count() else "")
    row = page.locator("#ft-list tr.ft-row", has=page.locator("button.ft-dup"))
    ok("row shows the longest chain and says results differ",
       "2 steps" in row.inner_text() and "results differ" in row.inner_text(), row.inner_text().replace("\t", " | "))
    dup.click()
    page.wait_for_selector("#ft-list tr.ft-member[data-trace]")
    members = page.locator("#ft-list tr.ft-member[data-trace]")
    ok("×3 lists the three repeats", members.count() == 3 and "▾" in dup.inner_text(), str(members.count()))
    target = members.nth(1).get_attribute("data-trace")
    members.nth(1).click()
    page.wait_for_function(f"location.hash === '#flagtrace/{target}'")
    ok("a repeat opens its own profile", page.locator(f"#ft-list tr.ft-member.ft-sel[data-trace='{target}']").count() == 1)
    page.wait_for_timeout(6000)  # one auto-refresh
    ok("opened group survives a refresh", page.locator("#ft-list tr.ft-member[data-trace]").count() == 3)
    page.locator("#ft-list button.ft-dup").click()
    page.wait_for_function("document.querySelectorAll('#ft-list tr.ft-member').length === 0")
    ok("×3 again closes the list", "▸" in page.inner_text("#ft-list button.ft-dup"))
    page.uncheck("#ft-group")
    page.wait_for_function(f"document.querySelectorAll('{GROUP_ROWS}').length === 6")
    ok("ungrouped shows every profile", "6 profiles" in page.inner_text("#ft-count").lower()
       and page.inner_text("#ft-list >> xpath=../thead/tr/th[1]").lower().startswith("request time"), page.inner_text("#ft-count"))
    page.reload()
    page.wait_for_selector("#ft-list tr.ft-row")
    page.wait_for_timeout(500)
    ok("choice kept after reload", not page.is_checked("#ft-group") and rows.count() == 6, str(rows.count()))
    page.check("#ft-group")
    page.wait_for_function(f"document.querySelectorAll('{GROUP_ROWS}').length === 4")
    ok("grouping back on", True)
    browser.close()
ok("no page errors", not errors, "; ".join(errors)[:300])
server.shutdown()
sys.exit(0 if all(r[1] for r in results) else 1)
