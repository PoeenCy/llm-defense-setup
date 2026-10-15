"""Browser acceptance for the FLAG TRACE tab, step 2 of 2 (see serve_fixture.py).
Needs Playwright; CHROMIUM=<path> selects an already installed browser."""
import json, os, sys
from pathlib import Path
from playwright.sync_api import sync_playwright
DATA = Path(sys.argv[1]); BASE = os.environ.get("DASHBOARD", "http://127.0.0.1:18080")
SHOTS = Path(os.environ.get("SHOTS", DATA))
traces = json.loads((DATA / "traces.json").read_text())
results, errors = [], []
def ok(name, cond, detail=""):
    results.append((name, bool(cond), detail)); print(("PASS " if cond else "FAIL ") + name, detail, flush=True)
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=os.environ.get('CHROMIUM') or None)
    context = browser.new_context(viewport={"width": 1600, "height": 1000})
    context.grant_permissions(["clipboard-read", "clipboard-write"], origin=BASE)
    page = context.new_page()
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.add_init_script("window.__alerts=[]; window.alert=(m)=>window.__alerts.push(String(m));")
    page.goto(BASE + "/#flagtrace")
    page.wait_for_selector("#ft-list tr.ft-row")
    rows = page.locator("#ft-list tr.ft-row")
    ok("list shows 4 profiles", rows.count() == 4, page.inner_text("#ft-count"))
    ok("pending profile listed with state", "pending" in rows.nth(0).inner_text(), rows.nth(0).inner_text())
    ok("worker status shown", "no worker" in page.inner_text("#ft-worker"), page.inner_text("#ft-worker"))
    # ingest decoder mode: config default, lowered from the UI, kept on reload, reset
    page.wait_for_function("document.querySelector('#ft-decoder-state').innerText.startsWith('decoder')")
    ok("decoder shows config default", page.input_value("#ft-decoder") == "full"
       and page.inner_text("#ft-decoder-state") == "decoder full" and not page.is_visible("#ft-decoder-reset"),
       page.inner_text("#ft-decoder-state"))
    ok("decoder status explains the mode", "every body is decoded" in page.get_attribute("#ft-decoder-state", "title")
       and "searched" in page.get_attribute("#ft-decoder-state", "title"), page.get_attribute("#ft-decoder-state", "title")[:120])
    page.select_option("#ft-decoder", "gated")
    page.wait_for_function("document.querySelector('#ft-decoder-state').innerText.includes('GATED')")
    ok("gated set from the UI", "applies from the next capture" in page.inner_text("#ft-decoder-out")
       and page.is_visible("#ft-decoder-reset"), page.inner_text("#ft-decoder-state"))
    page.once("dialog", lambda d: d.dismiss())
    page.select_option("#ft-decoder", "off")
    page.wait_for_timeout(500)
    ok("cancelling OFF keeps the mode", page.input_value("#ft-decoder") == "gated"
       and "GATED" in page.inner_text("#ft-decoder-state"), page.inner_text("#ft-decoder-state"))
    dialogs = []
    page.once("dialog", lambda d: (dialogs.append(d.message), d.accept()))
    page.select_option("#ft-decoder", "off")
    page.wait_for_function("document.querySelector('#ft-decoder-state').innerText.includes('OFF')")
    ok("OFF asks first and is shown in red", dialogs and "OFF" in dialogs[0]
       and "state-stopped" in page.get_attribute("#ft-decoder-state", "class"), page.inner_text("#ft-decoder-state"))
    page.reload()
    page.wait_for_function("document.querySelector('#ft-decoder-state').innerText.includes('OFF')")
    ok("OFF kept after reload", page.input_value("#ft-decoder") == "off" and "dashboard" in page.get_attribute("#ft-decoder-state", "title"))
    page.click("#ft-decoder-reset")
    page.wait_for_function("document.querySelector('#ft-decoder-state').innerText === 'decoder full'")
    ok("reset returns to config default", page.input_value("#ft-decoder") == "full" and not page.is_visible("#ft-decoder-reset")
       and "config default" in page.inner_text("#ft-decoder-out"), page.inner_text("#ft-decoder-out"))
    page.wait_for_selector("#ft-list tr.ft-row")
    rows = page.locator("#ft-list tr.ft-row")
    # open the two-run profile from the list
    page.locator(f"#ft-list tr[data-trace='{traces['/files/f1aaaa']}']").click()
    page.wait_for_selector("#ft-steps tr.ft-row")
    ok("hash has trace id", page.evaluate("location.hash") == "#flagtrace/" + traces["/files/f1aaaa"], page.evaluate("location.hash"))
    steps = page.locator("#ft-steps tr.ft-row")
    roles = page.locator("#ft-steps .ft-role").all_inner_texts()
    ok("timeline has anchor + data-linked", any("anchor" in r for r in roles) and sum("data-linked" in r for r in roles) == 3, str(roles))
    numbers = [steps.nth(i).locator("td").first.inner_text() for i in range(steps.count())]
    ok("timeline is the flow only, numbered 1..4", numbers == ["1", "2", "3", "4"], str(numbers))
    # Tulip column: one link per step, resolved at display time. This fixture
    # has no Tulip, so every cell must say why instead of erroring or hanging.
    ok("timeline column is Tulip, not Quality",
       "TULIP" in page.inner_text("#ft-steps >> xpath=../thead/tr").upper()
       and "QUALITY" not in page.inner_text("#ft-steps >> xpath=../thead/tr").upper())
    page.wait_for_function("[...document.querySelectorAll('#ft-steps td.ft-tulip')].every(c => c.innerText.trim() !== '…')",
                           timeout=60000)
    cells = page.locator("#ft-steps td.ft-tulip")
    ok("every step has a Tulip cell", cells.count() == page.locator("#ft-steps tr[data-tx]").count(), str(cells.count()))
    reasons = [c.locator("[title]").first.get_attribute("title") if c.locator("[title]").count() else None
               for c in cells.all()]
    ok("unreachable Tulip is explained, not crashed", all(reasons), str(reasons[:1])[:120])
    ok("step quality is still shown", "resp:" in page.inner_text("#ft-steps"))
    ok("history select has 2 results", page.locator("#ft-runs option").count() == 2, page.inner_text("#ft-runs"))
    page.wait_for_selector("#ft-evidence .ft-card")
    ok("anchor evidence shows flag mark", page.locator("#ft-evidence mark.ft-mark-flag").count() >= 1)
    page.screenshot(path=str(SHOTS / "01-profile.png"), full_page=True)
    # value roles: what each value is, with the flag ID turned into a template
    vroles = page.locator("#ft-values .ft-vrole").all_inner_texts()
    ok("values table lists target, linked and generated",
       all(any(r in v for v in vroles) for r in ("target", "linked", "generated")), str(vroles))
    ok("flag ID becomes a template", "../../notes/{flag_id}.txt" in page.inner_text("#ft-values"))
    ok("flag-ID source status shown", "available" in page.inner_text("#ft-values-summary"),
       page.inner_text("#ft-values-summary")[:120])
    chain_copy = page.locator("#ft-summary .ft-chain-copy")
    ok("linked result has Copy chain beside its state", chain_copy.count() == 1
       and chain_copy.evaluate("b => b.previousElementSibling.classList.contains('state-running')"),
       page.inner_text("#ft-summary")[:160])
    chain_copy.click()
    page.wait_for_function("document.querySelector('#ft-summary .ft-chain-copy').innerText === 'Copied'")
    ok("quick Copy chain does not expand source preview", page.locator("#ft-script-preview").is_hidden())
    step_copies = page.locator("#ft-steps .ft-step-copy")
    ok("every timeline step has its request Copy", step_copies.count() == steps.count(),
       f"{step_copies.count()} buttons for {steps.count()} steps")
    step_copies.first.click()
    page.wait_for_function("document.querySelector('#ft-steps .ft-step-copy').innerText === 'Copied'")
    ok("quick step Copy does not expand source preview", page.locator("#ft-script-preview").is_hidden())
    ok("script artifacts shown", page.locator("#ft-scripts tr.ft-row").count() == 5,
       page.inner_text("#ft-scripts-summary"))
    ok("chain is generated but not claimed reproduced",
       "supported" in page.inner_text("#ft-scripts") and "not_run" in page.inner_text("#ft-scripts"),
       page.inner_text("#ft-scripts")[:200])
    page.locator("#ft-scripts .ft-script-copy").last.click()
    page.wait_for_function("!document.querySelector('#ft-script-preview').hidden")
    ok("script loaded through scoped artifact endpoint", "def exploit(" in page.inner_text("#ft-script-preview"))
    page.locator("#ft-values tr.ft-row", has_text="linked").first.click()
    page.wait_for_function("document.querySelectorAll('#ft-evidence .ft-card').length === 2")
    heads = page.locator("#ft-evidence .ft-card-head").all_inner_texts()
    ok("linked value shows its source and its use", "Source" in heads[0] and "Value (linked)" in heads[1],
       " | ".join(h[:40] for h in heads))
    page.screenshot(path=str(SHOTS / "01b-values.png"), full_page=True)
    # click the cookie edge: source + destination evidence with highlighted token
    edge = page.locator("#ft-edges tr.ft-row", has_text="cookie").first
    edge.click()
    page.wait_for_function("document.querySelectorAll('#ft-evidence .ft-card').length === 2")
    heads = page.locator("#ft-evidence .ft-card-head").all_inner_texts()
    ok("edge shows source and destination", "Source" in heads[0] and "Destination" in heads[1], " | ".join(h[:60] for h in heads))
    ok("both cards highlight the token row", page.locator("#ft-evidence tr.ft-hl-row").count() == 2)
    ok("two timeline steps selected", page.locator("#ft-steps tr.ft-sel").count() == 2)
    page.screenshot(path=str(SHOTS / "02-edge.png"), full_page=True)
    # older run via the selector, deep link includes run id, then back
    older = page.locator("#ft-runs option").nth(1).get_attribute("value")
    page.select_option("#ft-runs", older)
    page.wait_for_function(f"location.hash.endsWith('{older}')")
    page.wait_for_function("document.querySelector('#ft-summary').innerText.includes('older result')")
    ok("older run selectable", True, page.evaluate("location.hash")[-16:])
    page.reload(); page.wait_for_selector("#ft-steps tr.ft-row")
    page.wait_for_function("document.querySelector('#ft-summary').innerText.includes('older result')")
    ok("deep link to older run survives reload", page.input_value("#ft-runs") == older)
    page.go_back(); page.wait_for_function(f"!location.hash.endsWith('{older}')")
    page.wait_for_function("!document.querySelector('#ft-summary').innerText.includes('older result')")
    ok("back returns to latest result", page.evaluate("location.hash") == "#flagtrace/" + traces["/files/f1aaaa"])
    # html payload profile: captured markup is text, nothing runs
    page.goto(BASE + "/#flagtrace/" + traces["/files/hxfile01"]); page.reload()
    page.wait_for_selector("#ft-evidence .ft-card")
    page.locator("#ft-evidence details").evaluate_all("ds => ds.forEach(d => d.open = true)")
    txt = page.inner_text("#ft-evidence")
    ok("markup rendered as text", '<script>alert("xss")</script>' in txt)
    ok("no element injected", page.locator("#ft-evidence script, #ft-evidence img").count() == 0)
    page.wait_for_timeout(500)
    ok("no alert executed", page.evaluate("window.__alerts.length") == 0)
    page.screenshot(path=str(SHOTS / "03-html-payload.png"), full_page=True)
    # pending + degraded profile: older result shown, newer request pending, quality visible
    page.goto(BASE + "/#flagtrace/" + traces["/files/dgfile"]); page.reload()
    page.wait_for_selector("#ft-steps tr.ft-row")
    head = page.inner_text("#ft-head")
    ok("pending request shown over kept result", "pending" in head and page.locator("#ft-runs option").count() == 1, head[:160])
    ok("incomplete step quality visible", "resp:incomplete_body" in page.inner_text("#ft-steps"))
    # retrace from the UI queues a new request
    page.click("#ft-retrace")
    page.wait_for_function("document.querySelector('#ft-retrace-out').innerText.includes('queued')")
    ok("retrace queued", True, page.inner_text("#ft-retrace-out"))
    # other tabs still route and the flag-trace polling stops
    for tab in ("events", "rules", "services", "monitor"):
        page.click(f"#tabnav button[data-tab='{tab}']")
        ok(f"tab {tab} routes", page.evaluate("location.hash") == "#" + tab and page.is_visible(f"#tab-{tab}"))
    ok("polling stopped off-tab", page.evaluate("FT.timer") is None)
    page.go_back()
    # Tab switches replace the history entry (existing design), so Back goes to
    # the previous real navigation: the html-payload profile, which must open.
    page.wait_for_function("FT.trace && location.hash === '#flagtrace/' + FT.trace")
    ok("browser back reopens the previous profile", page.evaluate("location.hash") == "#flagtrace/" + traces["/files/hxfile01"]
       and page.is_visible("#tab-flagtrace"), page.evaluate("location.hash"))
    page.goto(BASE + "/#flagtrace/" + "0" * 64); page.reload(); page.wait_for_timeout(800)
    ok("unknown profile handled", "not found" in page.inner_text("#ft-detail").lower())
    browser.close()
ok("no page errors", not errors, "; ".join(errors)[:300])
sys.exit(0 if all(r[1] for r in results) else 1)
