# Dashboard — where things live

One feature = one backend file + one frontend file. To debug a tab, open only those two.

| Tab | Backend (FastAPI) | Frontend | Host-side action (runs in `host_agent.py`) |
|---|---|---|---|
| Monitor (alert feed, stats, watchdog, ML hints, IOC box) | `app/routes/live.py` | `static/js/monitor.js` | — |
| System Status panel | `app/routes/status.py` | `static/js/status.js` | `health_check.py` (repo root) |
| Events | `app/routes/events.py` | `static/js/events.js` | — |
| Rules — Suricata | `app/routes/rules.py`, generator `app/rulegen/suricata.py` | `static/js/rules.js` | `hostagent/actions/suricata.py` |
| Rules — ctf_proxy | `app/routes/rules.py`, generator `app/rulegen/ctfproxy.py` | `static/js/rules.js` | `hostagent/actions/ctfproxy.py` |
| Rules — load flow from Tulip, quick picks | `app/routes/tulip.py` | `static/js/rules.js` | — |
| Event → Tulip flow lookup (Events "Tulip flow" column, Make rule, Ask LLM) | `app/routes/tulip.py` (`/api/tulip/resolve`) | `static/js/events.js` | — |
| Guide tab (Vietnamese usage guide) | — | `static/index.html` (`#tab-guide`) | — |
| Ask LLM | `app/routes/analyze.py` | `static/js/events.js` | — |
| Services | `app/routes/services.py` | `static/js/services.js` | `hostagent/actions/services.py` + whitelist `hostagent/registry.py` |
| Config | `app/routes/services.py` | `static/js/config.js` | `hostagent/actions/config.py` |
| Hunt (query events + Tulip flows to reconstruct an attack) | `app/routes/hunt.py` | `static/js/hunt.js` | — |
| Applied (which rules are live + hit counts) | `app/routes/applied.py` | `static/js/applied.js` | `hostagent/actions/ctfproxy.py` (get) |
| Rule library (prepared alert rules) | `app/routes/rules.py` (`/api/rules/library`) | `static/js/rules.js` | — |

Shared: `app/core/` (settings, Redis client, `run_op()` = ask the host agent), `static/js/core.js`
(state, modal, toast, `escHtml`), `static/js/api.js` (fetch helpers), `static/js/main.js` (tab routing, startup).

## How a write works (why the dashboard can't break things by itself)

The dashboard container has **no docker socket and no SSH keys**. Anything that changes the
system is sent as a named request through Redis (`run_op()` in `app/core/ops.py`) to
`host_agent.py` on the host, which only executes actions listed in
`hostagent/actions/__init__.py` and only touches services listed in `hostagent/registry.py`.
Every change is validated first (Suricata `-T`, Python compile check, `validate-config.sh`),
backed up, and written to the Events tab (source `host-agent`).

## Logs when something is wrong

```bash
docker logs ctf-dashboard --tail 50     # backend errors (routes)
tail -50 .host-agent.log                # host agent (rule apply, service control, config)
```
Frontend errors: browser devtools console (F12). Each JS file is small and named after its tab.

## Tests

```bash
python3 dashboard/tests/test_rulegen.py   # rule generators: escaping, sid allocation, injection safety, fail-open
```
