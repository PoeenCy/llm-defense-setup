# STATUS.md — Resume Audit (Step A)

Generated: 2026-10-08
Scope: map every item from the prior spec to its actual state in this repo, with evidence.

## ⚠️ Critical finding before reading the table

The continuation spec describes several components that **do not exist anywhere in this
repository** — they are not "broken," they were never built here:

| Spec component | Searched for | Result |
|---|---|---|
| `ctf_proxy` (reverse proxy, rule→harness→deploy→SLA loop) | `find . -iname "*proxy*"` | **Not found.** No directory, no code, no config. |
| Mock vulnbox (for single-machine testing) | `vulnbox-deploy/` contents | Only contains **deploy scripts for a real vulnbox** (`deploy-capture.sh`, `deploy-honeytoken.sh`, `deploy-os-watchdog.sh`). No mock/simulated target service exists. |
| MCP (Model Context Protocol) server for read-only Mongo | `grep -rln "mcp" .` | **Not found.** `ioc-brain/ioc_api.py:74` has a comment *mentioning* "MCP approach" but the actual code uses `pymongo` directly — no MCP server, no MCP client. |
| `analyze-flow <flow_id>` CLI | — | Does not exist. `ioc-brain` only exposes `POST /analyze` (HTTP, takes `log_snippet` or `flow_id` in a JSON body) — no CLI wrapper. |
| Tulip `services/configurations.py` (`vm_ip` + `services=[{ip,port,name}]`) | `offline-bundle/repos/tulip/` | Tulip here is **OpenAttackDefenseTools/tulip**, which is `.env`-based (`VM_IP`, `BPF`, etc.), not `services/configurations.py`. That file format belongs to a different/older Tulip fork. |
| AnythingLLM workspace grounded on `vault/` | `ls vault/` | **`vault/` is empty.** No documents indexed, no workspace configured for RAG. |

**This means Steps B–D as written assume an architecture that isn't present.** Before I touch
the LLM fix (B) or build config generators (D) for `ctf_proxy`/MCP, I need you to confirm:
is this spec describing a **different/future target** you want me to build from scratch now,
or is there prior work (a different session/branch?) that was supposed to land here and didn't?
I don't want to invent a `ctf_proxy` and an MCP server under the assumption they're "resumed"
when there's no trace of them ever existing.

The rest of this audit covers what **does** exist, which is a different (smaller, already
working) stack: `detection`, `ml-fingerprint`, `watchdog`, `ioc-brain`, `dashboard`, Tulip +
Suricata, `bringup.sh`/`teardown.sh`, offline-bundle tooling.

## Audit table (prior spec items → actual state)

| Item | State | Evidence |
|---|---|---|
| Mock vulnbox | **Not found** | No mock/simulated service exists; `services.json` points `vulnbox.ip` at `10.0.0.2`, a host that isn't actually running anything — watchdog correctly reports it down (see Watchdog row). |
| Capture → Tulip | **Pass** | Built a real pcap (TCP handshake + HTTP flag exfil), dropped into `traffic/`. Tulip assembler log: `Processed 11 packets`, `Copied 1 rows into table [flow]`. DB query confirms: `ip_src=10.60.1.5, ip_dst=10.0.0.2, tags=["tcp","http","flag-out"], flags=["BBBB...B="]`. Suricata also independently alerted on the same pcap after a ruleset was added (see below). |
| Deterministic detection (flag-out, <2s) | **Pass** | `time curl -X POST :9999/test/inject-flag` → `{"status":"injected"}`, `real 0m0.021s`. Real pcap-based flag-out alert fired within the 1s poll interval. |
| Honeytoken alert | **Pass** | `curl -X POST :9999/honeytoken` → recorded; `/alerts/recent` shows `type: honeytoken, confidence: HIGH, src_ip: ...`. |
| Suricata → detection wiring | **Was broken, now fixed** | `SuricataIngester` in `detection_service.py` read `TRAFFIC_DIR/eve.json` (wrong path) and the container never mounted Suricata's log dir at all — the feature could never have worked. Fixed: added `SURICATA_DIR` env var, fixed the path, mounted `./suricata/log:/suricata:ro`. Verified live: added a 2-rule test ruleset, Suricata fired 3 alerts, detection log shows `🚨 ALERT: [suricata] [1000001] CTF-TEST Login endpoint accessed`, confirmed via `/alerts/recent`. **Still only a 2-rule test file** — real ruleset (e.g. ET Open) not yet installed. |
| Unified dashboard, priority ordering | **Partial** | `/api/alerts` returns all alert types (flag-out, honeytoken, suricata, sla-down) correctly. Have **not** verified visual priority-ordering/coloring in the actual rendered UI (no browser automation tool available this session) — only confirmed at the API/data layer. |
| `bringup.sh` / `teardown.sh` | **Pass** | Full run completed, health checks: Detection/Dashboard/IOC-Brain/Tulip-UI/AnythingLLM all UP. (Redis shows WARN in the health check but that's a false alarm — the check does an HTTP GET against a non-HTTP service; `redis-cli ping` → `PONG`.) |
| LLM brain (`ioc-brain`) | **Was broken, now partially fixed** | See detailed root-cause below. Chat-template bug fixed; `/analyze` now returns schema-valid JSON end-to-end (verified). **No MCP layer** (direct pymongo, not proven read-only via MCP specifically — see gaps). **No AnythingLLM/vault grounding** (vault is empty). |
| `ctf_proxy` loop (rule→harness→deploy→SLA-green) | **Not found** | See critical finding above. |
| SLA watchdog | **Pass** | Correctly detects the (intentionally absent) mock vulnbox as down: `WATCHDOG ALERT: SERVICE DOWN: svc1 on 10.0.0.2:9001/tcp — timeout`. Logic is sound; just has nothing real to watch yet. |
| OS watchdog (file-integrity + clean snapshot) | **Partial — untested** | `vulnbox-deploy/os-watchdog-agent.sh` exists (snapshot + diff + realtime monitor per earlier work) but has never been deployed or run against a real/mock target in this session. No pass/fail evidence yet. |
| Fingerprint-bot (ML, DBSCAN) | **Partial — in progress** | `ml-fingerprint` container is running and actively processing: log shows `Tick 1: 1 new flows`, `Warmup phase (1/3 ticks)`. Needs ~3 ticks (~6 min) plus synthetic checker-bot-vs-anomalous traffic (per original Task 5 spec) to actually validate clustering output. Not yet run to completion. |

## LLM root-cause note (relevant to Step B)

**Root cause:** The GGUF quant in use (`hf.co/Mungert/Foundation-Sec-8B-GGUF:Q4_K_M`) ships with
no chat-template metadata — `ollama show --modelfile` revealed `TEMPLATE {{ .Prompt }}`, meaning
Ollama never applied system/user role markers. The model received system + user text
concatenated with no structure, so it free-ran instead of following instructions (sample
observed output: `"What is the password?\n\n`AAAA...=`"` instead of JSON).

**Fix:** Foundation-Sec-8B is Llama-3.1-8B based. Built a wrapper model
(`ioc-brain/Foundation-Sec.Modelfile` → `ollama create foundation-sec-8b-chat`) with the
standard Llama-3 chat template (`<|start_header_id|>...<|eot_id|>`) and explicit stop tokens.
`services.json` and `ioc_api.py` now point at `foundation-sec-8b-chat`;
`pull-and-save.sh`/the base pull source is preserved separately as `llm_base_model`.

**Separately found:** this machine's `docker` CLI is backed by **podman** (`docker info` →
`Server Version: 5.4.2`, a podman version string, not a docker-ce release). Custom bridge
networks don't NAT `host.docker.internal` back to the host correctly here (confirmed: resolves
to a link-local IP, but the TCP connect times out), which made `ioc-brain` unable to reach
Ollama on the host at all (`LLM unavailable: Failed to connect to Ollama`) — a **second,
independent bug** layered on top of the template issue. Fixed with an auto-detecting fallback:
`bringup.sh` now checks for the podman signature and sets `DOCKER_HOST_GATEWAY` to the real
docker0/podman bridge gateway IP when needed; `docker-compose.yml`'s three affected services
(`ioc-brain`, `dashboard`, `anythingllm`) now use `${DOCKER_HOST_GATEWAY:-host.docker.internal}`
so real Docker Engine hosts are unaffected.

**Measured latency (CPU-only — no GPU visible in this session, `nvidia-smi` fails):**
cold-start `/analyze` call end-to-end = **90.8s** (`num_predict` capped at 400, down from the
code's original 1024 after a request without a cap ran for 20+ minutes and had to be killed).
This is the single biggest open risk for Step B/E's "latency recorded" acceptance — 90s per
call does not fit inside a typical 2-minute CTF tick if called per-flow.

## Gaps against Step B's specific acceptance criteria (not yet met)

1. "analyze-flow <flow_id> reading Tulip over a read-only Mongo MCP" — no MCP exists; current
   code reads Mongo directly via `pymongo` with a client the code treats as read-only by
   convention/connection string, not enforced by an MCP boundary. The `/mongo/test` endpoint
   mentioned in the original task list (`"write_rejected": true`) was never verified this
   session.
2. "AnythingLLM grounded chat on vault/" — vault is empty; no workspace/embedding verified.
3. Context-length / chunking for large flows — not tested.
4. Retry-on-non-JSON — current `parse_ioc_json()` falls back to a `LOW confidence,
   "not valid JSON"` stub rather than retrying the LLM call.

## Recommendation

Given the critical finding above, I'd rather confirm scope with you than silently build a
`ctf_proxy` + MCP server as if "resuming" — that's new architecture, not a fix. Suggest either:
(a) treat B/C/D as new work and I scope it properly before writing code, or
(b) if `ctf_proxy`/MCP/mock-vulnbox were meant to live in a different repo/location, point me
there and I'll audit that instead.

---

## 2026-10-08 — B, C (partial), D, E completed (new scope, approved plan)

User chose "build from scratch" for `ctf_proxy` + mock-vulnbox + MCP. Full plan at
`~/.claude/plans/cozy-tickling-lemon.md`. All of the below is implemented and tested live, not
just coded.

### New components built
- **`mock-vulnbox/`** — svc1 (FastAPI, intentional SQLi-bypass flaw) + svc2 (raw TCP echo).
- **`offline-bundle/repos/ctf_proxy/`** — real upstream `ByteLeMani/ctf_proxy` (Python IPS for
  A/D CTFs), not reinvented. nginx edge container claims `vulnbox.ip` (10.0.0.2) via a static IP
  on `ctf-net`; `mock-vulnbox` sits behind it, reachable only by Docker DNS. One example filter
  (`proxy/filter_modules/svc1/svc1_in.py`, `sqli_login`) blocks the mock vuln's SQLi bypass.
- **`mcp-tulip/`** — MCP server (`mcp` SDK, pinned `<2` — v2 renamed `FastMCP`→`MCPServer`,
  breaks this code) exposing `get_flow`/`search_flows` over Postgres. Write-safety is enforced
  by a dedicated `tulip_ro` Postgres role (`GRANT SELECT` only) — verified a real `DELETE` is
  rejected by Postgres itself (`permission denied for table flow`), not by app convention.
- **`generators/`** (renamed from `scripts/`) — added `gen-ctfproxy.py`; `gen-tulip-env.py` kept.
- **`services.json`** — added `mock_vulnbox`, `ctf_proxy` (incl. `keyword`), `mcp` sections;
  removed the stale `tulip.mongo_port` (Tulip uses Postgres, confirmed, not Mongo — never real).
- **`validate-config.sh`** — validates the new sections, plus a **keyword byte-sync check**
  between `services.json` and the generated `ctf_proxy/proxy/config/config.json` — tested by
  deliberately drifting the keyword (validator correctly FAILs with the exact mismatch), then
  re-running the generator (validator correctly passes again).
- **`bringup.sh`** — runs `gen-ctfproxy.py`, starts `mock-vulnbox`/`mcp-tulip`, then starts
  `ctf_proxy`'s separate compose project after `ctf-net` exists. Also now **probes** candidate
  bridge gateways live (`nc -z`) instead of trusting a single `docker network inspect` value —
  needed because which gateway actually NATs to the host flipped between runs on this podman-
  backed host (10.88.0.1 worked once, then stopped; 172.17.0.1 has been reliable).

### Step E acceptance — run live, in order
1. `ioc-brain` → MCP → real flow fetch → LLM: `POST /analyze {"flow_id": "<real>"}` returned
   schema-valid IOC JSON correctly identifying `attacker_ip: 10.60.9.9` and the real flag
   (`QCYM5CGWGP8KI34N0WRXULDJ7GZTDB=`) grounded in actual Postgres data, not a log string.
   **Latency: 118.93s** (CPU-only, no GPU visible this session) — larger than the Step B
   log-snippet measurement (90.8s) since full flow+items is a bigger prompt. This is still the
   biggest open risk for a live competition tick cycle.
2. `offline-bundle/repos/ctf_proxy/harness.py` — PASS both checks: legit `/login`+`/flag`
   succeeds through the proxy edge, SQLi payload blocked with response starting with the exact
   configured keyword (`CTFMONITOR_BLOCKED svc1 sqli_login`).
3. Capture → detection → Tulip, through the ctf_proxy edge address (not the backend): a pcap
   representing the legit flag-fetch flow was processed; `detection`'s `/alerts/recent` showed
   `flag-out` within the 1s poll tick; Tulip's `flow` table shows the same flow tagged
   `["tcp","http","flag-out"]` with `flags: ["QCYM5CGWGP8KI34N0WRXULDJ7GZTDB="]`.
4. SLA watchdog: one `SERVICE DOWN`→`SERVICE RESTORED` cycle during ctf_proxy's own startup
   race (expected, ~30s), green continuously after — including through the attack/analysis
   steps above.
5. MCP write-rejection: confirmed directly against Postgres (see above).

### 2026-10-08 (later) — fixed: JSON retry + dead `/mongo/test` crash

User reported a live hallucination: `foundation-sec-8b-chat` sometimes echoes prompt-instruction
text ("Your analysis is incorrect. Please try again... You MUST respond with ONLY valid JSON")
instead of returning JSON, confirming gap #4 above actually occurs in practice. Fixed in
`ioc-brain/ioc_api.py`:
- `parse_ioc_json()` now raises `IocParseError` instead of silently returning a stub, so the
  caller can tell a real failure apart from a merely low-confidence (but valid) result.
- `/analyze` now **retries once** with an added corrective system message
  ("...no other text, no explanation, no markdown") before falling back to the LOW-confidence
  stub. `format="json"` (Ollama grammar-constrained decoding) was already present in the code
  but is evidently not sufficient alone for this quantized model.
- Also found and fixed a **live crash bug**: `/mongo/test` still called `get_mongo_readonly()`,
  which no longer exists (removed when the MCP path replaced direct pymongo) — any call to that
  endpoint would have thrown `NameError`. Replaced with `/mcp/test`, which calls the real
  `search_flows` MCP tool; verified: `{"status": "connected", "flow_count_sampled": 8}`.
- Trade-off accepted: a retry roughly doubles worst-case latency (~240s) on CPU-only inference,
  but only triggers on an actual parse failure — most calls succeed on the first attempt per
  the Step E measurements above.

Note: a `DEMO.md` exists in the repo (user-authored presentation script) referencing ports/
container names that don't match what's actually running (e.g. dashboard `:5050` vs actual
`:8080`, ioc-brain `:8000` vs actual `:5001`, Tulip UI `:5000` vs actual `:3000`, container
names without the `ctf-` prefix, env var `TULIP_POSTGRES_URI` vs actual `POSTGRES_RO_URI`) —
flagged to the user separately; not corrected here since STATUS.md's job is to record this
system's real state, not the demo script.

### 2026-10-08 (later still) — found + fixed: nginx stale-DNS hang, DEMO.md port/credential bugs

While hardening `DEMO.md` for a live audience, found a real operational bug: restarting the
`proxy` container alone (e.g. to toggle verbose logging) leaves `nginx` with a **stale cached
IP** for the `proxy` hostname (nginx resolves `upstream { server proxy:9001; }` once at config
load, not per-connection) — every request then hangs until nginx's own connect-timeout/failover
logic kicks in, which can take much longer than a presenter's patience. **Fix: always restart
`nginx` together with `proxy`**, never one alone. Confirmed clean after restarting both: harness
passes immediately.

Also found while verifying `DEMO.md`'s exact commands against the real system (not just
reading them):
- The block response is raw TCP bytes with no HTTP status line (`block_packet()` sends
  `KEYWORD + service + attack_name` directly over the socket) — `curl -s` on it prints an
  **empty body + `HTTP 000`**, not the `403`/keyword text DEMO.md originally claimed. Fixed by
  pointing that step at `harness.py` (already proven correct, uses a raw socket) instead of
  raw `curl`.
- DEMO.md's "legit SLA" example used credentials `player`/`ctf123`, which don't exist in
  `mock-vulnbox` (only `admin`/`sup3rs3cr3t` is defined in `svc1_http.py`) — would have shown
  401 on stage. Fixed.
- Several port/container-name mismatches throughout (dashboard `:5050`→`:8080`, ioc-brain
  `:8000`→`:5001`, detection endpoints incorrectly pointed at ioc-brain's port, Tulip UI
  `:5000`→`:3000`, bare container names missing the `ctf-` prefix, `TULIP_POSTGRES_URI`→
  `POSTGRES_RO_URI`, and commands targeting `10.0.0.2` directly from the **host** terminal —
  that address is only reliably reachable from inside `ctf-net`, not from the host shell on
  this podman setup; host-facing commands now use `127.0.0.1` via the published port instead).

### Known rough edges (deferred, not blocking)
- Gateway-detection flakiness on this podman-backed host (mitigated with live probing, but the
  underlying podman networking behavior itself is still unexplained/non-deterministic).
- `ctf_proxy` filter hot-reload was observed to not take effect once without a container
  restart (worked on every other attempt) — cause not isolated; harness.py should be re-run
  after any filter edit to confirm, don't assume hot-reload alone is sufficient evidence.
- AnythingLLM/vault RAG grounding — still deferred per the approved plan.
- ml-fingerprint full acceptance — still separate/in-progress, not part of this plan's scope.
