# INVENTORY.md — Item A: full component audit (pre-rebuild)

> Produced before any files were moved, per SPEC build order (A → B → C → …).
> Every top-level directory and every `docker-compose.yml` service is tagged:
> **legal-runtime** (non-AI, allowed in contest mode) · **AI/prep-only** (must be
> quarantined, never started in contest mode) · **dead/remove** (stale, no longer
> used) · **ambiguous** (needs an explicit call before Item C moves it).
>
> Grep basis: `ollama|transformers|torch|llama.cpp|vllm|anythingllm|openai|mcp|llm`
> across all source files (excluding `offline-bundle/`, `.git/`), plus `mongo`
> across the same set. Full greps run during this audit; evidence below quotes
> the hits that mattered.

## Legend

| Tag | Meaning |
|---|---|
| **legal** | No AI/model dependency found. Belongs under `contest-runtime/`. |
| **AI** | Invokes or exists only to serve a generative model / MCP-to-LLM path. Belongs under `prep-only/`. |
| **dead** | Stale reference (old Mongo-based design, unrelated stray artifact). Remove. |
| **ambiguous** | Not generative, but touches "AI/ML" under the contest's literal wording, or has no single obvious zone. Flagged for an explicit decision, not moved yet. |

---

## Top-level directories

| Path | Tag | Evidence / notes |
|---|---|---|
| `dashboard/` | **legal**, with one **AI**-touching route | FastAPI app (`main.py`, `routes/*.py`, `rulegen/*.py`), static UI (`static/`). No ollama/torch import anywhere in `dashboard/app/`. One exception: `dashboard/app/routes/analyze.py` (24 lines) calls out to `ioc-brain` (`IOC_API_URL` env) for the "Analyze"/rule-generation-from-LLM feature. The route itself does no inference — it's an HTTP client to the quarantined service. **Decision needed for Item D/E**: in `MODE=contest` this route must either be absent from the compose/image, or return a clear "disabled in contest mode" response, and the matching UI control (static/js) must be hidden — see Item D acceptance ("no effect in contest mode regardless of flag"). |
| `detection/` | **legal** | `detection_service.py` — flag-out regex (`FLAG_REGEX` env), honeytoken HTTP collector, Suricata `eve.json` ingester. Pure stdlib + `redis`/`fastapi`/`dpkt`/`scapy`. No AI imports. → `contest-runtime/detection/`. |
| `watchdog/` | **legal** | `watchdog_service.py` — SLA prober (socket connect/timeout timing) reading `services.json`. No AI imports. → `contest-runtime/watchdog/`. |
| `hostagent/` + root `host_agent.py` | **legal** | The one long-running **host** (non-container) process: pushes status every 15s, executes a whitelisted action set (`actions/{config,ctfproxy,firewall,services,suricata}.py`) requested by the dashboard over a Redis queue (`ops_requests`). Deterministic command execution only (docker/systemctl/file writes), no AI. → `contest-runtime/` (co-located with `dashboard/` and `watchdog/`, since it's the host-side executor for both — exact subfolder is an Item C placement call, not yet moved). |
| `generators/` | **legal** | `gen-ctfproxy.py`, `gen-tulip-env.py` — pure config templating from `services.json`. → `contest-runtime/config/`. |
| `services.json`, `validate-config.sh` | **legal** | Central config + validator. Already has no Mongo field (see Dead section) and an `mcp.*` section (see Ambiguous — the `mcp` section here is Tulip-Postgres-only info consumed by `mcp-tulip/`, which is itself tagged AI below because its only consumer is `ioc-brain`). → `contest-runtime/config/`. |
| `suricata/` | **legal** | IDS config/rules/log dirs (`etc/`, `lib/rules/`, `log/`) — rule-based, no AI. → `contest-runtime/detection/` or `monitor/` (placement call in Item C). |
| `rules-library/` | **legal** | Ready-to-enable rule templates: `ctfproxy/*.py` (block methods, fail-open, content-matched), `suricata/*.rules` (3260 lines total across 15 files — 12 hand-written categories + 3 ET-style response/web-server/exploit files), `nginx/block-rules.conf`. All deterministic pattern matching. → `contest-runtime/defense/` (ctfproxy + nginx) and `contest-runtime/detection/` (suricata) — currently one directory serving both zones, needs a split in Item C. |
| `vulnbox-deploy/` | **legal** | `deploy-capture.sh`, `deploy-capture-pull.sh` (tcpdump+pcap pull), `deploy-honeytoken.sh`, `deploy-ctfproxy.sh` (opt-in proxy insertion in front of a live service, re-verifies every precondition over SSH, never edits the target's own files), `deploy-os-watchdog.sh` + `os-watchdog-agent.sh` (process/conn/file-hash/cron drift agent, runs ON the vulnbox host, reports to monitor). All deterministic shell, no AI. → split across `contest-runtime/monitor/` (capture), `contest-runtime/detection/` (honeytoken), `contest-runtime/defense/` (ctfproxy insertion), `contest-runtime/watchdog/` (os-watchdog). |
| `traffic/` | **legal** (runtime data, not code) | pcap capture landing dir, gitignored except retention. Stays wherever `monitor/` ends up. |
| `vault/` | **AI** | Only ever mounted into `ioc-brain` and `anythingllm` (`docker-compose.yml` volumes) as the RAG document source. Gitignored except `.gitkeep`. → `prep-only/ai-ioc/vault/`. |
| `config-backups/` | **legal** (runtime data) | Written by `hostagent/actions/config.py` on every config apply (rollback support). Not code — stays with wherever config/hostagent land. |
| `bringup.sh`, `deploy-all.sh`, `teardown.sh` | **legal**, needs rework | Orchestration entrypoints. Currently start **everything** unconditionally, including `ioc-brain`/`mcp-tulip`/`anythingllm` (see `docker-compose.yml` evidence below) and have no `MODE` concept at all — this is the Item B gap. Also contains the only comment admitting the Mongo language is stale: `bringup.sh:14` *"Safety: read-only MongoDB."* (dead comment, Tulip is Postgres — see Dead section). |
| `health_check.py`, `health-check.sh` | **legal** | Status probes consumed by `hostagent`'s status loop and the dashboard. No AI. |
| `mock-vulnbox/` | **ambiguous** | Toy vulnerable app (`svc1_http.py`, `svc2_tcp.py`, plain `python:3.11-slim`, no AI). Used only for local rehearsal before competition day (`services.json.mock_vulnbox.enabled`, default `false`); `bringup.sh` already skips it when disabled. It is not part of the real contest defense stack and isn't listed anywhere in the SPEC's `contest-runtime/` zones. **Recommendation**: move to `prep-only/training/` (practice/rehearsal use, matches §1's description of that zone) rather than `contest-runtime/`, since it exists purely to exercise the pipeline, not to defend anything during the real 8 hours. Flagging for explicit confirmation before Item C moves it, since this changes `bringup.sh`'s current behavior (it's currently reachable in contest mode, just disabled by a flag, not physically absent). |
| `ioc-brain/` | **AI** | `ioc_api.py` — `import ollama`, calls `ollama_lib.AsyncClient(...).chat(model=LLM_MODEL, ...)` (`ioc_api.py:158,171`); ships `Foundation-Sec.Modelfile` (Ollama model build file). This is the generative LLM analysis endpoint (`/analyze`, `/generate-rule`). → `prep-only/ai-ioc/`. |
| `mcp-tulip/` | **AI** | MCP server (`from mcp.server.fastmcp import FastMCP`, `mcp_server.py:16`) exposing read-only Postgres access. Does no inference itself, but its **only** caller anywhere in the repo is `ioc-brain` (`MCP_URL` in `ioc_api.py:53`, `fetch_flow_from_mcp`) — nothing in `detection/`, `watchdog/`, or `dashboard/` talks to it. Per the SPEC's own grep list (`ollama/transformers/torch/mcp/llm`), MCP itself is treated as AI-adjacent, and since it exists solely to feed the quarantined LLM, it has no standalone reason to stay in `contest-runtime/`. → `prep-only/ai-ioc/`. |
| `llm-host/` | **AI** | `setup-llm-host.sh` — installs/configures Ollama + builds the Foundation-Sec model on a **separate dedicated machine**. Not part of `docker-compose.yml` (no service), but it's pure AI-host bootstrap tooling. → `prep-only/ai-ioc/` (or `prep-only/ai-ioc/llm-host/` to keep the "run this on a different machine" framing intact). |
| `ml-fingerprint/` | **ambiguous — flagged for explicit ruling** | `fingerprint_service.py`: `from sklearn.cluster import DBSCAN`, `from sklearn.preprocessing import StandardScaler` (lines 36-37). Online unsupervised clustering of L3/L4 flow features (inter-arrival time, packet size, handshake flags) to flag traffic that deviates from the checker-bot cluster — explicitly a **hint-only** layer, never auto-blocks (`fingerprint_service.py:16-20`). This is **not** generative AI and is **not** deep learning (no `torch`/`transformers`), so it doesn't trip the SPEC's explicit dependency list in Item 3's compliance check. However, the contest's hard constraint in §0 reads *"no AI may execute... including local AI/ML models"* — DBSCAN is a textbook ML model. **Recommendation**: treat this as exactly the "optional ML classifier" the SPEC's own `prep-only/ml-classifier/` zone anticipates (§1, Item D) — default OFF, config-gated (`enable_ml_classifier`), absent from the contest compose, requiring BTC confirmation in writing to enable. This loses a currently-working detection signal from the default contest stack unless BTC explicitly signs off; raising it now rather than deciding unilaterally, since Item F's acceptance criteria don't mention it and STATUS.md itself notes *"ml-fingerprint full acceptance — still separate/in-progress"* (not yet a proven, load-bearing signal). |
| `offline-bundle/` | **mixed, needs rebuild** | Gitignored, regenerable via `pull-and-save.sh`. Currently bundles **everything** together (Tulip/ctf_proxy/pcap-broker repos, redis/nginx/mysql/php images for mock services, **and** `mintplexlabs/anythingllm`, `ollama` wheel, near-empty `ollama-models/` (4KB — model blobs aren't actually captured yet, so today's "offline AI bundle" doesn't even work), plus dead Mongo artifacts — see below). Item I requires this split: a legal-only offline bundle for `contest-runtime`, and a separate prep-only bundle (or an explicit `--with-ai` flag) for `prep-only`. |
| `docs/` | **mixed** | `ARCHITECTURE.md`, `DASHBOARD_GUIDE.md`, `GOLIVE.md`, `RUNBOOK.md`, `SCHEMA.md`, `STATUS.md`, `RULE_COOKBOOK.md`, `DEMO.md` — all describe the legal stack (DEMO.md also has known factual drift from STATUS.md, unrelated to this spec). `REMOTE_LLM.md` is AI-only (dedicated Ollama host doc) → should move or be clearly marked as a `prep-only` doc. |
| `__pycache__/` (root) | **dead** | Build artifact, already gitignored; delete on sight, not a real component. |

## `docker-compose.yml` services (single master file today — Item B/C splits this)

| Service | Tag | Evidence |
|---|---|---|
| `mock-vulnbox` | ambiguous (see above) | `docker-compose.yml:15-25` |
| `redis` | legal | `docker-compose.yml:30-43` — shared alert/hint queue, no AI |
| `detection` | legal | `docker-compose.yml:48-76` |
| `ml-fingerprint` | ambiguous (see above) | `docker-compose.yml:81-101` |
| `watchdog` | legal | `docker-compose.yml:106-123` |
| `mcp-tulip` | **AI** | `docker-compose.yml:132-145` — joins `tulip-internal` network *only* to serve `ioc-brain` |
| `ioc-brain` | **AI** | `docker-compose.yml:147-174` — `OLLAMA_HOST`, `LLM_MODEL`, `EMBED_MODEL`, `GPU_LAYERS` env; depends on `mcp-tulip` |
| `dashboard` | legal (see analyze.py caveat above) | `docker-compose.yml:179-207` — `IOC_API_URL` env wires it to the quarantined service for one feature only |
| `anythingllm` | **AI** | `docker-compose.yml:212-233` — `mintplexlabs/anythingllm:latest`, `LLM_PROVIDER=ollama` |

**Today, `bringup.sh` has no gate at all** — every one of these (including `ioc-brain`, `mcp-tulip`, `anythingllm`) starts unconditionally. This is the single biggest compliance gap and is what Item B/D close.

## Mongo remnants (to remove — Tulip has used Postgres/TimescaleDB for a while; `services.json`/`validate-config.sh` are already clean, these are the leftovers)

| Location | What | Action |
|---|---|---|
| `pull-and-save.sh:38` | `"mongo:7.0"` in the image pull list | Remove — nothing in the stack runs Mongo |
| `pull-and-save.sh:97` | `"pymongo>=4.7.0"` in the wheel list | Remove |
| `offline-restore.sh:88` | `pymongo` in the pip install fallback line | Remove |
| `offline-bundle/images/mongo_7.0.tar` | Stale pulled image (gitignored, local only) | Delete locally; stops being regenerated once the two lines above are removed |
| `offline-bundle/wheels/pymongo-4.18.2-*.whl` | Stale wheel (gitignored, local only) | Delete locally |
| `ioc-brain/ioc_api.py:9,13,48,50-52` | Comments *about* Mongo, explaining it's NOT used (MCP/Postgres replaced it) | No code change needed, but these comments move wholesale with the file into `prep-only/ai-ioc/` — fine as-is, already accurate |
| `rules-library/ctfproxy/block-injection.py:36` | `"""NoSQL (Mongo-style) injection...` | **Not a remnant** — this is a real detection rule for NoSQL injection against target services (which may use Mongo even though Tulip doesn't). Keep. |
| `docs/STATUS.md`, `docs/DEMO.md`, `docs/RUNBOOK.md`, `docs/SCHEMA.md` | Historical mentions of the old Mongo design / a `/mongo/test` endpoint | Already superseded in STATUS.md itself (documents the `/mongo/test` → `/mcp/test` fix); `RUNBOOK.md:347-348` and `SCHEMA.md:91` still reference the dead `/mongo/test` curl example and a `mongo_port` field that no longer exists in `services.json` — fix during Item J doc pass. |

## Other dead/stray items found (not Mongo, not AI — just noise)

| Location | Note |
|---|---|
| `offline-bundle/images/localhost_aquahome-northflank_test.tar` | Not referenced anywhere in `pull-and-save.sh`'s image list — appears to be an unrelated image saved into this directory by hand or by another project. Gitignored (local only). Delete. |
| `offline-bundle/images/composer_2.tar` | Also not in `pull-and-save.sh`'s list; `mock-vulnbox` only uses `python:3.11-slim` (no PHP/composer anywhere in this repo). Stray. Delete. |
| `offline-bundle/images/moby_buildkit_buildx-stable-1.tar` | Buildkit is needed to *build* images, not to run the contest stack; bundling it as a runtime image is unnecessary bloat (~harmless, but not something `offline-restore.sh` needs to load). Leave out of the next bundle rebuild. |
| `.host-agent.log`, `.status-pusher.log`, `.claude/scheduled_tasks.lock` | Runtime/tooling artifacts, already gitignored (except `.claude/`, which isn't part of the app). No action needed. |

---

## Summary tally

- **legal-runtime** (move into `contest-runtime/`): `dashboard/` (minus the ioc-brain call), `detection/`, `watchdog/`, `hostagent/` + `host_agent.py`, `generators/`, `services.json`, `validate-config.sh`, `suricata/`, `rules-library/`, `vulnbox-deploy/`, `traffic/`, `config-backups/`, `health_check.py`, `health-check.sh`, `bringup.sh`/`deploy-all.sh`/`teardown.sh` (reworked for MODE).
- **AI/prep-only**: `ioc-brain/`, `mcp-tulip/`, `anythingllm` (compose service), `llm-host/`, `vault/`, `docs/REMOTE_LLM.md`.
- **dead/remove**: Mongo lines in `pull-and-save.sh`/`offline-restore.sh` + their stale local artifacts, 3 stray `offline-bundle/images/*.tar` files, root `__pycache__/`.
- **ambiguous — needs a decision before Item C/D proceed**:
  1. `ml-fingerprint/` — ML (DBSCAN) but not generative; recommend quarantining to `prep-only/ml-classifier/` per the SPEC's own zone, BTC-gated, but this removes a working (if not-yet-fully-accepted) detection signal from the default contest stack.
  2. `mock-vulnbox/` — recommend `prep-only/training/` since it's rehearsal-only, not real defense.
  3. `dashboard/app/routes/analyze.py` (+ matching UI) — needs a concrete "absent/disabled in contest mode" design, not just left pointing at a dead URL.

No item above is unclassified. Proceeding to Item B (mode switch) next, pending your call on the three ambiguous items.
