# CTF Monitor Hub — Operations Runbook

> **Role:** Lead monitor machine for Attack-Defense CTF.  
> **This box:** Ingests traffic, runs detection, serves the situational-awareness dashboard.  
> **No LLM / generative-AI path exists in this repo** (removed — see `docs/STATUS.md`). The only
> model-adjacent component is the optional `ml-fingerprint` classifier (sklearn, non-generative,
> off by default) — see Item D's compliance notes in `docs/STATUS.md` if that matters for your
> contest's rules.

---

## Quick-Start — the 1-click

```bash
MODE=contest bash deploy-all.sh
```
(`MODE=prep` instead for home/practice use — enables the optional `ml-fingerprint` classifier
and `mock-vulnbox` rehearsal target if `services.json` turns them on. **Never use `MODE=prep` on
contest day.**)

Runs, in order: **preflight** (docker/docker-compose/python3 present, the `redis` Python module
importable — auto-installs it via pip if missing, and **fails loudly with the exact fix command**
if it still can't, rather than letting `host_agent.py` crash silently later) → config validation
→ local stack (Tulip/detection/dashboard/watchdog) → remote capture (auto-detects the external
interface, no docker-bridge name needed) → ctf_proxy (only if `ctf_proxy.insertion` in
`services.json` is filled in and every precondition re-verifies over SSH — otherwise skips
cleanly and you stay in monitor-only mode) → a final `health-check.sh` report. **Safe to re-run
any time** — every step is idempotent, nothing here deletes data.

If the vulnbox is unreachable, the local stack still comes up fine (steps 4-5 log a clear
warning and continue); you'll just have no live traffic until that's fixed. See this file's
Troubleshooting → "Always start here" (`health-check.sh`) for diagnosing what's actually wrong.

### First-time setup (before you can run deploy-all.sh at all)

This part cannot be automated away — the values below are specific to your team and your
contest's network, and only a human can enter them correctly. Everything AFTER this step is
scripted and self-checking.

```bash
# 1. Edit the central config — this is the ONLY file you hand-edit
nano contest-runtime/config/services.json
#   Must fill in at minimum: team_id, vulnbox.ip, monitor_host.ip, flag.regex,
#   teams_cidr, services[] (your real service ports). See docs/SCHEMA.md for
#   every field, and docs/GOLIVE.md for the organizer-handoff checklist.

# 2. Validate config — catches typos/missing fields BEFORE anything else runs
bash contest-runtime/config/validate-config.sh
#   Any [FAIL] line here must be fixed before continuing — nothing downstream
#   will work right with an invalid config, and later steps will say so too.

# 3. (while you still have internet) Bundle everything for offline use
bash pull-and-save.sh       # ~10-20 min, downloads several GB of images/wheels/repos
```

### Air-gapped machine, competition day

```bash
# 1. Copy offline-bundle/ from the prep machine (USB/LAN transfer)
rsync -a offline-bundle/ /path/to/Setup_tool/offline-bundle/

# 2. Restore from bundle (zero network calls) — prints [FATAL] and stops if
#    offline-bundle/ is missing or incomplete, rather than half-restoring
bash offline-restore.sh

# 3. 1-click bring-up
MODE=contest bash deploy-all.sh
```

**If something in steps 1-3 fails:** every script in this repo (`validate-config.sh`,
`bringup.sh`, `offline-restore.sh`, `deploy-all.sh`) prints a `[FATAL]`/`[FAIL]` line and a
non-zero exit code on real problems — it does not continue silently into a half-working state.
If you see a plain Python traceback instead of one of those, that's itself a bug worth reporting,
not something to work around by re-running blindly.

---

## Architecture Overview

```
                    ┌─────────────────────────────────────────┐
                    │          Monitor Machine (this box)      │
                    │                                          │
  vulnbox ──pcap──▶ │  Tulip (TimescaleDB + Assembler)        │
  (pcap-broker)     │    ▲                                     │
                    │    │ flows                               │
                    │  ┌─┴──────────────────────────────────┐  │
                    │  │         Detection Layer (Item 4)   │  │
                    │  │  • flag-out regex scan              │  │
                    │  │  • Suricata alert ingester          │  │
                    │  │  • honeytoken HTTP collector        │  │
                    │  └────────────────┬───────────────────┘  │
                    │                   │ alerts                │
                    │  ┌────────────────▼───────────────────┐  │
                    │  │         Redis (alert queue)         │  │
                    │  └──┬─────────────┬───────────────────┘  │
                    │     │             │                       │
                    │  ┌──▼──┐      ┌──▼──────────────────┐   │
                    │  │ML FP│      │  Dashboard (Item 8)  │   │
                    │  │prep-│      │  WebSocket → browser │   │
                    │  │only │      └─────────────────────┘    │
                    │  └─────┘                                 │
                    │  Watchdog (SLA poller, Item 7)            │
                    └─────────────────────────────────────────┘
```

---

## Services & Ports

| Service | Port | Description |
|---------|------|-------------|
| Dashboard | 8080 | Unified monitoring UI |
| Tulip UI | 3000 | Flow inspection |
| Detection/Honeytoken | 9999 | Alert collector + honeytoken |
| Redis | 6380 | Shared alert queue |

`MODE=prep` only (never on contest day): `mock-vulnbox` (toy target) and `ml-fingerprint`
(bot-deviation hints over Redis, no published port) — both off by default, see `services.json`.

---


## Bring-Up Order

Services **must** start in this order (handled by `bringup.sh`):

1. **Redis** — shared alert queue (all other services depend on it)
2. **Tulip stack** — traffic ingestion + TimescaleDB
3. **Detection service** — flag-out scanner, honeytoken collector
4. **Watchdog** — SLA poller
5. **Dashboard** — unified UI
6. *(`MODE=prep` only)* **ML Fingerprint** — bot fingerprinter (warmup: 3 ticks), if
   `services.json`'s `ml_classifier.enabled` is true
7. *(`MODE=prep` only)* **mock-vulnbox** — rehearsal target, if `mock_vulnbox.enabled` is true

---


## Offline Restore Procedure

> Use on a clean, air-gapped machine. Must have `offline-bundle/` transferred first.

```bash
# Prerequisites
which docker && docker compose version   # Docker 24+ with the compose v2 plugin
which python3                             # Python 3.11+
python3 -c "import redis" || pip3 install --user redis   # host_agent.py needs this

# Step 1: Load Docker images (fails loudly if offline-bundle/ is missing/incomplete)
bash offline-restore.sh

# Step 2: Verify
docker images | grep tulip           # should show tulip-* images
docker images | grep redis           # should show redis:7-alpine

# Step 3: Bring up
MODE=contest bash bringup.sh --offline
```

### Verifying air-gap compliance

```bash
# All of these should FAIL (timeout/refused) on an air-gapped machine:
curl --connect-timeout 3 https://docker.io
curl --connect-timeout 3 https://pypi.org
```

---

## Acceptance Tests (run after bring-up)

### Test 1: Flag-out detection fires in <2s

```bash
# Inject a fake flag-out alert
curl -X POST http://localhost:9998/test/inject-flag
# Expect: 200 OK + alert appears on dashboard within 2s
```

### Test 2: Honeytoken alert

```bash
# Trigger honeytoken endpoint
curl -X POST http://localhost:9999/honeytoken
# Expect: alert type=honeytoken appears on dashboard
```

### Test 3: SLA watchdog fires in <5s

```bash
# Stop a mock service (e.g. block port with iptables)
sudo iptables -I INPUT -p tcp --dport 9001 -j REJECT
sleep 5
curl http://localhost:8080/api/alerts | python3 -m json.tool | grep sla-down
# Restore
sudo iptables -D INPUT -p tcp --dport 9001 -j REJECT
```

### Test 4: Dashboard shows all signal types

1. Run tests 1, 2, 3 above
2. Open `http://localhost:8080`
3. Verify: flag-out (red), honeytoken (red), sla-down (red) all visible
4. Verify priority order: flag-out/honeytoken at top, ML hints at bottom (`MODE=prep` only)

---


## Deploying Vulnbox-Side Components

> **This is what we actually run in practice — NOT the pcap-broker design described
> elsewhere in older docs.** `pcap_broker_port` in services.json is unused; real
> capture goes over SSH + tcpdump + rsync pull, because the vulnbox here is a
> Docker container on a shared Azure host we don't control, reached only via
> `ssh dfcd-vbox` (an alias in `~/.ssh/config`, ProxyJump through the gameserver).

### Step 0 — confirm you can even reach it

```bash
ssh dfcd-vbox "echo OK"
```
If this times out ("Connection timed out during banner exchange"), the Azure VMs
are probably stopped/deallocated. **You (or the organizer) must start them from
the Azure portal/CLI — Claude/no tool here can do that.** Nothing below will work
until this succeeds.

### Step 1 — start capture + pull loop (one script, idempotent)

```bash
bash contest-runtime/monitor/deploy-capture-pull.sh
```
This SSHes in, starts `tcpdump -Z root -i <docker_bridge> -w ... -G 30` on the
vulnbox-host (writing 30s-rotated pcap files to `/tmp/ctf-capture-<pid>/` —
**not persistent across a VM reboot**, must be redone every time the VM restarts),
then loops locally pulling files back into `./traffic/` every 15s via rsync.

**Run it as a long-lived watch** (e.g. the Monitor tool, or a terminal you leave
open) — if it stops, pcaps pile up on the remote side instead of reaching Tulip,
and nothing errors loudly to tell you.

### Step 2 — deploy ctf_proxy in front of the real service (optional, for blocking)

See **"Deploying ctf_proxy Against a Real Vulnbox"** below — this is a separate,
riskier step (touches the live service's port binding) and is not part of basic
monitoring/capture.

### Step 3 — OS watchdog / honeytoken (same pattern as before, if you have root on the vulnbox)

```bash
bash contest-runtime/watchdog/deploy-os-watchdog.sh
bash contest-runtime/detection/deploy-honeytoken.sh
```

### Verify capture is actually producing usable data

Don't just check the loop is running — check Tulip is turning files into flows:

```bash
docker exec tulip-timescale-1 psql 'postgres://tulip@timescale:5432/tulip' \
  -c "SELECT count(*), max(time) FROM flow;"
# max(time) should be within the last minute or two if traffic is live.
# If count never grows and docker logs tulip-assembler-1 keeps saying
# "Processed 0 packets" on files you can see have real packets in them
# (check with: tcpdump -r traffic/<file>.pcap | wc -l) — see the BPF gotcha below.
```

---

## Deploying ctf_proxy Against a Real Vulnbox

> This inserts a filtering proxy into the actual traffic path for EVERY TCP service listed in
> `services.json` (one deploy, all of them). **It WILL cause a few seconds of downtime** per
> service when its port binding flips over — confirm this is an acceptable risk window before
> doing it during a scored round. UDP services are never touched — ctf_proxy itself can't proxy
> UDP (see its own README); use the Dashboard's content-based firewall block for those instead.

This is config-driven and automated (`contest-runtime/defense/deploy-ctfproxy.sh`,
called by `deploy-all.sh`), because the only safe way to insert a proxy in
front of a *live* service is to know exactly which compose file/service/network
it lives in. Guessing at an unfamiliar layout risks a bad edit to a real
service's config. The script does nothing by default and only acts once you
tell it where to look — and even then it re-verifies every assumption over SSH
immediately before touching anything, skipping cleanly (per service, not all-
or-nothing) if any check fails for that one.

### Point it at the real target(s)

Shared connection settings, edit `services.json` → `ctf_proxy.insertion`:
```json
"insertion": {
    "mode": "docker-compose",
    "remote_compose_file": "~/practice-setup/<team>/docker-compose.yml",
    "remote_compose_service": "public-proxy",
    "remote_network_name": "<team>_proxy-public",
    "remote_ssh_alias": "dfcd-vbox"
}
```
Default `mode` is `"disabled"` — i.e. monitor-only, nothing attempted. You find
`remote_network_name` with `ssh <alias> "docker network ls"` on the vulnbox-host
(it's whatever network the target service's own compose file defines, usually
named `<project>_<network-key-in-that-compose-file>`).

Per-service: each entry in `services[]` may set its own `compose_service` (the
compose service name backing THAT port, if it differs from the shared
`remote_compose_service` above) and must set `layer` (`l7-http`/`l7-https` →
ctf_proxy parses it as HTTP; `l4-raw` → raw TCP, filters only see bytes; `l4-udp`
or `proto: "udp"` → skipped entirely, not eligible). A service with no
`compose_service` falls back to the shared `remote_compose_service` field above
— that's what keeps a single-service config written before this field existed
working unchanged.

### What it actually does (same steps whether you run it by hand or let the script)

```bash
bash contest-runtime/defense/deploy-ctfproxy.sh
```
1. Builds the list of eligible services (`proto: "tcp"` in `services[]`); logs a warning and
   skips any `"proto": "udp"` entries. For each eligible service, verifies: SSH reachable
   (checked once), compose file exists, its `compose_service` is defined in it, that service
   actually publishes the target port, the shared network exists, `docker compose` is available
   remotely. A service that fails its own check is skipped (warning, not fatal) — it doesn't
   block the others.
2. Copies `ctf_proxy` source to the vulnbox-host (`~/ctf-proxy-<team_id>/`) — once, shared by
   every service.
3. Writes ONE `proxy/config/config.json` with one entry per eligible service: `name` = the
   service's name (sanitized to a valid Python identifier — it becomes a module name), `target_ip`
   = its compose SERVICE NAME (not an IP; resolved via Docker DNS once ctf_proxy joins the
   network), `target_port` = the container-internal port found in step 1, `listen_port` = its
   public port from `services.json`, `http` = `true` only for `l7-http`/`l7-https`.
4. Writes ctf_proxy's own `docker-compose.yml` — `nginx`'s `ports:` lists every eligible
   service's public port, `nginx`+`proxy` join the vulnbox's **existing** network instead of
   creating their own.
5. Removes the public port line from each eligible service's ORIGINAL compose file (the whole
   file backed up once, first service to touch it, as `<file>.pre-ctfproxy.bak`) and recreates
   each affected compose service (deduped if two ports share one compose service) to release the
   ports — this is the few-seconds-downtime moment, once per distinct compose service.
6. Builds + starts ctf_proxy once (shared container, serves all services), with a built-in
   recovery for a known startup race (see below), then checks each service's public port — curls
   it if it looks like HTTP, otherwise a raw TCP connect check — to confirm real traffic still
   gets through before declaring success.

Re-running the script is safe: a service that already has ctf_proxy in front of it (its original
port binding is already gone) fails its own precondition check and is skipped — no double-insert,
and the live filter content for services that were already running is never touched (`rsync`
never overwrites `filter_modules/<service>/` once it exists on the remote; verified with
`rsync --dry-run` before trusting this).

**Known gotcha, already handled by the script — nginx container boots into a
broken state:** `docker logs <ctfproxy>-nginx` repeating `host not found in
upstream "proxy:<port>"` even though the hostname resolves fine from every
other container on the same network means the nginx container got created
with no network attached (`docker inspect <name> --format
'{{json .NetworkSettings.Networks}}'` prints `{}`). A plain restart does not
fix this — the script detects this exact state and does `docker rm -f` +
fresh `up -d` automatically. If you're ever doing this by hand instead, same fix.

`filter_modules/<service>/<service>_in.py` on the remote starts as an empty template, one per
service — ctf_proxy passes everything through until you write actual detection rules there (via
the Dashboard's RULES tab 3b, pick the right service from its dropdown if there's more than one —
see the Tulip/Dashboard workflow a few sections up). Don't assume "ctf_proxy is running" means
"attacks are being blocked."

---

## ML Bot Fingerprinter — Notes (`MODE=prep` only, off by default)

> **⚠️ HINT LAYER ONLY. Not an alarm. Human decision required before action.** Not generative
> AI — sklearn DBSCAN clustering. Gated by `services.json`'s `ml_classifier.enabled` (default
> `false`) AND `MODE=prep`; has no effect at all under `MODE=contest` regardless of the flag.

- Fingerprints by: inter-arrival time cadence, packet size distribution, TCP handshake order, per-tick flow count
- **Does NOT fingerprint by IP alone** — organizer may NAT all checker traffic
- After 3 tick windows (~6 min): starts labeling deviants from checker cluster
- Labels: `bot-like` (matches checker pattern) vs `deviant` (anomalous cadence/sizes)
- Deviant flows appear in Dashboard → "ML Bot Hints" panel (purple)
- DBSCAN parameters: eps=1.5, min_samples=3 (tune in `prep-only/ml-classifier/fingerprint_service.py`)

---

## Changing Configuration

**Edit only `contest-runtime/config/services.json`.** Then:

```bash
bash contest-runtime/config/validate-config.sh
MODE=contest bash teardown.sh
MODE=contest bash bringup.sh
```

All components re-read from services.json on next start. Nothing else needs editing.

---

## Updating Suricata Rules

Suricata rules live in `contest-runtime/detection/suricata/lib/rules/`. Add `.rules` files there:

```bash
# Example: add a flag-out rule
cat >> contest-runtime/detection/suricata/lib/rules/ctf-flagout.rules << 'EOF'
alert tcp any any -> any any (msg:"CTF Flag Exfiltration"; pcre:"/[A-Z0-9]{31}=/"; sid:9000001; rev:1;)
EOF

# Reload Suricata (if using Tulip's Suricata container)
docker exec tulip-suricata-1 suricatasc -c reload-rules
```

---


## File Structure

```
Setup_tool/
├── contest-runtime/              ← everything allowed to run during the 8h contest
│   ├── config/
│   │   ├── services.json         ← EDIT THIS (single source of truth)
│   │   ├── validate-config.sh    ← config validator (incl. keyword drift check)
│   │   └── generators/           ← emit each tool's native config from services.json
│   │       ├── gen-tulip-env.py  ← → offline-bundle/repos/tulip/.env (used)
│   │       └── gen-ctfproxy.py   ← writes a LOCAL offline-bundle/repos/ctf_proxy/proxy/config/
│   │                                config.json targeting mock_vulnbox.hostname; still called by
│   │                                bringup.sh, but nothing in docker-compose.*.yml runs a local
│   │                                ctf_proxy container that reads it — the real deploy path
│   │                                (deploy-ctfproxy.sh) generates its OWN config.json directly
│   │                                on the remote vulnbox-host instead. Orphaned, harmless.
│   ├── detection/                ← flag-out regex scanner, honeytoken, Suricata ruleset
│   ├── watchdog/                 ← SLA poller + OS-watchdog deploy scripts
│   ├── monitor/                  ← vulnbox capture deploy scripts
│   ├── defense/                  ← ctf_proxy deploy script + rule templates
│   ├── dashboard/                ← unified monitoring UI
│   ├── hostagent/ + host_agent.py ← host-side action executor for the Dashboard
│   └── health_check.py           ← one-shot diagnostic (also feeds Dashboard's System Status)
│
├── prep-only/                    ← NEVER started when MODE=contest
│   ├── ml-classifier/            ← optional sklearn bot-deviation classifier (off by default)
│   └── training/mock-vulnbox/    ← toy vulnerable services, rehearsal only
│
├── docker-compose.contest.yml    ← the ONLY compose file MODE=contest ever touches
├── docker-compose.prep.yml       ← MODE=prep overlay (mock-vulnbox, ml-fingerprint)
├── bringup.sh                    ← one-command start (MODE=contest|prep required)
├── teardown.sh                   ← graceful stop (always tears down both compose files)
├── deploy-all.sh                 ← 1-click: preflight → bringup → vulnbox capture/traps/ctf_proxy
├── pull-and-save.sh              ← build offline bundle (run with internet, before the contest)
├── offline-restore.sh            ← restore on an air-gapped machine (zero network calls)
│
├── docs/                         ← everything besides this file
│   ├── SCHEMA.md                 ← services.json field reference
│   ├── ARCHITECTURE.md           ← how the system works, data-flow first
│   ├── RUNBOOK.md                ← this file
│   ├── STATUS.md                 ← what's actually verified to work, with evidence
│   ├── GOLIVE.md                 ← organizer-handoff / contest-day transition checklist
│   └── DEMO.md                   ← live-presentation script (pre-flight checks, fallbacks)
│
├── traffic/                      ← pcap files (Tulip + detection both watch this dir)
│
└── offline-bundle/               ← build artifact (gitignored — run pull-and-save.sh to create)
    ├── images/                   ← Docker .tar archives
    ├── wheels/                   ← Python .whl files
    ├── repos/                    ← cloned upstream: tulip, ctf_proxy, pcap-broker
    └── services.json             ← config snapshot
```

---


## Troubleshooting

### Always start here

```bash
bash health-check.sh
```
One-shot, read-only diagnostic covering every failure mode we've actually hit
in practice (disk space, container status, vulnbox SSH reachability, pull
loop, Tulip flow freshness). Each line names the exact fix command. Run this
BEFORE trying to debug anything by hand — most incidents below were things
this script would have caught in 10 seconds instead of a long manual
investigation.

### Quick table

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Dashboard blank | WebSocket connection failed | Check Redis is up: `docker compose -f docker-compose.contest.yml ps redis` |
| No Tulip flows at all | Pull loop not running / vulnbox unreachable | `ssh dfcd-vbox "echo OK"` first, then `bash contest-runtime/monitor/deploy-capture-pull.sh` |
| `ssh dfcd-vbox` times out at banner exchange | Remote VM(s) stopped/deallocated | Start them from your cloud portal/CLI — not fixable from this machine |
| Flows exist but count stuck, old timestamp only | Pull loop silently died (e.g. Monitor watch expired) | Check `ps aux \| grep rsync`; restart the pull loop |
| Watchdog shows unknown | Can't reach vulnbox | Check vulnbox IP in `contest-runtime/config/services.json` |
| `deploy-all.sh` dies at "Preflight checks" | Missing docker/docker-compose/python3, or `redis` python module won't install | Read the `[FAIL]` line — it names the exact missing thing. For `redis`, check `/tmp/pip-redis-install.log` |

### Real incidents hit in practice — full root cause (so you don't need to re-debug from scratch)

**1. Disk fills up to 100%, everything silently breaks (rsync, docker, writes)**
- Symptom: pull loop looks "stuck" with no error printed; `docker` commands hang or fail oddly.
- Check: `df -h /` — if near 100%, this is it.
- Real cause here was Docker layer/build cache piling up across many rebuild
  cycles, not pcap data. Fix, in order of how much it reclaims:
  ```bash
  docker builder prune -af   # buildx cache — often the single biggest offender
  docker image prune -af
  ```
- **Don't assume it's the pcap files** — `du -sh traffic/` to rule that out
  first; a full disk from unrelated Docker cache looks identical from the
  pull-loop's point of view.

**2. tcpdump dies with "Permission denied" after exactly one file rotation**
- Cause: `sudo tcpdump` drops from root to the `tcpdump` user after opening the
  first capture file. The second file (after `-G <seconds>` rotates) gets
  created by that dropped-privilege user and often can't be written.
- Fix: always launch with `sudo tcpdump -Z root ...` to keep root for every
  rotation, not just the first file. Already baked into
  `contest-runtime/monitor/deploy-capture-pull.sh` — if you ever hand-roll a tcpdump
  command instead of using that script, don't forget this flag.

**3. Pulled pcap files process "0 packets" in Tulip despite having real traffic in them**
- This is NOT a truncated/mid-write file (check that first: `tcpdump -r
  traffic/<file>.pcap | wc -l` — if it shows real packets, the file is fine).
- Real cause: Tulip's assembler applies the `BPF` filter (from `.env`, derived
  from `services.json`'s `port` field) even when reading already-captured
  files, not just live interfaces. If capture happens on a Docker bridge
  **behind a NAT** (public port 8003 → container's internal port 80), the BPF
  filter for "port 8003" matches nothing, because the bridge only ever sees
  port 80.
- Fix: add `"capture_port": 80` next to that service's `"port": 8003` entry in
  `services.json` (only needed when the capture point is downstream of a NAT —
  a traditional vulnbox capturing on a plain NIC doesn't need this).
  `contest-runtime/config/generators/gen-tulip-env.py` prefers `capture_port` over `port` for the BPF
  string if present. After editing, re-run:
  ```bash
  python3 contest-runtime/config/generators/gen-tulip-env.py
  cd offline-bundle/repos/tulip && docker compose up -d assembler
  ```
- Diagnose quickly which port the capture point actually sees:
  ```bash
  tcpdump -r traffic/<file>.pcap "port <public_port>" | wc -l   # 0 = mismatch
  tcpdump -r traffic/<file>.pcap "port <container_port>" | wc -l # should be >0
  ```

**4. Pulling a pcap file mid-write gives Tulip a truncated copy it never retries**
- Symptom: assembler log shows `PCAP OpenOffline error: truncated dump file`
  once, then never looks at that filename again even though a later rsync
  would have gotten the complete file.
- Fix already in `deploy-capture-pull.sh`: only rsync files the remote `find`
  reports as older than ~35s (one rotation period) — i.e. tcpdump has
  definitely moved on to the next file and this one is done being written.
  If you ever write a pull loop by hand, keep this guard; a bare
  `rsync -az remote:dir/ local/` every N seconds WILL eventually grab a file
  mid-write and lose that chunk of traffic silently.

**6. A container started by hand (`docker compose up -d <svc>`) crashes on empty config**
- Cause: compose got its values from environment variables that only existed inside
  `bringup.sh`'s shell. Fixed: `bringup.sh` now writes them to `./.env`, which compose reads
  automatically. If you see it again, re-run `MODE=contest bash bringup.sh` once to regenerate `.env`.

**7. Restricting an endpoint by client IP doesn't work on this machine**
- Docker here is rootless podman: every inbound connection reaches the container from the
  netns gateway (e.g. 10.0.0.20), never the real client IP. Anything that must not be public
  has to be on a port bound to `127.0.0.1`, not behind an IP check. (This is also why the
  honeytoken alert's `src_ip` is the gateway, not the attacker.)

**8. Every control-plane port was listening on 0.0.0.0 (reachable from the competition VPN)**
- Fixed: Dashboard (8080) and Tulip web UI (3000) bind `${BIND_IP}` (services.json
  `monitor_host.bind_ip`, default `127.0.0.1`, intentionally settable to a LAN IP so teammates
  can open them -- see `CONFIG.md`). Redis, the detection admin/test API, and Tulip's Postgres
  are hardcoded to `127.0.0.1` in `docker-compose.contest.yml` / patched that way by
  `gen-tulip-env.py` and do **not** follow `bind_ip` at all (fixed 2026-10-16 -- they used to,
  which meant opening the Dashboard to a LAN also handed out the alert queue, `/test/inject-flag`,
  and the raw flow database). Only port 9999 (honeytoken + OS-watchdog intake) is public by
  design. Check any time: `ss -tlnp | grep -vE '127\.0\.0\.1|:9999 '` -- anything left should be
  `BIND_IP`'s own address (8080/3000) or something outside this repo entirely (see the next
  section if an organizer-side firewall is also in the picture).

**5. ctf_proxy's nginx container stuck with no network attached**
- See the "Known gotcha" note under "Deploying ctf_proxy Against a Real
  Vulnbox" above. Short version: `docker rm -f` the nginx container and
  `docker compose up -d nginx` again; a plain `restart` does not fix it.

### Khi firewall/router của BTC (pfSense hoặc tương đương) cấu hình khác giả định

Mọi thứ trong repo này (`ctf_proxy`, capture, honeytoken, OS-watchdog) đứng **sau** một thiết bị
mạng do ban tổ chức quản lý — thường là pfSense hoặc tương tự, làm NAT/port-forward/firewall
giữa "mạng ngoài" (nơi checker + đối thủ ở) và vulnbox/mạng team. **Mình không cấu hình được cái
đó, chỉ có thể TEST để biết nó đang xử lý traffic kiểu gì**, rồi thích nghi — không đoán. Mục
này cho một quy trình tự chẩn đoán, không cần tôi ngồi cạnh.

Nguyên tắc chung: *mọi container/service bên mình "lên" (`docker ps` xanh hết) không có nghĩa
traffic thật sự đi qua đúng đường*. Luôn test bằng traffic thật qua đúng port public, không chỉ
tin vào trạng thái container.

**1. NAT reflection / hairpin — lỗi pfSense kinh điển nhất trong hạ tầng CTF**

Triệu chứng: checker (chạy từ máy chấm điểm, ngoài mạng team) thấy service UP bình thường, nhưng
tự mình `curl` vào chính IP/port public của mình (từ MÁY TRONG CÙNG MẠNG team, hoặc từ chính
vulnbox) lại timeout/refused — dù service chạy tốt khi test qua `localhost`/IP nội bộ.

```bash
# Từ bên trong mạng team (vulnbox hoặc máy monitor), test đúng IP/port PUBLIC,
# không phải IP nội bộ:
curl -m 5 http://<IP public của vulnbox>:<port public>/
```

Nếu timeout/refused dù service chạy tốt qua IP nội bộ: pfSense có setting tên **"NAT
Reflection"** (hoặc "hairpin NAT") đang tắt — traffic từ TRONG mạng gửi tới IP PUBLIC của chính
mạng đó không được NAT phản hồi lại vào trong, dù traffic từ NGOÀI vào vẫn bình thường. Đây
**không phải lỗi của mình**, và checker thật (luôn ở ngoài mạng team) **không bị ảnh hưởng gì**
— chỉ gây nhiễu khi TỰ mình test. Nếu cần tự test từ trong mạng, test qua IP/port NỘI BỘ thay vì
IP public, hoặc nhờ ai ở ngoài mạng team test giúp.

**2. Hướng kết nối một chiều — đã gặp thật (xem `docs/STATUS.md` 2026-10-16)**

Đừng bao giờ coi "SSH monitor→vulnbox chạy được" là bằng chứng "mọi hướng kết nối đều ổn". SSH
chỉ chứng minh ĐÚNG MỘT hướng. Honeytoken/OS-watchdog cần hướng ngược lại (vulnbox→monitor) —
**hai bài test độc lập, không suy ra từ nhau được**. Quy trình test chuẩn (đã dùng thật):

```bash
# Hướng monitor -> vulnbox (SSH, capture, ctf_proxy deploy đều cần cái này):
ssh <vulnbox_ssh_alias> echo ok

# Hướng vulnbox -> monitor (honeytoken/OS-watchdog push cần cái này) --
# dựng một listener tạm, KHÔNG liên quan tới service nào đang chạy, để loại
# trừ khả năng do port/container cụ thể nào đó bị chặn riêng:
python3 -m http.server 19999 --bind 0.0.0.0 &     # chạy TRÊN máy monitor
ssh <vulnbox_ssh_alias> "curl -m 5 http://<IP máy monitor>:19999/"
kill %1                                            # dọn ngay sau khi test
```

Timeout ở bài test 2 (không phải "connection refused" — refused nghĩa là tới được, chỉ không ai
nghe) = firewall/router chặn chiều đó, không phải lỗi service. Hệ thống đã có cơ chế dự phòng
cho đúng tình huống này (honeytoken/OS-watchdog tự chuyển sang kiểu hỏi-ngược qua SSH, xem
`contest-runtime/hostagent/oswatchdog_pull.py` / `honeytoken_pull.py`) — **không cần sửa gì cả**,
chỉ cần biết để không hoảng khi thấy cảnh báo "can NOT reach" lúc deploy.

**3. ctf_proxy "mất tích" dù vẫn chạy — port-forward trỏ sai đích**

`ctf_proxy` hoạt động bằng cách CHIẾM đúng port public mà service gốc từng bind, trên CHÍNH máy
vulnbox — nó không tự "chen" vào giữa đường truyền ở tầng mạng. Nếu pfSense's NAT rule được cấu
hình trỏ cứng vào một IP nội bộ cụ thể (ví dụ IP riêng của container service gốc) từ trước khi
ctf_proxy được cài, thay vì trỏ vào IP của HOST vulnbox, traffic vẫn có thể đi tắt tới thẳng
service gốc, **bỏ qua hoàn toàn ctf_proxy** — rule chặn build xong, apply xong, báo thành công,
nhưng thực tế không chặn được gì vì traffic chưa từng đi qua.

```bash
# Xác nhận traffic qua port public THỰC SỰ tới đúng process ctf_proxy, không
# phải thẳng tới service gốc:
ssh <vulnbox_ssh_alias> "ss -tlnp | grep ':<port public> '"
# phải thấy process ctf_proxy (nginx/proxy container), không phải service gốc

# Test thật: gửi 1 request chứa chuỗi mà ctf_proxy ĐANG chặn, qua đúng IP/port
# PUBLIC (không phải localhost trên vulnbox) -- nếu service vẫn trả response
# bình thường (không bị khoá/đóng kết nối) dù rule báo "đã áp dụng", traffic
# không đi qua ctf_proxy.
```

Nếu phát hiện đúng trường hợp này: báo BTC port-forward đang trỏ sai đích (vào IP container cụ
thể thay vì IP host), hoặc dùng "Fallback block — theo NỘI DUNG" (tab SERVICES, iptables trên
chính vulnbox, không phụ thuộc NAT của BTC) làm phương án tạm trong lúc chờ sửa.

**4. Source IP bị NAT/masquerade mất, không còn là IP thật của kẻ tấn công**

Nếu pfSense (hoặc router giữa các team) làm NAT nguồn (masquerade) traffic giữa các team với
nhau, mọi traffic tới vulnbox của mình có thể trông như xuất phát từ MỘT IP duy nhất (IP NAT của
router) bất kể đội nào thật sự gửi — giống hệt vấn đề đã gặp với rootless podman (RUNBOOK mục 7
ở trên, netns gateway thay cho IP khách thật). Dấu hiệu: `teams_cidr` trong `services.json` không
còn phân biệt được gì, mọi honeytoken/watchdog alert đều ghi cùng một `src_ip`.

Không có cách tự sửa từ phía mình (NAT xảy ra ở thiết bị của BTC) — nếu nghi ngờ đúng trường hợp
này, đừng dựa vào so khớp IP nguồn để phân biệt checker/đồng minh/đối thủ; ưu tiên chặn/nhận diện
theo **nội dung request** (đã có sẵn: multi-condition ctf_proxy rule, Suricata content-match) hơn
là theo IP.

**5. Danh sách port cần hỏi BTC mở sẵn (chuẩn bị trước khi vào mạng thi)**

Nếu nghi pfSense của giải chặn mặc định (default-deny) những gì không được khai báo trước, đây
là toàn bộ danh sách port **thực sự** cần cho hệ thống này hoạt động — không hơn:

| Port/hướng | Ai cần nó | Nếu bị chặn |
|---|---|---|
| Port service public (`services[].port`), hướng ngoài→vulnbox | Traffic game thật (checker + đối thủ) | Hầu như không bao giờ bị chặn — đây là chính service đang thi; nếu bị chặn thì không ai chấm điểm được, báo BTC ngay |
| SSH tới vulnbox (`vulnbox.ssh_port` hoặc alias của `capture_ssh_alias`), hướng monitor→vulnbox | Capture, ctf_proxy deploy, honeytoken/OS-watchdog deploy, cơ chế pull mới | Gần như luôn mở (team tự quản lý vulnbox của mình); nếu không SSH được, mọi tính năng ở Phase 1/2 trong `docs/GOLIVE.md` đều không chạy được |
| Port 9999, hướng vulnbox→monitor | Honeytoken/OS-watchdog push (không bắt buộc — đã có cơ chế pull thay thế) | Không cần báo BTC mở riêng — hệ thống tự hoạt động qua cơ chế pull dù hướng này bị chặn (đã test thật, xem mục 2 trên) |

Không có port nào khác cần BTC mở thêm cho repo này — mọi thứ còn lại (Dashboard, Tulip, Redis,
API quản trị) chỉ chạy nội bộ trên máy monitor, không đi qua mạng thi.

---

*Built for 8-hour Attack-Defense CTF. Air-gap ready. No auto-blocking. Human decision only.*
