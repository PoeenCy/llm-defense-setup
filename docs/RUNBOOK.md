# CTF Monitor Hub — Operations Runbook

> **Role:** Lead monitor machine for Attack-Defense CTF.  
> **This box:** Ingests traffic, runs detection, produces IOCs, serves situational-awareness dashboard.  
> **Hardware:** Parrot Linux, 16 GB RAM, RTX 3050 (4 GB VRAM).

---

## Quick-Start (you have internet)

```bash
# 1. Edit the central config
nano services.json          # set vulnbox IP, flag regex, service ports

# 2. Validate config
bash validate-config.sh

# 3. Bundle everything for offline use
bash pull-and-save.sh       # ~20-40 min, downloads ~15-25 GB

# 4. Bring everything up
bash bringup.sh
```

## Quick-Start (air-gapped machine, competition day)

```bash
# 1. Copy offline-bundle/ from prep machine (USB/LAN transfer)
rsync -a offline-bundle/ /path/to/Setup_tool/offline-bundle/

# 2. Restore from bundle (zero network calls)
bash offline-restore.sh

# 3. Bring up
bash bringup.sh --offline
```

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
                    │  │hints│      │  WebSocket → browser │   │
                    │  └─────┘      └─────────────────────┘    │
                    │                                           │
                    │  IOC Brain (load on demand, Item 6)       │
                    │  Foundation-Sec-8B Q4 + Ollama            │
                    │  AnythingLLM (RAG over vault/)            │
                    │                                           │
                    │  Watchdog (SLA poller, Item 7)            │
                    └─────────────────────────────────────────┘
```

---

## Services & Ports

| Service | Port | Description |
|---------|------|-------------|
| Dashboard | 8080 | Unified monitoring UI |
| Tulip UI | 3000 | Flow inspection |
| IOC Brain API | 5001 | LLM analysis endpoint |
| AnythingLLM | 3001 | RAG Q&A over vault/ |
| Detection/Honeytoken | 9999 | Alert collector + honeytoken |
| Redis | 6380 | Shared alert queue |
| Ollama | 11434 | LLM API (load on demand) |

---

## Bring-Up Order

Services **must** start in this order (handled by `bringup.sh`):

1. **Redis** — shared alert queue (all other services depend on it)
2. **Tulip stack** — traffic ingestion + TimescaleDB
3. **Detection service** — flag-out scanner, honeytoken collector
4. **Watchdog** — SLA poller
5. **ML Fingerprint** — bot fingerprinter (warmup: 3 ticks)
6. **IOC Brain** — load-on-demand LLM
7. **Dashboard** — unified UI
8. **AnythingLLM** — RAG (optional, loads last)
9. **Ollama** — serve LLM on demand

---

## Offline Restore Procedure

> Use on clean, air-gapped machine. Must have `offline-bundle/` transferred.

```bash
# Prerequisites
which docker && docker --version    # Docker 24+
which python3                        # Python 3.11+
which ollama                         # Ollama 0.2+

# Step 1: Load Docker images
bash offline-restore.sh

# Step 2: Verify
docker images | grep tulip           # should show tulip-* images
docker images | grep redis           # should show redis:7-alpine
ollama list                          # should show Foundation-Sec-8B and nomic-embed-text

# Step 3: Bring up
bash bringup.sh --offline
```

### Verifying air-gap compliance

```bash
# All of these should FAIL (timeout/refused) on air-gapped machine:
curl --connect-timeout 3 https://docker.io
curl --connect-timeout 3 https://pypi.org
curl --connect-timeout 3 https://ollama.ai
```

---

## Acceptance Tests (run after bring-up)

### Test 1: Flag-out detection fires in <2s

```bash
# Inject a fake flag-out alert
curl -X POST http://localhost:9999/test/inject-flag
# Expect: 200 OK + alert appears on dashboard within 2s
```

### Test 2: Honeytoken alert

```bash
# Trigger honeytoken endpoint
curl -X POST http://localhost:9999/honeytoken
# Expect: alert type=honeytoken appears on dashboard
```

### Test 3: IOC analysis

```bash
# Analyze a flow snippet
curl -s -X POST http://localhost:5001/analyze \
  -H "Content-Type: application/json" \
  -d '{"log_snippet": "POST /login HTTP/1.1\nHost: 10.0.0.2:9001\nAuthorization: Basic YWRtaW46QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQQ=\n\n{\"password\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}"}' \
  | python3 -m json.tool
# Expect: structured IOC JSON with attacker_ip, technique, mitre_attack fields
```

### Test 4: SLA watchdog fires in <5s

```bash
# Stop a mock service (e.g. block port with iptables)
sudo iptables -I INPUT -p tcp --dport 9001 -j REJECT
sleep 5
curl http://localhost:8080/api/alerts | python3 -m json.tool | grep sla-down
# Restore
sudo iptables -D INPUT -p tcp --dport 9001 -j REJECT
```

### Test 5: Dashboard shows all three signal types

1. Run tests 1, 2, 4 above
2. Open `http://localhost:8080`
3. Verify: flag-out (red), honeytoken (red), sla-down (red) all visible
4. Verify priority order: flag-out/honeytoken at top, ML hints at bottom

---

## Deploying Vulnbox-Side Components

> Run these from the monitor machine, once you have SSH access to the vulnbox.

```bash
# 1. Deploy pcap capture (tcpdump + pcap-broker)
bash vulnbox-deploy/deploy-capture.sh

# 2. Deploy OS integrity watchdog agent
bash vulnbox-deploy/deploy-os-watchdog.sh

# 3. Deploy honeytoken traps
bash vulnbox-deploy/deploy-honeytoken.sh
```

All scripts read parameters from `services.json` — no hardcoding needed.

### Verify vulnbox capture is streaming

```bash
# From monitor, check that pcap-broker is sending traffic
nc -v "$VULNBOX_IP" 4242 | xxd | head -5
# Should see pcap global header: d4 c3 b2 a1 ...
```

---

## IOC Brain — LLM Usage

The LLM is **never** kept resident in RAM. It loads on each request and is released after.

```bash
# Analyze a Tulip flow by ID
curl -X POST http://localhost:5001/analyze \
  -H "Content-Type: application/json" \
  -d '{"flow_id": "<tulip-flow-id>"}'

# Analyze raw log snippet
curl -X POST http://localhost:5001/analyze \
  -H "Content-Type: application/json" \
  -d '{"log_snippet": "paste raw traffic or log here"}'

# Test MongoDB is read-only
curl http://localhost:5001/mongo/test
# Expect: write_rejected=true
```

**Latency on RTX 3050 (4 GB VRAM, Q4_K_M 8B, gpu_layers=20):**

| First call (cold) | Subsequent calls | GPU memory |
|-------------------|-----------------|------------|
| ~15-25s           | ~8-15s          | ~2.5 GB    |

> Latency measured at match start and recorded here. Update with real figures.

---

## ML Bot Fingerprinter — Notes

> **⚠️ HINT LAYER ONLY. Not an alarm. Human decision required before action.**

- Fingerprints by: inter-arrival time cadence, packet size distribution, TCP handshake order, per-tick flow count
- **Does NOT fingerprint by IP alone** — organizer may NAT all checker traffic
- After 3 tick windows (~6 min): starts labeling deviants from checker cluster
- Labels: `bot-like` (matches checker pattern) vs `deviant` (anomalous cadence/sizes)
- Deviant flows appear in Dashboard → "ML Bot Hints" panel (purple)
- DBSCAN parameters: eps=1.5, min_samples=3 (tune in `ml-fingerprint/fingerprint_service.py`)

---

## Changing Configuration

**Edit only `services.json`.** Then:

```bash
bash validate-config.sh
bash teardown.sh
bash bringup.sh
```

All components re-read from services.json on next start. Nothing else needs editing.

---

## Updating Suricata Rules

Suricata rules live in `suricata/rules/`. Add `.rules` files there:

```bash
# Example: add a flag-out rule
cat >> suricata/rules/ctf-flagout.rules << 'EOF'
alert tcp any any -> any any (msg:"CTF Flag Exfiltration"; pcre:"/[A-Z0-9]{31}=/"; sid:9000001; rev:1;)
EOF

# Reload Suricata (if using Tulip's Suricata container)
docker exec tulip-suricata suricatasc -c reload-rules
```

---

## File Structure

```
Setup_tool/
├── services.json              ← EDIT THIS (single source of truth)
├── docker-compose.yml         ← Monitor hub services
├── bringup.sh                 ← One-command start (generators → services)
├── teardown.sh                ← Graceful stop
├── validate-config.sh         ← Config validator (incl. keyword drift check)
├── pull-and-save.sh           ← Build offline bundle
├── offline-restore.sh         ← Restore on air-gapped machine
│
├── docs/                      ← Everything besides this file
│   ├── SCHEMA.md              ← services.json field reference
│   ├── ARCHITECTURE.md        ← How the system works, data-flow first
│   ├── RUNBOOK.md             ← This file
│   ├── STATUS.md              ← What's actually verified to work, with evidence
│   └── DEMO.md                ← Live-presentation script (pre-flight checks, fallbacks)
│
├── generators/                ← Emit each tool's native config from services.json
│   ├── gen-tulip-env.py       ← → offline-bundle/repos/tulip/.env
│   └── gen-ctfproxy.py        ← → offline-bundle/repos/ctf_proxy/proxy/config/config.json
│
├── detection/                 ← Flag-out regex scanner + honeytoken + Suricata ingester
├── ml-fingerprint/            ← L3/L4 bot fingerprinter (DBSCAN)
├── watchdog/                  ← SLA poller
├── ioc-brain/                 ← Load-on-demand LLM API (reads flows via mcp-tulip)
├── mcp-tulip/                 ← MCP server: read-only Postgres access to Tulip's flow DB
├── mock-vulnbox/              ← Toy vulnerable services for single-machine testing
├── dashboard/                 ← Unified monitoring UI
│
├── suricata/lib/rules/        ← Suricata ruleset (starter — swap in a real feed before competition)
├── traffic/                   ← Pcap files (Tulip + detection both watch this dir)
├── vault/                     ← Documents for AnythingLLM RAG (currently empty)
│
├── vulnbox-deploy/            ← Deploy scripts for a REAL vulnbox (NOT auto-run)
│   ├── deploy-capture.sh
│   ├── deploy-os-watchdog.sh
│   ├── deploy-honeytoken.sh
│   └── os-watchdog-agent.sh
│
└── offline-bundle/            ← Build artifact (gitignored — run pull-and-save.sh to create)
    ├── images/                ← Docker .tar archives
    ├── wheels/                ← Python .whl files
    ├── repos/                 ← Cloned upstream: tulip, ctf_proxy, pcap-broker
    ├── ollama-models/         ← LLM + embedding model blobs
    └── services.json          ← Config snapshot
```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Dashboard blank | WebSocket connection failed | Check Redis is up: `docker compose ps redis` |
| No Tulip flows | Pcap-broker not running on vulnbox | `bash vulnbox-deploy/deploy-capture.sh` |
| IOC Brain 503 | Ollama not running | `ollama serve &` |
| LLM model missing | Model not pulled | `ollama pull <model-name>` |
| Detection not firing | Traffic dir empty | Check `./traffic/` has .pcap files |
| Watchdog shows unknown | Can't reach vulnbox | Check vulnbox IP in services.json |

---

*Built for 8-hour Attack-Defense CTF. Air-gap ready. No auto-blocking. Human decision only.*
