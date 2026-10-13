# services.json Schema Reference

> **Every** component in the CTF monitoring hub reads exclusively from
> `contest-runtime/config/services.json`.
> **Never** hardcode IPs, ports, or flag formats elsewhere — every port used anywhere in this
> repo (capture BPF filter, ctf_proxy, watchdog polling, dashboard rule builders) is read from
> this file at runtime, not baked into code.
>
> No LLM/generative-AI field exists in this schema — there is no such component in this repo.

---

## Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `_comment` | string | no | Human-readable note; ignored by parsers |
| `team_id` | string | **yes** | Unique team identifier, used in log labels and ctf_proxy's remote directory name (`~/ctf-proxy-<team_id>`) |
| `vulnbox` | object | **yes** | Vulnbox connectivity & capture config |
| `monitor_host` | object | **yes** | This machine's IPs and service ports |
| `flag` | object | **yes** | Flag format & gameserver submit config |
| `teams_cidr` | string | **yes** | CIDR of all teams (used for traffic filtering) |
| `gameserver_hint` | object | no | Optional gameserver IP hint |
| `honeytoken` | object | **yes** | Decoy flag config for trap detection |
| `tulip` | object | **yes** | Tulip service port config |
| `mock_vulnbox` | object | **yes** | Rehearsal-only toy target config, read even in `MODE=contest` to decide whether `bringup.sh` must assert it's NOT running |
| `ctf_proxy` | object | **yes** | Edge-mitigation proxy config: keyword, nginx failover tuning, and how/whether to insert it against a real vulnbox |
| `ml_classifier` | object | **yes** | Compliance gate for the optional ml-fingerprint classifier |
| `services` | array | **yes** | List of vulnbox services to monitor — one or more, any mix of TCP/UDP/HTTP/raw |
| `retention` | object | no | Disk-space guard tiers (see below); every field optional, defaults are safe |

---

## `vulnbox` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ip` | string (IPv4) | **yes** | Vulnbox IP on organizer LAN |
| `ssh_user` | string | **yes** | SSH user for deploy scripts — often a restricted "team patch key" that only reaches your own public-proxy container, not full root |
| `ssh_port` | integer | **yes** | SSH port |
| `capture_iface` | string | **yes** | Network interface to capture on, or `"auto"` to let `deploy-capture-pull.sh` detect the external interface via `ip route` |
| `pcap_broker_port` | integer | **yes** | Port where pcap-broker server listens on vulnbox, if it has one (rare — most setups use SSH+tcpdump instead, see `capture_ssh_alias`) |
| `capture_ssh_alias` | string | no | SSH alias (from `~/.ssh/config`, can include a `ProxyJump`) with ENOUGH access to run `tcpdump -Z root` — used by `deploy-capture-pull.sh` when the team's own SSH user (above) can't. Needed whenever capture and "the team's own service SSH" are two different levels of access (common: admin SSH to the vulnbox-host vs. a restricted per-team key) |
| `docker_bridge` | string or null | no | Override: the exact docker bridge interface name to capture on, only if `capture_iface: "auto"`'s `ip route` probe genuinely picks the wrong one (rare) |
| `note` | string | no | Free-form reminder |

---

## `monitor_host` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ip` | string (IPv4) | **yes** | This machine's LAN IP on the competition network |
| `dashboard_port` | integer | **yes** | Dashboard HTTP port |
| `alert_queue_port` | integer | **yes** | Redis port for the shared alert/ops queue |
| `bind_ip` | string (IPv4) | no | Address the control-plane ports (dashboard, redis, Tulip, Postgres) listen on. `127.0.0.1` (default/safe) = only this machine. Set to a LAN IP only to let a teammate on a trusted network open the dashboard — these ports have no auth. The honeytoken collector port always listens on all interfaces regardless, by design (it must be reachable from the vulnbox) |
| `bind_ip_note` | string | no | Reminder of the above |

There is no `ioc_api_port` or any LLM-related field here — that component was removed from the
repo entirely.

---

## `flag` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `regex` | string | **yes** | Python-compatible regex matching a valid flag |
| `submit_url` | string | no | Gameserver flag submission URL (PUT with header `X-Team-Token`, token kept OUT of this file) |
| `note` | string | no | Reminder to verify with organizer |

---

## `teams_cidr` string

- CIDR notation (e.g. `"10.13.2.0/24"`)
- Used by Suricata rules and the flag-out detector to know which traffic is inter-team

---

## `gameserver_hint` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ip` | string (IPv4) | no | Suspected gameserver IP |
| `note` | string | no | Human warning about NATing |

---

## `honeytoken` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `flag` | string | **yes** | The decoy flag value (must NOT be a real flag, must still match `flag.regex`) |
| `endpoint_port` | integer | **yes** | Port where the honeytoken collector listens on monitor host |
| `note` | string | no | Placement reminder |

---

## `tulip` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `web_port` | integer | **yes** | Tulip web UI port |
| `ingestor_port` | integer | **yes** | Tulip ingestor API port |
| `note` | string | no | Tulip stores flows in TimescaleDB/Postgres, not Mongo — there is no `mongo_port` field |

---

## `mock_vulnbox` object

Rehearsal-only toy target (`prep-only/training/mock-vulnbox/`), never real defense.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | boolean | **yes** | `false` = real vulnbox mode. Only ever actually started when `enabled: true` AND `MODE=prep` both hold — `MODE=contest` never starts it regardless of this flag, and asserts it's not already running |
| `hostname` | string | **yes** | Docker DNS name the container answers to on `ctf-net` (default `"mock-vulnbox"`) |
| `note` | string | no | Reminder |

---

## `ctf_proxy` object

Config for the edge-mitigation proxy ([ctf_proxy](https://github.com/ByteLeMani/ctf_proxy),
vendored under `offline-bundle/repos/ctf_proxy`).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyword` | string | **yes** | String ctf_proxy sends back on a blocked connection (`"<keyword> <service> <rule>"`, raw bytes, no HTTP status line). Detection's `PROXY_BLOCK_RE` parses this — must stay the single source other tools read from, never hardcoded elsewhere |
| `listen_ip` | string | **yes** | IP ctf_proxy listens on (inside the vulnbox's own docker network) |
| `nginx` | object | **yes** | Failover tuning: `connect_timeout`, `max_fails`, `fail_timeout` (seconds) — passed straight to ctf_proxy's own `generate_nginx_conf.py` |
| `dos` | object | **yes** | `{"enabled": bool, "duration": int, "interval": int}` — ctf_proxy's optional attacker-slowdown feature (keeps a blocked socket open, periodically sending bytes) |
| `insertion` | object | **yes** | Where/how to insert ctf_proxy against a REAL vulnbox — see below |
| `note` | string | no | Reminder that `keyword` must stay in sync |

### `ctf_proxy.insertion` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mode` | string | **yes** | `"disabled"` (default, monitor-only — nothing attempted) or `"docker-compose"` (real insertion via `deploy-ctfproxy.sh`) |
| `remote_ssh_alias` | string | if mode is `docker-compose` | SSH alias with access to the vulnbox-host's docker/compose |
| `remote_compose_file` | string | if mode is `docker-compose` | Path (on the vulnbox-host) to the compose file that owns the target service(s) |
| `remote_compose_service` | string | no | **Shared fallback** compose service name, used by any `services[]` entry that doesn't set its own `compose_service` (see below) — keeps a config written before per-service `compose_service` existed working unchanged |
| `remote_network_name` | string | if mode is `docker-compose` | The docker network ctf_proxy's own `nginx`+`proxy` containers must join (usually `<project>_<network-key>`, found with `docker network ls` on the vulnbox-host) |

---

## `ml_classifier` object

Compliance gate for the optional `ml-fingerprint` service (`prep-only/ml-classifier/`), the
only remaining non-generative model in this repo (sklearn DBSCAN clustering).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | boolean | **yes** | Default `false`. Has **no effect** when `MODE=contest` regardless of value — `bringup.sh` never merges `docker-compose.prep.yml` in contest mode, full stop. Only ever gates the service under `MODE=prep`, and only with BTC's written sign-off. |
| `note` | string | no | Reminder of the above |

---

## `services` array

Each element describes ONE service to monitor — the array can hold any number of them, mixing
protocols/layers freely. Capture (tcpdump BPF filter) and Suricata already read **every** entry
here with no limit; ctf_proxy insertion (`deploy-ctfproxy.sh`) also loops over all of them, but
only ever fronts the ones with `proto: "tcp"` (see `layer`/`compose_service` below).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **yes** | Short service identifier (used in Tulip tags, Suricata rules, and — sanitized to a valid Python identifier — as ctf_proxy's own module/filter name if this service is eligible for ctf_proxy) |
| `port` | integer | **yes** | Public TCP/UDP port on the vulnbox. Can be changed at any time just by editing this field + redeploying — nothing in the codebase hardcodes a port number |
| `proto` | string | **yes** | `"tcp"` or `"udp"`. `"udp"` services are captured and alerted on exactly like TCP ones, but are **never** eligible for ctf_proxy (it can't proxy UDP at all) — use the Dashboard's content-based firewall block for those |
| `layer` | string | **yes** | `"l7-http"` / `"l7-https"` (ctf_proxy parses it as HTTP, filters get `url`/`path`/`method`/`parameters`/`headers`/`raw_body`) or `"l4-raw"` (raw TCP, filters only get the raw bytes of the current message) or `"l4-udp"` (informational only — same effect as `proto: "udp"` for ctf_proxy eligibility) |
| `compose_service` | string | no | The docker-compose service name on the vulnbox-host that's currently binding this service's `port` — needed by `deploy-ctfproxy.sh` to know which port line to remove and which container to recreate. Falls back to `ctf_proxy.insertion.remote_compose_service` when omitted (single-service configs written before this field existed keep working with zero changes) |
| `description` | string | no | Human-readable service description |
| `note` | string | no | Free-form per-service reminder |

---

## `retention` object

Disk-space guard run every 60s by `contest-runtime/hostagent/retention.py`. Three escalating
tiers: (1) delete old captured pcaps, (2) prune Docker's own dangling images/build-cache (always
safe — never touches anything running), (3) opt-in only — drop old Tulip flow data.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pcap_keep_minutes` | integer | no | Delete pcaps older than this once detection has scanned them; `0` (default) = off |
| `pcap_max_gb` | number | no | Keep `traffic/` under this size, oldest files first (default `5`) |
| `min_free_gb` | number | no | Keep at least this much disk free; triggers pcap deletion, then Docker pruning (default `10`) |
| `tulip_flow_retention_hours` | number | no | **Last resort, opt-in only.** `0` (default) = never touch Tulip's own flow data. If disk is still below `min_free_gb` after pcap cleanup *and* Docker pruning, host_agent drops TimescaleDB chunks from Tulip's `flow`/`flow_item` tables older than this many hours. This deletes real captured contest flows — leave at `0` unless you understand that tradeoff. |
| `note` | string | no | Reminder of the above |

---

## Validation

Run `bash contest-runtime/config/validate-config.sh` after every edit to `services.json`.
It `exit 1`s loudly on any missing required field or type mismatch, and separately warns if the
LOCAL `offline-bundle/repos/ctf_proxy/proxy/config/config.json` (written by the orphaned
`gen-ctfproxy.py` generator, still called by `bringup.sh` — see `docs/RUNBOOK.md`'s File
Structure section) has a `keyword` that drifted from this file's. This check is unrelated to the
REAL remote deploy (`deploy-ctfproxy.sh` writes its own `config.json` directly on the
vulnbox-host, never reading or writing this local file).
