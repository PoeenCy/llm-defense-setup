# services.json Schema Reference

> **Every** component in the CTF monitoring hub reads exclusively from `services.json`.  
> **Never** hardcode IPs, ports, or flag formats elsewhere.

---

## Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `_comment` | string | no | Human-readable note; ignored by parsers |
| `team_id` | string | **yes** | Unique team identifier, used in log labels |
| `vulnbox` | object | **yes** | Vulnbox connectivity & capture config |
| `monitor_host` | object | **yes** | This machine's IPs and service ports |
| `flag` | object | **yes** | Flag format & gameserver submit config |
| `teams_cidr` | string | **yes** | CIDR of all teams (used for traffic filtering) |
| `gameserver_hint` | object | no | Optional gameserver IP hint |
| `honeytoken` | object | **yes** | Decoy flag config for trap detection |
| `tulip` | object | **yes** | Tulip service port config |
| `ollama` | object | **yes** | LLM / embedding model config |
| `anythingllm` | object | **yes** | AnythingLLM RAG server config |
| `services` | array | **yes** | List of vulnbox services to monitor |

---

## `vulnbox` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ip` | string (IPv4) | **yes** | Vulnbox IP on organizer LAN |
| `ssh_user` | string | **yes** | SSH user for deploy scripts |
| `ssh_port` | integer | no (default 22) | SSH port |
| `capture_iface` | string | **yes** | Network interface to capture on (e.g. `eth0`) |
| `pcap_broker_port` | integer | **yes** | Port where pcap-broker server listens on vulnbox |

---

## `monitor_host` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ip` | string (IPv4) | **yes** | This machine's LAN IP |
| `dashboard_port` | integer | **yes** | Dashboard HTTP port |
| `alert_queue_port` | integer | **yes** | Redis port for the shared alert queue |
| `ioc_api_port` | integer | **yes** | IOC analysis REST API port |

---

## `flag` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `regex` | string | **yes** | Python-compatible regex matching a valid flag |
| `submit_url` | string | no | Gameserver flag submission URL |
| `note` | string | no | Reminder to verify with organizer |

---

## `teams_cidr` string

- CIDR notation (e.g. `"10.60.0.0/16"`)
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
| `flag` | string | **yes** | The decoy flag value (must NOT be a real flag) |
| `endpoint_port` | integer | **yes** | Port where the honeytoken collector listens on monitor host |
| `note` | string | no | Placement reminder |

---

## `tulip` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `web_port` | integer | **yes** | Tulip web UI port |
| `mongo_port` | integer | **yes** | MongoDB port (internal) |
| `ingestor_port` | integer | **yes** | Tulip ingestor API port |

---

## `ollama` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `port` | integer | **yes** | Ollama HTTP API port |
| `llm_model` | string | **yes** | Ollama model tag for the LLM |
| `embed_model` | string | **yes** | Ollama model tag for embeddings |
| `gpu_layers` | integer | **yes** | Number of model layers to offload to GPU |
| `note` | string | no | Usage reminder |

---

## `anythingllm` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `port` | integer | **yes** | AnythingLLM web UI / API port |

---

## `services` array

Each element:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **yes** | Short service identifier (used in Tulip tags, Suricata rules) |
| `port` | integer | **yes** | TCP/UDP port on vulnbox |
| `proto` | string | **yes** | `"tcp"` or `"udp"` |
| `layer` | string | **yes** | `"l7-http"`, `"l7-https"`, `"l4-raw"`, `"l4-udp"` |
| `description` | string | no | Human-readable service description |

---

## Validation

Run `./validate-config.sh` after every edit to `services.json`.  
It will `exit 1` loudly on any missing required field or type mismatch.
