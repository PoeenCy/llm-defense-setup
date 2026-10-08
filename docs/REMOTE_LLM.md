# REMOTE_LLM.md — Running Ollama on a dedicated machine

By default the whole stack — including the LLM — runs on one machine (see
[`RUNBOOK.md`](RUNBOOK.md)). This doc covers splitting it into two: the monitor host
(everything else) and a dedicated LLM host (just Ollama + the model).

## Why split

- The 8B model is slow on CPU (measured ~90–120s per `/analyze` call — see
  [`STATUS.md`](STATUS.md)). A machine with a real GPU dedicated to just the LLM removes
  that bottleneck without taking CPU/RAM away from capture, Tulip, and detection.
- Keeps the monitor host lighter during competition, when every core matters for packet
  processing.

## 1. On the LLM machine

Clone this repo there too (the setup script needs `ioc-brain/Foundation-Sec.Modelfile`):

```bash
git clone <this-repo>
cd Setup_tool
sudo bash llm-host/setup-llm-host.sh <monitor-host-ip>
```

This installs Ollama if missing, configures it to listen on `0.0.0.0:11434` (default is
`127.0.0.1`-only, unreachable from another machine), **firewalls port 11434 to only the
monitor host's IP**, builds `foundation-sec-8b-chat` from the Modelfile (same chat-template
fix documented in `STATUS.md` — the upstream GGUF has no template, so Ollama ignores the
system prompt without it), and pulls `nomic-embed-text`.

> **Security note — read this if the LLM host is on the competition network itself:**
> every other team is on that network too. An unauthenticated Ollama API reachable by
> anyone lets them burn your compute, read your prompts, or DoS it. The setup script's
> firewall restriction (step 3) is not optional on a shared network — only skip it
> (`--allow-all`) on a network you fully control (e.g. a private VPN between your two
> machines).

The script prints this machine's IP at the end — that's what goes in the next step.

## 2. On the monitor host

Edit `services.json`:

```json
"ollama": {
  "host": "192.168.1.50",
  "port": 11434,
  ...
}
```

Leave every other `ollama.*` field as-is — `llm_model`/`embed_model` must match what you
built on the LLM host. Then:

```bash
bash validate-config.sh   # confirms: "ollama.host = 192.168.1.50 (remote LLM machine...)"
bash bringup.sh
```

`bringup.sh` picks this up automatically: when `ollama.host` is set, it's used directly as
`OLLAMA_RESOLVED_HOST` for `ioc-brain` and `anythingllm` — no podman-gateway probing, no
`DOCKER_HOST_GATEWAY` involved, since a LAN IP is a normal network hop (unlike reaching a
service on the monitor host's own machine through its container bridge, which is the whole
reason that probing logic exists in the single-machine case). Tulip's Postgres stays on the
monitor host regardless — only the LLM moves.

## 3. Verify

```bash
# From the monitor host:
curl -s http://192.168.1.50:11434/api/tags | python3 -m json.tool | grep foundation-sec-8b-chat

# From anywhere else on the network, this should now time out / be refused —
# confirming the firewall rule is actually doing something:
curl -s --max-time 3 http://192.168.1.50:11434/api/tags
```

## Reverting to single-machine

Set `ollama.host` back to `""` in `services.json` and re-run `bringup.sh`.
