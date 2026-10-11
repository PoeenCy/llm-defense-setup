#!/usr/bin/env python3
"""
health_check.py — single source of truth for "is everything actually running"
checks, used two ways:
  1. CLI, human-readable:        python3 health_check.py
  2. Feeds the Dashboard panel:  python3 health_check.py --push [--loop 15]
     (writes JSON to Redis key "system_status"; dashboard_server.py serves it
     at GET /api/status, the "System Status" panel in index.html polls that)

Runs on the HOST (not in a container) because several checks need things a
container would need extra mounts for (docker CLI, ssh config/keys). Keep
every check read-only -- this must never be the thing that changes state.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
CONFIG = ROOT / "services.json"


def _cfg():
    return json.loads(CONFIG.read_text())


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def check_disk():
    code, out, _ = _run("df -h / | awk 'NR==2{print $5}' | tr -d '%'")
    pct = int(out) if out.isdigit() else -1
    if pct < 0:
        return {"name": "Disk space", "status": "unknown", "detail": "could not read df output"}
    if pct >= 95:
        return {"name": "Disk space", "status": "down", "detail": f"{pct}% full — docker builder prune -af"}
    if pct >= 85:
        return {"name": "Disk space", "status": "slow", "detail": f"{pct}% full"}
    return {"name": "Disk space", "status": "up", "detail": f"{pct}% full"}


def check_containers():
    names = ["tulip-timescale-1", "tulip-assembler-1", "tulip-api-1", "tulip-frontend-1",
             "tulip-enricher-1", "tulip-suricata-1", "ctf-detection", "ctf-dashboard", "ctf-watchdog",
             "ctf-ml-fingerprint"]
    rows = []
    for name in names:
        code, out, _ = _run(f"docker inspect -f '{{{{.State.Status}}}}' {name}")
        if code != 0 or not out:
            rows.append({"name": name, "status": "unknown", "detail": "not deployed this session"})
        elif out == "running":
            rows.append({"name": name, "status": "up", "detail": "running"})
        else:
            rows.append({"name": name, "status": "down", "detail": out})
    return rows


def check_vulnbox_ssh(cfg):
    alias = cfg.get("vulnbox", {}).get("capture_ssh_alias")
    if not alias:
        return {"name": "Vulnbox SSH", "status": "unknown", "detail": "capture_ssh_alias not set"}
    code, _, _ = _run(f"timeout 10 ssh -o ConnectTimeout=8 -o BatchMode=yes {alias} echo OK", timeout=12)
    if code == 0:
        return {"name": "Vulnbox SSH", "status": "up", "detail": f"ssh {alias} reachable"}
    return {"name": "Vulnbox SSH", "status": "down", "detail": f"ssh {alias} unreachable — Azure VM may be stopped"}


def check_pull_loop():
    # the bracket trick ([r]sync, not rsync) stops pgrep -f from matching its
    # own argv -- a bare pattern here would always "succeed" against itself
    code, out, _ = _run("pgrep -f '[r]sync.*ctf-capture' | head -1")
    if code == 0 and out:
        return {"name": "Capture pull loop", "status": "up", "detail": "rsync loop running"}
    return {"name": "Capture pull loop", "status": "down", "detail": "not running — bash vulnbox-deploy/deploy-capture-pull.sh"}


def check_traffic_freshness():
    traffic_dir = ROOT / "traffic"
    if not traffic_dir.is_dir():
        return {"name": "Traffic freshness", "status": "unknown", "detail": "traffic/ missing"}
    newest = 0.0
    for p in traffic_dir.glob("*.pcap"):
        newest = max(newest, p.stat().st_mtime)
    if newest == 0.0:
        return {"name": "Traffic freshness", "status": "unknown", "detail": "no .pcap files yet"}
    age = time.time() - newest
    if age < 120:
        return {"name": "Traffic freshness", "status": "up", "detail": f"newest pcap {int(age)}s old"}
    return {"name": "Traffic freshness", "status": "down", "detail": f"newest pcap {int(age)}s old (stalled)"}


def check_flow_freshness():
    code, out, _ = _run(
        "docker exec tulip-timescale-1 psql -t -A 'postgres://tulip@timescale:5432/tulip' "
        "-c \"SELECT count(*), extract(epoch from (now() - max(time)))::int FROM flow;\""
    )
    if code != 0 or not out or "|" not in out:
        return {"name": "Tulip flows", "status": "unknown", "detail": "could not query (is tulip-timescale-1 up?)"}
    count_s, age_s = out.split("|")
    try:
        age = int(age_s)
    except ValueError:
        return {"name": "Tulip flows", "status": "unknown", "detail": f"{count_s} rows, age unknown"}
    if age < 180:
        return {"name": "Tulip flows", "status": "up", "detail": f"{count_s} rows, newest {age}s old"}
    return {"name": "Tulip flows", "status": "down",
            "detail": f"{count_s} rows but newest {age}s old — check BPF/capture_port mismatch (RUNBOOK #3)"}


def check_ctfproxy(cfg):
    ins = cfg.get("ctf_proxy", {}).get("insertion", {})
    if ins.get("mode") != "docker-compose":
        return {"name": "ctf_proxy (blocking layer)", "status": "unknown", "detail": "monitor-only mode (insertion disabled)"}
    team = cfg.get("team_id", "team")
    alias = ins.get("remote_ssh_alias", "")
    if not alias:
        return {"name": "ctf_proxy (blocking layer)", "status": "unknown", "detail": "remote_ssh_alias not set"}
    code, out, _ = _run(
        f"timeout 10 ssh -o ConnectTimeout=8 {alias} "
        f"\"docker inspect -f '{{{{.State.Status}}}}' ctfproxy-{team}-nginx ctfproxy-{team}-proxy 2>/dev/null\"",
        timeout=12,
    )
    if code == 0 and out.count("running") == 2:
        return {"name": "ctf_proxy (blocking layer)", "status": "up", "detail": "nginx+proxy running on vulnbox-host"}
    if code != 0:
        return {"name": "ctf_proxy (blocking layer)", "status": "down", "detail": "vulnbox unreachable"}
    return {"name": "ctf_proxy (blocking layer)", "status": "down", "detail": f"not fully up: {out or 'no containers found'}"}


def check_retention():
    cfg = _cfg()
    port = cfg.get("monitor_host", {}).get("alert_queue_port", 6380)
    try:
        import redis
        raw = redis.Redis(host="localhost", port=port, decode_responses=True, socket_timeout=3).get("retention_status")
    except Exception as e:
        return {"name": "PCAP auto-cleanup", "status": "unknown", "detail": f"redis: {e}"}
    if not raw:
        return {"name": "PCAP auto-cleanup", "status": "down", "detail": "not running — host_agent.py down? (bash deploy-all.sh)"}
    st = json.loads(raw)
    pol = st["policy"]
    return {"name": "PCAP auto-cleanup", "status": "up",
            "detail": f"traffic/ {st['size_mb']} MB in {st['files']} files, {st['free_gb']} GB free · "
                      f"keeps {pol['keep_min']} min / max {pol['max_bytes'] // 1024 ** 3} GB"}


def check_ml():
    """ML fingerprinter publishes its own state to Redis (key ml_status)."""
    cfg = _cfg()
    port = cfg.get("monitor_host", {}).get("alert_queue_port", 6380)
    try:
        import redis
        raw = redis.Redis(host="localhost", port=port, decode_responses=True, socket_timeout=3).get("ml_status")
    except Exception as e:
        return {"name": "ML bot fingerprint", "status": "unknown", "detail": f"redis: {e}"}
    if not raw:
        return {"name": "ML bot fingerprint", "status": "down",
                "detail": "no status for 6+ min — docker restart ctf-ml-fingerprint"}
    st = json.loads(raw)
    s = st.get("state")
    if s == "active":
        return {"name": "ML bot fingerprint", "status": "up",
                "detail": f"tick {st['tick']}: {st.get('flows_last_tick', 0)} clients, "
                          f"{st.get('deviants_last_tick', 0)} deviant, bot cluster {st.get('bot_cluster_size', 0)}"}
    if s == "warmup":
        return {"name": "ML bot fingerprint", "status": "slow",
                "detail": f"warming up {st['tick']}/{st['warmup_ticks']} ticks (~{st['tick_window_s']}s each)"}
    return {"name": "ML bot fingerprint", "status": "slow",
            "detail": f"{s}: {st.get('note', 'waiting for traffic')} (ports {st.get('service_ports')})"}


def check_ollama():
    code, _, _ = _run("systemctl is-active --quiet ollama")
    if code == 0:
        return {"name": "Ollama", "status": "up", "detail": "systemd service active"}
    code, _, _ = _run("curl -s -o /dev/null --max-time 3 http://localhost:11434/api/tags")
    if code == 0:
        return {"name": "Ollama", "status": "up", "detail": "API responding"}
    return {"name": "Ollama", "status": "down", "detail": "not responding — systemctl start ollama"}


def run_all():
    cfg = _cfg()
    rows = [check_disk()]
    rows += check_containers()
    rows.append(check_vulnbox_ssh(cfg))
    rows.append(check_pull_loop())
    rows.append(check_traffic_freshness())
    rows.append(check_flow_freshness())
    rows.append(check_ctfproxy(cfg))
    rows.append(check_ml())
    rows.append(check_retention())
    rows.append(check_ollama())
    return {"checked_at": time.time(), "items": rows}


COLOR = {"up": "\033[0;32m[OK]  \033[0m", "down": "\033[0;31m[FAIL]\033[0m",
         "slow": "\033[1;33m[WARN]\033[0m", "unknown": "\033[1;33m[WARN]\033[0m"}


def print_human(result):
    for row in result["items"]:
        tag = COLOR.get(row["status"], row["status"])
        print(f"{tag} {row['name']}: {row['detail']}")


def push_redis(result, cfg):
    import redis
    port = cfg.get("monitor_host", {}).get("alert_queue_port", 6380)
    r = redis.Redis(host="localhost", port=port, decode_responses=True)
    r.set("system_status", json.dumps(result), ex=120)


def main():
    args = sys.argv[1:]
    as_json = "--json" in args
    push = "--push" in args
    loop_s = None
    if "--loop" in args:
        loop_s = int(args[args.index("--loop") + 1])

    def once():
        result = run_all()
        if push:
            push_redis(result, _cfg())
        if as_json:
            print(json.dumps(result))
        elif not push:
            print_human(result)
        return result

    if loop_s:
        while True:
            once()
            time.sleep(loop_s)
    else:
        once()


if __name__ == "__main__":
    main()
