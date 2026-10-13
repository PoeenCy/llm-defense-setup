"""Services tab: live state of everything in registry.py + start/stop/restart."""
import os
import signal
from concurrent.futures import ThreadPoolExecutor

from .. import registry
from ..common import ROOT, audit, cfg, container_state, run, ssh
from . import ctfproxy

OPS = {
    "container": ("start", "stop", "restart"),
    "capture": ("start", "stop", "restart"),
    "ctfproxy": ("pause_filter", "resume_filter", "restart", "uninstall"),
    "oswatchdog": ("start", "stop", "restart"),
}
OSWD = ["bash", str(ROOT / "watchdog" / "deploy-os-watchdog.sh")]
PULL_PIDFILE = ROOT / "monitor" / ".capture-pull.pid"


def _pull_loop_pid() -> int | None:
    try:
        pid = int(PULL_PIDFILE.read_text().strip())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


def _capture_state() -> tuple[str, str]:
    alias = cfg().get("vulnbox", {}).get("capture_ssh_alias")
    local = "running" if _pull_loop_pid() else "stopped"
    if not alias:
        return "unknown", "vulnbox.capture_ssh_alias not set"
    code, out = ssh(alias, "pgrep -f 'tcpdump -Z root' >/dev/null && echo RUNNING || echo STOPPED", timeout=15)
    if code != 0:
        return ("degraded" if local == "running" else "stopped"), f"vulnbox unreachable; local pull loop {local}"
    remote = "running" if "RUNNING" in out else "stopped"
    if remote == "running" and local == "running":
        return "running", "tcpdump on vulnbox + local pull loop both running"
    if remote == local == "stopped":
        return "stopped", "not capturing"
    return "degraded", f"remote tcpdump {remote}, local pull loop {local}"


def _ctfproxy_state() -> tuple[str, str]:
    services = ctfproxy.eligible_services(cfg())
    if not services:
        return "disabled", "no TCP services in services.json for ctf_proxy to front"
    x0, err = ctfproxy._ctx({})
    if err:
        return "disabled", "monitor-only mode (ctf_proxy.insertion.mode is not docker-compose)"
    sans = " ".join(ctfproxy._q(s["san"]) for s in services)
    cmd = (f"docker inspect -f '{{{{.State.Status}}}}' ctfproxy-{x0['team']}-nginx ctfproxy-{x0['team']}-proxy 2>/dev/null; "
           f"for s in {sans}; do test -f ~/{x0['base']}/filter-backups/${{s}}_in.py.paused-rules && echo \"PAUSED:$s\"; done")
    code, out = ssh(x0["alias"], cmd, timeout=15)
    if code == 255 or code < 0:
        return "unknown", "vulnbox unreachable over SSH — state unknown"
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    container_states = [l for l in lines if not l.startswith("PAUSED:")]
    paused = [l.split(":", 1)[1] for l in lines if l.startswith("PAUSED:")]
    if container_states.count("running") != 2:
        return "down", f"containers: {', '.join(container_states) or 'not found'}"
    if not paused:
        return "running", f"filtering active ({len(services)} service(s))"
    if len(paused) == len(services):
        return "paused", "in the traffic path, but filtering paused on all services — everything passes"
    return "degraded", f"filtering paused on: {', '.join(paused)}; still active on the rest"


def _state_of(svc: dict) -> dict:
    kind = svc["kind"]
    if kind == "container":
        st = container_state(svc["target"])
        state, detail = ("running" if st == "running" else "stopped" if st in ("exited", "created") else st), st
    elif kind == "capture":
        state, detail = _capture_state()
    elif kind == "oswatchdog":
        code, out = run(OSWD + ["--status"], timeout=40)
        st = (out.strip().splitlines() or ["unknown"])[-1]
        state = {"running": "running", "stopped": "stopped", "absent": "absent"}.get(st, "unknown")
        detail = {"running": "agent running on the vulnbox host, reporting to this machine",
                  "stopped": "installed but not running", "absent": "not installed — press Start",
                  }.get(st, "vulnbox unreachable — state unknown")
    else:
        state, detail = _ctfproxy_state()
    ops = [] if svc["protected"] else list(OPS.get(kind, ()))
    return {**{k: svc[k] for k in ("id", "group", "label", "kind", "protected", "note")},
            "state": state, "detail": detail, "ops": ops}


def list_services(payload, rdb):
    svcs = registry.all_services()
    with ThreadPoolExecutor(max_workers=8) as pool:
        items = list(pool.map(_state_of, svcs))
    return {"ok": True, "items": items}


def _capture(op: str) -> tuple[bool, str]:
    alias = cfg().get("vulnbox", {}).get("capture_ssh_alias")
    if op in ("stop", "restart"):
        pid = _pull_loop_pid()
        if pid:
            # Kill only the loop and its own children. NOT killpg: the loop was
            # spawned from this agent and can share its process group.
            run(["pkill", "-TERM", "-P", str(pid)], timeout=10)
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        PULL_PIDFILE.unlink(missing_ok=True)
        if alias:
            ssh(alias, "sudo -n pkill -f 'tcpdump -Z root' || true", timeout=20)
        if op == "stop":
            return True, "Capture stopped (remote tcpdump + local pull loop). Already-captured pcaps are kept."
    code, out = run(["bash", str(ROOT / "monitor" / "deploy-capture-pull.sh"), "--background"], timeout=90)
    return code == 0, out[-1500:]


def control(payload, rdb):
    svc = registry.get(str(payload.get("id", "")))
    op = str(payload.get("op", ""))
    if svc is None:
        return {"ok": False, "output": "unknown service"}
    if svc["protected"]:
        return {"ok": False, "output": f"{svc['label']} is protected — control it from a terminal ({svc['note']})"}
    if op not in OPS.get(svc["kind"], ()):
        return {"ok": False, "output": f"operation {op!r} not allowed for {svc['label']}"}

    if svc["kind"] == "container":
        code, out = run(["docker", op, svc["target"]], timeout=120)
        ok = code == 0
        msg = f"{op} {svc['target']}: " + ("done" if ok else out)
    elif svc["kind"] == "capture":
        ok, msg = _capture(op)
    elif svc["kind"] == "oswatchdog":
        code, out = run(OSWD + (["--stop"] if op == "stop" else []), timeout=120)
        ok = code == 0 and "[SKIP]" not in out
        msg = out[-1500:]
    else:
        if op == "restart":
            x, err = ctfproxy._ctx({})
            if err:
                return {"ok": False, "output": err}
            code, out = ssh(x["alias"], f"docker restart ctfproxy-{x['team']}-proxy", timeout=90)
            ok, msg = code == 0, ("proxy container restarted (nginx left running so traffic keeps flowing)" if code == 0 else out)
        else:
            res = getattr(ctfproxy, op)({}, rdb)
            return res
    audit(rdb, f"{svc['label']}: {op} — {'OK' if ok else 'FAILED'}", ok, kind="service-control")
    return {"ok": ok, "output": msg}
