"""ctf_proxy filter rules on the vulnbox-host (reached with the admin SSH alias
from services.json). Filter source travels over stdin, never inside the remote
command line.

One ctf_proxy deployment (contest-runtime/defense/deploy-ctfproxy.sh) fronts
EVERY TCP service in services.json -- each gets its own filter_modules/<name>/
pair, matching ctf_proxy's own services[] list in its config.json. Every
action here takes a "service" in its payload to say which one; it defaults to
the first eligible service when omitted, for backward compatibility with
single-service configs. UDP services are never eligible -- ctf_proxy only
proxies TCP/HTTP (see its own README) -- use the content-based firewall block
(hostagent/actions/firewall.py) for those instead."""
import ast
import re
import shlex
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from ..common import audit, cfg, ssh, stamp

# Redis hash method-name -> ISO timestamp of the first time that method
# appeared in the live filter, one hash per service (ADDED_KEY_PREFIX + name).
# Same idea as Suricata's suricata_rule_added, lets the dashboard show "when
# was this rule added" per row.
ADDED_KEY_PREFIX = "ctfproxy_rule_added:"

PASSTHROUGH = '''from src.stream import Stream, TCPStream, HTTPStream

# PAUSED from the dashboard. The real rules are saved next to this file as
# <service>_in.py.paused-rules and come back with "Resume filtering".
class Module():

    def execute(self, stream: Stream):
        return None
'''


def _sanitize(name: str) -> str:
    """Must match a valid Python module name -- ctf_proxy imports
    filter_modules/<name>/<name>_in.py as a module literally named that."""
    n = re.sub(r"[^a-zA-Z0-9_]", "_", (name or "").strip()) or "svc"
    return "s_" + n if n[0].isdigit() else n


def eligible_services(c: dict) -> list[dict]:
    """Every TCP service in services.json -- what deploy-ctfproxy.sh inserted
    ctf_proxy in front of. UDP services are never eligible."""
    ins = c.get("ctf_proxy", {}).get("insertion", {})
    out = []
    for s in c.get("services", []):
        if s.get("proto", "tcp") != "tcp":
            continue
        out.append({
            "name": s["name"], "san": _sanitize(s["name"]), "port": s.get("port"),
            "http": s.get("layer") in ("l7-http", "l7-https"),
            "compose_service": s.get("compose_service") or ins.get("remote_compose_service") or "",
        })
    return out


def list_services(payload, rdb):
    """Pure config read, no SSH -- lets the dashboard populate a service
    picker even if the vulnbox/host_agent round-trip is slow."""
    c = cfg()
    services = eligible_services(c)
    return {"ok": True, "services": services}


def _ctx(payload):
    c = cfg()
    ins = c.get("ctf_proxy", {}).get("insertion", {})
    if ins.get("mode") != "docker-compose":
        return None, "ctf_proxy insertion is disabled in services.json (monitor-only mode) — nothing to manage."
    alias = ins.get("remote_ssh_alias")
    if not alias:
        return None, "ctf_proxy.insertion.remote_ssh_alias is not set"
    services = eligible_services(c)
    if not services:
        return None, "no TCP services in services.json — nothing for ctf_proxy to manage"
    want = str(payload.get("service") or "").strip()
    svc = next((s for s in services if s["name"] == want), None) if want else services[0]
    if svc is None:
        return None, f"unknown service {want!r} — available: {', '.join(s['name'] for s in services)}"
    team = c.get("team_id", "team")
    base = f"ctf-proxy-{team}"
    san = svc["san"]
    return {
        "alias": alias, "team": team, "base": base, "service": svc["name"],
        "file": f"{base}/proxy/filter_modules/{san}/{san}_in.py",
        # filter_modules/<service>/ is root-owned on some vulnbox setups -- NEW
        # files can't be created there (only the existing <service>_in.py can
        # be overwritten in place), so the paused-rules stash and per-apply
        # backups live in the (user-owned) backups dir instead.
        "paused": f"{base}/filter-backups/{san}_in.py.paused-rules",
        "backups": f"{base}/filter-backups",
        "backup_prefix": f"{san}_in.py.",
        "added_key": ADDED_KEY_PREFIX + svc["name"],
    }, None


def _q(p: str) -> str:
    """Remote paths are relative to the SSH user's home; quote them for the shell."""
    return shlex.quote(p)


def _is_paused(x) -> bool:
    code, _ = ssh(x["alias"], f"test -f {_q(x['paused'])}", timeout=20)
    return code == 0


def _method_names(source: str) -> set[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Module":
            names |= {f.name for f in node.body
                      if isinstance(f, ast.FunctionDef) and f.name != "execute" and not f.name.startswith("__")}
    return names


def _compiles(source: str) -> str | None:
    try:
        ast.parse(source)
    except SyntaxError as e:
        return f"Python syntax error line {e.lineno}: {e.msg}"
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(source)
        path = f.name
    try:
        compile(Path(path).read_text(), path, "exec")
    finally:
        Path(path).unlink(missing_ok=True)
    if "class Module" not in source or "def execute" not in source:
        return "file must still define class Module with def execute"
    return None


def get(payload, rdb):
    x, err = _ctx(payload)
    if err:
        return {"ok": False, "output": err}
    paused = _is_paused(x)
    target = x["paused"] if paused else x["file"]
    code, out = ssh(x["alias"], f"cat {_q(target)}", timeout=30)
    if code != 0:
        return {"ok": False, "output": f"Could not read {target} on {x['alias']}: {out}"}
    return {"ok": True, "source": out + ("\n" if not out.endswith("\n") else ""), "paused": paused,
            "service": x["service"], "path": f"{x['alias']}:~/{target}"}


def apply(payload, rdb):
    x, err = _ctx(payload)
    if err:
        return {"ok": False, "output": err}
    source = payload.get("source")
    if not isinstance(source, str) or len(source) > 512 * 1024:
        return {"ok": False, "output": "source must be a string under 512 KB"}
    problem = _compiles(source)
    if problem:
        audit(rdb, f"ctf_proxy filter upload REJECTED ({x['service']}): {problem}", False)
        return {"ok": False, "output": "Not uploaded: " + problem}
    paused = _is_paused(x)
    target = x["paused"] if paused else x["file"]
    old_code, old_out = ssh(x["alias"], f"cat {_q(target)}", timeout=30)
    old_names = _method_names(old_out) if old_code == 0 else set()
    ts = stamp()
    # Write directly into the existing file rather than write-tmp-then-rename:
    # filter_modules/<service>/ is root-owned on some vulnbox setups (ctf_proxy's
    # own install leaves it that way) so the SSH user can't create a NEW
    # directory entry there -- only `mkdir`/`cp` into the (user-owned) backups
    # dir and an in-place write to the ALREADY-existing, world-writable file work.
    backup_name = x["backup_prefix"] + ts
    cmd = (f"mkdir -p {_q(x['backups'])} && cp {_q(target)} {_q(x['backups'] + '/' + backup_name)} && "
           f"cat > {_q(target)}")
    code, out = ssh(x["alias"], cmd, timeout=40, input_text=source)
    if code != 0:
        audit(rdb, f"ctf_proxy filter upload failed ({x['service']}): {out}", False)
        return {"ok": False, "output": f"Upload failed: {out}"}
    # Record the first-seen time for any method new in this upload -- hsetnx
    # so re-uploading unrelated edits never resets an existing method's time.
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        for name in _method_names(source) - old_names:
            rdb.hsetnx(x["added_key"], name, now_iso)
    except Exception:
        pass  # metadata only -- never block a real apply over this
    if paused:
        audit(rdb, f"ctf_proxy rules saved while PAUSED ({x['service']}, backup {backup_name}) — take effect on Resume", True)
        return {"ok": True, "output": f"Saved (backup {backup_name}). Filtering is PAUSED, so these rules take effect when you press Resume."}
    time.sleep(3)
    code, state = ssh(x["alias"], f"docker inspect -f '{{{{.State.Status}}}}' ctfproxy-{x['team']}-proxy", timeout=20)
    n = source.count("def ") - 1
    audit(rdb, f"ctf_proxy filter applied ({x['service']}, {n} rule methods, backup {backup_name})", True)
    return {"ok": True, "output": f"Uploaded, ctf_proxy hot-reloads it (no restart). {n} rule method(s). "
                                  f"Backup: filter-backups/{backup_name}. Proxy container: {state.strip()}"}


def delete_method(payload, rdb):
    """Remove one rule method by name from the live filter and re-apply (same
    syntax-check+backup+upload path as apply()) -- the one-click undo for a
    rule that turns out to be blocking the checker / hurting SLA."""
    name = str(payload.get("name") or "").strip()
    if not name or not re.match(r"^[A-Za-z_]\w*$", name):
        return {"ok": False, "output": "a valid method name is required"}
    cur = get(payload, rdb)
    if not cur.get("ok"):
        return cur
    source = cur["source"]
    pat = re.compile(rf"^    def {re.escape(name)}\(self.*?(?=^    def |\Z)", re.S | re.M)
    new_source, n = pat.subn("", source)
    if n == 0:
        return {"ok": False, "output": f"method {name!r} not found in the current filter"}
    result = apply({**payload, "source": new_source}, rdb)
    if result.get("ok"):
        audit(rdb, f"ctf_proxy rule {name}() deleted ({cur.get('service')})", True)
        try:
            rdb.hdel(ADDED_KEY_PREFIX + cur.get("service", ""), name)
        except Exception:
            pass
    return result


def rollback(payload, rdb):
    x, err = _ctx(payload)
    if err:
        return {"ok": False, "output": err}
    target = x["paused"] if _is_paused(x) else x["file"]
    cmd = (f"latest=$(ls -1 {_q(x['backups'])}/{x['backup_prefix']}* 2>/dev/null | sort | tail -1); "
           f"[ -n \"$latest\" ] || {{ echo NOBACKUP; exit 3; }}; cp \"$latest\" {_q(target)} && rm \"$latest\" && echo \"$latest\"")
    code, out = ssh(x["alias"], cmd, timeout=30)
    if code == 3 or "NOBACKUP" in out:
        return {"ok": False, "output": f"No ctf_proxy filter backups to roll back to for '{x['service']}'."}
    if code != 0:
        return {"ok": False, "output": f"Rollback failed: {out}"}
    audit(rdb, f"ctf_proxy filter rolled back ({x['service']}) to {out.strip().rsplit('/', 1)[-1]}", True)
    res = get(payload, rdb)
    return {"ok": True, "output": f"Restored {out.strip()}", "source": res.get("source", "")}


def _pause_targets(payload) -> list[str]:
    """A specific service if named; otherwise EVERY eligible service -- the
    SERVICES tab's global Pause/Resume button is a kill switch and a partial
    pause (filtering still live on a service nobody noticed) defeats that."""
    want = str(payload.get("service") or "").strip()
    if want:
        return [want]
    return [s["name"] for s in eligible_services(cfg())]


def pause_filter(payload, rdb):
    targets = _pause_targets(payload)
    if not targets:
        return {"ok": False, "output": "no TCP services in services.json — nothing for ctf_proxy to manage"}
    results = []
    for name in targets:
        x, err = _ctx({**payload, "service": name})
        if err:
            return {"ok": False, "output": err}
        if _is_paused(x):
            results.append(f"{name}: already paused")
            continue
        cmd = f"mkdir -p {_q(x['backups'])} && cp {_q(x['file'])} {_q(x['paused'])} && cat > {_q(x['file'])}"
        code, out = ssh(x["alias"], cmd, timeout=30, input_text=PASSTHROUGH)
        if code != 0:
            return {"ok": False, "output": f"Pause failed for {name}: {out}"}
        results.append(f"{name}: paused")
    audit(rdb, f"ctf_proxy filtering PAUSED ({', '.join(targets)}) — traffic passes through unfiltered", True, kind="service-control")
    return {"ok": True, "output": "Filtering paused: ctf_proxy stays in the path but blocks nothing.\n" + "\n".join(results)}


def resume_filter(payload, rdb):
    targets = _pause_targets(payload)
    if not targets:
        return {"ok": False, "output": "no TCP services in services.json — nothing for ctf_proxy to manage"}
    results = []
    for name in targets:
        x, err = _ctx({**payload, "service": name})
        if err:
            return {"ok": False, "output": err}
        if not _is_paused(x):
            results.append(f"{name}: not paused")
            continue
        code, out = ssh(x["alias"], f"cat {_q(x['paused'])} > {_q(x['file'])} && rm {_q(x['paused'])}", timeout=30)
        if code != 0:
            return {"ok": False, "output": f"Resume failed for {name}: {out}"}
        results.append(f"{name}: resumed")
    audit(rdb, f"ctf_proxy filtering RESUMED ({', '.join(targets)})", True, kind="service-control")
    return {"ok": True, "output": "Filtering resumed with saved rules.\n" + "\n".join(results)}


def uninstall(payload, rdb):
    """Emergency exit: take ctf_proxy out of the traffic path entirely for
    EVERY service and give the public ports back to the original services
    (restores the whole compose file deploy-ctfproxy.sh backed up once,
    before touching anything). A few seconds of downtime while the ports
    move — use when ctf_proxy itself is the problem, not just one rule."""
    c = cfg()
    ins = c.get("ctf_proxy", {}).get("insertion", {})
    alias = ins.get("remote_ssh_alias")
    compose_file = ins.get("remote_compose_file", "")
    if not alias or not compose_file:
        return {"ok": False, "output": "ctf_proxy.insertion.remote_ssh_alias/remote_compose_file not set — can't restore"}
    services = eligible_services(c)
    compose_services = sorted({s["compose_service"] for s in services if s["compose_service"]})
    if not compose_services:
        return {"ok": False, "output": "no service has a compose_service set — can't restore"}
    team = c.get("team_id", "team")
    bak = compose_file + ".pre-ctfproxy.bak"
    compose_dir = compose_file.rsplit("/", 1)[0]
    svc_args = " ".join(shlex.quote(s) for s in compose_services)
    cmd = (f"set -e; test -f {bak}; "
           f"cd ~/ctf-proxy-{team} && docker compose stop; "
           f"cp {bak} {compose_file}; "
           f"cd {compose_dir} && docker compose up -d {svc_args}; "
           "sleep 3")
    for s in services:
        cmd += (f"; curl -s -o /dev/null -w '{s['name']}: HTTP %{{http_code}}\\n' "
                f"--max-time 8 http://localhost:{int(s['port'])}/ || true")
    code, out = ssh(alias, cmd, timeout=180)
    ok = code == 0
    audit(rdb, f"ctf_proxy UNINSTALLED from traffic path — original port bindings restored ({out[-120:]})", ok,
          kind="service-control")
    return {"ok": ok, "output": out if ok else f"Uninstall failed (check {alias} manually): {out}"}
