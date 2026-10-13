"""ctf_proxy filter rules on the vulnbox-host (reached with the admin SSH alias
from services.json). Filter source travels over stdin, never inside the remote
command line."""
import ast
import re
import shlex
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from ..common import audit, cfg, ssh, stamp

# Redis hash method-name -> ISO timestamp of the first time that method
# appeared in the live filter. Same idea as Suricata's suricata_rule_added,
# lets the dashboard show "when was this rule added" per row.
ADDED_KEY = "ctfproxy_rule_added"

PASSTHROUGH = '''from src.stream import Stream, TCPStream, HTTPStream

# PAUSED from the dashboard. The real rules are saved next to this file as
# web_in.py.paused-rules and come back with "Resume filtering".
class Module():

    def execute(self, stream: Stream):
        return None
'''


def _ctx():
    c = cfg()
    ins = c.get("ctf_proxy", {}).get("insertion", {})
    if ins.get("mode") != "docker-compose":
        return None, "ctf_proxy insertion is disabled in services.json (monitor-only mode) — nothing to manage."
    alias = ins.get("remote_ssh_alias")
    if not alias:
        return None, "ctf_proxy.insertion.remote_ssh_alias is not set"
    team = c.get("team_id", "team")
    base = f"ctf-proxy-{team}"
    return {
        "alias": alias, "team": team, "base": base,
        "file": f"{base}/proxy/filter_modules/web/web_in.py",
        # filter_modules/web/ is root-owned on some vulnbox setups -- NEW
        # files can't be created there (only the existing web_in.py/web_out.py
        # can be overwritten in place), so the paused-rules stash lives in the
        # (user-owned) backups dir instead, never inside that directory.
        "paused": f"{base}/filter-backups/web_in.py.paused-rules",
        "backups": f"{base}/filter-backups",
        "compose_file": ins.get("remote_compose_file", ""),
        "service": ins.get("remote_compose_service", ""),
        "port": c.get("services", [{}])[0].get("port"),
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
    x, err = _ctx()
    if err:
        return {"ok": False, "output": err}
    paused = _is_paused(x)
    target = x["paused"] if paused else x["file"]
    code, out = ssh(x["alias"], f"cat {_q(target)}", timeout=30)
    if code != 0:
        return {"ok": False, "output": f"Could not read {target} on {x['alias']}: {out}"}
    return {"ok": True, "source": out + ("\n" if not out.endswith("\n") else ""), "paused": paused,
            "path": f"{x['alias']}:~/{target}"}


def apply(payload, rdb):
    x, err = _ctx()
    if err:
        return {"ok": False, "output": err}
    source = payload.get("source")
    if not isinstance(source, str) or len(source) > 512 * 1024:
        return {"ok": False, "output": "source must be a string under 512 KB"}
    problem = _compiles(source)
    if problem:
        audit(rdb, f"ctf_proxy filter upload REJECTED: {problem}", False)
        return {"ok": False, "output": "Not uploaded: " + problem}
    paused = _is_paused(x)
    target = x["paused"] if paused else x["file"]
    old_code, old_out = ssh(x["alias"], f"cat {_q(target)}", timeout=30)
    old_names = _method_names(old_out) if old_code == 0 else set()
    ts = stamp()
    # Write directly into the existing file rather than write-tmp-then-rename:
    # filter_modules/web/ is root-owned on some vulnbox setups (ctf_proxy's own
    # install leaves it that way) so the SSH user can't create a NEW directory
    # entry there -- only `mkdir`/`cp` into the (user-owned) backups dir and an
    # in-place write to the ALREADY-existing, world-writable web_in.py work.
    cmd = (f"mkdir -p {_q(x['backups'])} && cp {_q(target)} {_q(x['backups'] + '/web_in.py.' + ts)} && "
           f"cat > {_q(target)}")
    code, out = ssh(x["alias"], cmd, timeout=40, input_text=source)
    if code != 0:
        audit(rdb, f"ctf_proxy filter upload failed: {out}", False)
        return {"ok": False, "output": f"Upload failed: {out}"}
    # Record the first-seen time for any method new in this upload -- hsetnx
    # so re-uploading unrelated edits never resets an existing method's time.
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        for name in _method_names(source) - old_names:
            rdb.hsetnx(ADDED_KEY, name, now_iso)
    except Exception:
        pass  # metadata only -- never block a real apply over this
    if paused:
        audit(rdb, f"ctf_proxy rules saved while PAUSED (backup {ts}) — take effect on Resume", True)
        return {"ok": True, "output": f"Saved (backup {ts}). Filtering is PAUSED, so these rules take effect when you press Resume."}
    time.sleep(3)
    code, state = ssh(x["alias"], f"docker inspect -f '{{{{.State.Status}}}}' ctfproxy-{x['team']}-proxy", timeout=20)
    n = source.count("def ") - 1
    audit(rdb, f"ctf_proxy filter applied ({n} rule methods, backup {ts})", True)
    return {"ok": True, "output": f"Uploaded, ctf_proxy hot-reloads it (no restart). {n} rule method(s). "
                                  f"Backup: filter-backups/web_in.py.{ts}. Proxy container: {state.strip()}"}


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
    result = apply({"source": new_source}, rdb)
    if result.get("ok"):
        audit(rdb, f"ctf_proxy rule {name}() deleted", True)
        try:
            rdb.hdel(ADDED_KEY, name)
        except Exception:
            pass
    return result


def rollback(payload, rdb):
    x, err = _ctx()
    if err:
        return {"ok": False, "output": err}
    target = x["paused"] if _is_paused(x) else x["file"]
    cmd = (f"latest=$(ls -1 {_q(x['backups'])}/web_in.py.* 2>/dev/null | sort | tail -1); "
           f"[ -n \"$latest\" ] || {{ echo NOBACKUP; exit 3; }}; cp \"$latest\" {_q(target)} && rm \"$latest\" && echo \"$latest\"")
    code, out = ssh(x["alias"], cmd, timeout=30)
    if code == 3 or "NOBACKUP" in out:
        return {"ok": False, "output": "No ctf_proxy filter backups to roll back to."}
    if code != 0:
        return {"ok": False, "output": f"Rollback failed: {out}"}
    audit(rdb, f"ctf_proxy filter rolled back to {out.strip().rsplit('/', 1)[-1]}", True)
    res = get({}, rdb)
    return {"ok": True, "output": f"Restored {out.strip()}", "source": res.get("source", "")}


def pause_filter(payload, rdb):
    x, err = _ctx()
    if err:
        return {"ok": False, "output": err}
    if _is_paused(x):
        return {"ok": True, "output": "Already paused."}
    cmd = f"mkdir -p {_q(x['backups'])} && cp {_q(x['file'])} {_q(x['paused'])} && cat > {_q(x['file'])}"
    code, out = ssh(x["alias"], cmd, timeout=30, input_text=PASSTHROUGH)
    if code != 0:
        return {"ok": False, "output": f"Pause failed: {out}"}
    audit(rdb, "ctf_proxy filtering PAUSED (all traffic passes through unfiltered)", True, kind="service-control")
    return {"ok": True, "output": "Filtering paused: ctf_proxy stays in the path but blocks nothing. Your rules are kept and come back on Resume."}


def resume_filter(payload, rdb):
    x, err = _ctx()
    if err:
        return {"ok": False, "output": err}
    if not _is_paused(x):
        return {"ok": True, "output": "Not paused."}
    code, out = ssh(x["alias"], f"cat {_q(x['paused'])} > {_q(x['file'])} && rm {_q(x['paused'])}", timeout=30)
    if code != 0:
        return {"ok": False, "output": f"Resume failed: {out}"}
    audit(rdb, "ctf_proxy filtering RESUMED", True, kind="service-control")
    return {"ok": True, "output": "Filtering resumed with your saved rules."}


def uninstall(payload, rdb):
    """Emergency exit: take ctf_proxy out of the traffic path entirely and give
    the public port back to the original service (restores the compose file
    deploy-ctfproxy.sh backed up). A few seconds of downtime while the port
    moves — use when ctf_proxy itself is the problem."""
    x, err = _ctx()
    if err:
        return {"ok": False, "output": err}
    if not x["compose_file"] or not x["service"]:
        return {"ok": False, "output": "remote_compose_file/remote_compose_service not set — can't restore"}
    bak = x["compose_file"] + ".pre-ctfproxy.bak"
    compose_dir = x["compose_file"].rsplit("/", 1)[0]
    cmd = (f"set -e; test -f {bak}; "
           f"cd ~/{_q(x['base'])} && docker compose stop; "
           f"cp {bak} {x['compose_file']}; "
           f"cd {compose_dir} && docker compose up -d {shlex.quote(x['service'])}; "
           f"sleep 3; curl -s -o /dev/null -w 'HTTP %{{http_code}}' --max-time 8 http://localhost:{int(x['port'])}/ || true")
    code, out = ssh(x["alias"], cmd, timeout=180)
    ok = code == 0
    audit(rdb, f"ctf_proxy UNINSTALLED from traffic path — original port binding restored ({out[-60:]})", ok,
          kind="service-control")
    return {"ok": ok, "output": out if ok else f"Uninstall failed (check {x['alias']} manually): {out}"}
