"""Config tab: edit services.json from the dashboard, safely."""
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..common import CONFIG_PATH, ROOT, audit, run, stamp

BACKUPS = ROOT / "config-backups"
REDEPLOY_LOG = ROOT / ".redeploy-from-dashboard.log"
# containers that read services.json only at startup (mounted read-only)
READS_CONFIG_AT_START = ["ctf-detection", "ctf-watchdog"]


def _validate_text(text: str) -> tuple[bool, str]:
    try:
        json.loads(text)
    except ValueError as e:
        return False, f"Not valid JSON: {e}"
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(text)
        tmp = f.name
    try:
        code, out = run(["bash", str(ROOT / "config" / "validate-config.sh"), tmp], timeout=60)
    finally:
        Path(tmp).unlink(missing_ok=True)
    out = re.sub(r"\x1b\[[0-9;]*m", "", out)
    clean = "\n".join(l for l in out.splitlines() if "[OK]" not in l)
    return code == 0, (clean or out)[-4000:]


def validate(payload, rdb):
    ok, out = _validate_text(payload.get("text", ""))
    return {"ok": ok, "output": ("✓ Config is valid.\n" if ok else "✗ Config has problems:\n") + out}


def apply(payload, rdb):
    text = payload.get("text", "")
    ok, out = _validate_text(text)
    if not ok:
        audit(rdb, "services.json change REJECTED by validate-config.sh", False, kind="config-change")
        return {"ok": False, "output": "Not saved — validation failed:\n" + out}
    BACKUPS.mkdir(exist_ok=True)
    ts = stamp()
    shutil.copy2(CONFIG_PATH, BACKUPS / f"services.json.{ts}")
    # Overwrite IN PLACE (same inode). Containers bind-mount this single file;
    # a write-tmp-then-rename would leave them reading the old inode forever.
    with open(CONFIG_PATH, "r+") as f:
        f.seek(0)
        f.write(text if text.endswith("\n") else text + "\n")
        f.truncate()
    audit(rdb, f"services.json updated from dashboard (backup config-backups/services.json.{ts})", True, kind="config-change")
    if not payload.get("restart"):
        return {"ok": True, "output": f"Saved (backup {ts}). Not applied yet — press 'Save & apply' when ready."}
    # bringup.sh regenerates every derived config (.env, Tulip .env, ctf_proxy
    # config) and recreates containers whose settings changed; then restart the
    # ones that only read services.json at startup. Runs detached: it may
    # restart this dashboard, so the request can't wait for it.
    updated = json.loads(text)
    containers = list(READS_CONFIG_AT_START)
    flagtrace = updated.get("flagtrace") or {}
    if flagtrace.get("enabled"):
        containers.append("ctf-flagtrace")
        # Only when enabled: bringup.sh has just stopped a disabled worker, and
        # restarting it here would bring it back.
        if (flagtrace.get("trace") or {}).get("enabled"):
            containers.append("ctf-flagtrace-worker")
    mode = os.environ.get("MODE", "contest")
    if mode not in ("contest", "prep"):
        return {"ok": False, "output": "Invalid MODE; config saved but redeploy refused"}
    if mode == "prep" and updated.get("ml_classifier", {}).get("enabled"):
        containers.append("ctf-ml-fingerprint")
    restart_cmd = " && ".join(f"docker restart {c}" for c in containers)
    script = f"cd {shlex.quote(str(ROOT.parent))} && MODE={mode} bash bringup.sh && {restart_cmd} && echo REDEPLOY_DONE"
    with open(REDEPLOY_LOG, "w") as log:
        subprocess.Popen(["bash", "-c", script], stdout=log, stderr=subprocess.STDOUT,
                         start_new_session=True, cwd=str(ROOT.parent))
    return {"ok": True, "output": f"Saved (backup {ts}). Re-deploying in the background — the page may "
                                  "disconnect for ~1-2 min while containers restart. Progress: 'Show redeploy log'."}


def rollback(payload, rdb):
    backups = sorted(BACKUPS.glob("services.json.*")) if BACKUPS.exists() else []
    if not backups:
        return {"ok": False, "output": "No config backups."}
    latest = backups[-1]
    with open(CONFIG_PATH, "r+") as f:   # in place, see apply()
        f.seek(0)
        f.write(latest.read_text())
        f.truncate()
    latest.unlink()
    audit(rdb, f"services.json rolled back to {latest.name} (not re-deployed yet)", True, kind="config-change")
    return {"ok": True, "output": f"Restored {latest.name}. Press 'Save & apply' to re-deploy with it.",
            "text": CONFIG_PATH.read_text()}


def redeploy_log(payload, rdb):
    if not REDEPLOY_LOG.exists():
        return {"ok": True, "output": "No redeploy has been started from the dashboard yet."}
    tail = REDEPLOY_LOG.read_text(errors="replace").splitlines()[-60:]
    clean = [re.sub(r"\x1b\[[0-9;]*m", "", l) for l in tail]
    return {"ok": True, "output": "\n".join(clean), "done": any("REDEPLOY_DONE" in l for l in clean)}
