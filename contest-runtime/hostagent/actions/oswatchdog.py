"""OS-watchdog allowlist control (vulnbox-side). A one-time baseline diff
(os-watchdog-agent.sh) can't tell the organizer's checker legitimately
SSHing in to plant/verify a flag apart from a real intrusion -- both just
look like "something not in baseline" to it. Rather than guess the
checker's exact process/cron/IP signature in advance (usually not published
before the contest), a human who sees an alert and recognizes it marks that
exact (alert type, substring of its detail) pair here so it stops repeating
every CHECK_INTERVAL -- any genuinely NEW/different alert still fires
normally. Never silences a whole alert TYPE, only the specific text a human
has already seen and confirmed is not an attack."""
import shlex

from ..common import audit, cfg, ssh

BIN = "/usr/local/bin/os-watchdog-agent.sh"


def _alias():
    return cfg().get("vulnbox", {}).get("capture_ssh_alias") or ""


def allow(payload, rdb):
    alias = _alias()
    if not alias:
        return {"ok": False, "output": "vulnbox.capture_ssh_alias not set in services.json"}
    alert_type = str(payload.get("alert_type") or "").strip()
    pattern = str(payload.get("pattern") or "").strip()
    if not alert_type or not pattern:
        return {"ok": False, "output": "alert_type and pattern are both required"}
    if len(pattern) > 2000:
        return {"ok": False, "output": "pattern too long (max 2000 chars)"}
    cmd = f"sudo {BIN} allow {shlex.quote(alert_type)} {shlex.quote(pattern)}"
    code, out = ssh(alias, cmd, timeout=20)
    if code != 0:
        return {"ok": False, "output": f"Failed to add to allowlist: {out}"}
    audit(rdb, f"OS-watchdog allowlist: added [{alert_type}] matching {pattern[:80]!r} -- marked known-good", True)
    return {"ok": True, "output": out or "Added to allowlist."}


def unallow(payload, rdb):
    """Remove one allowlist entry by exact (alert_type, pattern) -- the undo
    button for a mistaken or too-broad allow."""
    alias = _alias()
    if not alias:
        return {"ok": False, "output": "vulnbox.capture_ssh_alias not set in services.json"}
    alert_type = str(payload.get("alert_type") or "").strip()
    pattern = str(payload.get("pattern") or "").strip()
    if not alert_type or not pattern:
        return {"ok": False, "output": "alert_type and pattern are both required"}
    cmd = f"sudo {BIN} unallow {shlex.quote(alert_type)} {shlex.quote(pattern)}"
    code, out = ssh(alias, cmd, timeout=20)
    if code != 0:
        return {"ok": False, "output": f"Failed to remove from allowlist: {out}"}
    audit(rdb, f"OS-watchdog allowlist: removed [{alert_type}]", True)
    return {"ok": True, "output": out or "Removed."}


def list_allowed(payload, rdb):
    alias = _alias()
    if not alias:
        return {"ok": False, "output": "vulnbox.capture_ssh_alias not set in services.json"}
    cmd = f"sudo {BIN} allow-list"
    code, out = ssh(alias, cmd, timeout=20)
    if code != 0:
        return {"ok": False, "output": f"Failed to read allowlist: {out}"}
    entries = []
    for line in out.splitlines():
        if "|" in line:
            t, p = line.split("|", 1)
            entries.append({"alert_type": t, "pattern": p})
    return {"ok": True, "entries": entries}
