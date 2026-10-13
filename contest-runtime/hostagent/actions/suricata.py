"""Suricata ruleset: test-then-apply, rollback, and dry-run against captured traffic."""
import json
import shutil

from ..common import ROOT, audit, find_container, run, stamp

RULES_DIR = ROOT / "detection" / "suricata" / "lib" / "rules"
LIVE = RULES_DIR / "suricata.rules"
STAGING = RULES_DIR / ".staging.rules"
TESTFILE = RULES_DIR / ".test.rules"
BACKUPS = RULES_DIR / "backups"
IN_CONTAINER = "/var/lib/suricata/rules"
MAX_BYTES = 16 * 1024 * 1024


def _container():
    return find_container("suricata")


def _syntax_test(container: str, filename: str) -> tuple[bool, str]:
    code, out = run(["docker", "exec", container, "suricata", "-T", "-c", "/etc/suricata/suricata.yaml",
                     "-S", f"{IN_CONTAINER}/{filename}", "-l", "/tmp"], timeout=120)
    return code == 0, "\n".join(out.splitlines()[-25:])


def _check_payload(rules) -> str | None:
    if not isinstance(rules, str):
        return "rules must be a string"
    if len(rules.encode()) > MAX_BYTES:
        return f"rules too large (> {MAX_BYTES} bytes)"
    return None


def apply(payload, rdb):
    rules = payload.get("rules")
    err = _check_payload(rules)
    if err:
        return {"ok": False, "output": err}
    container = _container()
    if not container:
        return {"ok": False, "output": "Suricata container is not running — start it from the Services tab or run deploy-all.sh"}
    STAGING.write_text(rules)
    ok, out = _syntax_test(container, STAGING.name)
    if not ok:
        STAGING.unlink(missing_ok=True)
        audit(rdb, "Suricata rule apply REJECTED (failed syntax test) — live rules untouched", False)
        return {"ok": False, "output": "Rule test FAILED — live rules were NOT changed.\n\n" + out}
    BACKUPS.mkdir(exist_ok=True)
    ts = stamp()
    if LIVE.exists():
        shutil.copy2(LIVE, BACKUPS / f"suricata.rules.{ts}")
    STAGING.replace(LIVE)
    # SIGUSR2 = live rule swap, no restart: already-processed pcaps are not
    # re-read (a restart replays the whole traffic dir and duplicates alerts).
    code, out2 = run(["docker", "kill", "-s", "USR2", container])
    if code != 0:
        audit(rdb, f"Suricata rules written but reload signal failed: {out2}", False)
        return {"ok": False, "output": f"Rules saved (backup {ts}) but reload failed: {out2}"}
    n = sum(1 for l in rules.splitlines() if l.strip() and not l.strip().startswith("#"))
    audit(rdb, f"Suricata rules applied ({n} active rules, backup {ts})", True)
    return {"ok": True, "output": f"Test passed, {n} active rules applied and live-reloaded.\n"
                                  f"Previous version backed up as backups/suricata.rules.{ts}"}


def delete_rule(payload, rdb):
    """Remove one rule by sid from the live ruleset and re-apply (same
    test+backup+reload path as apply()) -- the one-click undo for a rule
    that turns out to be hurting SLA."""
    sid = str(payload.get("sid") or "").strip()
    if not sid:
        return {"ok": False, "output": "sid is required"}
    if not LIVE.exists():
        return {"ok": False, "output": "no live ruleset to edit"}
    lines = LIVE.read_text().splitlines()
    kept = [ln for ln in lines if f"sid:{sid};" not in ln.replace(" ", "")]
    if len(kept) == len(lines):
        return {"ok": False, "output": f"sid {sid} not found in the live ruleset"}
    result = apply({"rules": "\n".join(kept) + "\n"}, rdb)
    if result.get("ok"):
        audit(rdb, f"Suricata rule sid:{sid} deleted", True)
    return result


def rollback(payload, rdb):
    backups = sorted(BACKUPS.glob("suricata.rules.*")) if BACKUPS.exists() else []
    if not backups:
        return {"ok": False, "output": "No backups to roll back to."}
    latest = backups[-1]
    shutil.copy2(latest, LIVE)
    latest.unlink()
    container = _container()
    if container:
        run(["docker", "kill", "-s", "USR2", container])
    audit(rdb, f"Suricata rules rolled back to {latest.name}", True)
    return {"ok": True, "output": f"Rolled back to {latest.name} and reloaded.", "rules": LIVE.read_text()}


def test_traffic(payload, rdb):
    """Run the candidate rules alone, in a throwaway second Suricata process
    inside the same container, over the N most recent captured pcaps. Answers
    "what would this rule have fired on?" — including the checker bot —
    before it ever touches the live ruleset."""
    rules = payload.get("rules")
    err = _check_payload(rules)
    if err:
        return {"ok": False, "output": err}
    files = max(1, min(int(payload.get("files", 30)), 300))
    container = _container()
    if not container:
        return {"ok": False, "output": "Suricata container is not running"}
    TESTFILE.write_text(rules)
    ok, out = _syntax_test(container, TESTFILE.name)
    if not ok:
        TESTFILE.unlink(missing_ok=True)
        return {"ok": False, "output": "Rule has syntax errors — fix before testing on traffic:\n\n" + out}
    script = (
        "set -e; rm -rf /tmp/rt; mkdir -p /tmp/rt/in /tmp/rt/log; "
        f"ls -t /traffic/*.pcap 2>/dev/null | head -n {files} | while read f; do "
        # copies, not symlinks: Suricata's pcap-directory mode skips symlinks
        "  [ -s \"$f\" ] && cp \"$f\" /tmp/rt/in/; done; "
        "n=$(ls /tmp/rt/in | wc -l); echo \"FILES=$n\"; [ \"$n\" -gt 0 ] || exit 0; "
        f"suricata -c /etc/suricata/suricata.yaml -S {IN_CONTAINER}/{TESTFILE.name} -r /tmp/rt/in "
        "-l /tmp/rt/log -k none --set unix-command.enabled=no >/tmp/rt/run.log 2>&1 || "
        "{ echo RUNFAIL; tail -20 /tmp/rt/run.log; exit 0; }; "
        "grep '\"event_type\":\"alert\"' /tmp/rt/log/eve.json 2>/dev/null || true"
    )
    code, out = run(["docker", "exec", container, "sh", "-c", script], timeout=280)
    TESTFILE.unlink(missing_ok=True)
    lines = out.splitlines()
    n_files = next((int(l.split("=", 1)[1]) for l in lines if l.startswith("FILES=")), 0)
    if "RUNFAIL" in lines:
        return {"ok": False, "output": "Suricata failed while replaying traffic:\n" + out}
    if n_files == 0:
        return {"ok": True, "files": 0, "total": 0, "by_sid": {}, "samples": [],
                "output": "No captured pcaps yet — nothing to test against."}
    by_sid, samples, flows = {}, [], set()
    for l in lines:
        if not l.startswith("{"):
            continue
        try:
            e = json.loads(l)
        except ValueError:
            continue
        a = e.get("alert", {})
        key = str(a.get("signature_id"))
        by_sid.setdefault(key, {"signature": a.get("signature"), "count": 0})
        by_sid[key]["count"] += 1
        flows.add((e.get("src_ip"), e.get("dest_ip"), e.get("dest_port")))
        if len(samples) < 40:
            samples.append({"ts": e.get("timestamp"), "src": f"{e.get('src_ip')}:{e.get('src_port')}",
                            "dst": f"{e.get('dest_ip')}:{e.get('dest_port')}", "sid": a.get("signature_id"),
                            "signature": a.get("signature")})
    total = sum(v["count"] for v in by_sid.values())
    sources = sorted({f[0] for f in flows if f[0]})
    return {"ok": True, "files": n_files, "total": total, "by_sid": by_sid, "samples": samples,
            "distinct_sources": sources[:50],
            "output": f"Replayed {n_files} most recent pcap file(s): {total} match(es) "
                      f"from {len(sources)} distinct source IP(s)."}
