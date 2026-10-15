"""The ONLY things the dashboard may start/stop/restart, and how. Anything not
listed here cannot be touched from the UI, whatever a request says.

kind:
  container — local docker container, controlled with docker start/stop/restart
              (NOT `docker compose up`, which would recreate it; start/stop keep
              the container's existing configuration)
  capture   — the remote tcpdump + local pull loop pair
  ctfproxy  — the remote filtering proxy (pause/resume filtering, uninstall)
  oswatchdog — the OS integrity agent on the vulnbox host (vulnbox-deploy/deploy-os-watchdog.sh)
protected — shown with live status, but no buttons: stopping it would cut off
            the dashboard (or this agent) itself. Fix those from a terminal.
"""

SERVICES = [
    # id,                group,        label,                         kind,        target,                 protected, note
    ("tulip-web",        "Tulip",      "Tulip web UI",                "container", "tulip-frontend-1",     False, "Flow browser on :3000"),
    ("tulip-api",        "Tulip",      "Tulip API",                   "container", "tulip-api-1",          False, "Backs the Tulip UI and the Rules tab's 'load from flow'"),
    ("tulip-assembler",  "Tulip",      "Tulip assembler",             "container", "tulip-assembler-1",    False, "Turns pcaps into flows — stopped = no new flows"),
    ("tulip-enricher",   "Tulip",      "Tulip enricher",              "container", "tulip-enricher-1",     False, "Adds Suricata tags to flows"),
    ("tulip-flagids",    "Tulip",      "Tulip flagids",               "container", "tulip-flagids-1",      False, ""),
    ("tulip-db",         "Tulip",      "Tulip database (timescale)",  "container", "tulip-timescale-1",    False, "Stopping it stops all of Tulip"),
    ("suricata",         "Detection",  "Suricata IDS",                "container", "tulip-suricata-1",     False, "Signature engine; rules in the Rules tab"),
    ("detection",        "Detection",  "Flag-out / honeytoken detector", "container", "ctf-detection",     False, "Stopped = no flag-out alerts"),
    ("watchdog",         "Detection",  "SLA watchdog",                "container", "ctf-watchdog",         False, "Polls your service ports"),
    ("flagtrace",        "Detection",  "Flag-trace ingest",           "container", "ctf-flagtrace",        False, "Transactions, tokens and durable trace queue"),
    ("flagtrace-worker", "Detection",  "Flag-trace trace worker",     "container", "ctf-flagtrace-worker", False, "Builds trace profiles; stopped = flag-outs queue up, ingest keeps running"),
    ("ml",               "Detection",  "ML bot fingerprinter",        "container", "ctf-ml-fingerprint",   False, "Hints only"),
    ("capture",          "Capture",    "Traffic capture (remote tcpdump + pull)", "capture", None,         False, "Stopped = Tulip/Suricata get no new traffic"),
    ("os-watchdog",      "Capture",    "OS watchdog (agent on vulnbox host)", "oswatchdog", None,      False, "Reports new processes, cron, ssh keys, changed binaries"),
    ("ctfproxy",         "Blocking",   "ctf_proxy filtering",         "ctfproxy",  None,                   False, "Pause = rules off, traffic still flows"),
    ("dashboard",        "Core",       "Dashboard (this page)",       "container", "ctf-dashboard",        True,  "Restart from a terminal: docker restart ctf-dashboard"),
    ("redis",            "Core",       "Redis (event bus)",           "container", "ctf-redis",            True,  "Everything talks through it — restart from a terminal"),
]

FIELDS = ("id", "group", "label", "kind", "target", "protected", "note")


def all_services() -> list[dict]:
    return [dict(zip(FIELDS, row)) for row in SERVICES]


def get(svc_id: str) -> dict | None:
    return next((s for s in all_services() if s["id"] == svc_id), None)
