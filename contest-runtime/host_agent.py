#!/usr/bin/env python3
"""
host_agent.py — the one long-running process on the HOST (not in a container).

  1. Pushes System Status (health_check.py) to Redis every 15s.
  2. Executes the whitelisted actions the dashboard requests (hostagent/actions/):
     Suricata test/apply/rollback/replay, ctf_proxy filter get/apply/rollback/
     pause/resume/uninstall, service start/stop/restart, config validate/apply.
     The dashboard container has no docker socket and no SSH keys on purpose.

Run:  python3 host_agent.py      (deploy-all.sh starts it in the background,
                                  log in .host-agent.log)
Code: hostagent/  — agent.py (loops), registry.py (what may be controlled),
                    actions/*.py (one file per area).
"""
from hostagent.agent import main

if __name__ == "__main__":
    main()
