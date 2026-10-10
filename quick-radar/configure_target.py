#!/usr/bin/env python3
"""Update defense config without shell interpolation or automatic target generation."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
from defense_config import DEFAULTS, load_config, read_env, ssh_args


def write_env(path, cfg):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.gd1-config-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write('# Configuration values are data; keep secrets off Git.\n')
            for key, value in cfg.items():
                handle.write(f'{key}={shlex.quote(str(value))}\n')
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)


def main():
    root = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('ip', nargs='?')
    p.add_argument('port', nargs='?')
    p.add_argument('key', nargs='?')
    p.add_argument('ports', nargs='?')
    p.add_argument('team', nargs='?')
    p.add_argument('--config', type=Path, default=root / 'config.env')
    p.add_argument('--check-ssh', action='store_true', help='explicitly test configured host after saving')
    a = p.parse_args()
    cfg = dict(DEFAULTS)
    cfg.update(read_env(a.config))
    if a.ip:
        for key, value in [('VULNBOX_IP',a.ip),('SSH_PORT',a.port),('SSH_KEY',a.key),('SERVICE_PORTS',a.ports),('MY_TEAM_ID',a.team)]:
            if value is not None:
                cfg[key] = value
    else:
        for key in ('VULNBOX_IP','SSH_PORT','SSH_USER','SSH_KEY','SERVICE_PORTS','MY_TEAM_ID','CHECKER_IPS'):
            cfg[key] = input(f'{key} [{cfg[key]}]: ').strip() or cfg[key]
    a.config.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.gd1-config-', dir=a.config.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write('# Defense config: values are read as data. Keep secrets off Git.\n')
            for key, value in cfg.items():
                handle.write(f'{key}={shlex.quote(str(value))}\n')
        validated = load_config(temp)
        os.replace(temp, a.config)
    finally:
        Path(temp).unlink(missing_ok=True)
    if a.config.resolve() == (root / 'config.env').resolve():
        # Synchronize own-team identity only. Preserve practiced ATK adapters,
        # secrets and opponent addressing instead of guessing a new target list.
        attack_path = root / 'ATK/config.env'
        attack_cfg = read_env(attack_path)
        for key in ('VULNBOX_IP', 'MY_TEAM_ID', 'TOTAL_TEAMS', 'SERVICE_PORTS'):
            attack_cfg[key] = cfg[key]
        write_env(attack_path, attack_cfg)
    print(f'Updated {a.config}; no opponent targets generated.')
    if a.check_ssh:
        return subprocess.run(ssh_args(validated) + ['true'], check=False).returncode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
