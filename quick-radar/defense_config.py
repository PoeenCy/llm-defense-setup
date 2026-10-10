#!/usr/bin/env python3
"""Read defense dotenv as data, never execute config.env as shell code."""
import argparse
import ipaddress
import os
from pathlib import Path
import re
import shlex
import sys

DEFAULTS = {
    'VULNBOX_IP': '10.13.2.10', 'SSH_PORT': '2201', 'SSH_USER': 'root',
    'SSH_KEY': '~/.ssh/cyberknight_id', 'SSH_HOST_KEY_CHECKING': 'yes',
    'SSH_KNOWN_HOSTS': '~/.ssh/known_hosts', 'SSH_LOG_USER': '',
    'SERVICE_PORTS': '80 8080 3000 8000', 'MY_TEAM_ID': '1', 'TOTAL_TEAMS': '20',
    'CHECKER_IPS': '10.13.1.10', 'TEAM_IP_MAP': '',
    'RADAR_ALLOWED_HOSTS': 'localhost 127.0.0.1 ::1', 'RADAR_HOST': '127.0.0.1', 'RADAR_PORT': '8888', 'RADAR_TOKEN': '',
    'OLLAMA_URL': 'http://127.0.0.1:11434/api/generate',
    'OLLAMA_MODEL': 'foundation-sec-8b-chat:latest', 'AI_TIMEOUT': '120',
    'NGINX_ACCESS_LOG': '/var/log/nginx/access.log',
    'PCAP_DIR': '/var/lib/gd1/pcaps', 'PCAP_MAX_MB': '25', 'PCAP_FILES': '16', 'PCAP_LOCAL_FILES': '64',
    'LOCAL_PCAP_DIR': './runtime/pcaps', 'PCAP_SYNC_INTERVAL': '10',
    'TARGET_IP_TEMPLATE': '', 'TARGET_PORT_TEMPLATE': '',
}


def read_env(path):
    result = {}
    path = Path(path).expanduser()
    if not path.exists():
        return result
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        key = key.strip()
        if not sep or not re.fullmatch(r'[A-Z][A-Z0-9_]*', key):
            raise ValueError(f'{path}:{number}: expected KEY=value')
        parts = shlex.split(value, comments=True, posix=True)
        if len(parts) > 1:
            raise ValueError(f'{path}:{number}: quote values containing spaces')
        result[key] = parts[0] if parts else ''
    return result


def load_config(path=None):
    cfg = dict(DEFAULTS)
    if path:
        cfg.update(read_env(path))
    if path and 'CHECKER_IP' in cfg and 'CHECKER_IPS' not in read_env(path):
        cfg['CHECKER_IPS'] = cfg['CHECKER_IP']
    cfg.update({k: os.environ[k] for k in DEFAULTS if k in os.environ})
    ipaddress.ip_address(cfg['VULNBOX_IP'])
    for key in ('SSH_PORT', 'RADAR_PORT'):
        if not cfg[key].isdigit() or not 1 <= int(cfg[key]) <= 65535:
            raise ValueError(f'{key}: invalid port')
    for key in ('SERVICE_PORTS',):
        if not cfg[key].split() or any(not p.isdigit() or not 1 <= int(p) <= 65535 for p in cfg[key].split()):
            raise ValueError(f'{key}: invalid ports')
    for key in ('MY_TEAM_ID', 'TOTAL_TEAMS', 'AI_TIMEOUT', 'PCAP_MAX_MB', 'PCAP_FILES', 'PCAP_LOCAL_FILES', 'PCAP_SYNC_INTERVAL'):
        if not cfg[key].isdigit() or int(cfg[key]) < 1:
            raise ValueError(f'{key}: must be positive')
    if int(cfg['MY_TEAM_ID']) > int(cfg['TOTAL_TEAMS']):
        raise ValueError('MY_TEAM_ID exceeds TOTAL_TEAMS')
    for ip in cfg['CHECKER_IPS'].split():
        ipaddress.ip_address(ip)
    for key in ('SSH_USER', 'SSH_LOG_USER'):
        if cfg[key] and not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_.-]*', cfg[key]):
            raise ValueError(f'{key}: invalid username')
    if cfg['SSH_HOST_KEY_CHECKING'] not in ('yes', 'accept-new'):
        raise ValueError('SSH_HOST_KEY_CHECKING: use yes or accept-new')
    if not re.fullmatch(r'/[a-zA-Z0-9_./-]+', cfg['NGINX_ACCESS_LOG']):
        raise ValueError('NGINX_ACCESS_LOG: expected absolute path without shell characters')
    for key in ('SSH_KEY', 'SSH_KNOWN_HOSTS'):
        cfg[key] = os.path.expanduser(cfg[key])
    return cfg


def ssh_args(cfg, *, logs=False):
    args = ['ssh', '-F', '/dev/null', '-p', cfg['SSH_PORT'],
            '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
            '-o', f"StrictHostKeyChecking={cfg['SSH_HOST_KEY_CHECKING']}",
            '-o', f"UserKnownHostsFile={cfg['SSH_KNOWN_HOSTS']}",
            '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes']
    if cfg['SSH_KEY']:
        args += ['-i', cfg['SSH_KEY'], '-o', 'IdentitiesOnly=yes']
    user = (cfg['SSH_LOG_USER'] or cfg['SSH_USER']) if logs else cfg['SSH_USER']
    return args + [f"{user}@{cfg['VULNBOX_IP']}"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--shell', action='store_true')
    args = parser.parse_args()
    cfg = load_config(args.config)
    if args.shell:
        for key in DEFAULTS:
            print(f'export {key}={shlex.quote(cfg[key])}')
    else:
        print('Defense configuration valid (no network requests).')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
