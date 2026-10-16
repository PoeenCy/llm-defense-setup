#!/usr/bin/env python3
"""Session-owned tcpdump + closed-file shipping, one independent session per
vulnbox host (contest-runtime/config/services.json's vulnboxes[]). No age
heuristic or broad kill.

Multi-host: a host is only captured if its own services[] is non-empty --
an entry with no services configured yet is skipped (nothing to filter
for), not an error. Each host's remote session is fully independent: one
host's SSH being down, disk-full, or otherwise degraded never stops the
others from being pulled. All hosts ship into the SAME local traffic/
directory; filenames are already prefixed by a per-session uuid (unique
per host's session, never reused), so nothing from two hosts can collide.
"""
import argparse
import fcntl
import hashlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
STATE = HERE / ".capture-session.json"
PID = HERE / ".capture-pull.pid"
LOG = HERE / ".capture-pull.log"


def ssh(alias, command, *, data=None, timeout=20):
    return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "--", alias, command],
                          input=data, capture_output=True, check=True, timeout=timeout).stdout


def atomic_json(path, value):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as f:
        json.dump(value, f)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load_states() -> dict:
    """{host_name: {session, alias, remote_dir}, ...}. Also accepts the old
    single-session shape (pre-multi-host) so an upgrade doesn't orphan a
    session still running on a vulnbox -- treated as one host named "_legacy"."""
    if not STATE.exists():
        return {}
    raw = json.loads(STATE.read_text())
    if "session" in raw and "alias" in raw:  # old single-host shape
        return {"_legacy": raw}
    return raw


def save_states(states: dict):
    atomic_json(STATE, states)


def remote_status(state):
    d = shlex.quote(state["remote_dir"])
    return ssh(state["alias"], f"if test -f {d}/stopped; then echo STOPPED; elif test -f {d}/runner.pid && sudo -n kill -0 $(cat {d}/runner.pid) 2>/dev/null; then echo RUNNING; else echo STOPPED; fi").decode().strip()


def stop_remote(state):
    d = shlex.quote(state["remote_dir"])
    # PID is accepted only if the process command still contains this session.
    cmd = f"if test -f {d}/runner.pid; then p=$(cat {d}/runner.pid); case \"$(ps -p \"$p\" -o args=)\" in *{d}*) sudo -n kill -TERM \"$p\" ;; esac; fi"
    ssh(state["alias"], cmd)
    for _ in range(15):
        if remote_status(state) == "STOPPED":
            return
        time.sleep(1)
    raise RuntimeError("owned capture did not stop; session files kept")


def publish_file(staging, dest, metadata):
    """Durable publication; ready marker is the final visibility boundary."""
    with staging.open("rb") as f:
        os.fsync(f.fileno())
        sha = hashlib.file_digest(f, "sha256").hexdigest()
    if dest.exists():
        with dest.open("rb") as f:
            if hashlib.file_digest(f, "sha256").hexdigest() != sha:
                raise ValueError("capture filename collision")
        staging.unlink()
    else:
        staging.replace(dest)
    atomic_json(dest.with_suffix(dest.suffix + ".ready"), {**metadata, "sha256": sha})


def pull_once(state, cfg):
    traffic = ROOT / "traffic"
    staging = traffic / ".incoming"
    staging.mkdir(parents=True, exist_ok=True)
    keep_free = float(cfg.get("retention", {}).get("min_free_gb", 1)) * 1024**3
    if shutil.disk_usage(traffic).free < keep_free:
        raise RuntimeError("monitor disk below retention.min_free_gb; shipping paused")
    d = shlex.quote(state["remote_dir"])
    # Only files in done/ have been closed. Callback order is bounded by
    # excluding everything newer than the oldest still-open file.
    listing = ssh(state["alias"], f"find {d}/done -maxdepth 1 -name '*.pcap' -printf '%f\\n'; echo --OPEN--; find {d}/open -maxdepth 1 -name '*.pcap' -printf '%f\\n'").decode()
    done, _, opened = listing.partition("--OPEN--\n")
    oldest_open = min(opened.splitlines(), default="~")
    for name in sorted(done.splitlines()):
        if not name.startswith("cap_") or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_." for c in name):
            raise ValueError("unexpected capture filename")
        if name >= oldest_open:
            continue
        dest = traffic / (state["session"] + "_" + name)
        temp = staging / (dest.name + ".part")
        with temp.open("wb") as f:
            cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "--", state["alias"],
                   "cat -- " + shlex.quote(state["remote_dir"] + "/done/" + name)]
            subprocess.run(cmd, stdout=f, check=True, timeout=120)
        publish_file(temp, dest, {"session": state["session"], "host": state.get("host", "?"),
                                   "source": cfg.get("flagtrace", {}).get("capture_source", "vulnbox")})
        # done/ is created by runner.sh under sudo, so it's root-owned; a
        # plain rm from this unprivileged ssh user can't unlink inside it
        # (confirmed live: every pull left the remote file behind forever).
        ssh(state["alias"], "sudo -n rm -- " + shlex.quote(state["remote_dir"] + "/done/" + name))


def start_host(cfg, vb, previous=None):
    """Start (or resume, if already running) one host's capture session.
    Raises on failure -- caller decides whether that stops just this host
    or the whole run."""
    if previous:
        if remote_status(previous) == "RUNNING":
            return previous
        pull_once(previous, cfg)  # drain closed final files before a new session
    alias = vb["capture_ssh_alias"]
    ssh(alias, "sudo -n true")
    iface = vb.get("docker_bridge") or vb.get("capture_iface", "auto")
    if iface == "auto":
        iface = ssh(alias, "ip route show default | awk '/default/ {print $5; exit}'").decode().strip()
    if not iface:
        raise ValueError(f"[{vb['name']}] capture interface could not be determined")
    opts = cfg.get("capture", {})
    rotation = int(opts.get("rotate_seconds", 30))
    max_kb = int(opts.get("remote_max_mb", 512)) * 1024
    if rotation < 1 or max_kb < 1024:
        raise ValueError("invalid capture limits")
    ports = sorted({int(s.get("capture_port", s["port"])) for s in vb.get("services", [])})
    if not ports or any(p < 1 or p > 65535 for p in ports):
        raise ValueError(f"[{vb['name']}] invalid or empty capture ports")
    bpf = " or ".join(f"port {p}" for p in ports)
    session = uuid.uuid4().hex
    directory = "/tmp/ctf-capture-" + session
    ssh(alias, "mkdir -p " + shlex.quote(directory))
    ssh(alias, "cat > " + shlex.quote(directory + "/runner.sh"), data=(HERE / "capture-remote.sh").read_bytes())
    args = [directory, iface, str(rotation), str(max_kb), bpf]
    command = "nohup sudo -n bash " + shlex.quote(directory + "/runner.sh") + " " + shlex.join(args)
    command += " </dev/null >" + shlex.quote(directory + "/capture.log") + " 2>&1 &"
    ssh(alias, command)
    state = {"session": session, "alias": alias, "remote_dir": directory, "host": vb["name"]}
    time.sleep(1)
    if remote_status(state) != "RUNNING":
        raise RuntimeError(f"[{vb['name']}] capture failed to start; inspect {directory}/capture.log")
    return state


def start_all(cfg) -> dict:
    """Best-effort across every host with services configured: one host
    failing to start (bad SSH, no services yet, etc.) is logged and does
    NOT stop the others."""
    previous = load_states()
    states = {}
    for vb in cfg["vulnboxes"]:
        if not vb.get("services"):
            continue  # nothing to filter for yet -- not an error
        name = vb["name"]
        try:
            states[name] = start_host(cfg, vb, previous.get(name))
        except Exception as exc:
            print(f"[{name}] capture start failed: {exc!r}", flush=True)
    save_states(states)
    return states


def loop(cfg):
    # flock is held for the whole loop; repeated deploys do not spawn another
    # owner or another remote tcpdump session.
    with (HERE / ".capture-pull.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Capture loop already running", flush=True)
            return
        states = start_all(cfg)
        PID.write_text(str(os.getpid()))
        stopping = False
        def signal_stop(*_):
            nonlocal stopping
            stopping = True
        signal.signal(signal.SIGTERM, signal_stop)
        signal.signal(signal.SIGINT, signal_stop)
        try:
            while not stopping and states:
                for name in list(states):
                    state = states[name]
                    try:
                        pull_once(state, cfg)
                        if remote_status(state) == "STOPPED":
                            pull_once(state, cfg)
                            print(f"[{name}] capture stopped remotely (quota or exit); files preserved", flush=True)
                            del states[name]
                            save_states(states)
                    except Exception as exc:
                        print(f"[{name}] capture pull degraded: {exc!r}", flush=True)
                for _ in range(int(cfg.get("capture", {}).get("pull_seconds", 5))):
                    if stopping:
                        break
                    time.sleep(1)
        finally:
            for name, state in states.items():
                try:
                    stop_remote(state)
                    pull_once(state, cfg)
                except Exception as exc:
                    print(f"[{name}] shutdown drain failed: {exc!r}", flush=True)
            PID.unlink(missing_ok=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--background", action="store_true")
    p.add_argument("--stop", action="store_true")
    p.add_argument("--status", action="store_true")
    args = p.parse_args()
    cfg = json.loads((HERE.parent / "config/services.json").read_text())
    if args.status:
        states = load_states()
        if not states:
            print("STOPPED")
        for name, state in states.items():
            print(f"{name}: {remote_status(state)}")
    elif args.stop:
        if PID.exists():
            pid = int(PID.read_text())
            cmdline = Path(f"/proc/{pid}/cmdline")
            if cmdline.exists() and str(Path(__file__).resolve()).encode() in cmdline.read_bytes():
                os.kill(pid, signal.SIGTERM)
                for _ in range(25):
                    if not PID.exists():
                        return
                    time.sleep(1)
        states = load_states()
        for name, state in states.items():
            try:
                stop_remote(state)
                pull_once(state, cfg)
            except Exception as exc:
                print(f"[{name}] stop failed: {exc!r}", flush=True)
    elif args.background:
        if PID.exists():
            try:
                os.kill(int(PID.read_text()), 0)
                print("Capture loop already running")
                return
            except (OSError, ValueError):
                pass
        with LOG.open("ab") as log:
            proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve())], stdout=log, stderr=log, start_new_session=True)
        for _ in range(25):
            if proc.poll() is not None:
                raise RuntimeError("capture loop exited; inspect " + str(LOG))
            if PID.exists():
                print(f"Capture running: pid {PID.read_text()}, log {LOG}")
                return
            time.sleep(1)
        raise RuntimeError("capture startup timed out; inspect " + str(LOG))
    else:
        loop(cfg)


if __name__ == "__main__":
    main()
