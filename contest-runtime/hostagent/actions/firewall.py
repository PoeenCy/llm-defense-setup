"""Fallback blocking: drop an attacker's IP with iptables on the vulnbox HOST.

This is the degraded block mode for when ctf_proxy is NOT in the traffic path.
Suricata only alerts (it reads a copy of the traffic on the monitor machine, so
by the time it sees an exploit it already reached the service). The only way to
actually stop traffic without ctf_proxy is at the vulnbox's own firewall, and
only per source IP — coarse, but it works.

The vulnbox sees the real attacker IP on its external interface (same place
tcpdump captures, pre-NAT), so IP blocking is meaningful here (unlike inside a
rootless-podman container, where every connection looks like the netns gateway).

DANGER: blocking the scoring checker's IP = SLA loss. The dashboard asks for an
explicit IP and confirms; nothing here is automatic. All our drops live in a
dedicated CTFBLOCK chain so we can list/flush only our own rules.
"""
import ipaddress

from ..common import audit, cfg, ssh

CHAIN = "CTFBLOCK"


def _alias():
    return (cfg().get("vulnbox") or {}).get("capture_ssh_alias") or ""


def _valid_ip(v: str):
    try:
        return str(ipaddress.ip_address(v.strip()))
    except ValueError:
        return None


def _ensure_chain(alias: str):
    # Create our chain and hook it at the top of INPUT, both idempotent.
    ssh(alias, f"sudo -n iptables -N {CHAIN} 2>/dev/null; "
               f"sudo -n iptables -C INPUT -j {CHAIN} 2>/dev/null || sudo -n iptables -I INPUT 1 -j {CHAIN}",
        timeout=20)


def list_blocks(payload, rdb):
    alias = _alias()
    if not alias:
        return {"ok": False, "output": "vulnbox.capture_ssh_alias not set"}
    code, out = ssh(alias, f"sudo -n iptables -S {CHAIN} 2>/dev/null", timeout=20)
    if code == 255 or code < 0:
        return {"ok": False, "output": "vulnbox unreachable over SSH"}
    ips = []
    for line in out.splitlines():
        parts = line.split()
        if parts[:2] == ["-A", CHAIN] and "-s" in parts:
            ips.append(parts[parts.index("-s") + 1].split("/")[0])
    return {"ok": True, "chain": CHAIN, "blocked": ips,
            "note": "empty / chain missing is normal if nothing has been blocked yet"}


def block_ip(payload, rdb):
    alias = _alias()
    if not alias:
        return {"ok": False, "output": "vulnbox.capture_ssh_alias not set"}
    ip = _valid_ip(str(payload.get("ip", "")))
    if not ip:
        return {"ok": False, "output": "not a valid IP address"}
    gw = (cfg().get("gameserver_hint") or {}).get("ip")
    if ip == gw:
        return {"ok": False, "output": f"{ip} is the gameserver/checker — refusing (would lose SLA)"}
    _ensure_chain(alias)
    code, out = ssh(alias,
                    f"sudo -n iptables -C {CHAIN} -s {ip} -j DROP 2>/dev/null "
                    f"|| sudo -n iptables -A {CHAIN} -s {ip} -j DROP",
                    timeout=20)
    ok = code == 0
    audit(rdb, f"firewall: blocked {ip} on vulnbox ({'ok' if ok else out[:200]})", ok, kind="firewall")
    return {"ok": ok, "output": f"blocked {ip}" if ok else (out or "iptables failed (needs passwordless sudo on the vulnbox)")}


def unblock_ip(payload, rdb):
    alias = _alias()
    if not alias:
        return {"ok": False, "output": "vulnbox.capture_ssh_alias not set"}
    ip = _valid_ip(str(payload.get("ip", "")))
    if not ip:
        return {"ok": False, "output": "not a valid IP address"}
    code, out = ssh(alias, f"sudo -n iptables -D {CHAIN} -s {ip} -j DROP 2>/dev/null; echo DONE", timeout=20)
    ok = code == 0
    audit(rdb, f"firewall: unblocked {ip} on vulnbox", ok, kind="firewall")
    return {"ok": ok, "output": f"unblocked {ip}" if ok else out}
