"""Fallback blocking: drop traffic with iptables on the vulnbox HOST, for when
ctf_proxy is NOT in the traffic path.

Suricata only alerts (it reads a copy of the traffic on the monitor machine, so
by the time it sees an exploit it already reached the service). Without
ctf_proxy inline, the only way to actually stop traffic is the vulnbox's own
firewall. Two modes, both opt-in and confirmed by the operator -- nothing here
is automatic:

  IP block (CHAIN)         -- drop everything from one source IP. Coarse, but
                               works, and the vulnbox sees the real attacker IP
                               on its external interface (pre-NAT) -- unlike
                               inside a rootless-podman container where every
                               connection looks like the netns gateway.
                               DANGER: if the organizer NATs the checker bot
                               through the same IP as an attacker (seen in
                               practice), this blocks the checker too = SLA
                               loss. The dashboard confirms explicitly, and the
                               scoring gameserver's own IP is refused outright.

  Content block (CONTENT_CHAIN) -- drop only TCP packets whose payload
                               contains a specific literal string, using
                               iptables' `string` match -- independent of
                               source IP, so it still works even when
                               attacker and checker share one. This mirrors
                               ctf_proxy's own rule philosophy (match request
                               CONTENT, never IP/User-Agent -- see
                               contest-runtime/defense/rules-library/README.md)
                               applied at the iptables layer instead. The
                               operator supplies the exact literal copied from
                               the real attack payload (same discipline as a
                               ctf_proxy/Suricata rule) -- never a broad guess
                               -- and should still validate narrowness via
                               "Test on recent traffic" (Suricata) first.
                               The pattern is sent hex-encoded so it is never
                               interpolated into the remote shell as raw text.
"""
import binascii
import ipaddress

from ..common import audit, cfg, ssh

CHAIN = "CTFBLOCK"
CONTENT_CHAIN = "CTFBLOCK_CONTENT"
MAX_PATTERN_LEN = 256


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


def _ensure_content_chain(alias: str):
    ssh(alias, f"sudo -n iptables -N {CONTENT_CHAIN} 2>/dev/null; "
               f"sudo -n iptables -C INPUT -j {CONTENT_CHAIN} 2>/dev/null || sudo -n iptables -I INPUT 1 -j {CONTENT_CHAIN}",
        timeout=20)


def _hex_pattern(pattern: str) -> tuple[str, str]:
    """Returns (hex, error). hex is lowercase [0-9a-f]+ only -- safe to put
    directly into a remote shell command, since the SSH layer never accepts
    raw payload text in the command itself (see ../common.py's ssh())."""
    pattern = pattern.strip()
    if not pattern:
        return "", "pattern required -- copy the exact literal from the attack payload, never a broad guess"
    if len(pattern) > MAX_PATTERN_LEN:
        return "", f"pattern too long (max {MAX_PATTERN_LEN} chars) -- narrow it to the specific malicious literal"
    try:
        hexstr = binascii.hexlify(pattern.encode("utf-8")).decode("ascii")
    except Exception as e:
        return "", f"could not encode pattern: {e}"
    return hexstr, ""


def _dport_clause(port) -> str:
    if not port:
        return ""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return ""
    if not (0 < port < 65536):
        return ""
    return f" -p tcp --dport {port}"


def list_content_blocks(payload, rdb):
    alias = _alias()
    if not alias:
        return {"ok": False, "output": "vulnbox.capture_ssh_alias not set"}
    code, out = ssh(alias, f"sudo -n iptables -S {CONTENT_CHAIN} 2>/dev/null", timeout=20)
    if code == 255 or code < 0:
        return {"ok": False, "output": "vulnbox unreachable over SSH"}
    rules = []
    for line in out.splitlines():
        if not line.startswith(f"-A {CONTENT_CHAIN}"):
            continue
        parts = line.split()
        # iptables' own -S/--list-rules output re-renders a --hex-string rule
        # using the --string flag name, but the value is still the hex digits
        # we originally supplied -- not re-decoded. Accept either flag name.
        flag = "--hex-string" if "--hex-string" in parts else ("--string" if "--string" in parts else None)
        hexstr = parts[parts.index(flag) + 1].strip('"') if flag else ""
        try:
            text = binascii.unhexlify(hexstr).decode("utf-8", errors="replace")
        except Exception:
            text = "<undecodable>"
        port = parts[parts.index("--dport") + 1] if "--dport" in parts else ""
        rules.append({"pattern": text, "port": port, "raw": line})
    return {"ok": True, "chain": CONTENT_CHAIN, "rules": rules,
            "note": "each rule drops any TCP packet whose payload contains this literal, regardless of source IP"}


def block_content(payload, rdb):
    """Drop TCP packets matching a literal payload substring -- works even
    when the attacker shares an IP with the checker bot (see module
    docstring). The pattern is hex-encoded before ever touching a shell."""
    alias = _alias()
    if not alias:
        return {"ok": False, "output": "vulnbox.capture_ssh_alias not set"}
    hexstr, err = _hex_pattern(str(payload.get("pattern", "")))
    if err:
        return {"ok": False, "output": err}
    dport = _dport_clause(payload.get("port"))
    _ensure_content_chain(alias)
    rule = f'{CONTENT_CHAIN}{dport} -m string --hex-string "{hexstr}" --algo bm -j DROP'
    code, out = ssh(alias,
                    f"sudo -n iptables -C {rule} 2>/dev/null || sudo -n iptables -A {rule}",
                    timeout=20)
    ok = code == 0
    pattern_preview = str(payload.get("pattern", ""))[:80]
    audit(rdb, f"firewall: content-blocked {pattern_preview!r} on vulnbox"
               f"{' (port ' + str(payload.get('port')) + ')' if payload.get('port') else ' (all TCP ports)'}"
               f" ({'ok' if ok else out[:200]})", ok, kind="firewall")
    return {"ok": ok, "output": f"blocked content {pattern_preview!r}" if ok
            else (out or "iptables failed (needs passwordless sudo on the vulnbox, and the `string` match module)")}


def unblock_content(payload, rdb):
    alias = _alias()
    if not alias:
        return {"ok": False, "output": "vulnbox.capture_ssh_alias not set"}
    hexstr, err = _hex_pattern(str(payload.get("pattern", "")))
    if err:
        return {"ok": False, "output": err}
    dport = _dport_clause(payload.get("port"))
    rule = f'{CONTENT_CHAIN}{dport} -m string --hex-string "{hexstr}" --algo bm -j DROP'
    code, out = ssh(alias, f"sudo -n iptables -D {rule} 2>/dev/null; echo DONE", timeout=20)
    ok = code == 0
    audit(rdb, f"firewall: content-unblocked {str(payload.get('pattern', ''))[:80]!r} on vulnbox", ok, kind="firewall")
    return {"ok": ok, "output": "unblocked" if ok else out}
