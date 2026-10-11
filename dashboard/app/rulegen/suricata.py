"""Build a Suricata rule from a structured description (the Rule Builder form).

Pure functions, no I/O — see tests/test_rulegen.py. The output is still
validated by `suricata -T` (host_agent) before it can reach the live ruleset;
this module's job is to make the common cases impossible to get wrong by hand
(content escaping, sticky-buffer/direction mismatches, sid collisions).
"""
import re

SID_BASE = 9100000
SID_MAX = 9199999

REQUEST_BUFFERS = {
    "http.uri", "http.uri.raw", "http.method", "http.request_body", "http.header",
    "http.cookie", "http.user_agent", "http.host", "http.request_line",
}
RESPONSE_BUFFERS = {"http.response_body", "http.stat_code", "http.response_line"}
HTTP_BUFFERS = REQUEST_BUFFERS | RESPONSE_BUFFERS
RAW_BUFFER = "payload"


def escape_content(value: str) -> str:
    """Suricata content string: printable ASCII stays literal, everything with
    special meaning (" ; \\ |) or non-printable becomes |hex| bytes."""
    out, hex_run = [], []
    for b in value.encode("utf-8"):
        literal = 0x20 <= b <= 0x7E and chr(b) not in '";\\|'
        if literal:
            if hex_run:
                out.append("|" + " ".join(hex_run) + "|")
                hex_run = []
            out.append(chr(b))
        else:
            hex_run.append(f"{b:02X}")
    if hex_run:
        out.append("|" + " ".join(hex_run) + "|")
    return "".join(out)


def escape_msg(msg: str) -> str:
    return msg.replace("\\", "\\\\").replace('"', '\\"').replace(";", "\\;")


def escape_pcre(pattern: str) -> str:
    return pattern.replace("/", "\\/").replace('"', '\\"').replace(";", "\\;")


def next_sid(existing_rules: str) -> int:
    used = [int(m) for m in re.findall(r"\bsid\s*:\s*(\d+)", existing_rules or "")]
    ours = [s for s in used if SID_BASE <= s <= SID_MAX]
    return (max(ours) + 1) if ours else SID_BASE


def build_rule(spec: dict, existing_rules: str = "") -> dict:
    """spec keys: msg, proto(http|tcp|udp), direction(to_server|to_client),
    port(int|None), src_ip(str|None), matches[{buffer, value, mode(contains|regex),
    nocase, negate}], sid(optional). Returns {rule, sid, warnings, errors}."""
    errors, warnings = [], []
    proto = spec.get("proto", "http")
    direction = spec.get("direction", "to_server")
    if proto not in ("http", "tcp", "udp"):
        errors.append(f"unsupported proto {proto!r}")
    if direction not in ("to_server", "to_client"):
        errors.append(f"unsupported direction {direction!r}")

    msg = (spec.get("msg") or "").strip() or "CUSTOM rule"
    port = spec.get("port")
    port_s = str(int(port)) if port not in (None, "", "any") else "any"
    src_ip = (spec.get("src_ip") or "").strip() or "any"
    if src_ip != "any" and not re.fullmatch(r"[0-9a-fA-F:.\/\[\],!]+", src_ip):
        errors.append(f"src_ip {src_ip!r} is not an IP/CIDR")

    if direction == "to_server":
        header = f"{proto} {src_ip} any -> any {port_s}"
    else:
        header = f"{proto} any {port_s} -> {src_ip} any"

    opts = [f'msg:"{escape_msg(msg)}"', f"flow:established,{direction}"]
    matches = spec.get("matches") or []
    if not matches:
        errors.append("at least one match condition is required")
    for i, m in enumerate(matches, 1):
        buf = m.get("buffer") or (RAW_BUFFER if proto != "http" else "http.uri")
        value = m.get("value") or ""
        mode = m.get("mode", "contains")
        if not value:
            errors.append(f"match #{i}: empty value")
            continue
        if buf != RAW_BUFFER and buf not in HTTP_BUFFERS:
            errors.append(f"match #{i}: unknown buffer {buf!r}")
            continue
        if buf in HTTP_BUFFERS and proto != "http":
            errors.append(f"match #{i}: {buf} needs proto http")
        if buf in REQUEST_BUFFERS and direction == "to_client":
            errors.append(f"match #{i}: {buf} is a request buffer but direction is to_client (server responses)")
        if buf in RESPONSE_BUFFERS and direction == "to_server":
            errors.append(f"match #{i}: {buf} is a response buffer but direction is to_server (client requests)")
        if buf != RAW_BUFFER:
            opts.append(buf)
        neg = "!" if m.get("negate") else ""
        if mode == "regex":
            try:
                re.compile(value)
            except re.error as e:
                errors.append(f"match #{i}: invalid regex: {e}")
            flags = "i" if m.get("nocase") else ""
            opts.append(f'pcre:{neg}"/{escape_pcre(value)}/{flags}"')
        elif m.get("hex"):
            hexstr = re.sub(r"[^0-9a-fA-F]", "", value)
            if not hexstr or len(hexstr) % 2:
                errors.append(f"match #{i}: hex value must be an even number of hex digits")
                continue
            spaced = " ".join(hexstr[j:j + 2].upper() for j in range(0, len(hexstr), 2))
            opts.append(f'content:{neg}"|{spaced}|"')
        else:
            opts.append(f'content:{neg}"{escape_content(value)}"')
            if m.get("nocase"):
                opts.append("nocase")
            if len(value.encode()) < 4 and not neg:
                warnings.append(f"match #{i}: very short content ({value!r}) — expect many false positives, incl. the checker bot")

    sid = spec.get("sid") or next_sid(existing_rules)
    try:
        sid = int(sid)
    except (TypeError, ValueError):
        errors.append(f"sid {sid!r} is not a number")
        sid = next_sid(existing_rules)
    if re.search(rf"\bsid\s*:\s*{sid}\s*;", existing_rules or ""):
        errors.append(f"sid {sid} already exists in the current ruleset")
    opts += [f"sid:{sid}", "rev:1"]

    if all(m.get("negate") for m in matches if m.get("value")):
        warnings.append("every condition is negated — this will match almost all traffic")

    rule = f"alert {header} (" + "; ".join(opts) + ";)"
    return {"rule": rule, "sid": sid, "warnings": warnings, "errors": errors}
