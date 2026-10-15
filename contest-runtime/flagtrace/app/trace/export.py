"""P2.5 immutable Python artifacts built from the evidence of one trace run.

The exporter starts from the captured HTTP/1 request bytes.  A single-request
artifact therefore sends those bytes verbatim.  A chain changes only byte
ranges that have an unambiguous value role, then repairs Content-Length.  This
keeps duplicate fields/headers, multipart boundaries, binary bodies and the
captured encoding instead of silently normalising them through a high-level
HTTP client.

Generation is pure: no network calls and no writes.  The worker persists the
returned artifacts in the same commit as the run.  Raw TCP deliberately stays
unsupported until Phase 1 records reliable send/receive turn byte spans.
"""
import base64
import hashlib
import json
import keyword
import re
from urllib.parse import quote, quote_plus, unquote, unquote_plus

from . import contracts

EXPORTER_VERSION = "p2.5.2"
MAX_REQUEST_ARTIFACT = 2 * 1024 * 1024
MAX_CHAIN_ARTIFACT = 8 * 1024 * 1024


RUNTIME = r'''import argparse
import base64
import gzip
import http.client
import json
import random
import re
import socket
import string
import urllib.parse
import zlib


def _patch(raw, patches):
    for start, end, expected, replacement in sorted(patches, reverse=True):
        if raw[start:end] != expected:
            raise RuntimeError("captured request no longer matches patch plan")
        raw = raw[:start] + replacement + raw[end:]
    if patches:
        head, sep, body = raw.partition(b"\r\n\r\n")
        if sep:
            line = b"Content-Length: " + str(len(body)).encode()
            head, n = re.subn(br"(?im)^Content-Length\s*:\s*\d+\s*$", line, head, count=1)
            if not n and body:
                head += b"\r\n" + line
            raw = head + sep + body
    return raw


def _send(host, port, raw, timeout=10):
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.sendall(raw)
        response = http.client.HTTPResponse(sock)
        response.begin()
        body = response.read()
        return response.status, list(response.getheaders()), body
    finally:
        sock.close()


def _header(headers, name, occurrence=0):
    values = [v for k, v in headers if k.lower() == name.lower()]
    if occurrence >= len(values):
        _missing("header %r" % name, "the response sent %d of them" % len(values), b"")
    return values[occurrence]


def _cookie(headers, name, occurrence=0):
    values = []
    for key, value in headers:
        if key.lower() != "set-cookie":
            continue
        first = value.split(";", 1)[0]
        key, sep, val = first.partition("=")
        if sep and key.strip() == name:
            values.append(val.strip())
    if occurrence >= len(values):
        _missing("cookie %r" % name, "the response set %d of them" % len(values), b"")
    return values[occurrence]


def _pairs(pairs):
    return {"__pairs__": pairs}


def _missing(what, found, body):
    """A value this step needs is not in the response.

    Nearly always the step before failed (an account that already exists, an
    expired token, a changed service), so name what did come back instead of
    only printing the path that was looked for.
    """
    seen = body[:300].decode("utf-8", "replace") if body else ""
    raise ValueError("no %s in this response: %s. The step meant to produce it probably failed.%s"
                     % (what, found, (" Response began: " + repr(seen)) if seen else ""))


def _json_at(body, path):
    node = json.loads(body.decode("utf-8"), object_pairs_hook=_pairs)
    i = 0
    while i < len(path):
        if isinstance(node, dict) and "__pairs__" in node:
            key, occurrence = path[i], path[i + 1]
            matches = [v for k, v in node["__pairs__"] if k == key]
            if occurrence >= len(matches):
                _missing("%r (at %r)" % (path, path[:i]),
                         "this object has %r" % ([k for k, _ in node["__pairs__"]][:12],), body)
            node, i = matches[occurrence], i + 2
        elif isinstance(node, list):
            if not isinstance(path[i], int) or path[i] >= len(node):
                _missing("%r (at %r)" % (path, path[:i]), "the list here has %d item(s)" % len(node), body)
            node, i = node[path[i]], i + 1
        else:
            _missing("%r (at %r)" % (path, path[:i]),
                     "found %s there, which is neither an object nor a list" % json.dumps(node)[:60], body)
    return str(node)


def _between(body, before, after):
    start = body.find(before) + len(before) if before else 0
    if start < (len(before) if before else 0):
        raise ValueError("response context before value not found")
    end = body.find(after, start) if after else len(body)
    if end < 0:
        raise ValueError("response context after value not found")
    return body[start:end].decode("latin-1")


def _decode(headers, body):
    encodings = [x.strip().lower() for x in _header(headers, "content-encoding", 0).split(",")] \
        if any(k.lower() == "content-encoding" for k, _ in headers) else []
    for encoding in reversed(encodings):
        if encoding == "gzip":
            body = gzip.decompress(body)
        elif encoding == "deflate":
            try:
                body = zlib.decompress(body)
            except zlib.error:
                body = zlib.decompress(body, -15)
        elif encoding not in ("", "identity"):
            raise RuntimeError("unsupported response content-encoding: " + encoding)
    # Some services send a raw DEFLATE body without Content-Encoding. Phase 1
    # records this as a decoded representation, so mirror that evidence when
    # replaying instead of scanning compressed bytes for the flag regex.
    if not encodings:
        for wbits in (-15, 15):
            try:
                decoded = zlib.decompress(body, wbits)
            except zlib.error:
                continue
            if decoded and decoded != body:
                body = decoded
                break
    return body


def _rnd(length, alphabet):
    return "".join(random.SystemRandom().choice(alphabet) for _ in range(length))
'''


def _b64(data):
    return base64.b64encode(data).decode()


def _artifact(kind, transaction_id, position, filename, support, warnings, content):
    raw = content.encode()
    cap = MAX_CHAIN_ARTIFACT if kind == "chain" else MAX_REQUEST_ARTIFACT
    if len(raw) > cap:
        support = contracts.SCRIPT_UNSUPPORTED
        warnings = [*warnings, f"artifact exceeds the {cap}-byte safety limit"]
        content = "# Unsupported: generated artifact exceeded its safety limit.\n"
        raw = content.encode()
    return {"kind": kind, "transaction_id": transaction_id, "position": position,
            "format": "python", "filename": filename, "exporter_version": EXPORTER_VERSION,
            "content_hash": hashlib.sha256(raw).hexdigest(), "support": support,
            "warnings": sorted(set(warnings)), "content": raw}


def _unsupported(kind, tx, position, filename, reason):
    return _artifact(kind, tx, position, filename, contracts.SCRIPT_UNSUPPORTED, [reason],
                     "# Unsupported by Flag-trace exporter " + EXPORTER_VERSION + ": " + reason + "\n")


def _request_script(raw, port, label):
    return """#!/usr/bin/env python3
# Flag-trace {version} · captured request {label}
{runtime}

RAW = base64.b64decode({raw!r})

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    status, headers, body = _send(args.host, args.port or {port}, RAW)
    print("HTTP", status)
    for key, value in headers:
        print(f"{{key}}: {{value}}")
    print()
    try:
        print(_decode(headers, body).decode("utf-8", "replace"))
    except Exception:
        print(base64.b64encode(body).decode())
""".format(version=EXPORTER_VERSION, label=label, runtime=RUNTIME, raw=_b64(raw), port=port)


def _split_raw(raw):
    head, sep, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    return head, sep, body, lines


def _request_target_bounds(raw):
    first = raw.split(b"\r\n", 1)[0]
    left = first.find(b" ") + 1
    right = first.find(b" ", left)
    return left, right, first[left:right]


def _pair_span(data, base, name, occurrence):
    seen = 0
    cursor = 0
    for part in data.split(b"&"):
        eq = part.find(b"=")
        raw_name = part if eq < 0 else part[:eq]
        try:
            decoded = unquote_plus(raw_name.decode("ascii"))
        except (UnicodeError, ValueError):
            decoded = raw_name.decode("latin-1")
        if decoded == str(name):
            if seen == occurrence:
                start = cursor + (eq + 1 if eq >= 0 else len(part))
                captured = part[eq + 1:] if eq >= 0 else b""
                try:
                    decoded = unquote_plus(captured.decode("ascii"))
                    direct = decoded.encode("utf-8")
                    if captured == direct:
                        style = "utf8"
                    elif captured == quote_plus(decoded, safe="").encode():
                        style = "url"
                    elif captured == quote(decoded, safe="").encode():
                        style = "quote"
                    else:
                        style = "unknown_url"
                except (UnicodeError, ValueError):
                    style = "unknown_url"
                return base + start, base + cursor + len(part), captured, style
            seen += 1
        cursor += len(part) + 1
    return None


def _header_spans(raw):
    head = raw.partition(b"\r\n\r\n")[0]
    out, cursor = [], 0
    for i, line in enumerate(head.split(b"\r\n")):
        start = cursor
        cursor += len(line) + 2
        if i == 0:
            continue
        key, colon, value = line.partition(b":")
        if not colon:
            continue
        lead = len(value) - len(value.lstrip(b" \t"))
        out.append((key.decode("latin-1"), start + len(key) + 1 + lead, start + len(line)))
    return out


def _json_pairs_get(node, path):
    i = 0
    while i < len(path):
        if isinstance(node, dict) and "__pairs__" in node:
            key, occurrence = path[i], path[i + 1]
            node = [v for k, v in node["__pairs__"] if k == key][occurrence]
            i += 2
        elif isinstance(node, list):
            node = node[path[i]]
            i += 1
        else:
            raise KeyError(path)
    return node


def _field(parsed, location):
    category = location[1]
    if category in ("cookie", "query", "form"):
        key = {"cookie": "cookies", "query": "query", "form": "form"}[category]
        name, occurrence = location[2], location[3]
        return [v for k, v in parsed.get(key, []) if k == name][occurrence]
    if category == "header":
        return parsed.get("headers", [])[location[3]][1]
    if category == "path":
        return parsed.get("path_segments", [])[location[2]]
    if category == "json":
        return _json_pairs_get(parsed["json_pairs"], location[2:])
    if category == "multipart":
        part = parsed.get("multipart", [])[location[3]]
        return part.get("filename") if location[-1] == "filename" else base64.b64decode(part["data"]).decode("utf-8")
    return None


def _wire_span(raw, parsed, location, field_value, token_value=None):
    """Return (start,end,captured-bytes,encoder). Encoder names a runtime
    expression used to preserve the captured representation of a replacement."""
    category = location[1]
    head, sep, body, _ = _split_raw(raw)
    body_base = len(head) + len(sep)
    if category == "query":
        left, _, target = _request_target_bounds(raw)
        q = target.find(b"?")
        if q >= 0:
            return _pair_span(target[q + 1:], left + q + 1, location[2], location[3])
    if category == "form":
        return _pair_span(body, body_base, location[2], location[3])
    if category == "path":
        left, _, target = _request_target_bounds(raw)
        path = target.split(b"?", 1)[0]
        cursor = 1 if path.startswith(b"/") else 0
        for i, part in enumerate(path.lstrip(b"/").split(b"/")):
            if i == location[2]:
                try:
                    decoded = unquote(part.decode("ascii"))
                    style = "utf8" if part == decoded.encode("utf-8") else "quote"
                except (UnicodeError, ValueError):
                    style = "unknown_url"
                return left + cursor, left + cursor + len(part), part, style
            cursor += len(part) + 1
    if category == "header":
        spans = _header_spans(raw)
        index = location[3]
        if 0 <= index < len(spans):
            _, start, end = spans[index]
            needle = str(token_value if token_value is not None else field_value).encode("latin-1")
            at = raw.find(needle, start, end)
            if at >= 0 and raw.find(needle, at + 1, end) < 0:
                return at, at + len(needle), needle, "latin1"
    if category == "cookie":
        needle = str(token_value if token_value is not None else field_value).encode("latin-1")
        matches = []
        for name, start, end in _header_spans(raw):
            if name.lower() == "cookie":
                at = start
                while True:
                    at = raw.find(needle, at, end)
                    if at < 0:
                        break
                    matches.append(at); at += len(needle)
        occurrence = location[3]
        if occurrence < len(matches):
            at = matches[occurrence]
            return at, at + len(needle), needle, "latin1"
    if category == "json":
        candidates = []
        for ensure_ascii in (True, False):
            encoded = json.dumps(field_value, ensure_ascii=ensure_ascii, separators=(",", ":")).encode("utf-8")
            if encoded not in [c[0] for c in candidates]:
                candidates.append((encoded, "json_ascii" if ensure_ascii else "json_utf8"))
        found = []
        for encoded, style in candidates:
            pos = [m.start() for m in re.finditer(re.escape(encoded), body)]
            found += [(body_base + p, encoded, style) for p in pos]
        if len(found) == 1:
            at, encoded, style = found[0]
            return at, at + len(encoded), encoded, style
    if category == "body" and len(location) >= 4:
        start, end = int(location[2]), int(location[3])
        if 0 <= start <= end <= len(body):
            return body_base + start, body_base + end, body[start:end], "latin1"
    return None


def _encode_expr(expr, style):
    if style == "url":
        return f'urllib.parse.quote_plus(str({expr}), safe="").encode()'
    if style == "quote":
        return f'urllib.parse.quote(str({expr}), safe="").encode()'
    if style == "json_ascii":
        return f'json.dumps({expr}, ensure_ascii=True, separators=(",", ":")).encode()'
    if style == "json_utf8":
        return f'json.dumps({expr}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")'
    if style == "utf8":
        return f'str({expr}).encode("utf-8")'
    if style == "unknown_url":
        return None
    return f'str({expr}).encode("latin-1")'


def _alphabet(value):
    if value and value.isdigit():
        return "string.digits"
    if value and re.fullmatch(r"[0-9a-f]+", value):
        return '"0123456789abcdef"'
    if value and re.fullmatch(r"[a-z]+", value):
        return "string.ascii_lowercase"
    if value and re.fullmatch(r"[A-Z]+", value):
        return "string.ascii_uppercase"
    if value and re.fullmatch(r"[A-Za-z0-9]+", value):
        return "string.ascii_letters + string.digits"
    return None


def _pyvar(name):
    name = re.sub(r"\W", "_", str(name or "value"))
    if not name or name[0].isdigit():
        name = "value_" + name
    return name + "_" if keyword.iskeyword(name) else name


def _template_expr(value, item):
    source = value
    if item.get("transform") == ["base64"]:
        try:
            source = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_").decode("utf-8")
        except (ValueError, UnicodeError):
            return None
    pieces, cursor = [], 0
    for part in sorted(item.get("parts") or [], key=lambda p: p["start"]):
        pieces.append(repr(source[cursor:part["start"]]))
        pieces.append(f"str({_pyvar(part['var'])})")
        cursor = part["end"]
    pieces.append(repr(source[cursor:]))
    expr = " + ".join(pieces) or "''"
    if item.get("transform") == ["base64"]:
        expr = f"base64.b64encode(({expr}).encode()).decode()"
    return expr


def _header_occurrence(parsed, location):
    name, index = location[2].lower(), location[3]
    return sum(1 for key, _ in parsed.get("headers", [])[:index] if key.lower() == name)


def _extract_expr(location, source):
    if source.get("resp_raw") is None or source.get("resp_raw_truncated") or source.get("resp_body_truncated"):
        return None
    encodings = []
    for key, value in source.get("resp_parsed", {}).get("headers", []):
        if key.lower() == "content-encoding":
            encodings += [x.strip().lower() for x in value.split(",") if x.strip()]
    if any(x not in ("identity", "gzip", "deflate") for x in encodings):
        return None
    category = location[1] if location and len(location) > 1 else None
    if category == "json":
        return f"_json_at(body, {location[2:]!r})"
    if category == "header":
        return f"_header(headers, {location[2]!r}, {_header_occurrence(source['resp_parsed'], location)})"
    if category == "cookie":
        return f"_cookie(headers, {location[2]!r}, {location[3]})"
    if category == "body" and len(location) >= 4 and source.get("resp_body") is not None:
        start, end = int(location[2]), int(location[3])
        body = source["resp_body"]
        before, after = body[max(0, start - 10):start], body[end:end + 10]
        return f"_between(body, base64.b64decode({_b64(before)!r}), base64.b64decode({_b64(after)!r}))"
    return None


def _support_max(a, b):
    rank = {contracts.SCRIPT_SUPPORTED: 0, contracts.SCRIPT_NEEDS_EDIT: 1, contracts.SCRIPT_UNSUPPORTED: 2}
    return a if rank[a] >= rank[b] else b


def build(reader, cfg, result, values):
    """Return a computed scripts section containing immutable artifact data."""
    bundles = {step.transaction_id: reader.export_transaction(step.transaction_id) for step in result.steps}
    artifacts = []
    for step in result.steps:
        bundle = bundles.get(step.transaction_id)
        name = f"request-{step.position:02d}.py"
        if not bundle:
            artifacts.append(_unsupported("request", step.transaction_id, step.position, name,
                                          "transaction evidence is unavailable"))
        elif bundle["proto"] != "http":
            artifacts.append(_unsupported("request", step.transaction_id, step.position, name,
                                          "raw TCP needs Phase 1 turn/byte-span mapping"))
        elif bundle.get("req_raw") is None or bundle.get("req_raw_truncated"):
            artifacts.append(_unsupported("request", step.transaction_id, step.position, name,
                                          "captured raw request is missing or storage-truncated"))
        else:
            content = _request_script(bundle["req_raw"], bundle["dst_port"], step.transaction_id[:12])
            artifacts.append(_artifact("request", step.transaction_id, step.position, name,
                                       contracts.SCRIPT_SUPPORTED, [], content))

    chain = _chain_script(cfg, result, values, bundles)
    artifacts.append(chain)
    counts = {state: sum(1 for a in artifacts if a["support"] == state) for state in contracts.SCRIPT_SUPPORT}
    overall = contracts.SCRIPT_SUPPORTED
    for artifact in artifacts:
        overall = _support_max(overall, artifact["support"])
    return {"state": "computed", "exporter_version": EXPORTER_VERSION, "support": overall,
            "counts": counts, "verification": contracts.VERIFY_NOT_RUN, "artifacts": artifacts}


def _chain_script(cfg, result, values, bundles):
    warnings, support = [], contracts.SCRIPT_SUPPORTED
    if any(not b or b["proto"] != "http" for b in bundles.values()):
        return _unsupported("chain", None, None, "chain.py",
                            "raw TCP needs Phase 1 turn/byte-span mapping")
    if any(b.get("req_raw") is None or b.get("req_raw_truncated") for b in bundles.values()):
        return _unsupported("chain", None, None, "chain.py",
                            "one or more captured requests are missing or storage-truncated")
    reduced = [q for q in result.coverage.ingest_quality if q.endswith(":decoder_gated") or q.endswith(":decoder_off")]
    if reduced:
        support = contracts.SCRIPT_NEEDS_EDIT
        warnings.append("ingest decoder was lowered; decoded-only steps or values may be absent")
    if result.state == contracts.RUN_PARTIAL:
        support = contracts.SCRIPT_NEEDS_EDIT
        warnings.append("trace result is partial")

    by_tx = {}
    for item in values:
        by_tx.setdefault(item["transaction_id"], []).append(item)
    token_values = {}
    for bundle in bundles.values():
        token_values.update(bundle.get("token_values", {}))

    generated, linked_after, needs_target = {}, {}, False
    for item in values:
        roles = item.get("parts") or [item]
        for role in roles:
            kind, var = role.get("role", item.get("role")), role.get("var", item.get("var"))
            var = _pyvar(var) if var else var
            if kind == contracts.VALUE_TARGET:
                needs_target = True
            if kind == contracts.VALUE_GENERATED and var and var not in generated:
                original = token_values.get(item.get("token_id"))
                if item.get("parts"):
                    full = _field(bundles[item["transaction_id"]]["req_parsed"], item["location"])
                    original = str(base64.b64decode(full).decode("utf-8") if item.get("transform") == ["base64"] else full)
                    original = original[role["start"]:role["end"]]
                original = str(original if original is not None else item.get("value_preview", ""))
                alphabet = _alphabet(original)
                if item.get("ambiguous") or role.get("ambiguous") or not alphabet:
                    support = _support_max(support, contracts.SCRIPT_NEEDS_EDIT)
                    warnings.append(f"generated value {var} is ambiguous or has no safe format inference")
                    generated[var] = repr(original)
                else:
                    generated[var] = f"_rnd({len(original)}, {alphabet})"
            if kind == contracts.VALUE_LINKED and var:
                evidence = role.get("evidence", item.get("evidence") or {})
                source = evidence.get("from")
                if source:
                    linked_after.setdefault(source["transaction_id"], []).append((var, source["location"]))

    lines = ["#!/usr/bin/env python3", f"# Flag-trace {EXPORTER_VERSION} · HTTP chain",
             RUNTIME, "", "def exploit(host, flag_id=None, port=None):"]
    if needs_target:
        lines += ["    if flag_id is None:", "        raise ValueError('flag_id is required for this chain')"]
    for var, expr in sorted(generated.items()):
        lines.append(f"    {var} = {expr}")
    if not generated and not needs_target:
        lines.append("    pass")
    lines.append("    found = []")
    pattern = cfg.regex.pattern if isinstance(cfg.regex.pattern, bytes) else cfg.regex.pattern.encode()
    lines.append(f"    flag_re = re.compile(base64.b64decode({_b64(pattern)!r}))")

    for step in result.steps:
        tx, bundle = step.transaction_id, bundles[step.transaction_id]
        raw = bundle["req_raw"]
        patches = []
        for item in by_tx.get(tx, []):
            if item.get("unresolved") or item.get("ambiguous") or item.get("role") == contracts.VALUE_UNKNOWN:
                support = _support_max(support, contracts.SCRIPT_NEEDS_EDIT)
                warnings.append(f"{tx[:12]} {item['location']}: {item.get('unresolved') or 'ambiguous/unknown value'}")
                continue
            field_value = _field(bundle["req_parsed"], item["location"])
            token_value = token_values.get(item.get("token_id"))
            expr = _template_expr(str(field_value), item) if item.get("parts") else _pyvar(item.get("var"))
            if not expr:
                continue
            span = _wire_span(raw, bundle["req_parsed"], item["location"], field_value, token_value)
            if span is None:
                support = _support_max(support, contracts.SCRIPT_NEEDS_EDIT)
                warnings.append(f"{tx[:12]} {item['location']}: exact wire span could not be located")
                continue
            start, end, captured, style = span
            encoded_expr = _encode_expr(expr, style)
            if encoded_expr is None:
                support = _support_max(support, contracts.SCRIPT_NEEDS_EDIT)
                warnings.append(f"{tx[:12]} {item['location']}: captured URL encoding cannot be reproduced safely")
                continue
            patches.append((start, end, captured, encoded_expr))
        lines.append(f"    # step {step.position}: {bundle.get('method') or 'HTTP'} {bundle.get('path') or ''} on port {bundle['dst_port']}")
        lines.append(f"    raw = base64.b64decode({_b64(raw)!r})")
        if patches:
            lines.append("    patches = [")
            for start, end, captured, expr in patches:
                lines.append(f"        ({start}, {end}, base64.b64decode({_b64(captured)!r}), {expr}),")
            lines.append("    ]")
            lines.append("    raw = _patch(raw, patches)")
        lines.append(f"    status, headers, wire_body = _send(host, port or {bundle['dst_port']}, raw)")
        lines.append("    body = _decode(headers, wire_body)")
        lines.append("    found.extend(x.decode('utf-8', 'replace') for x in flag_re.findall(body))")
        assigned = set()
        for var, location in linked_after.get(tx, []):
            if var in assigned:
                continue
            expr = _extract_expr(location, bundle)
            if expr is None:
                support = _support_max(support, contracts.SCRIPT_NEEDS_EDIT)
                warnings.append(f"{tx[:12]} {location}: linked response extractor is unsupported")
                lines.append(f"    # TODO: extract {var} from {location!r}")
            else:
                lines.append(f"    {var} = {expr}")
            assigned.add(var)
    lines += ["    return found", "", "", "if __name__ == '__main__':",
              "    parser = argparse.ArgumentParser()", "    parser.add_argument('host')",
              "    parser.add_argument('--port', type=int)",
              "    parser.add_argument('flag_id', nargs='?')", "    args = parser.parse_args()",
              "    print(exploit(args.host, args.flag_id, args.port))", ""]
    content = "\n".join(lines)
    return _artifact("chain", None, None, "chain.py", support, warnings, content)
