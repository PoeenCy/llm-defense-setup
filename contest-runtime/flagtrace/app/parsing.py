"""Evidence-preserving HTTP bodies and structured fields. Framing belongs to Go."""
import base64
import gzip
import json
import re
import zlib
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qsl, unquote, urlsplit


def bounded_inflate(data, wbits, limit):
    d = zlib.decompressobj(wbits)
    out = d.decompress(data, limit + 1)
    if len(out) > limit or d.unconsumed_tail:
        return out[:limit], "decode_truncated"
    return out, None if d.eof else "decode_incomplete"


def dechunk(data, limit):
    """Decode chunked framing. A message cut short (capture ended, connection
    lost) yields the chunks received so far plus decode_incomplete, so content
    decoding and the flag scan still see them; malformed framing still raises."""
    out = bytearray()
    while True:
        line, sep, data = data.partition(b"\r\n")
        if not sep:
            return bytes(out), "decode_incomplete"
        n = int(line.split(b";", 1)[0], 16)
        if n < 0:
            raise ValueError("invalid chunk size")
        if n == 0:
            return bytes(out), None
        cut = len(data) < n + 2
        if not cut and data[n:n+2] != b"\r\n":
            raise ValueError("invalid chunk")
        out.extend(data[:min(n, limit + 1 - len(out))])
        if len(out) > limit:
            return bytes(out[:limit]), "decode_truncated"
        if cut:
            return bytes(out), "decode_incomplete"
        data = data[n+2:]


def parse_message(raw, request, limit):
    header, sep, body = raw.partition(b"\r\n\r\n")
    result = {"headers": [], "cookies": [], "query": [], "form": [], "multipart": [], "issues": []}
    if not sep:
        result["issues"].append("missing_http_header")
        return result, raw[:limit]
    lines = header.split(b"\r\n")
    first = lines[0].decode("latin-1").split(" ")
    if request:
        result.update(method=first[0], target=first[1] if len(first) > 1 else "")
        url = urlsplit(result["target"])
        result["path"] = url.path
        result["path_segments"] = [unquote(x) for x in url.path.split("/")[1:]]
        result["query"] = parse_qsl(url.query, keep_blank_values=True, max_num_fields=10000)
    else:
        result["status"] = int(first[1]) if len(first) > 1 and first[1].isdigit() else None
    for line in lines[1:]:
        key, colon, value = line.partition(b":")
        if colon:
            result["headers"].append([key.decode("latin-1"), value.strip().decode("latin-1")])
    headers = {k.lower(): v for k, v in result["headers"]}
    for key, value in result["headers"]:
        if key.lower() == ("cookie" if request else "set-cookie"):
            parts = value.split(";") if request else value.split(";")[:1]
            for part in parts:
                k, eq, v = part.strip().partition("=")
                if eq:
                    result["cookies"].append([k, v])
    try:
        if "chunked" in headers.get("transfer-encoding", "").lower():
            body, issue = dechunk(body, limit)
            if issue:
                result["issues"].append(issue)
        encodings = [x.strip().lower() for x in headers.get("content-encoding", "").split(",") if x.strip()]
        for encoding in reversed(encodings):
            issue = None
            if encoding in ("gzip", "deflate"):
                try:
                    body, issue = bounded_inflate(body, 31 if encoding == "gzip" else 15, limit)
                except zlib.error:
                    if encoding != "deflate":
                        raise
                    body, issue = bounded_inflate(body, -15, limit)
            elif encoding == "br":
                import brotli
                decoder = brotli.Decompressor()
                decoded = bytearray()
                for i in range(0, len(body), 1024):
                    decoded.extend(decoder.process(body[i:i+1024]))
                    if len(decoded) > limit:
                        issue = "decode_truncated"
                        break
                body = bytes(decoded[:limit])
            elif encoding != "identity":
                result["issues"].append("unsupported_content_encoding:" + encoding)
                break
            if issue:
                result["issues"].append(issue)
    except Exception as exc:
        result["issues"].append("decode_error:" + type(exc).__name__)
    if len(body) > limit:
        result["issues"].append("scan_truncated")
    body = body[:limit]
    ctype = headers.get("content-type", "").lower()
    result["content_type"] = ctype
    result["body_type"] = "raw"
    try:
        if "application/json" in ctype or "+json" in ctype:
            result["body_type"] = "json"
            # pairs preserve duplicate keys, including nested object keys.
            result["json_pairs"] = json.loads(body, object_pairs_hook=lambda p: {"__pairs__": p})
        elif "application/x-www-form-urlencoded" in ctype:
            result["body_type"] = "form"
            result["form"] = parse_qsl(body.decode("utf-8"), keep_blank_values=True, max_num_fields=10000)
        elif "multipart/form-data" in ctype:
            result["body_type"] = "multipart"
            msg = BytesParser(policy=policy.default).parsebytes(b"Content-Type: " + headers["content-type"].encode("latin-1") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body)
            for part in msg.iter_parts():
                data = part.get_payload(decode=True) or b""
                result["multipart"].append({"name": part.get_param("name", header="content-disposition"),
                                           "filename": part.get_filename(), "content_type": part.get_content_type(),
                                           "data": base64.b64encode(data).decode()})
    except (ValueError, UnicodeError, RecursionError) as exc:
        result["issues"].append("body_parse_error:" + type(exc).__name__)
    return result, body


def path_template(path):
    def part(x):
        if x.isdigit():
            return "{n}"
        if re.fullmatch(r"[0-9a-fA-F-]{6,}", x) or (len(x) >= 16 and len(set(x)) >= 8):
            return "{id}"
        return x
    return "/".join(part(x) for x in path.split("/"))
