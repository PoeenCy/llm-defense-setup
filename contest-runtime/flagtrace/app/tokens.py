"""Token locations are typed paths, with a human-readable label for the API.

min_len only guards free-text body scans. A value in a structured location
(path segment, query, form, JSON, cookie, header, multipart) is meaningful even
when short, e.g. a flag ID 7731, so it uses struct_min_len; common values are
left for Phase 2 to filter by token_df at query time.
"""
import base64
import json
import re


def extract(parsed, body, side, options):
    out = []
    role = "consumed" if side == "req" else "produced"
    stop = set(options["stoplist"])
    cap = options["max_tokens"]

    def add(value, loc, parent=None, transform=None, span=None, derived=False, structured=True):
        if len(out) >= cap or value is None or isinstance(value, bool):
            return
        value = str(value)
        if parent is not None:
            minimum = options["sub_min_len"]
        else:
            minimum = options["struct_min_len"] if structured else options["min_len"]
        if len(value) < minimum or value.lower() in stop or len(value) > 16384:
            return
        idx = len(out)
        out.append({"value": value, "normalized_value": value, "role": role, "location": loc,
                    "parent": parent, "transform": transform or [], "span": span})
        if derived:
            return
        for n, match in enumerate(re.finditer(r"[^/._\-=&]+", value)):
            if match.group() != value:
                add(match.group(), loc + ["sub", n], idx, ["split"], [match.start(), match.end()], True)
        if len(value) > 8:
            try:
                decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True).decode("utf-8")
                if decoded.isprintable() and decoded != value:
                    add(decoded, loc + ["b64"], idx, ["base64"], derived=True)
            except (ValueError, UnicodeError):
                pass
        pieces = value.split(".")
        if len(pieces) == 3:
            try:
                claims = json.loads(base64.urlsafe_b64decode(pieces[1] + "=" * (-len(pieces[1]) % 4)))
                if isinstance(claims, dict):
                    for key, claim in claims.items():
                        if isinstance(claim, (str, int, float)):
                            add(claim, loc + ["jwt", key], idx, ["jwt_unverified"], derived=True)
            except (ValueError, UnicodeError):
                pass

    for category, key in (("cookie", "cookies"), ("query", "query"), ("form", "form")):
        occurrences = {}
        for name, value in parsed.get(key, []):
            n = occurrences.get(name, 0)
            occurrences[name] = n + 1
            add(value, [side, category, name, n])
    for i, value in enumerate(parsed.get("path_segments", [])):
        add(value, [side, "path", i])
    for i, (name, value) in enumerate(parsed.get("headers", [])):
        lname = name.lower()
        if lname in ("authorization", "location") or lname.startswith("x-"):
            # Strip the auth scheme ("Bearer <token>", "Token <token>"...) so the
            # credential is the same value that was issued, e.g. an access_token
            # in a login response. The scheme word is not the secret; keeping it
            # would stop the request's token from matching where it came from.
            if lname == "authorization":
                m = re.match(r"\s*(bearer|token|jwt|basic|digest)\s+(\S.*)", value, re.IGNORECASE)
                if m:
                    value = m.group(2).strip()
            add(value, [side, "header", lname, i])

    def walk(obj, loc, depth=0):
        if depth > 32 or len(out) >= cap:
            return
        if isinstance(obj, dict) and "__pairs__" in obj:
            occurrences = {}
            for k, v in obj["__pairs__"]:
                n = occurrences.get(k, 0)
                occurrences[k] = n + 1
                walk(v, loc + [k, n], depth + 1)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, loc + [i], depth + 1)
        elif isinstance(obj, (str, int, float)):
            add(obj, loc)
    if "json_pairs" in parsed:
        walk(parsed["json_pairs"], [side, "json"])
    for i, part in enumerate(parsed.get("multipart", [])):
        loc = [side, "multipart", part["name"], i]
        add(part["filename"], loc + ["filename"])
        try:
            add(base64.b64decode(part["data"]).decode("utf-8"), loc + ["body"])
        except UnicodeError:
            pass
    if parsed.get("body_type", "raw") == "raw":
        for match in re.finditer(rb"[A-Za-z0-9_./=+\-]{6,256}", body):
            value = match.group().decode("ascii")
            if len(set(value)) >= 4:
                add(value, [side, "body", match.start(), match.end()], span=[match.start(), match.end()], structured=False)
    return out, len(out) >= cap
