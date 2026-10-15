"""Chain grouping (P2.4b, B7): flag-outs whose chains have the same shape.

The shape of a chain is its steps in order, each one the request method, the
path through the normalizer the checker baseline also uses, and the names of
the request fields. Values never enter it, so a new session, username or file
ID on every run of an exploit lands in the same group, and so does the same
exploit sent by another team. Value roles do not enter it either: a group must
not depend on what B6 inferred, which itself may use group evidence later.

A group says the chains look alike. It does not say they exploit the same bug.
"""
import json

from ..analysis import uid
from ..background import ALL_VALUES
from ..parsing import path_template
from ..tokens import extract

# Bumped when the shape of a step changes (normalizer or field naming), which
# moves profiles to new groups; the worker re-analyses the ones left behind.
NORMALIZER_VERSION = "n1"
# Free text is not a field: its "names" are byte offsets.
SKIPPED_CATEGORIES = ("body", "path")


def field_name(location):
    """A field's name without its occurrence or position, e.g. form:user,
    header:authorization, json:user.name, multipart:file.filename."""
    category = location[1]
    if category == "json":
        return "json:" + ".".join(str(k) for k in location[2:] if isinstance(k, str))
    if category == "multipart":
        return f"multipart:{location[2]}.{location[4] if len(location) > 4 else ''}"
    return f"{category}:{location[2]}"


def request_fields(req_parsed):
    """Sorted, distinct names of the fields a request sent."""
    parsed = json.loads(req_parsed) if isinstance(req_parsed, str) else (req_parsed or {})
    tokens, _ = extract(parsed, b"", "req", ALL_VALUES)
    return sorted({field_name(t["location"]) for t in tokens
                   if t["parent"] is None and t["location"][1] not in SKIPPED_CATEGORIES})


def step_shape(row, req_parsed):
    if row["proto"] != "http":
        # Raw TCP has no request line or fields to compare; its steps only
        # count. Such groups are coarse and say so through proto.
        return {"proto": row["proto"] or "raw"}
    return {"proto": "http", "method": row["method"] or "", "path": path_template(row["path"] or ""),
            "fields": request_fields(req_parsed)}


def describe(shape):
    """One line for lists: 'POST /login → GET /files/{id}'."""
    return " → ".join(f"{s['method']} {s['path']}" if s["proto"] == "http" else s["proto"] for s in shape)


def signature(reader, game_id, service, nodes, order):
    """The group a run belongs to, computed in the run's read snapshot."""
    ids = list(order)
    parsed = dict(reader.db.execute(
        f"SELECT id,req_parsed FROM transactions WHERE id IN ({','.join('?' * len(ids))})", ids).fetchall()) if ids else {}
    shape = [step_shape(nodes[tx]["row"], parsed.get(tx)) for tx in ids]
    canonical = json.dumps({"v": NORMALIZER_VERSION, "service": service, "steps": shape},
                           sort_keys=True, separators=(",", ":"))
    return {"state": "computed", "group_id": uid("chain-group", game_id, canonical),
            "normalizer_version": NORMALIZER_VERSION, "service": service, "steps": len(shape),
            "description": describe(shape), "shape": shape}


def backfill_trigger():
    return "auto:grouping:" + NORMALIZER_VERSION
