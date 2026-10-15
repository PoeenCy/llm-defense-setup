"""B6: what each value a chain sends is, so a script knows how to obtain it.

Every request field of every step the engine examined gets one role:

  linked     an earlier response carried it: extract it from that response
  generated  the attacker sent it first and reused it later: make up a new one
  target     nothing in the traffic produced it and it is this team's flag ID:
             it becomes the exploit's flag_id parameter
  unknown    it looks like an identifier, but nothing explains where it came from
  constant   everything else, sent verbatim. Counted, not listed.

Roles rest on the edges the engine found, plus flag IDs for "target". Flag IDs
come from the checker's own putflag sessions, an import or the contest's API.
With none of those the section says so and nothing is called a target, so a
missing source is never mistaken for "this exploit needs no flag ID".

A field can be partly variable: "../../notes/7731.txt" with 7731 a flag ID is
the template "../../notes/{flag_id}.txt". Parts come from the engine's split
sub-tokens and, for flag IDs, from a bounded substring search. That search also
looks inside base64 (re-encodable, so the template carries the transform) but
not inside a JWT, which cannot be re-signed and is reported unresolved.

Reads here are bounded by their own limits, not by the job's row budget, so a
run the search cut short still gets the steps it examined classified.
"""
import json
import re
from dataclasses import dataclass, field

from ..background import ALL_VALUES
from ..parsing import path_template
from ..tokens import extract
from . import contracts
from .repository import category, location_of

MAX_VALUES = 500           # listed (non-constant) fields per run
MAX_LOOKUPS = 5000         # distinct strings looked up as flag IDs per run
MAX_FLAG_ROWS = 2000       # flag-ID records read per run
BODY_LIMIT = 256 * 1024    # unstructured request body searched for flag IDs
SHORT_FLAG_ID = 4          # a flag ID this short may match by coincidence
PREVIEW = 64
TEMPLATE_PREVIEW = 1024
MAX_EVIDENCE = 5
# Reasons the engine gave for not linking a value that leave its origin open.
# "repeated_in_same_step" is not one: an earlier run of the same step sent the
# same value, which is what a constant looks like.
OPEN_NOTES = ("no_source_in_scope", "no_compatible_field", "source_not_earlier",
              "equal_timestamp_order_unknown", "source_missing", contracts.LIMIT_NODES)
PRECEDENCE = {contracts.VALUE_LINKED: 0, contracts.VALUE_TARGET: 1, contracts.VALUE_GENERATED: 2,
              contracts.VALUE_UNKNOWN: 3}
BASIS_RANK = {b: i for i, b in enumerate(contracts.FLAG_ID_BASES)}
# Where a flag ID could sit inside a longer value: alphanumeric runs, the
# engine's own split pieces, and identifier-like runs that keep separators.
PIECES = (re.compile(r"[A-Za-z0-9]+"), re.compile(r"[^/._\-=&\s]+"), re.compile(r"[\w.@+\-:]+"))


def preview(value):
    value = str(value)
    return value[:PREVIEW] + ("…" if len(value) > PREVIEW else "")


# An identifier has none of these; a query text or a sentence does.
NOT_IDENTIFIER = re.compile(r"[\s{}()\[\]<>\"',;:!|^`*$]")


def id_like(value, decoded=None):
    """The baseline normalizer's view: digits, hex and long random strings fold
    to a placeholder, words and paths stay as they are. A GraphQL query or any
    text with spaces/brackets folds too, but is not an identifier, and neither
    is an encoding of words ("/flag/flag" in base64): both are constant payloads."""
    if NOT_IDENTIFIER.search(value) or path_template(value) == value:
        return False
    return decoded is None or (not NOT_IDENTIFIER.search(decoded) and path_template(decoded) != decoded)


def var_base(location):
    """A readable variable name from where a value sat: the cookie, form, query
    or header name, the last JSON key, or the path position. A piece split out
    of a longer value is named as a part of it ("username_part")."""
    loc, suffix = list(location or []), ""
    while len(loc) > 3:
        if loc[-1] == "b64":
            loc = loc[:-1]
        elif loc[-2] == "jwt":
            return _ident(str(loc[-1]))
        elif loc[-2] == "sub" and isinstance(loc[-1], int):
            loc, suffix = loc[:-2], "_part"
        else:
            break
    return _ident(_name(loc)) + suffix


def _name(loc):
    cat = loc[1] if len(loc) > 1 else "body"
    if cat in ("cookie", "query", "form", "header", "multipart") and len(loc) > 2:
        name = str(loc[2]) + ("_filename" if cat == "multipart" and "filename" in loc[4:] else "")
    elif cat == "json":
        keys = [x for x in loc[2:] if isinstance(x, str)]
        name = keys[-1] if keys else "json"
    elif cat == "path" and len(loc) > 2:
        name = f"path_{loc[2]}"
    else:
        name = "body"
    return name


def _ident(name):
    name = re.sub(r"\W+", "_", name).strip("_").lower() or "value"
    return "v_" + name if name[0].isdigit() else name


def pieces(text):
    out = {text}
    for rx in PIECES:
        out.update(rx.findall(text))
    return out


def render(value, parts):
    """Template with each part replaced by {var}; literal braces doubled, so the
    result is a str.format template."""
    out, at = [], 0
    for start, end, var in sorted(parts):
        out.append(value[at:start].replace("{", "{{").replace("}", "}}"))
        out.append("{" + var + "}")
        at = end
    out.append(value[at:].replace("{", "{{").replace("}", "}}"))
    return "".join(out)


@dataclass
class Role:
    kind: str
    key: tuple
    base: str
    evidence: dict = field(default_factory=dict)
    ambiguous: bool = False


class Vars:
    """One name per variable, stable in step order. Values that share a source
    (one session cookie used by three requests) share a name."""

    def __init__(self):
        self.by_key, self.taken = {}, set()

    def name(self, role):
        if role.key in self.by_key:
            return self.by_key[role.key]
        name, n = role.base, 1
        while name in self.taken:
            n += 1
            name = f"{role.base}_{n}"
        self.by_key[role.key] = name
        self.taken.add(name)
        return name


class FlagIds:
    """This team's flag IDs for the anchor's service, and how strongly each
    record can be tied to the request that used it."""

    def __init__(self, reader, cfg, anchor_row):
        self.reader, self.service = reader, anchor_row["service"]
        self.owner, self.validity = cfg.team_id, cfg.flag_validity_ticks
        flags = anchor_row["flags_found"]
        flags = json.loads(flags) if isinstance(flags, str) else (flags or [])
        puts = reader.flag_puts(flags)
        self.put_ticks = {p["tick"] for p in puts if p["tick"] is not None}
        self.put_conns = {p["conn_id"] for p in puts if p["conn_id"]}
        self.puts = [{"tick": p["tick"], "transaction_id": p["transaction_id"]} for p in puts]
        self.game_total, self.sources = reader.flag_id_counts(self.service, self.owner)
        self.available = sum(self.sources.values())
        self.by_value, self.capped, self.matched, self.refused = {}, False, set(), {}
        self.patterns = {}

    def load(self, lookups):
        if not self.available or not lookups:
            return
        rows = self.reader.flag_ids_matching(self.service, self.owner, lookups, MAX_FLAG_ROWS)
        self.capped = len(rows) >= MAX_FLAG_ROWS
        for row in rows:
            self.by_value.setdefault(row["value"], []).append(row)

    def check(self, value, tick):
        """(evidence, ambiguous) when `value` is an acceptable flag ID for a
        request in `tick`, else (None, reasons the records were refused)."""
        accepted, refused = [], set()
        for row in self.by_value.get(value, ()):
            if tick is not None and row["tick"] is not None and row["tick"] > tick:
                refused.add("flag_id_published_after_request")
                continue
            if self.validity and tick is not None and row["tick"] is not None and row["tick"] <= tick - self.validity:
                refused.add("flag_id_outside_validity_window")
                continue
            if row["source"] == "checker_put" and row["conn_id"] and row["conn_id"] in self.put_conns:
                basis = contracts.BASIS_SAME_PUT
            elif row["tick"] in self.put_ticks:
                basis = contracts.BASIS_PUT_TICK
            elif self.validity:
                basis = contracts.BASIS_WINDOW
            else:
                basis = contracts.BASIS_EARLIER
            accepted.append((row, basis))
        if not accepted:
            if refused:
                # A flag ID the request did use, refused on timing: shown, so a
                # wrong validity setting is visible rather than silent.
                self.refused.setdefault(value, set()).update(refused)
            return None, sorted(refused)
        accepted.sort(key=lambda a: (BASIS_RANK[a[1]], -(a[0]["tick"] or 0), a[0]["source"]))
        self.matched.add(value)
        owners = {row["owner_team_id"] for row, _ in accepted}
        evidence = {"basis": accepted[0][1], "short": len(value) < SHORT_FLAG_ID,
                    "flag_ids": [{"source": row["source"], "tick": row["tick"], "owner_team_id": row["owner_team_id"],
                                  "basis": basis} for row, basis in accepted[:MAX_EVIDENCE]]}
        return evidence, len(value) < SHORT_FLAG_ID or len(owners) > 1

    def occurrences(self, text, tick):
        """Accepted flag IDs inside `text`, bounded by non-alphanumerics:
        [(start, end, value, evidence, ambiguous)]."""
        out = []
        for value in sorted(pieces(text) & self.by_value.keys()):
            evidence, ambiguous = self.check(value, tick)
            if evidence is None:
                continue
            rx = self.patterns.get(value)
            if rx is None:
                rx = self.patterns[value] = re.compile(r"(?<![A-Za-z0-9])" + re.escape(value) + r"(?![A-Za-z0-9])")
            out += [(m.start(), m.end(), value, evidence, ambiguous) for m in rx.finditer(text)]
        return out

    def summary(self):
        if self.available:
            status = "available"
        else:
            status = "none_for_scope" if self.game_total else "none"
        notes = []
        if status == "none":
            notes.append("no flag-ID source (checker putflag, import or API) has produced a flag ID yet: "
                         "no value can be called a target, ID-like values without a source are unknown")
        elif status == "none_for_scope":
            notes.append(f"flag IDs exist, but none for service {self.service}"
                         + (f" owned by {self.owner}" if self.owner else ""))
        if self.owner is None:
            notes.append("team_id is not configured: flag IDs of every team are considered")
        if not self.validity:
            notes.append("game.flag_validity_ticks is not configured: a flag ID of any earlier tick is accepted")
        if self.capped:
            notes.append(f"only the newest {MAX_FLAG_ROWS} matching flag-ID records were read")
        return {"status": status, "service": self.service, "owner_team_id": self.owner,
                "validity_ticks": self.validity, "records_in_scope": self.available,
                "records_in_game": self.game_total, "sources": self.sources,
                "matched_values": len(self.matched), "leaked_flag_puts": self.puts,
                "refused": [{"value_preview": preview(v), "reasons": sorted(r)}
                            for v, r in sorted(self.refused.items())[:MAX_EVIDENCE]],
                "notes": notes}


class Classifier:
    def __init__(self, reader, cfg, anchor_row, nodes, examined, edges):
        """`examined` maps each step whose request values the engine searched to
        {"tokens": [(token, outcome)], "complete": bool, "reason": str|None};
        an outcome is ("edge", Edge), ("noise", reason), ("none", note) or
        ("cut", limit). Steps absent from it were never searched."""
        self.reader, self.nodes, self.examined = reader, nodes, examined
        self.by_dst = {e.dst_token_id: e for e in edges if e.dst_token_id}
        # Every value a request of an examined step sent, to recognise a
        # response that only echoed it (register returning the username).
        # Only values the engine treated as values count: a word split out of
        # the path ("image" of /image-sharing/) is not something a response
        # could be echoing back.
        self.value_of, self.sent = {}, {}
        for tx, info in examined.items():
            for token, outcome in info["tokens"]:
                self.value_of[token["id"]] = token["normalized_value"]
                if outcome[0] != "noise":
                    self.sent.setdefault((tx, token["normalized_value"]), token)
        # Later uses of a value first sent here: reused by a request, or
        # handed back through an echoing response.
        self.reused = {}
        for e in edges:
            if e.kind == contracts.EDGE_REQUEST_REUSE and e.src_token_id:
                self.reused.setdefault(e.src_token_id, []).append(e)
            echo = self.echo_source(e)
            if echo is not None:
                self.reused.setdefault(echo["id"], []).append(e)
        self.flag_ids = FlagIds(reader, cfg, anchor_row)
        self.vars = Vars()

    def tick_of(self, tx):
        node = self.nodes.get(tx)
        return node["row"]["tick"] if node else None

    # ── roles of single values ──────────────────────────────────────────
    def echo_source(self, e):
        """The request token a response_to_request edge really started from,
        when the response only echoed a value its own request sent; else None.
        A script then reuses what it sent instead of reading it back."""
        if e.kind != contracts.EDGE_RESPONSE_TO_REQUEST:
            return None
        value = self.value_of.get(e.dst_token_id)
        return self.sent.get((e.src_transaction_id, value)) if value is not None else None

    def edge_role(self, token_id, value, tick):
        """Role of a value the engine linked to a source, or None. Request
        reuse and echoing responses are followed back to where the value
        entered the traffic; a response that produced it makes it linked."""
        e = self.by_dst.get(token_id)
        if e is None:
            return None
        hops, cur, seen, echoed = [], e, {token_id}, False
        while True:
            hops.append(cur.key())
            if cur.kind == contracts.EDGE_RESPONSE_TO_REQUEST:
                echo = self.echo_source(cur)
                if echo is None:
                    return self._linked(cur, hops[:-1], ambiguous=e.ambiguous)
                echoed = True
                root_id, root_loc = echo["id"], location_of(echo)
            else:
                root_id, root_loc = cur.src_token_id, cur.src_location
            root_tx = cur.src_transaction_id
            nxt = self.by_dst.get(root_id)
            if nxt is None or root_id in seen or len(hops) >= 16:
                break
            seen.add(root_id)
            cur = nxt
        first = {"transaction_id": root_tx, "location": root_loc}
        first_tick = self.tick_of(root_tx)
        evidence, ambiguous = self.flag_ids.check(value, tick if first_tick is None else first_tick)
        if evidence:
            return Role(contracts.VALUE_TARGET, ("flag_id", value), "flag_id",
                        {**evidence, "first_sent_in": first, "via": hops}, ambiguous)
        evidence = {"kind": e.kind, "edge_key": e.key(), "first_sent_in": first, "via": hops}
        if echoed:
            evidence["echoed_by_response"] = True
        return Role(contracts.VALUE_GENERATED, ("gen", root_id), var_base(root_loc), evidence,
                    e.ambiguous or len(value) < SHORT_FLAG_ID)

    def _linked(self, e, via, ambiguous=False):
        evidence = {"kind": e.kind, "edge_key": e.key(),
                    "from": {"transaction_id": e.src_transaction_id, "location": e.src_location}}
        if via:
            evidence["via"] = via
        return Role(contracts.VALUE_LINKED, ("src", e.src_token_id), var_base(e.src_location), evidence,
                    e.ambiguous or ambiguous)

    def root_role(self, token_id, location, value, tick):
        """Role of a value no earlier message produced: a flag ID, or one the
        attacker made up and then reused."""
        evidence, ambiguous = self.flag_ids.check(value, tick)
        reused_by = [{"transaction_id": x.dst_transaction_id, "location": x.dst_location}
                     for x in self.reused.get(token_id, ())][:MAX_EVIDENCE] if token_id else []
        if evidence:
            if reused_by:
                evidence["reused_by"] = reused_by
            return Role(contracts.VALUE_TARGET, ("flag_id", value), "flag_id", evidence, ambiguous)
        if reused_by:
            # One chain cannot tell a made-up value from a short constant the
            # attacker picked (an admin ID 1); grouping several chains can.
            return Role(contracts.VALUE_GENERATED, ("gen", token_id), var_base(location),
                        {"first_sent": True, "reused_by": reused_by}, len(value) < SHORT_FLAG_ID)
        return None

    def role(self, token_id, location, value, tick):
        role = self.edge_role(token_id, value, tick) if token_id else None
        if role and role.kind == contracts.VALUE_LINKED:
            # Linked wins: a script takes it from the response. A flag-ID match
            # is still worth showing.
            evidence, _ = self.flag_ids.check(value, tick)
            if evidence:
                role.evidence["also_matches_flag_id"] = evidence
        return role or self.root_role(token_id, location, value, tick)

    def target_part(self, value, evidence, ambiguous):
        return Role(contracts.VALUE_TARGET, ("flag_id", value), "flag_id", evidence, ambiguous)

    # ── one request field ───────────────────────────────────────────────
    def field(self, tx, tick, loc, value, children, tokens, kids):
        """The entry for one top-level field, or None when it is a constant.
        `children` are the field's derived values from the parsed request,
        `tokens` maps location → (token, outcome), `kids` parent id → tokens."""
        tok, outcome = tokens.get(json.dumps(loc), (None, None))
        tid = tok["id"] if tok else None
        role = self.role(tid, loc, value, tick)
        if role:
            return self.entry(tx, loc, tok, value, role, var=self.vars.name(role))

        # Part of the value is variable: split pieces with a role, flag IDs
        # inside it. Highest precedence first, longest first, no overlaps.
        parts = []
        for child, child_outcome in kids.get(tid, ()) if tid else ():
            span = _json(child["span"])
            if _json(child["transform"]) != ["split"] or not span:
                continue
            r = self.role(child["id"], location_of(child), child["normalized_value"], tick)
            # A word split out of a value ("image" of image-sharing) is part of
            # its shape, even when a response happened to carry the same word:
            # only an identifier-like piece, or a flag ID, becomes a variable.
            if r and (r.kind == contracts.VALUE_TARGET or id_like(child["normalized_value"])):
                parts.append((span[0], span[1], r))
        for start, end, fid, evidence, ambiguous in self.flag_ids.occurrences(value, tick):
            parts.append((start, end, self.target_part(fid, evidence, ambiguous)))
        if parts:
            return self.templated(tx, loc, tok, value, parts)

        # Encoded values. Base64 can be rebuilt around a template; a JWT claim
        # cannot be changed without the signing key.
        decoded = next((c for c in children if c["transform"] == ["base64"]), None)
        for child, _ in kids.get(tid, ()) if tid else ():
            transform = _json(child["transform"])
            if "base64" in transform:
                inner = child["normalized_value"]
                r = self.role(child["id"], location_of(child), inner, tick)
                if r:
                    return self.templated(tx, loc, tok, value, [(0, len(inner), r)], decoded=inner)
            elif "jwt_unverified" in transform:
                r = self.role(child["id"], location_of(child), child["normalized_value"], tick)
                if r:
                    r.evidence["claim"] = location_of(child)[-1]
                    return self.entry(tx, loc, tok, value, r, unresolved="jwt_unverified", whole_var=False)
        if decoded:
            inner = [(s, e, self.target_part(fid, ev, amb))
                     for s, e, fid, ev, amb in self.flag_ids.occurrences(decoded["value"], tick)]
            if inner:
                return self.templated(tx, loc, tok, value, inner, decoded=decoded["value"])

        # Nothing explains it. Only an identifier-looking value with an open
        # origin is worth a human's attention; words and repeats are constants.
        if outcome and outcome[0] in ("none", "cut") and outcome[1] in OPEN_NOTES \
                and id_like(value, decoded["value"] if decoded else None):
            role = Role(contracts.VALUE_UNKNOWN, ("unknown", tx, json.dumps(loc)), "unknown",
                        {"reason": outcome[1]})
            return self.entry(tx, loc, tok, value, role, var=self.vars.name(role))
        unknown = []
        for child, child_outcome in kids.get(tid, ()) if tid else ():
            span = _json(child["span"])
            if _json(child["transform"]) == ["split"] and span and child_outcome \
                    and child_outcome[0] in ("none", "cut") and child_outcome[1] in OPEN_NOTES \
                    and id_like(child["normalized_value"]):
                unknown.append((span[0], span[1], Role(contracts.VALUE_UNKNOWN, ("unknown", child["id"]),
                                                       "unknown", {"reason": child_outcome[1]})))
        if unknown:
            return self.templated(tx, loc, tok, value, unknown)
        return None

    def templated(self, tx, loc, tok, value, parts, decoded=None):
        chosen = []
        for start, end, role in sorted(parts, key=lambda p: (PRECEDENCE[p[2].kind], p[0] - p[1], p[0])):
            if all(end <= s or start >= e for s, e, _ in chosen):
                chosen.append((start, end, role))
        chosen.sort(key=lambda p: p[0])
        named = [(s, e, self.vars.name(r), r) for s, e, r in chosen]
        top = min((r for *_, r in named), key=lambda r: PRECEDENCE[r.kind])
        template = render(decoded if decoded is not None else value, [(s, e, v) for s, e, v, _ in named])
        evidence = {"parts": len(named)}
        if decoded is not None:
            evidence["decoded_preview"] = preview(decoded)
        return self.entry(tx, loc, tok, value, Role(top.kind, (), "", evidence, any(r.ambiguous for *_, r in named)),
                          template=template, transform=["base64"] if decoded is not None else [],
                          parts=[{"start": s, "end": e, "var": v, "role": r.kind, "ambiguous": r.ambiguous,
                                  "evidence": r.evidence} for s, e, v, r in named], whole_var=False)

    def entry(self, tx, loc, tok, value, role, var=None, template=None, transform=(), parts=(),
              unresolved=None, whole_var=True):
        evidence = dict(role.evidence)
        if template and len(template) > TEMPLATE_PREVIEW:
            template = template[:TEMPLATE_PREVIEW] + "…"
            evidence["template_truncated"] = True
        return {"value_key": contracts.value_key(tx, loc), "transaction_id": tx,
                "token_id": tok["id"] if tok else None, "location": loc, "role": role.kind,
                "var": var if whole_var else (self.vars.name(role) if unresolved else None),
                "value_preview": preview(value), "value_length": len(value), "template": template,
                "parts": list(parts), "transform": list(transform), "unresolved": unresolved,
                "session_cookie": role.kind == contracts.VALUE_LINKED and category(loc) == "cookie"
                                  and not parts and not transform,
                "ambiguous": bool(role.ambiguous), "evidence": evidence}

    # ── unstructured bodies ─────────────────────────────────────────────
    def body(self, tx, tick, text, tokens, kids):
        """Raw TCP payloads and HTTP bodies without structure: linked/generated
        tokens where the engine found them, flag IDs wherever they occur."""
        out, taken, counted = [], [], 0
        for key, (tok, outcome) in tokens.items():
            loc = location_of(tok)
            if category(loc) != "body" or tok["parent_id"]:
                continue
            counted += 1
            value = tok["normalized_value"]
            role = self.role(tok["id"], loc, value, tick)
            decoded = next((k["normalized_value"] for k, _ in kids.get(tok["id"], ())
                            if "base64" in (_json(k["transform"]) or [])), None)
            if role is None and outcome and outcome[0] in ("none", "cut") and outcome[1] in OPEN_NOTES \
                    and id_like(value, decoded):
                role = Role(contracts.VALUE_UNKNOWN, ("unknown", tx, key), "unknown", {"reason": outcome[1]})
            if role:
                out.append(self.entry(tx, loc, tok, value, role, var=self.vars.name(role)))
                if len(loc) >= 4 and role.kind != contracts.VALUE_UNKNOWN:
                    taken.append((loc[2], loc[3]))
        for start, end, fid, evidence, ambiguous in self.flag_ids.occurrences(text, tick):
            if any(not (end <= s or start >= e) for s, e in taken):
                continue
            role = self.target_part(fid, evidence, ambiguous)
            loc = ["req", "body", start, end]
            out.append(self.entry(tx, loc, None, fid, role, var=self.vars.name(role)))
            taken.append((start, end))
        return out, counted

    # ── the whole run ───────────────────────────────────────────────────
    def run(self, order, skipped, limits):
        steps, capped = [], False
        for tx in order:
            if tx not in self.examined:
                continue
            parsed, body = self.reader.request_fields(tx, BODY_LIMIT)
            items, _ = extract(parsed, b"", "req", ALL_VALUES)
            fields = []
            for n, item in enumerate(items):
                if item["parent"] is None:
                    fields.append({"location": item["location"], "value": item["value"], "children": []})
                    index = len(fields) - 1
                    item["field"] = index
                else:
                    owner = items[item["parent"]].get("field")
                    if owner is not None:
                        fields[owner]["children"].append({"value": item["value"], "transform": item["transform"]})
            text = body.decode("latin-1") if body else ""
            steps.append((tx, fields, text))
        # Structured values first: if the lookup has to be capped, the body
        # text of large raw payloads is what goes.
        lookups = {}
        for _, fields, _ in steps:
            for f in fields:
                lookups.update(dict.fromkeys(sorted(pieces(f["value"]))))
                for child in f["children"]:
                    # Decoded base64 and JWT claims hold values the raw text hides.
                    lookups.update(dict.fromkeys(sorted(pieces(child["value"]))))
        for _, _, text in steps:
            if text:
                lookups.update(dict.fromkeys(sorted(pieces(text))))
        if len(lookups) > MAX_LOOKUPS:
            capped = True
        self.flag_ids.load(list(lookups)[:MAX_LOOKUPS])

        values, counts, constants = [], {r: 0 for r in contracts.VALUE_ROLES}, 0
        for tx, fields, text in steps:
            tick = self.tick_of(tx)
            info = self.examined[tx]
            tokens = {json.dumps(location_of(t)): (t, o) for t, o in info["tokens"]}
            kids = {}
            for t, o in info["tokens"]:
                if t["parent_id"]:
                    kids.setdefault(t["parent_id"], []).append((t, o))
            for f in fields:
                entry = self.field(tx, tick, f["location"], f["value"], f["children"], tokens, kids)
                if entry is None:
                    constants += 1
                else:
                    values.append(entry)
            body_entries, body_tokens = self.body(tx, tick, text, tokens, kids)
            values += body_entries
            constants += max(0, body_tokens - sum(1 for e in body_entries if e["token_id"]))
        for entry in values:
            counts[entry["role"]] += 1
        counts[contracts.VALUE_CONSTANT] = constants

        # A step the search never opened (depth or budget) has no classified
        # values; one it left part-way has some, the rest unexamined.
        not_classified = []
        for tx in order:
            info = self.examined.get(tx)
            if info is None:
                not_classified.append({"transaction_id": tx, "reason": skipped.get(tx), "partly": False})
            elif not info["complete"]:
                not_classified.append({"transaction_id": tx, "reason": info["reason"], "partly": True})
        truncated = len(values) > MAX_VALUES
        partial = bool(limits or not_classified or capped or truncated or self.flag_ids.capped)
        summary = {"state": "partial" if partial else "computed", "flag_ids": self.flag_ids.summary(),
                   "counts": counts, "steps_classified": len(steps), "steps_not_classified": not_classified,
                   "lookups_capped": capped, "values_truncated": truncated,
                   # Whatever is not listed is sent verbatim.
                   "unlisted_means": contracts.VALUE_CONSTANT}
        return summary, values[:MAX_VALUES]


def classify(reader, cfg, anchor_row, nodes, examined, skipped, edges, order, limits):
    """(summary, values) for one run. `order` is the display order of steps,
    `skipped` says why a step was never examined."""
    return Classifier(reader, cfg, anchor_row, nodes, examined, edges).run(order, skipped, limits)


def _json(value):
    if value is None:
        return None
    return json.loads(value) if isinstance(value, str) else value
