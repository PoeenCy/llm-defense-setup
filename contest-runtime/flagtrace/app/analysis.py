"""Pure transaction enrichment; SQLite mutation is confined to store.py."""
import base64
import hashlib
import json
from collections import OrderedDict

from common import flag_decoders
from .parsing import parse_message
from .tokens import extract

# Decoder result cache. Most bodies have no finding and cost an entry of a few
# dozen bytes; the byte cap is what bounds the bodies whose decodings are kept.
CACHE_ENTRIES = 4096
CACHE_BYTES = 64 * 1024 * 1024


def uid(*parts):
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


def transaction_id(cfg, record):
    """Known before enrichment, so a transaction already stored (a replayed
    capture after a restart) is skipped without parsing or decoding it again."""
    return uid(cfg.game_id, record["conn_id"], record["seq"])


class Decoder:
    """The flag decoder as ingest runs it: per mode, with identical bodies
    decoded once.

    The same exploit or the same static page arrives over and over, so a
    finished search is reused by body content and flag regex. A search that
    ran out of budget is not reused: it stopped at an arbitrary point, and
    another try may get further. The search depends only on the body (the
    flags already visible in it are part of the body), so a reused result is
    the result the decoder would have produced.
    """

    def __init__(self, cfg, mode=None, entries=CACHE_ENTRIES, max_bytes=CACHE_BYTES):
        self.cfg = cfg
        self.mode = mode or cfg.options["decoder_mode"]
        self.entries, self.max_bytes = entries, max_bytes
        self.cache, self.bytes = OrderedDict(), 0
        self.stats = {"searched": 0, "cache_hits": 0, "exhausted": 0, "skipped_gated": 0, "skipped_off": 0}

    def search(self, body):
        """(findings as (path, data) pairs, exhausted, skip reason or None)."""
        if self.mode == "off":
            self.stats["skipped_off"] += 1
            return (), False, "decoder_off"
        if self.mode == "gated" and not flag_decoders.looks_encoded(body):
            self.stats["skipped_gated"] += 1
            return (), False, "decoder_gated"
        regex = self.cfg.regex
        key = hashlib.sha256(regex.pattern + b"\0" + body).digest()
        cached = self.cache.get(key)
        if cached is not None:
            self.cache.move_to_end(key)
            self.stats["cache_hits"] += 1
            return cached, False, None
        engine = flag_decoders.Engine(regex, budget=self.cfg.options["decode_budget"],
                                      known_flags={m.group() for m in regex.finditer(body)})
        findings = tuple((f.path, f.data) for f in engine.search(body))
        self.stats["searched"] += 1
        if engine.exhausted():
            self.stats["exhausted"] += 1
            return findings, True, None
        self._remember(key, findings)
        return findings, False, None

    def _remember(self, key, findings):
        size = len(key) + sum(len(path) + len(data) for path, data in findings)
        if not self.entries or size > self.max_bytes // 16:
            return
        self.cache[key] = findings
        self.bytes += size
        while len(self.cache) > self.entries or self.bytes > self.max_bytes:
            old_key, old = self.cache.popitem(last=False)
            self.bytes -= len(old_key) + sum(len(path) + len(data) for path, data in old)

    def status(self):
        return {**self.stats, "cache_entries": len(self.cache), "cache_bytes": self.bytes}


def enrich(record, cfg, decoder=None):
    """`decoder` carries the mode and the result cache across transactions;
    without one the body is decoded in the configured mode, uncached."""
    tag = cfg.tag(record)
    txid = transaction_id(cfg, record)
    decoder = decoder or Decoder(cfg, entries=0)
    reps, tokens, sightings, parsed = [], [], [], {}
    issues = list(record.get("quality") or [])
    scan_limit, store_limit = cfg.options["max_scan_bytes"], cfg.options["max_body_stored"]

    def representation(side, kind, data, parent=None, transform=None, spans=None):
        rid = uid(txid, side, kind, len(reps))
        reps.append({"id": rid, "side": side, "kind": kind, "data": data[:store_limit],
                     "parent_id": parent, "transform": transform or [], "spans": spans or [],
                     "original_size": len(data), "truncated": int(len(data) > store_limit)})
        for m in cfg.regex.finditer(data[:scan_limit]):
            sightings.append({"representation_id": rid, "value": m.group().decode("utf-8", "replace"),
                              "side": side, "start": m.start(), "end": m.end()})
        if len(data) > scan_limit:
            issues.append(side + ":scan_truncated")
        if len(data) > store_limit:
            issues.append(side + ":storage_truncated")
        return rid

    for side, field in (("req", "request"), ("resp", "response")):
        raw = base64.b64decode(record[field].get("data") or "", validate=True)
        rid = representation(side, "raw", raw, spans=record[field].get("spans"))
        p, body = ({"body_type": "raw", "issues": []}, raw[:scan_limit])
        if record["proto"] == "http" and raw:
            try:
                p, body = parse_message(raw, side == "req", scan_limit)
            except (ValueError, RecursionError) as exc:
                issues.append(side + ":parse_error:" + type(exc).__name__)
        issues.extend(side + ":" + x for x in p.get("issues", []))
        parsed[side] = p
        body_rid = representation(side, "body", body, rid, ["http_body"] if record["proto"] == "http" else [])
        extracted, capped = extract(p, body, side, cfg.options["token"])
        if capped:
            issues.append(side + ":token_limit")
        ids = [uid(txid, side, "token", n) for n in range(len(extracted))]
        for n, token in enumerate(extracted):
            # Header/path values belong to the raw message. Body offsets refer
            # to the body representation, never to compressed wire bytes.
            category = token["location"][1]
            tokens.append({**token, "id": ids[n], "parent_id": ids[token["parent"]] if token["parent"] is not None else None,
                           "representation_id": rid if category in ("cookie", "header", "path", "query") else body_rid,
                           "observed_ts": (record[field].get("end_ts") if side == "resp" else record[field].get("ts")) or record["request"]["ts"]})
        # Work directly on the reconstructed body. No packet-level encoding
        # heuristic: a flag may straddle packets or occur in a nested field.
        if body and cfg.options["decode_budget"]:
            findings, exhausted, skipped = decoder.search(body)
            for path, data in findings:
                representation(side, "decoded", data, body_rid, [path])
            if exhausted:
                issues.append(side + ":decode_budget_exhausted")
            if skipped:
                # Not decoded by choice: "no flag here" must not be read from it.
                issues.append(side + ":" + skipped)
    outgoing = {s["value"] for s in sightings if s["side"] == "resp"}
    incoming = {s["value"] for s in sightings if s["side"] == "req"}
    unsafe = any(x in issues for x in ("ambiguous_direction", "encrypted", "http2_unsupported", "upgraded_protocol"))
    if tag["is_checker"]:
        classification = "checker"
    elif not outgoing:
        classification = "no_flag_observed"
    elif outgoing <= incoming:
        classification = "echo"
    elif unsafe:
        classification = "unclassified"
    else:
        classification = "flag_out_candidate"
    return {"id": txid, "record": record, "tag": tag, "parsed": parsed, "representations": reps,
            "tokens": tokens, "sightings": sightings, "quality": sorted(set(issues)),
            "flags_found": sorted(outgoing), "flag_out": classification == "flag_out_candidate", "classification": classification}
