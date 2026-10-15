"""One config snapshot per ingest generation; no dependencies beyond stdlib."""
import hashlib
import ipaddress
import json
import math
import re
from datetime import datetime
from pathlib import Path

DEFAULTS = {
    "enabled": False, "capture_source": "vulnbox", "idle_seconds": 120,
    "max_age_seconds": 600, "max_connection_bytes": 8 * 1024 * 1024,
    "max_connections": 4096, "max_body_stored": 1024 * 1024,
    "max_scan_bytes": 2 * 1024 * 1024, "decode_budget": 0.1, "decoder_mode": "full",
    "poll_seconds": 2, "baseline_ticks": 10, "min_free_gb": 1, "max_file_attempts": 3,
    "token": {"min_len": 6, "struct_min_len": 2, "sub_min_len": 3, "max_tokens": 2000,
              "stoplist": ["true", "false", "null", "admin", "user", "login", "notes", "http", "https"]},
    "trace": {},
}

# How much of the flag decoder ingest runs. "full" decodes every body; "gated"
# only bodies the cheap looks_encoded() check flags, as detection does; "off"
# none, so a flag that only shows after decoding is not seen. The dashboard can
# override the configured mode at runtime (runtime_settings), file by file.
DECODER_MODES = ("full", "gated", "off")

# Phase 2 worker. These are starting values for tuning, not benchmarked ones.
TRACE_DEFAULTS = {
    "enabled": False, "poll_seconds": 1, "lease_seconds": 30, "max_attempts": 3,
    "algorithm_budget_ms": 1000, "max_depth": 8, "max_nodes": 64, "max_edges": 256,
    "max_tokens_per_node": 128, "max_candidates_per_token": 8, "max_query_rows": 5000,
    "same_service_only": True, "token_max_df": 0.3, "df_min_samples": 100,
}
# Nearby-traffic "context" was dropped in engine p2.3.2; its settings are named
# in the error so an old services.json says what to remove.
TRACE_REMOVED_KEYS = ("max_context", "context_window_seconds", "burst_gap_seconds")
# Only these keys change what an analysis means. Polling, leases and retry
# counts are operational, so changing them must not invalidate stored results
# or suggest a new analysis is warranted.
TRACE_ALGORITHM_KEYS = ("algorithm_budget_ms", "max_depth", "max_nodes", "max_edges",
                        "max_tokens_per_node", "max_candidates_per_token", "max_query_rows",
                        "same_service_only", "token_max_df", "df_min_samples")


def config_hash(algorithm):
    return hashlib.sha256(json.dumps(algorithm, sort_keys=True).encode()).hexdigest()


class Config:
    def __init__(self, raw):
        self.raw = raw
        block = raw.get("flagtrace") or {}
        self.options = {**DEFAULTS, **block, "token": {**DEFAULTS["token"], **block.get("token", {})},
                        "trace": {**TRACE_DEFAULTS, **(block.get("trace") or {})}}
        for key in ("idle_seconds", "max_age_seconds", "max_connection_bytes", "max_connections",
                    "max_body_stored", "max_scan_bytes", "poll_seconds", "baseline_ticks",
                    "max_file_attempts"):
            v = self.options[key]
            if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= 2**30:
                raise ValueError(f"flagtrace.{key} must be a positive integer")
        for key in ("decode_budget", "min_free_gb"):
            if not isinstance(self.options[key], (int, float)) or not math.isfinite(self.options[key]) or self.options[key] < 0:
                raise ValueError(f"invalid flagtrace.{key}")
        if self.options["decoder_mode"] not in DECODER_MODES:
            raise ValueError("flagtrace.decoder_mode must be one of " + ", ".join(DECODER_MODES))
        for key in ("min_len", "struct_min_len", "sub_min_len", "max_tokens"):
            if not isinstance(self.options["token"][key], int) or self.options["token"][key] < 1:
                raise ValueError(f"invalid token.{key}")
        self.validate_trace()
        game = raw.get("game") or {}
        self.game_id = str(game.get("id") or "")
        if not self.game_id or not game.get("start_time"):
            raise ValueError("game.id and game.start_time are required when Flag-trace is enabled")
        start = datetime.fromisoformat(game["start_time"].replace("Z", "+00:00"))
        if start.tzinfo is None:
            raise ValueError("game.start_time must include a timezone")
        self.start_us = int(start.timestamp() * 1_000_000)
        seconds = game.get("tick_seconds")
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds <= 0:
            raise ValueError("game.tick_seconds must be positive")
        self.tick_us = int(seconds * 1_000_000)
        # How many ticks a flag stays valid, from the rules of the game. Optional:
        # without it, a flag ID of any earlier tick is accepted and said so.
        validity = game.get("flag_validity_ticks")
        if validity is not None and (isinstance(validity, bool) or not isinstance(validity, int) or validity < 1):
            raise ValueError("game.flag_validity_ticks must be a positive integer")
        self.flag_validity_ticks = validity
        # Captures are taken on this team's vulnbox, so every flag-out leaks a
        # flag this team owns; flag IDs are matched against this owner.
        self.team_id = str(raw["team_id"]) if raw.get("team_id") else None
        self.checkers =[ipaddress.ip_network(x, strict=False) for x in game.get("checker_ips", [])]
        self.networks = []
        seen = set()
        for team in raw.get("teams", []):
            tid = str(team["id"])
            if tid in seen:
                raise ValueError(f"duplicate team id {tid}")
            seen.add(tid)
            for ip in team.get("ips", []):
                net = ipaddress.ip_network(ip, strict=False)
                if any(other.version == net.version and other.overlaps(net) and owner != tid for other, owner in self.networks):
                    raise ValueError(f"team network overlaps another team: {ip}")
                self.networks.append((net, tid))
        self.regex = re.compile(raw["flag"]["regex"].encode())
        if self.regex.search(b""):
            raise ValueError("flag.regex must not match empty bytes")
        self.endpoints = []
        self.services = {}
        for svc in raw["services"]:
            if svc.get("proto") != "tcp":
                continue
            ips = svc.get("capture_ips") or [raw["vulnbox"]["ip"]]
            for ip in ips:
                ip = str(ipaddress.ip_address(ip))
                for port in {svc["port"], svc.get("capture_port", svc["port"])}:
                    if not isinstance(port, int) or not 1 <= port <= 65535:
                        raise ValueError("invalid service port")
                    if (ip, port) in self.services and self.services[ip, port] != svc["name"]:
                        raise ValueError("ambiguous service endpoint")
                    self.services[ip, port] = svc["name"]
                    self.endpoints.append({"ip": ip, "port": port, "layer": svc.get("layer", "l4-raw")})
        if not self.endpoints:
            raise ValueError("Flag-trace needs at least one TCP service")
        self.version = hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()

    def validate_trace(self):
        trace = self.options["trace"]
        removed = sorted(set(trace) & set(TRACE_REMOVED_KEYS))
        if removed:
            raise ValueError("flagtrace.trace keys no longer used (context was removed): " + ", ".join(removed))
        unknown = set(trace) - set(TRACE_DEFAULTS)
        if unknown:
            raise ValueError("unknown flagtrace.trace keys: " + ", ".join(sorted(unknown)))
        if not isinstance(trace["enabled"], bool):
            raise ValueError("flagtrace.trace.enabled must be boolean")
        if trace["enabled"] and not self.options.get("enabled"):
            raise ValueError("flagtrace.trace.enabled requires flagtrace.enabled")
        for key in ("poll_seconds", "lease_seconds", "max_attempts", "algorithm_budget_ms", "max_depth",
                    "max_nodes", "max_edges", "max_tokens_per_node", "max_candidates_per_token",
                    "max_query_rows", "df_min_samples"):
            v = trace[key]
            if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= 2**30:
                raise ValueError(f"flagtrace.trace.{key} must be a positive integer")
        df = trace["token_max_df"]
        if isinstance(df, bool) or not isinstance(df, (int, float)) or not math.isfinite(df) or not 0 < df <= 1:
            raise ValueError("flagtrace.trace.token_max_df must be in (0, 1]")
        # A computation that may outlive its own lease would let a second worker
        # start the job while the first still intends to commit it.
        if trace["algorithm_budget_ms"] >= trace["lease_seconds"] * 1000:
            raise ValueError("flagtrace.trace.algorithm_budget_ms must be below lease_seconds")
        # Cross-service linking is not validated yet, so refuse it outright
        # rather than advertise a scope the engine has not been accepted for.
        if trace["same_service_only"] is not True:
            raise ValueError("flagtrace.trace.same_service_only must be true in this release")

    def algorithm_config(self):
        return {k: self.options["trace"][k] for k in TRACE_ALGORITHM_KEYS}

    def algorithm_hash(self):
        return config_hash(self.algorithm_config())

    @classmethod
    def load(cls, path):
        return cls(json.loads(Path(path).read_text()))

    def tag(self, record):
        ip = ipaddress.ip_address(record["src_ip"])
        team = next((tid for net, tid in self.networks if ip in net), None)
        checker = any(ip in net for net in self.checkers)
        return {"team_id": team, "source_key": f"team:{team}" if team else f"ip:{ip}",
                "is_checker": checker, "service": self.services.get((record["dst_ip"], record["dst_port"]), "unknown"),
                "tick": (record["request"]["ts"] - self.start_us) // self.tick_us}

    def transport(self):
        return {**{k: self.options[k] for k in ("idle_seconds", "max_age_seconds", "max_connection_bytes", "max_connections")},
                "endpoints": self.endpoints}


def validate_optional(raw):
    block = raw.get("flagtrace") or {}
    if not isinstance(block.get("enabled", False), bool):
        raise ValueError("flagtrace.enabled must be boolean")
    trace = block.get("trace") or {}
    if not isinstance(trace, dict):
        raise ValueError("flagtrace.trace must be an object")
    # Caught here too: with Flag-trace off the full Config is never built, and
    # an enabled worker block would otherwise pass validation unnoticed.
    if trace.get("enabled") and not block.get("enabled"):
        raise ValueError("flagtrace.trace.enabled requires flagtrace.enabled")
    if block.get("enabled"):
        Config(raw)
