"""Identities, statuses and the result shape Phase 2 commits and serves.

Three identities stay separate on purpose (INTEGRATION_BASELINE 3.1):

  transaction_id  one ingested request/response pair or raw TCP segment
  trace_id        the profile of one anchor transaction, stable across analyses
  run_id          one analysis result, bound to exactly one job

None of them is a Tulip flow ID. A reference to Tulip belongs in its own field
with a source and a confidence, never in place of one of these.

Execution state (job pending/running/done/failed) and evidence state (run
seed_only/linked/partial) are also separate: a finished job only means the
snapshot it saw was processed, not that an exploit chain was reproduced.
"""
import json
from dataclasses import asdict, dataclass, field

from ..analysis import uid

# Bumped when the algorithm changes in a way that makes old results stale.
# Independent of the DB schema version and of the ingest config version.
# p2.3.2: a result holds only the flag-out and the steps linked to it by value;
# nearby "context" traffic is no longer collected.
# p2.4.0: value roles (B6) are computed with every run.
# p2.5.x: immutable per-request and HTTP-chain artifacts are computed.
# p2.5.1: chain group (B7) and suspicious steps against the checker baseline
# (B8) are computed with every run.
ENGINE_VERSION = "p2.5.1"

# Job lifecycle. 'running' means leased by a worker; the lease, not the status,
# decides whether that worker may still commit.
JOB_PENDING, JOB_RUNNING, JOB_DONE, JOB_FAILED = "pending", "running", "done", "failed"
JOB_STATUSES = (JOB_PENDING, JOB_RUNNING, JOB_DONE, JOB_FAILED)

# Evidence state of a committed run.
RUN_SEED_ONLY = "seed_only"   # anchor stored, token linking not computed
RUN_LINKED = "linked"         # engine ran to completion within its budgets
RUN_PARTIAL = "partial"       # engine stopped on a budget/limit, result is cut
RUN_STATES = (RUN_SEED_ONLY, RUN_LINKED, RUN_PARTIAL)

# Step roles, as rendered in the UI. A result is the flow only: the flag-out
# and the steps a value links to it. Being near in time or on the same
# connection is not evidence and does not make a step.
ROLE_ANCHOR = "anchor"            # Phase 1 saw a response flag here and enqueued it
ROLE_DATA_LINKED = "data_linked"  # carries at least one value edge
ROLES = (ROLE_ANCHOR, ROLE_DATA_LINKED)
# Written by engines before p2.3.2 only. Such rows may still be stored in older
# runs; readers leave them out.
ROLE_CONTEXT = "context"

# Why a step is in the result.
REASON_FLAG_OUT = "flag_out"
REASON_TOKEN_LINK = "token_link"

# Edge kinds. The distinction is the whole point: a response really carried the
# value, versus the value was merely reused from an earlier request.
EDGE_RESPONSE_TO_REQUEST = "response_to_request"
EDGE_REQUEST_REUSE = "request_reuse"
EDGE_KINDS = (EDGE_RESPONSE_TO_REQUEST, EDGE_REQUEST_REUSE)

# Limits that can cut a result short; each one is reported by name.
LIMIT_DEADLINE = "algorithm_budget_ms"
LIMIT_DEPTH = "max_depth"
LIMIT_NODES = "max_nodes"
LIMIT_EDGES = "max_edges"
LIMIT_TOKENS = "max_tokens_per_node"
LIMIT_CANDIDATES = "max_candidates_per_token"
LIMIT_QUERY_ROWS = "max_query_rows"

# Value roles (B6): what each value a chain sends is, which is what decides how
# a script obtains it. Constants are counted, not listed: anything a result does
# not list is sent verbatim.
VALUE_LINKED = "linked"         # an earlier response carried it: extract it from there
VALUE_GENERATED = "generated"   # first sent by the attacker and reused later: make one up
VALUE_TARGET = "target"         # no source, matches this team's flag ID: a parameter
VALUE_UNKNOWN = "unknown"       # looks like an identifier, nothing explains it
VALUE_CONSTANT = "constant"
VALUE_ROLES = (VALUE_LINKED, VALUE_GENERATED, VALUE_TARGET, VALUE_UNKNOWN, VALUE_CONSTANT)
# Why a value is taken for a flag ID, strongest first.
BASIS_SAME_PUT = "same_put_session"   # seen in the checker session that stored the leaked flag
BASIS_PUT_TICK = "put_tick"           # flag ID of the tick the leaked flag was stored in
BASIS_WINDOW = "validity_window"      # within game.flag_validity_ticks of the request
BASIS_EARLIER = "earlier_tick"        # some earlier tick; no validity window configured
FLAG_ID_BASES = (BASIS_SAME_PUT, BASIS_PUT_TICK, BASIS_WINDOW, BASIS_EARLIER)

# Script support and replay verification are independent. A supported script
# has not necessarily been run, and reproduced is reserved for a recorded
# local-fixture execution of the exact artifact hash.
SCRIPT_SUPPORTED = "supported"
SCRIPT_NEEDS_EDIT = "needs_edit"
SCRIPT_UNSUPPORTED = "unsupported"
SCRIPT_SUPPORT = (SCRIPT_SUPPORTED, SCRIPT_NEEDS_EDIT, SCRIPT_UNSUPPORTED)
VERIFY_NOT_RUN = "not_run"
VERIFY_REPRODUCED = "reproduced"
VERIFY_FAILED = "failed"
VERIFY_STATES = (VERIFY_NOT_RUN, VERIFY_REPRODUCED, VERIFY_FAILED)

# P2.4/P2.5 sections are declared and explicitly not computed rather than
# returned as empty results, which would read as "nothing found".
NOT_COMPUTED = {"state": "not_computed"}
EXTENSION_SECTIONS = ("value_roles", "grouping", "suspects", "scripts")


def trace_id(game_id, anchor_transaction_id):
    return uid("trace", game_id, anchor_transaction_id)


def job_id(trace, trigger_key):
    """Deterministic in the trigger key: re-delivering the same trigger (PCAP
    replay, a resent retrace request) addresses the same job row."""
    return uid("job", trace, trigger_key)


def run_id(job):
    """One job has at most one successful run, so the run ID follows the job.
    A retried attempt that crashed after commit cannot create a second run."""
    return uid("run", job)


def value_key(transaction_id, location):
    """Identity of one classified request field inside a run."""
    return uid("value", transaction_id, json.dumps(location, separators=(",", ":")))


def evidence_key(kind, dst_token_id, dst_location, src_token_id):
    """Identity of one edge inside a run. Tokens may be absent on either end
    (raw TCP, values only present in parsed fields), so the location is part
    of the key as well."""
    return uid("edge", kind, dst_token_id or "", json.dumps(dst_location, separators=(",", ":")), src_token_id or "")


def artifact_id(run, kind, transaction_id, exporter_version, content_hash):
    return uid("artifact", run, kind, transaction_id or "", exporter_version, content_hash)


def verification_id(artifact, artifact_hash, fixture, started):
    return uid("verification", artifact, artifact_hash, fixture, started)


@dataclass
class Anchor:
    """The flag-out transaction a profile is about."""
    transaction_id: str
    game_id: str
    source_key: str
    team_id: str | None
    service: str
    tick: int | None
    conn_id: str | None
    seq_in_conn: int | None
    ts_request: int | None
    ts_response: int | None
    method: str | None
    path: str | None
    status: int | None
    proto: str | None
    classification: str = ""
    flags_found: list = field(default_factory=list)
    # Flags echoed back in the same transaction are evidence of a different
    # thing than flags the response added; B1 classification keeps both.
    flags_echoed: list = field(default_factory=list)
    quality: list = field(default_factory=list)


@dataclass
class Step:
    transaction_id: str
    position: int
    role: str
    reasons: list = field(default_factory=list)
    quality: list = field(default_factory=list)
    # Display-only summary so a timeline renders without a second round trip.
    summary: dict = field(default_factory=dict)


@dataclass
class Edge:
    kind: str
    dst_transaction_id: str
    dst_token_id: str | None
    dst_location: list
    dst_representation_id: str | None
    dst_observed_ts: int | None
    src_transaction_id: str | None
    src_token_id: str | None
    src_location: list | None
    src_representation_id: str | None
    src_observed_ts: int | None
    value_preview: str
    value_length: int
    transform: list = field(default_factory=list)
    # True when several sources scored equally; alternatives lists the ones not
    # chosen, within the configured limit.
    ambiguous: bool = False
    alternatives: list = field(default_factory=list)
    note: str = ""

    def key(self):
        return evidence_key(self.kind, self.dst_token_id, self.dst_location, self.src_token_id)


@dataclass
class Coverage:
    """What was looked at, and what was deliberately left out."""
    window_start_us: int | None = None
    window_end_us: int | None = None
    snapshot_wall: float = 0.0
    same_service_only: bool = True
    scope: dict = field(default_factory=dict)
    limits_hit: list = field(default_factory=list)
    # Consumed values with no acceptable source. Distinguishes "no link exists"
    # from "the search stopped early", which limits_hit covers.
    unexplained: list = field(default_factory=list)
    counters: dict = field(default_factory=dict)
    # Capture/decode issues counted over the steps of the result.
    ingest_quality: dict = field(default_factory=dict)
    # Game-wide capture problems at snapshot time (rejected/failed/late files).
    ingest_gaps: dict = field(default_factory=dict)


@dataclass
class RunResult:
    """The engine's output. Pure data: no SQL, no HTTP, no Redis."""
    state: str
    anchor: Anchor
    steps: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)
    warnings: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    analysis: dict = field(default_factory=dict)
    # Summary plus "values"; None when the run did not classify (seed mode).
    value_roles: dict | None = None
    # Summary plus in-memory artifact contents. The repository stores contents
    # in their own table; API run details only return bounded metadata.
    scripts: dict | None = None
    # The chain's shape and group ID (grouping.py), and the steps that differ
    # from the checker baseline as {summary, steps} (anomalies.py).
    grouping: dict | None = None
    suspects: dict | None = None

    def extensions(self):
        out = {name: dict(NOT_COMPUTED) for name in EXTENSION_SECTIONS}
        if self.value_roles is not None:
            out["value_roles"] = self.value_roles
        if self.scripts is not None:
            out["scripts"] = self.scripts
        if self.grouping is not None:
            out["grouping"] = self.grouping
        if self.suspects is not None:
            out["suspects"] = self.suspects
        return out

    def dto(self):
        """Serialized shape served by the API and asserted by the fixtures."""
        return {"state": self.state, "anchor": asdict(self.anchor),
                "steps": [asdict(s) for s in self.steps], "edges": [asdict(e) for e in self.edges],
                "coverage": asdict(self.coverage), "warnings": list(self.warnings),
                "metrics": dict(self.metrics), "analysis": dict(self.analysis), **self.extensions()}
