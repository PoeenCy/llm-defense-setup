"""Backwards value tracing from one flag-out transaction.

What this produces is an evidence graph, not a verdict. An edge says the same
value was observed in an earlier message and in this request; it does not prove
the earlier request caused this one. Everything that could not be explained,
and every limit that cut the search short, is reported alongside, because
"no link exists" and "the search stopped" must not look the same on screen.

Scope is one game, one source key and (in this release) one service, with the
checker excluded: its traffic carries the same flag IDs as every team and would
otherwise link all of them together.

The result is the flow only: the flag-out plus every step a value links to it.
Traffic that is merely near in time or shares a connection is not evidence, so
it is not collected: a one-request flag-out is a one-step result.
"""
import json
import time
from collections import deque

from ..config import config_hash
from ..parsing import path_template
from . import anomalies, contracts, export, grouping, values
from .repository import BODY_CATEGORY, CATEGORY_RANK, RowBudget, category, location_of

PREVIEW = 64
MAX_UNEXPLAINED = 50
# Quality tags that mean bytes are missing, as opposed to a decode limit.
INCOMPLETE_MARKERS = ("incomplete", "truncated", "missing", "parse_error", "gap")
# Structured categories, used both for ranking and for deciding whether two
# fields are compatible enough to call one a reuse of the other.
STRUCTURED = tuple(k for k in CATEGORY_RANK if k != BODY_CATEGORY)
# Values that read like words rather than identifiers, where they sit in a path
# or are a fragment split out of a longer value. Linked only on strong evidence.
LITERAL_REASONS = ("endpoint_literal", "literal_fragment")


def preview(value):
    value = str(value)
    return value[:PREVIEW] + ("…" if len(value) > PREVIEW else "")


class Engine:
    def __init__(self, reader, cfg, mode="full", algorithm=None):
        """`algorithm` is the job's config snapshot. A job enqueued under one
        config and executed after a restart under another still runs, and is
        recorded, with the settings it was requested with."""
        self.reader, self.cfg, self.mode = reader, cfg, mode
        self.trace = {**cfg.options["trace"], **(algorithm or {})}
        self.algorithm = {k: self.trace[k] for k in cfg.algorithm_config()}
        self.algorithm_hash = config_hash(self.algorithm)
        self.token_cfg = cfg.options["token"]
        self.stoplist = {x.lower() for x in self.token_cfg["stoplist"]}
        self.regex = cfg.regex

    # ── entry point ─────────────────────────────────────────────────────
    def analyse(self, anchor_id):
        started = time.monotonic()
        deadline = started + self.trace["algorithm_budget_ms"] / 1000.0
        budget = RowBudget(self.trace["max_query_rows"])
        self.reader.budget = budget
        counters = {"tokens_considered": 0, "tokens_skipped": {}, "candidates_examined": 0,
                    "queries": 0, "edges": 0, "nodes": 0}
        limits, warnings = [], []

        row = self.reader.transaction(anchor_id)
        if row is None:
            raise LookupError(f"anchor transaction {anchor_id} is not in this game")
        anchor = self._anchor(row)
        service = row["service"] if self.trace["same_service_only"] else None
        nodes = {anchor_id: {"row": row, "role": contracts.ROLE_ANCHOR,
                             "reasons": [contracts.REASON_FLAG_OUT]}}
        edges, unexplained = [], []
        if row["proto"] != "http":
            warnings.append("raw TCP anchor: Phase 1 tokens come from the merged body of each direction, "
                            "so automatic linking is coarser than for HTTP")
        if row["is_checker"]:
            warnings.append("anchor is checker traffic; it would not normally be enqueued")

        if self.mode == "seed":
            # P2.1 behaviour, kept reachable: store the anchor and say plainly
            # that linking was not attempted rather than return an empty graph.
            result = self._result(contracts.RUN_SEED_ONLY, anchor, nodes, edges, unexplained, limits,
                                  warnings, counters, budget, started)
            result.analysis["linking"] = dict(contracts.NOT_COMPUTED)
            return result

        # ── backwards BFS over consumed values ──────────────────────────
        # What happened to every value of every step searched is kept for the
        # value roles (B6); a step never opened is recorded with the reason.
        queue = deque([(anchor_id, 0)])
        seen_tokens = set()
        examined, skipped, stopped = {}, {}, None
        while queue:
            stopped = self._stop(deadline, budget, limits)
            if stopped:
                break
            tx_id, depth = queue.popleft()
            node_row = nodes[tx_id]["row"]
            if depth >= self.trace["max_depth"]:
                self._note(limits, contracts.LIMIT_DEPTH)
                skipped[tx_id] = contracts.LIMIT_DEPTH
                continue
            counters["queries"] += 1
            tokens = self.reader.consumed_tokens(tx_id, self.trace["max_tokens_per_node"] + 1)
            info = examined[tx_id] = {"tokens": [], "complete": True, "reason": None}
            seen = info["tokens"].append
            if len(tokens) > self.trace["max_tokens_per_node"]:
                self._note(limits, contracts.LIMIT_TOKENS)
                tokens = tokens[:self.trace["max_tokens_per_node"]]
                info.update(complete=False, reason=contracts.LIMIT_TOKENS)
            for token in tokens:
                stopped = self._stop(deadline, budget, limits)
                if stopped:
                    info.update(complete=False, reason=stopped)
                    break
                if token["id"] in seen_tokens:
                    continue
                seen_tokens.add(token["id"])
                counters["tokens_considered"] += 1
                reason = self._noise(token, node_row["service"])
                literal = reason in LITERAL_REASONS
                if reason and not literal:
                    counters["tokens_skipped"][reason] = counters["tokens_skipped"].get(reason, 0) + 1
                    seen((token, ("noise", reason)))
                    continue
                edge, note = self._link(token, node_row, service, counters, literal=literal)
                if edge is None and literal:
                    # No structured response produced it, so it is what it
                    # looked like: part of the endpoint, not a value.
                    counters["tokens_skipped"][reason] = counters["tokens_skipped"].get(reason, 0) + 1
                    seen((token, ("noise", reason)))
                    continue
                if edge is None:
                    if len(unexplained) < MAX_UNEXPLAINED:
                        unexplained.append({"transaction_id": tx_id, "token_id": token["id"],
                                            "location": location_of(token), "category": category(token["location"]),
                                            "value_preview": preview(token["normalized_value"]),
                                            "value_length": len(token["normalized_value"]), "reason": note})
                    seen((token, ("none", note)))
                    continue
                # The source has to become a step before the edge is kept: an
                # edge pointing at a step the result does not hold could not be
                # shown or opened. A source left out by the node budget makes
                # the result partial, it is not "no source".
                src = edge.src_transaction_id
                known = src in nodes
                if not known:
                    if len(nodes) >= self.trace["max_nodes"]:
                        self._note(limits, contracts.LIMIT_NODES)
                        seen((token, ("cut", contracts.LIMIT_NODES)))
                        continue
                    src_row = self.reader.transaction(src)
                    if src_row is None:
                        seen((token, ("none", "source_missing")))
                        continue
                if len(edges) >= self.trace["max_edges"]:
                    self._note(limits, contracts.LIMIT_EDGES)
                    info.update(complete=False, reason=contracts.LIMIT_EDGES)
                    break
                edges.append(edge)
                seen((token, ("edge", edge)))
                counters["edges"] += 1
                if not known:
                    nodes[src] = {"row": src_row, "role": contracts.ROLE_DATA_LINKED,
                                  "reasons": [contracts.REASON_TOKEN_LINK]}
                    queue.append((src, depth + 1))
        for tx_id in nodes:
            if tx_id not in examined and tx_id not in skipped:
                skipped[tx_id] = stopped or "not_reached"

        counters["nodes"] = len(nodes)
        state = contracts.RUN_PARTIAL if limits else contracts.RUN_LINKED
        roles, listed = values.classify(self.reader, self.cfg, row, nodes, examined, skipped, edges,
                                        self._order(nodes), limits)
        result = self._result(state, anchor, nodes, edges, unexplained, limits, warnings, counters,
                              budget, started)
        result.analysis["value_roles"] = roles
        result.metrics["values"] = len(listed)
        result.value_roles = {**roles, "values": listed}
        scripts = export.build(self.reader, self.cfg, result, listed)
        # Contents live in trace_script_artifacts; the run's immutable analysis
        # keeps only the version/status summary.
        result.analysis["scripts"] = {k: v for k, v in scripts.items() if k != "artifacts"}
        result.metrics["script_artifacts"] = len(scripts["artifacts"])
        # Same snapshot as the trace: the group and the baseline comparison
        # describe exactly the steps this run found.
        order = self._order(nodes)
        result.grouping = grouping.signature(self.reader, row["game_id"], row["service"], nodes, order)
        result.analysis["grouping"] = {k: v for k, v in result.grouping.items() if k != "shape"}
        summary, flagged = anomalies.check(self.reader, row["game_id"], row["service"], nodes, order)
        result.suspects = {**summary, "steps": flagged}
        result.analysis["suspects"] = summary
        result.metrics["duration_ms"] = round((time.monotonic() - started) * 1000, 3)
        result.scripts = scripts
        return result

    # ── linking ─────────────────────────────────────────────────────────
    def _link(self, token, node_row, service, counters, literal=False):
        """Choose one source for a consumed value, or explain why there is none.

        A word-like value in a path ("files", "dgfile") or split out of a longer
        value ("image" from "image-sharing") is only linked when a structured
        response field produced exactly that value as a whole: then it was an
        ID after all. Free text and other fragments are not enough, since words
        like these occur in every page, and it never takes the request-reuse
        fallback, since every call to an endpoint reuses its name.
        """
        value, used_at = token["normalized_value"], token["observed_ts"]
        limit = self.trace["max_candidates_per_token"]
        counters["queries"] += 1
        produced = self.reader.produced_candidates(value, service, node_row["source_key"], used_at,
                                                   node_row["id"], limit)
        counters["candidates_examined"] += len(produced)
        if literal:
            produced = [c for c in produced if category(c["location"]) in STRUCTURED and not c["parent_id"]]
        usable, rejected = self._filter_time(produced, token, node_row)
        if usable:
            best, alternatives, ambiguous = self._rank(usable, token, node_row)
            return self._edge(contracts.EDGE_RESPONSE_TO_REQUEST, token, best, alternatives, ambiguous,
                              "response carried this value"), None
        if literal:
            return None, "literal"
        counters["queries"] += 1
        reused = self.reader.consumed_candidates(value, service, node_row["source_key"], used_at,
                                                 node_row["id"], limit)
        counters["candidates_examined"] += len(reused)
        usable, rejected_reuse = self._filter_time(reused, token, node_row)
        # Compatible means the same kind of field: a form value reused in a form
        # field. This is how register → login is linked when no response ever
        # carried the value; it is an inference from reuse, not a transfer.
        # The same field of the same endpoint is not a hand-over between steps
        # but the step repeated: two runs of one exploit both send its constant
        # payload, and linking them would merge two separate chains.
        here = _step_key(node_row["method"], node_row["path"], token)
        compatible = [c for c in usable if category(c["location"]) == category(token["location"])
                      and _step_key(c["method"], c["path"], c) != here]
        if compatible:
            earliest = min(c["observed_ts"] for c in compatible)
            first = [c for c in compatible if c["observed_ts"] == earliest]
            best = sorted(first, key=lambda c: c["id"])[0]
            alternatives = [self._alternative(c) for c in compatible if c["id"] != best["id"]][:limit]
            return self._edge(contracts.EDGE_REQUEST_REUSE, token, best, alternatives, len(first) > 1,
                              "first observed use of this value in a compatible field"), None
        if any(category(c["location"]) == category(token["location"]) for c in usable):
            return None, "repeated_in_same_step"
        if usable:
            return None, "no_compatible_field"
        if rejected or rejected_reuse:
            return None, (rejected or rejected_reuse)[0]
        return None, "no_source_in_scope"

    def _filter_time(self, candidates, token, node_row):
        """A source must be observed before the use. Equal timestamps are only
        ordered inside one connection; across connections the order is unknown,
        so the candidate is reported instead of silently accepted."""
        usable, rejected = [], []
        for c in candidates:
            if c["observed_ts"] < token["observed_ts"]:
                usable.append(c)
            elif c["observed_ts"] == token["observed_ts"]:
                if c["conn_id"] == node_row["conn_id"] and (c["seq_in_conn"] or 0) < (node_row["seq_in_conn"] or 0):
                    usable.append(c)
                else:
                    rejected.append("equal_timestamp_order_unknown")
            else:
                rejected.append("source_not_earlier")
        return usable, rejected

    def _rank(self, candidates, token, node_row):
        """Structured response fields first, then a predecessor in the same
        connection, then the nearest source before the use. The ID is only a
        tie-break for stable output; it never means more confidence."""
        def score(c):
            structured = 0 if category(c["location"]) in STRUCTURED else 1
            same_conn = 0 if (c["conn_id"] == node_row["conn_id"]
                              and (c["seq_in_conn"] or 0) < (node_row["seq_in_conn"] or 0)) else 1
            return (structured, same_conn, -(c["observed_ts"] or 0))
        ordered = sorted(candidates, key=lambda c: (*score(c), c["id"]))
        best = ordered[0]
        tied = [c for c in ordered if score(c) == score(best)]
        alternatives = [self._alternative(c) for c in ordered[1:1 + self.trace["max_candidates_per_token"]]]
        return best, alternatives, len(tied) > 1

    def _alternative(self, c):
        return {"transaction_id": c["transaction_id"], "token_id": c["id"], "location": location_of(c),
                "observed_ts": c["observed_ts"], "role": c["role"],
                "method": c["method"], "path": c["path"]}

    def _edge(self, kind, token, source, alternatives, ambiguous, note):
        return contracts.Edge(
            kind=kind, dst_transaction_id=token["transaction_id"], dst_token_id=token["id"],
            dst_location=location_of(token), dst_representation_id=token["representation_id"],
            dst_observed_ts=token["observed_ts"], src_transaction_id=source["transaction_id"],
            src_token_id=source["id"], src_location=location_of(source),
            src_representation_id=source["representation_id"], src_observed_ts=source["observed_ts"],
            value_preview=preview(token["normalized_value"]), value_length=len(token["normalized_value"]),
            transform=_json(token["transform"]), ambiguous=ambiguous, alternatives=alternatives, note=note)

    # ── noise ───────────────────────────────────────────────────────────
    def _noise(self, token, service):
        value = token["normalized_value"]
        if value.lower() in self.stoplist:
            return "stoplist"
        cat = category(token["location"])
        if token["parent_id"]:
            minimum = self.token_cfg["sub_min_len"]
        else:
            minimum = self.token_cfg["min_len"] if cat == BODY_CATEGORY else self.token_cfg["struct_min_len"]
        if len(value) < minimum:
            return "too_short"
        # The flag itself links every request that ever carried it, which says
        # nothing about how it was obtained.
        if self.regex.search(value.encode("utf-8", "replace")):
            return "flag_value"
        samples = self.reader.service_samples(service)
        if samples >= self.trace["df_min_samples"]:
            df = self.reader.document_frequency(service, value)
            if df / samples > self.trace["token_max_df"]:
                return "common_value"
        # An endpoint name in the path is structure, not a value: linking on
        # "files" or "upload" would join every request to that endpoint. A word
        # split out of a longer value is the same kind of noise. The normalizer
        # the baseline uses decides what looks literal (digits, hex and long
        # random strings do not); _link still accepts such a value when a
        # structured response field produced it whole.
        if path_template(value) == value:
            if cat == "path":
                return "endpoint_literal"
            if token["parent_id"]:
                return "literal_fragment"
        return None

    # ── assembly ────────────────────────────────────────────────────────
    def _result(self, state, anchor, nodes, edges, unexplained, limits, warnings, counters, budget, started):
        steps, quality_counts = [], {}
        for position, tx_id in enumerate(self._order(nodes), start=1):
            node = nodes[tx_id]
            row = node["row"]
            issues = _json(row["quality"])
            for issue in issues:
                quality_counts[issue] = quality_counts.get(issue, 0) + 1
            steps.append(contracts.Step(
                transaction_id=tx_id, position=position, role=node["role"], reasons=sorted(set(node["reasons"])),
                quality=issues,
                summary={"method": row["method"], "path": row["path"], "status": row["status"],
                         "proto": row["proto"], "service": row["service"], "conn_id": row["conn_id"],
                         "seq_in_conn": row["seq_in_conn"], "ts_request": row["ts_request"],
                         "ts_response": row["ts_response"], "tick": row["tick"],
                         "source_key": row["source_key"], "team_id": row["team_id"],
                         "flags_found": _json(row["flags_found"]), "flag_out": row["flag_out"]}))
        coverage = contracts.Coverage(
            window_start_us=min((s.summary["ts_request"] or 0) for s in steps) if steps else None,
            window_end_us=anchor.ts_request, snapshot_wall=time.time(),
            same_service_only=bool(self.trace["same_service_only"]),
            scope={"game_id": anchor.game_id, "source_key": anchor.source_key,
                   "service": anchor.service if self.trace["same_service_only"] else None,
                   "team_id": anchor.team_id, "exclude_checker": True},
            limits_hit=sorted(set(limits)), unexplained=unexplained,
            counters={**counters, "rows_read": budget.used, "row_budget": budget.limit,
                      "unexplained_total": len(unexplained)},
            ingest_quality=quality_counts)
        # Two different things get reported separately: bytes that never
        # arrived or were cut when stored, and a decoder that stopped looking.
        # Both limit the evidence; only the first means the message is missing.
        if any(any(w in issue for w in INCOMPLETE_MARKERS) for issue in quality_counts):
            warnings.append("some steps were captured or stored incompletely; evidence shows what was "
                            "captured, not necessarily the whole message")
        if any("decode_budget" in issue for issue in quality_counts):
            warnings.append("the ingest decoder hit its budget on some steps, so nested encodings may "
                            "hold values this analysis never saw")
        reduced = sorted({issue.split(":", 1)[1] for issue in quality_counts
                          if issue.endswith((":decoder_gated", ":decoder_off"))})
        if reduced:
            warnings.append("some steps were ingested with the decoder lowered (" + ", ".join(reduced) + "), so "
                            "flags or values only visible after decoding were not looked for there")
        gaps = self.reader.ingest_gaps()
        coverage.ingest_gaps = gaps
        missing = gaps["error_files"] + gaps["late_files"] + gaps["rejected_files"]
        if missing:
            warnings.append(f"{missing} capture file(s) of this game were rejected, failed or arrived late; "
                            "steps carried in them may be missing from this trace")
        if limits:
            warnings.append("result is partial: " + ", ".join(sorted(set(limits))))
        metrics = {"duration_ms": round((time.monotonic() - started) * 1000, 3),
                   "steps": len(steps), "edges": len(edges),
                   "data_linked_steps": sum(1 for s in steps if s.role == contracts.ROLE_DATA_LINKED),
                   "rows_read": budget.used, "queries": counters["queries"]}
        analysis = {"engine_version": contracts.ENGINE_VERSION, "algorithm_hash": self.algorithm_hash,
                    "algorithm_config": self.algorithm, "mode": self.mode,
                    "ingest_config_versions": sorted({n["row"]["config_version"] for n in nodes.values()}
                                                     - {None}),
                    "manifest": {"transactions": [s.transaction_id for s in steps],
                                 "edge_keys": sorted(e.key() for e in edges)}}
        return contracts.RunResult(state=state, anchor=anchor, steps=steps, edges=edges, coverage=coverage,
                                   warnings=warnings, metrics=metrics, analysis=analysis)

    @staticmethod
    def _order(nodes):
        """Stable display order. Equal timestamps across connections are
        ordered for presentation only; that is not an ordering claim."""
        return sorted(nodes, key=lambda tx: ((nodes[tx]["row"]["ts_request"] or 0), nodes[tx]["row"]["conn_id"] or "",
                                             nodes[tx]["row"]["seq_in_conn"] or 0, tx))

    def _anchor(self, row):
        sightings = self.reader.flag_sightings(row["id"])
        incoming = {s["value"] for s in sightings if s["side"] == "req"}
        outgoing = {s["value"] for s in sightings if s["side"] == "resp"}
        return contracts.Anchor(
            transaction_id=row["id"], game_id=row["game_id"], source_key=row["source_key"],
            team_id=row["team_id"], service=row["service"], tick=row["tick"], conn_id=row["conn_id"],
            seq_in_conn=row["seq_in_conn"], ts_request=row["ts_request"], ts_response=row["ts_response"],
            method=row["method"], path=row["path"], status=row["status"], proto=row["proto"],
            classification=row["classification"], flags_found=_json(row["flags_found"]),
            flags_echoed=sorted(outgoing & incoming), quality=_json(row["quality"]))

    # ── budgets ─────────────────────────────────────────────────────────
    def _stop(self, deadline, budget, limits):
        """The name of the limit that ends the search, or None."""
        if budget is not None and budget.exceeded:
            self._note(limits, contracts.LIMIT_QUERY_ROWS)
            return contracts.LIMIT_QUERY_ROWS
        if time.monotonic() > deadline:
            self._note(limits, contracts.LIMIT_DEADLINE)
            return contracts.LIMIT_DEADLINE
        return None

    @staticmethod
    def _note(limits, name):
        if name not in limits:
            limits.append(name)


def _step_key(method, path, token):
    """Which field of which endpoint a value sat in, IDs in the path folded."""
    return method, path_template((path or "").split("?", 1)[0]), json.dumps(location_of(token))


def _json(value):
    if value is None:
        return []
    return json.loads(value) if isinstance(value, str) else value
