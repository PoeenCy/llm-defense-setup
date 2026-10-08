#!/usr/bin/env python3
"""
mcp-tulip — MCP server exposing READ-ONLY access to Tulip's flow data
(TimescaleDB/Postgres), for ioc-brain's /analyze flow_id path.

Write-safety is enforced at the database layer: the connection uses the
`tulip_ro` role, which only has SELECT grants (see bringup.sh / the one-time
GRANT statements this role was created with) — a write attempt is rejected
by Postgres itself, not by convention in this code.
"""
import json
import os

import psycopg2
import psycopg2.extras
from mcp.server.fastmcp import FastMCP

POSTGRES_RO_URI = os.environ.get(
    "POSTGRES_RO_URI", "postgresql://tulip_ro@localhost:5432/tulip"
)

mcp = FastMCP("tulip-readonly", host="0.0.0.0", port=int(os.environ.get("MCP_PORT", 8765)))


def _connect():
    conn = psycopg2.connect(POSTGRES_RO_URI)
    conn.set_session(readonly=True)  # belt-and-suspenders; the role itself already can't write
    return conn


@mcp.tool()
def get_flow(flow_id: str) -> dict:
    """Fetch one flow (metadata + ordered message items) by its UUID."""
    with _connect() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, time, ip_src, ip_dst, port_src, port_dst, duration, "
            "tags, flags, packets_count, packets_size FROM flow WHERE id = %s",
            (flow_id,),
        )
        flow = cur.fetchone()
        if not flow:
            return {"error": f"flow {flow_id} not found"}
        flow = dict(flow)
        flow["id"] = str(flow["id"])
        flow["time"] = flow["time"].isoformat() if flow["time"] else None

        cur.execute(
            "SELECT direction, kind, data FROM flow_item WHERE flow_id = %s ORDER BY time",
            (flow_id,),
        )
        items = []
        for row in cur.fetchall():
            data = bytes(row["data"])
            items.append({
                "direction": row["direction"],
                "kind": row["kind"],
                "data": data.decode("utf-8", errors="replace")[:8000],  # cap for context length
            })
        flow["items"] = items
        return flow


@mcp.tool()
def search_flows(
    src_ip: str = "", dst_ip: str = "", tag: str = "", limit: int = 20
) -> list[dict]:
    """Search flows by source IP, destination IP, and/or tag (e.g. 'flag-out')."""
    clauses, params = [], []
    if src_ip:
        clauses.append("ip_src = %s")
        params.append(src_ip)
    if dst_ip:
        clauses.append("ip_dst = %s")
        params.append(dst_ip)
    if tag:
        clauses.append("tags @> %s::jsonb")
        params.append(json.dumps([tag]))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    limit = max(1, min(limit, 100))

    with _connect() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            f"SELECT id, time, ip_src, ip_dst, port_src, port_dst, tags, flags "
            f"FROM flow {where} ORDER BY time DESC LIMIT %s",
            params + [limit],
        )
        results = []
        for row in cur.fetchall():
            row = dict(row)
            row["id"] = str(row["id"])
            row["time"] = row["time"].isoformat() if row["time"] else None
            results.append(row)
        return results


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
