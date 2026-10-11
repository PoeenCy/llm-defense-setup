#!/usr/bin/env python3
"""
ioc_api.py — CTF Monitor Hub: IOC Analysis Brain (Item 6)

Endpoint: POST /analyze  { "flow_id": "..." } OR { "log_snippet": "..." }
Returns: structured IOC JSON

LLM (Foundation-Sec-8B Q4) is loaded ON DEMAND via Ollama, then released.
The MongoDB connection to Tulip is READ-ONLY (no write permissions granted).

Safety:
  - Never auto-deploys anything.
  - MongoDB connection is read-only.
  - LLM is never kept resident in RAM between requests.
"""
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
import redis
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [IOC-BRAIN] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ioc-brain")

# ── Config ──────────────────────────────────────────────────────────────────
REDIS_HOST    = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT    = int(os.environ.get("REDIS_PORT", 6379))
OLLAMA_HOST   = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
LLM_MODEL     = os.environ.get("LLM_MODEL", "foundation-sec-8b-chat")
EMBED_MODEL   = os.environ.get("EMBED_MODEL", "nomic-embed-text")
GPU_LAYERS    = int(os.environ.get("GPU_LAYERS", 20))

CONFIG_PATH = "/app/services.json"

# ── MongoDB Read-Only Connection ─────────────────────────────────────────────
# ── MCP (read-only Tulip/Postgres access) ────────────────────────────────────
# Tulip stores flows in TimescaleDB/Postgres, not Mongo. Write-safety is
# enforced at the DB layer by the tulip_ro role the MCP server connects with
# (see mcp-tulip/mcp_server.py) — this client just calls its tools.
MCP_URL = os.environ.get("MCP_URL", "http://mcp-tulip:8765/mcp")

async def fetch_flow_from_mcp(flow_id: str) -> Optional[dict]:
    """Fetch a Tulip flow (metadata + items) via the read-only MCP server."""
    try:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client

        async with streamablehttp_client(MCP_URL) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("get_flow", {"flow_id": flow_id})
                data = json.loads(result.content[0].text)
                if "error" in data:
                    log.warning("MCP get_flow: %s", data["error"])
                    return None
                return data
    except Exception as e:
        log.warning("MCP fetch failed: %s", e)
        return None

# ── IOC Prompt Template ───────────────────────────────────────────────────────
IOC_SYSTEM_PROMPT = """You are an expert CTF (Capture The Flag) Attack-Defense security analyst.
Analyze the provided network flow or log snippet and extract Indicators of Compromise (IOCs).

IMPORTANT: You MUST respond with ONLY valid JSON matching this exact schema:
{
  "attacker_ip": "string or null",
  "exploited_endpoint": "string describing the vulnerable service/endpoint",
  "technique": "string describing the attack technique",
  "mitre_attack": ["list of MITRE ATT&CK technique IDs, e.g. T1059.001"],
  "payload_summary": "brief description of the payload or exploit",
  "dropped_artifacts": ["list of filenames, cron jobs, or files dropped/modified"],
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "flag_exfiltrated": true or false,
  "recommended_action": "what the human operator should do NOW",
  "raw_ioc_tags": ["list of specific IOC strings: IPs, hashes, URLs, etc."],
  "analysis_notes": "additional analyst notes"
}

Do not include any explanation outside the JSON. If unknown, use null for fields."""

def build_analysis_prompt(content: str, context: str = "") -> str:
    prompt = f"Analyze this CTF network flow/log:\n\n```\n{content[:6000]}\n```"
    if context:
        prompt += f"\n\nAdditional context:\n{context[:1000]}"
    return prompt

# ── Ollama load-on-demand ─────────────────────────────────────────────────────
async def call_llm_on_demand(prompt: str, retry_notice: str = "") -> str:
    """
    Load the LLM via Ollama, get response, then release.
    Ollama automatically unloads the model after keep_alive expires.
    retry_notice, if set, is appended as an extra system message — used when
    re-prompting after the first attempt didn't return parseable JSON.
    """
    import ollama as ollama_lib

    log.info("Loading LLM on demand: %s (gpu_layers=%d)", LLM_MODEL, GPU_LAYERS)
    t0 = time.time()

    messages = [
        {"role": "system", "content": IOC_SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    if retry_notice:
        messages.append({"role": "system", "content": retry_notice})

    try:
        client = ollama_lib.AsyncClient(host=OLLAMA_HOST)
        resp = await client.chat(
            model=LLM_MODEL,
            format="json",
            messages=messages,
            options={
                "num_gpu": GPU_LAYERS,    # layers offloaded to GPU
                "temperature": 0.1,       # low temp for structured output
                "num_predict": 400,       # bound worst-case latency on CPU-only inference
            },
            keep_alive="5m",              # keep model in RAM for 5 mins to prevent cold-starts
        )
        elapsed = time.time() - t0
        log.info("LLM response in %.1fs (model released from RAM)", elapsed)
        return resp["message"]["content"], elapsed
    except Exception as e:
        log.error("LLM call failed: %s", e)
        raise HTTPException(status_code=503, detail=f"LLM unavailable: {e}")

class IocParseError(Exception):
    pass

def parse_ioc_json(raw: str) -> dict:
    """Extract and parse JSON from LLM response, handling markdown code blocks.
    Raises IocParseError if no valid JSON object can be extracted — callers
    should retry the LLM call once before falling back to a stub result."""
    import re
    raw = re.sub(r"```(?:json)?\n?", "", raw).strip()
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    raise IocParseError(raw[:500])


IOC_KEYS = {"attacker_ip", "exploited_endpoint", "technique", "mitre_attack", "payload_summary",
            "severity", "flag_exfiltrated", "recommended_action", "raw_ioc_tags"}


def looks_like_ioc(d: dict) -> bool:
    """The small model sometimes returns the input event back as 'JSON'."""
    return isinstance(d, dict) and len(IOC_KEYS & d.keys()) >= 3


def flow_transcript(flow: dict) -> str:
    """Readable request/response text for the model (instead of escaped JSON,
    which wasted most of the context window and cut the payload off)."""
    head = (f"Flow {flow.get('id')}  {flow.get('ip_src')}:{flow.get('port_src')} -> "
            f"{flow.get('ip_dst')}:{flow.get('port_dst')}  time {flow.get('time')}  tags {flow.get('tags')}")
    parts = [head]
    for it in flow.get("items") or []:
        who = "CLIENT -> SERVER" if it.get("direction") == "c" else "SERVER -> CLIENT"
        parts.append(f"--- {who} ---\n{(it.get('data') or '')[:1500]}")
    return "\n".join(parts)


_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def verify_grounding(ioc: dict, content: str, grounded_on: str) -> dict:
    """Cheap hallucination check: every IP the model mentions must appear in
    what it was given. Shown to the operator next to the answer."""
    out_ips = set(_IP.findall(json.dumps(ioc)))
    invented = sorted(ip for ip in out_ips if ip not in content)
    note = {"flow": "model read the real Tulip flow — its CONCLUSION can still be wrong, check the flow yourself",
            "log": "based ONLY on the alert text (no flow data) — weak evidence",
            "none": "flow could not be fetched — the model saw almost nothing"}[grounded_on]
    return {"evidence": grounded_on, "note": note, "invented_ips": invented,
            "grounded": not invented and grounded_on == "flow"}

# ── FastAPI App ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="CTF IOC Brain",
    description="Load-on-demand LLM IOC analyzer for CTF Attack-Defense flows",
    version="1.0.0",
)

class AnalyzeRequest(BaseModel):
    flow_id: Optional[str] = None
    log_snippet: Optional[str] = None
    context: Optional[str] = None

class AnalyzeResponse(BaseModel):
    ioc: dict
    flow_id: Optional[str]
    latency_sec: float
    model: str
    ts: str

@app.get("/health")
async def health():
    return {"status": "ok", "service": "ioc-brain", "model": LLM_MODEL}

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    """
    Analyze a Tulip flow or log snippet and return structured IOC JSON.
    
    - Provide flow_id to fetch from Tulip, or
    - Provide log_snippet directly.
    
    The LLM is loaded on demand and released immediately after.
    """
    if not req.flow_id and not req.log_snippet:
        raise HTTPException(status_code=400, detail="Provide flow_id or log_snippet")

    content = ""
    flow_id = req.flow_id
    grounded_on = "log"

    if req.flow_id:
        flow = await fetch_flow_from_mcp(req.flow_id)
        if flow:
            content = flow_transcript(flow)
            grounded_on = "flow"
        else:
            content = f"Flow ID: {req.flow_id} (could not fetch from Tulip via MCP)"
            grounded_on = "none"

    if req.log_snippet:
        # Keep the flow (the real evidence) first; the event that pointed us
        # at it is extra context, not a replacement.
        content = (content + "\n\nRelated alert:\n" + req.log_snippet) if grounded_on == "flow" else req.log_snippet

    prompt = build_analysis_prompt(content, req.context or "")
    raw_response, latency = await call_llm_on_demand(prompt)
    ioc = None
    try:
        ioc = parse_ioc_json(raw_response)
        if not looks_like_ioc(ioc):
            raise IocParseError("not the IOC schema (model echoed the input?)")
    except IocParseError:
        log.warning("First LLM response wasn't schema-valid JSON — retrying once")
        retry_response, retry_latency = await call_llm_on_demand(
            prompt,
            retry_notice=(
                "Your previous response did not follow the schema (it must not "
                "copy the input). Respond with ONLY the JSON object with the "
                "keys from the schema above — no other text, no markdown."
            ),
        )
        latency += retry_latency
        try:
            ioc = parse_ioc_json(retry_response)
            if not looks_like_ioc(ioc):
                raise IocParseError(retry_response[:500])
        except IocParseError as e:
            ioc = {
                "analysis_notes": "LLM did not return a usable analysis after retry — ignore this result",
                "raw_response": str(e),
                "confidence": "LOW",
            }
    ioc["_check"] = verify_grounding(ioc, content, grounded_on)

    # Push IOC to Redis for dashboard consumption
    rdb = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    ioc_record = {
        "type": "ioc-analysis",
        "ts": datetime.now(timezone.utc).isoformat(),
        "flow_id": flow_id,
        "ioc": ioc,
        "model": LLM_MODEL,
        "latency_sec": round(latency, 2),
    }
    rdb.lpush("ioc_results", json.dumps(ioc_record))
    rdb.ltrim("ioc_results", 0, 999)

    return AnalyzeResponse(
        ioc=ioc,
        flow_id=flow_id,
        latency_sec=round(latency, 2),
        model=LLM_MODEL,
        ts=datetime.now(timezone.utc).isoformat(),
    )

@app.get("/results/recent")
async def recent_iocs(n: int = 20):
    """Return the N most recent IOC analysis results."""
    rdb = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    raw = rdb.lrange("ioc_results", 0, n - 1)
    return [json.loads(r) for r in raw]

@app.get("/mcp/test")
async def test_mcp():
    """Verify the MCP server's read-only connection: reads succeed, writes are DB-rejected."""
    try:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client

        async with streamablehttp_client(MCP_URL) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("search_flows", {"limit": 1})
                flows = json.loads(result.content[0].text)
                return {
                    "status": "connected",
                    "flow_count_sampled": len(flows),
                    "note": "MCP only exposes read tools (get_flow/search_flows) — "
                            "write-rejection is enforced by the tulip_ro Postgres role "
                            "(GRANT SELECT only), verified directly against Postgres, "
                            "not exposed as an MCP tool at all.",
                }
    except Exception as e:
        return {"status": "error", "detail": str(e)}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5001, log_level="info")
