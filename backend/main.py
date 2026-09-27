"""
SPECTER v7 — FastAPI Backend
Key fix: IOC→TTP graph edges are now created on every ingestion.
"""
from fastapi import FastAPI, UploadFile, File, HTTPException, Query, BackgroundTasks, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from loguru import logger
import asyncio, json, time, hmac, hashlib

from config import get_settings
from graph.neo4j_client import initialize_schema, close_driver, run_query
from graph.models import (
    upsert_ioc, upsert_many_iocs, upsert_ttp, upsert_actor,
    link_actor_to_ioc, link_ioc_to_ttp,
    get_active_iocs, get_critical_iocs, get_stats,
    search_iocs, get_graph_for_visualization, get_ioc_neighborhood,
    get_ioc_score_history,
)
from ingestion.unstructured import ingest_pdf, ingest_text, ingest_rss_feed, KNOWN_FEEDS
from ingestion.structured import pull_otx_pulses
from ingestion.nlp_parser import IOC
from soar.defanger import defang_ioc
from soar.webhooks import send_critical_alert, send_ingestion_summary_alert
from soar.firewall_gen import generate_iptables_script, generate_pfsense_aliases
from enrichment.virustotal import enrich_virustotal
from enrichment.shodan import enrich_shodan
from enrichment.cve import correlate_cves
from enrichment.cluster import cluster_iocs
from llm.summarizer import (
    generate_executive_brief, explain_confidence_score,
    generate_ttp_narrative, generate_ingestion_summary,
)

settings = get_settings()
app = FastAPI(title="SPECTER TIP", version="7.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000","http://localhost:5173","http://127.0.0.1:3000","http://127.0.0.1:5173"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    await initialize_schema()
    logger.info("SPECTER v7 started ✓")

@app.on_event("shutdown")
async def shutdown():
    await close_driver()

@app.get("/health")
async def health():
    return {"status":"ok","version":"7.0.0"}

@app.get("/api/stats")
async def get_dashboard_stats():
    return await get_stats()

# ══════════════════════════════════════════════════════
#  INGESTION — with proper IOC→TTP edge creation
# ══════════════════════════════════════════════════════

async def _link_ioc_ttps(iocs, ttps):
    """
    THE FIX: actually create IOC→TTP edges in Neo4j.
    Previously these were stored as a flat array property, never as graph edges.
    """
    ttp_map = {t.technique_id: t for t in ttps}
    for ioc in iocs:
        for tid in (ioc.ttp_tags or []):
            # Only link if TTP was actually extracted from this source
            if tid in ttp_map or any(t.technique_id == tid for t in ttps):
                try:
                    await link_ioc_to_ttp(ioc.value, tid)
                except Exception as e:
                    logger.debug(f"Edge {ioc.value}→{tid}: {e}")


def _count_by_type(iocs):
    c = {}
    for i in iocs:
        c[i.ioc_type] = c.get(i.ioc_type, 0) + 1
    return c


@app.post("/api/ingest/pdf")
async def ingest_pdf_route(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(400, "Only PDF files accepted")
    raw_bytes = await file.read()
    result = ingest_pdf(raw_bytes, source_label=f"pdf:{file.filename}")

    await upsert_many_iocs(result.iocs)
    for ttp in result.ttps:
        await upsert_ttp(ttp)

    # THE KEY FIX — create the actual graph edges
    await _link_ioc_ttps(result.iocs, result.ttps)

    critical = [i for i in result.iocs if i.confidence_score >= 80]
    breakdown = _count_by_type(result.iocs)
    top_ttps = [f"{t.technique_id} {t.technique_name}" for t in result.ttps[:5]]

    ai_summary = await generate_ingestion_summary(
        source=file.filename, ioc_count=len(result.iocs),
        ttp_count=len(result.ttps), top_ttps=top_ttps, ioc_breakdown=breakdown,
    )

    # One summary alert (not 500 individual ones)
    background_tasks.add_task(
        send_ingestion_summary_alert,
        file.filename, len(result.iocs), len(critical), len(result.ttps), ai_summary, breakdown,
    )

    return {
        "message": "PDF ingested", "filename": file.filename,
        "iocs_extracted": len(result.iocs), "ttps_detected": len(result.ttps),
        "critical_alerts_fired": len(critical), "ioc_types": breakdown,
        "ai_summary": ai_summary,
        "ttps": [{"id":t.technique_id,"name":t.technique_name,"tactic":t.tactic} for t in result.ttps],
    }


class TextIngestionRequest(BaseModel):
    text: str
    source_label: str = "manual_paste"

@app.post("/api/ingest/text")
async def ingest_text_route(req: TextIngestionRequest):
    result = ingest_text(req.text, req.source_label)
    await upsert_many_iocs(result.iocs)
    for ttp in result.ttps:
        await upsert_ttp(ttp)
    await _link_ioc_ttps(result.iocs, result.ttps)
    breakdown = _count_by_type(result.iocs)
    top_ttps = [f"{t.technique_id} {t.technique_name}" for t in result.ttps[:5]]
    ai_summary = await generate_ingestion_summary(
        source=req.source_label, ioc_count=len(result.iocs),
        ttp_count=len(result.ttps), top_ttps=top_ttps, ioc_breakdown=breakdown,
    )
    return {
        "message": "Text ingested", "source": req.source_label,
        "iocs_extracted": len(result.iocs), "ttps_detected": len(result.ttps),
        "ai_summary": ai_summary, "ioc_types": breakdown,
        "ttps": [{"id":t.technique_id,"name":t.technique_name,"tactic":t.tactic} for t in result.ttps],
    }

@app.post("/api/ingest/otx")
async def ingest_otx_route():
    iocs = await pull_otx_pulses(limit=100)
    count = await upsert_many_iocs(iocs)
    breakdown = {}
    for ioc in iocs:
        breakdown[ioc.ioc_type] = breakdown.get(ioc.ioc_type, 0) + 1
    return {"message":"OTX pull complete","iocs_ingested":count,"ioc_breakdown":breakdown}

@app.post("/api/ingest/rss")
async def ingest_rss_route(feed_url: str = Query(None)):
    feeds = [feed_url] if feed_url else KNOWN_FEEDS
    total, breakdown = 0, {}
    for feed in feeds:
        for r in ingest_rss_feed(feed):
            await upsert_many_iocs(r.iocs)
            for ttp in r.ttps:
                await upsert_ttp(ttp)
            await _link_ioc_ttps(r.iocs, r.ttps)
            total += len(r.iocs)
            for ioc in r.iocs:
                breakdown[ioc.ioc_type] = breakdown.get(ioc.ioc_type, 0) + 1
    return {"message":"RSS complete","total_iocs":total,"feeds":len(feeds),"ioc_breakdown":breakdown}


# ══════════════════════════════════════════════════════
#  IOC / GRAPH ROUTES
# ══════════════════════════════════════════════════════

@app.get("/api/iocs")
async def list_iocs(limit: int = Query(500, le=1000), ioc_type: str = Query(None)):
    iocs = await get_active_iocs(limit=limit)
    if ioc_type:
        iocs = [i for i in iocs if i.get("ioc_type") == ioc_type]
    return {"iocs": iocs, "count": len(iocs)}

@app.get("/api/iocs/critical")
async def list_critical_iocs(ioc_type: str = Query(None)):
    iocs = await get_critical_iocs()
    if ioc_type:
        iocs = [i for i in iocs if i.get("ioc_type") == ioc_type]
    return {"iocs": iocs, "count": len(iocs)}

@app.get("/api/iocs/search")
async def search_iocs_route(q: str = Query(..., min_length=2)):
    iocs = await search_iocs(q)
    return {"iocs": iocs, "count": len(iocs), "query": q}

@app.get("/api/iocs/{ioc_value}/neighborhood")
async def ioc_neighborhood(ioc_value: str, depth: int = Query(2, le=4)):
    return {"neighborhood": await get_ioc_neighborhood(ioc_value, depth)}

@app.get("/api/iocs/{ioc_value}/history")
async def ioc_history(ioc_value: str):
    return {"history": await get_ioc_score_history(ioc_value)}

@app.get("/api/graph")
async def get_graph():
    return await get_graph_for_visualization()

@app.get("/api/graph/neo4j-url")
async def neo4j_browser_url():
    """Returns the Neo4j browser URL with a pre-built Cypher query."""
    base = "http://localhost:7474/browser/"
    query = "MATCH p=(a)-[r]->(b) WHERE (a:IOC OR a:Actor) AND (b:TTP OR b:Actor OR b:IOC) RETURN p LIMIT 100"
    import urllib.parse
    return {"url": base, "query": query, "connect_url": "bolt://localhost:7687"}


# ══════════════════════════════════════════════════════
#  ENRICHMENT ROUTES
# ══════════════════════════════════════════════════════

@app.get("/api/enrich/virustotal/{ioc_value}")
async def vt_enrich(ioc_value: str):
    results = await enrich_virustotal(ioc_value)
    return results

@app.get("/api/enrich/shodan/{ip}")
async def shodan_enrich(ip: str):
    results = await enrich_shodan(ip)
    return results

@app.get("/api/enrich/cve")
async def cve_correlate(ttp_ids: str = Query(...)):
    ids = [t.strip() for t in ttp_ids.split(",") if t.strip()]
    results = await correlate_cves(ids)
    return results

@app.get("/api/enrich/clusters")
async def ioc_clusters():
    iocs = await get_critical_iocs()
    clusters = await cluster_iocs(iocs)
    return {"clusters": clusters}


# ══════════════════════════════════════════════════════
#  SOAR ROUTES
# ══════════════════════════════════════════════════════

class FirewallRequest(BaseModel):
    ioc_values: list[str]
    format: str = "iptables"

@app.post("/api/soar/firewall")
async def generate_firewall(req: FirewallRequest):
    iocs = []
    for value in req.ioc_values:
        res = await run_query("MATCH (n:IOC {value:$v}) RETURN n", {"v": value})
        if res:
            d = dict(res[0]["n"])
            if d.get("confidence_score", 0) >= 70:
                iocs.append(d)
    script = generate_pfsense_aliases(iocs) if req.format == "pfsense" else generate_iptables_script(iocs)
    fname  = "specter_pfsense.xml" if req.format == "pfsense" else "block_specter.sh"
    return {"script": script, "filename": fname, "iocs_included": len(iocs)}

@app.post("/api/soar/alert/{ioc_value}")
async def fire_alert(ioc_value: str, background_tasks: BackgroundTasks):
    res = await run_query("MATCH (n:IOC {value:$v}) RETURN n", {"v": ioc_value})
    if not res:
        raise HTTPException(404, "IOC not found")
    background_tasks.add_task(send_critical_alert, dict(res[0]["n"]))
    return {"message": "Alert fired", "ioc": ioc_value}


# ══════════════════════════════════════════════════════
#  DISCORD INTERACTION HANDLER
# ══════════════════════════════════════════════════════

@app.post("/discord/interactions")
async def discord_interactions(request: Request):

    body = await request.body()

    signature = request.headers.get("X-Signature-Ed25519")
    timestamp = request.headers.get("X-Signature-Timestamp")

    print("BODY:", body)
    print("SIG:", signature)
    print("TIME:", timestamp)
    print("PUBKEY:", settings.discord_public_key)

    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError

        print("PUBLIC KEY =", settings.discord_public_key)
        verify_key = VerifyKey(bytes.fromhex(settings.discord_public_key))

        verify_key.verify(
            timestamp.encode() + body,
            bytes.fromhex(signature)
        )

        print("SIGNATURE VERIFIED ✅")

    except Exception as e:
        print("VERIFY FAILED ❌")
        print(str(e))
        return Response(status_code=401)

    payload = json.loads(body)

    # Discord handshake
    if payload["type"] == 1:
        return {"type": 1}

    return {
        "type": 4,
        "data": {
            "content": "Discord interaction working!"
        }
    }


def _vt_embed(ioc: str, data: dict) -> dict:
    if "error" in data:
        return {"title": "VirusTotal — Error", "description": data["error"], "color": 0xFF8800}
    stats = data.get("stats", {})
    mal   = stats.get("malicious", 0)
    total = sum(stats.values()) or 1
    return {
        "title": f"🔬 VirusTotal Report — {ioc[:50]}",
        "color": 0xFF3333 if mal > 3 else 0xFF8800 if mal > 0 else 0x39FF14,
        "fields": [
            {"name": "Detections", "value": f"**{mal}/{total}** engines flagged this", "inline": True},
            {"name": "Community Score", "value": str(data.get("reputation", "N/A")), "inline": True},
            {"name": "Last Analysis", "value": data.get("last_analysis_date", "Unknown"), "inline": True},
            {"name": "Categories", "value": ", ".join(data.get("categories", {}).values())[:200] or "None", "inline": False},
        ],
    }

def _shodan_embed(ip: str, data: dict) -> dict:
    if "error" in data:
        return {"title": "Shodan — Error", "description": data["error"], "color": 0xFF8800}
    ports = data.get("ports", [])
    return {
        "title": f"🌐 Shodan Intel — {ip}",
        "color": 0xFF6600,
        "fields": [
            {"name": "Country", "value": data.get("country_name", "Unknown"), "inline": True},
            {"name": "ISP", "value": data.get("isp", "Unknown"), "inline": True},
            {"name": "Org", "value": data.get("org", "Unknown"), "inline": True},
            {"name": "Open Ports", "value": ", ".join(str(p) for p in ports[:15]) or "None", "inline": False},
            {"name": "Hostnames", "value": ", ".join(data.get("hostnames", [])[:5]) or "None", "inline": False},
            {"name": "Tags", "value": ", ".join(data.get("tags", [])) or "None", "inline": True},
        ],
    }


# ══════════════════════════════════════════════════════
#  LLM ROUTES
# ══════════════════════════════════════════════════════

class BriefRequest(BaseModel):
    ioc_summary: str
    ttp_summary: str
    source: str = "threat report"

@app.post("/api/llm/brief")
async def executive_brief(req: BriefRequest):
    brief = await generate_executive_brief(req.ioc_summary, req.ttp_summary, req.source)
    return {"brief": brief}

@app.get("/api/llm/explain/{ioc_value}")
async def explain_ioc_score(ioc_value: str):
    res = await run_query("MATCH (n:IOC {value:$v}) RETURN n", {"v": ioc_value})
    if not res:
        raise HTTPException(404, "IOC not found")
    ioc = dict(res[0]["n"])
    return {"ioc": ioc_value, "explanation": await explain_confidence_score(ioc), "score": ioc.get("confidence_score")}

@app.post("/api/llm/narrative")
async def ttp_narrative(ttps: list[dict]):
    return {"narrative": await generate_ttp_narrative(ttps)}


# ══════════════════════════════════════════════════════
#  ACTORS
# ══════════════════════════════════════════════════════

class ActorRequest(BaseModel):
    name: str
    aliases: list[str] = []
    nation: str = ""
    ioc_values: list[str] = []

@app.post("/api/actors")
async def create_actor(req: ActorRequest):
    actor = await upsert_actor(req.name, req.aliases, req.nation)
    for v in req.ioc_values:
        await link_actor_to_ioc(req.name, v)
    return {"actor": actor, "linked_iocs": len(req.ioc_values)}
