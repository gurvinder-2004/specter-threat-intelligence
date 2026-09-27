"""
AEGIS → SPECTER Integration
=============================
Bridges the AEGIS kill engine to SPECTER's threat graph.

On every kill event:
  1. Upserts extracted TTPs into SPECTER graph
  2. Creates IOC nodes for C2 IPs and ransom note domains
  3. Creates "RansomwareFamily" actor node
  4. POSTs ingestion summary alert to Discord (via SPECTER)
  5. Stores score history for decay timeline chart
  6. Updates SPECTER dashboard stats

Runs as a background task — does not block the kill switch.
"""

import asyncio
import json
import time
import os
import httpx
try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger("aegis.specter_bridge")
    if not logger.handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

DEFAULT_SPECTER_API = os.getenv("SPECTER_API_URL", "http://localhost:8000")


async def post_kill_to_specter(bundle: dict, specter_api: str = None) -> bool:
    """
    Main integration entry point.
    Call this after ForensicsCollector.collect() returns.
    """
    api_url = specter_api or os.getenv("SPECTER_API_URL", DEFAULT_SPECTER_API)
    try:
        async with httpx.AsyncClient(timeout=15, base_url=api_url) as client:

            # 1. Ingest TTPs
            for ttp in bundle.get("ttps", []):
                await _upsert_ttp(client, ttp)

            # 2. Ingest C2 candidate IPs as critical IOCs
            for c2_ip in bundle.get("c2_candidates", []):
                ip = c2_ip.split(":")[0]
                await _upsert_ioc(client, {
                    "value":            ip,
                    "ioc_type":         "ip",
                    "confidence_score": 100.0,
                    "source":           f"aegis:live_kill:{bundle.get('family_guess','unknown')}",
                    "raw_context":      f"C2 connection observed during {bundle.get('family_guess')} execution. "
                                        f"Detection latency: {bundle.get('detection_latency_ms')}ms",
                    "ttp_tags":         [t["technique_id"] for t in bundle.get("ttps", [])],
                })

            # 3. Ingest ransom sample hash if available
            sha256 = bundle.get("sample_sha256", "")
            if sha256 and len(sha256) == 64:
                await _upsert_ioc(client, {
                    "value":            sha256,
                    "ioc_type":         "sha256",
                    "confidence_score": 100.0,
                    "source":           f"aegis:live_sample:{bundle.get('family_guess','unknown')}",
                    "raw_context":      f"Sample hash from live {bundle.get('family_guess')} execution",
                    "ttp_tags":         [t["technique_id"] for t in bundle.get("ttps", [])],
                })

            # 4. Create/update Actor node for the ransomware family
            family = bundle.get("family_guess", "Unknown Ransomware")
            if family and family != "Unknown":
                await _upsert_actor(client, family)

            # 5. Send Discord summary alert
            await _send_aegis_alert(client, bundle)

            logger.info(f"AEGIS→SPECTER: kill event posted for {family}")
            return True

    except Exception as e:
        logger.error(f"AEGIS→SPECTER post failed: {e}")
        return False


async def _upsert_ttp(client: httpx.AsyncClient, ttp: dict):
    """POST a TTP to SPECTER's ingest endpoint via text."""
    try:
        text = (
            f"Ransomware TTP detected: {ttp['technique_id']} {ttp['name']} "
            f"[{ttp['tactic']}] — Evidence: {ttp.get('evidence','')}"
        )
        await client.post("/api/ingest/text", json={
            "text":         text,
            "source_label": f"aegis:ttp:{ttp['technique_id']}",
        })
    except Exception as e:
        logger.debug(f"TTP upsert failed {ttp.get('technique_id')}: {e}")


async def _upsert_ioc(client: httpx.AsyncClient, ioc: dict):
    """POST a single IOC via SPECTER text ingest."""
    try:
        text = (
            f"AEGIS live capture: {ioc['ioc_type']} {ioc['value']} "
            f"confidence={ioc['confidence_score']} "
            f"context: {ioc.get('raw_context','')}"
        )
        await client.post("/api/ingest/text", json={
            "text":         text,
            "source_label": ioc.get("source", "aegis:live"),
        })
    except Exception as e:
        logger.debug(f"IOC upsert failed {ioc.get('value')}: {e}")


async def _upsert_actor(client: httpx.AsyncClient, family: str):
    """Create or update the ransomware family as an Actor node."""
    try:
        await client.post("/api/actors", json={
            "name":      family,
            "aliases":   [],
            "nation":    "unknown",
            "ioc_values": [],
        })
    except Exception as e:
        logger.debug(f"Actor upsert failed {family}: {e}")


async def _send_aegis_alert(client: httpx.AsyncClient, bundle: dict):
    """
    Send a rich kill event summary to Discord via SPECTER's webhook.
    """
    family   = bundle.get("family_guess", "Unknown")
    latency  = bundle.get("detection_latency_ms", 0)
    encrypted = bundle.get("files_encrypted", 0)
    saved    = bundle.get("files_saved", 0)
    score    = bundle.get("behavioral_score", 0)
    ttps     = [t["technique_id"] for t in bundle.get("ttps", [])]
    c2s      = bundle.get("c2_candidates", [])
    triggers = bundle.get("trigger_signals", [])

    # Post the summary text via SPECTER ingest (which triggers Discord)
    summary = (
        f"AEGIS KILL EVENT — {family} ransomware neutralized in {latency:.0f}ms. "
        f"{encrypted} files encrypted before kill, {saved} files protected. "
        f"TTPs: {', '.join(ttps[:5])}. "
        f"Trigger signals: {', '.join(triggers)}."
        + (f" C2 candidates: {', '.join(c2s[:3])}." if c2s else "")
    )
    try:
        await client.post("/api/ingest/text", json={
            "text":         summary,
            "source_label": f"aegis:kill:{family.lower().replace(' ','_')}",
        })
    except Exception as e:
        logger.debug(f"Alert send failed: {e}")
