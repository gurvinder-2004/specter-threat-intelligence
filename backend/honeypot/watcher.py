"""
Cowrie Live Log Watcher
Runs as a background service, tails cowrie.json in real time,
and pushes each new attacker IP directly into SPECTER + Discord.

This runs in its own Docker container (cowrie_watcher).
"""
import asyncio
import json
import sys
import os
from pathlib import Path
from loguru import logger

# Allow imports from /app (backend root)
sys.path.insert(0, "/app")

from ingestion.nlp_parser import IOC

LOG_PATH = Path(os.getenv("COWRIE_LOG_PATH", "/cowrie_logs/cowrie.json"))
SPECTER_API = os.getenv("SPECTER_API_URL", "http://api:8000")
POLL_INTERVAL = 3   # seconds between file checks

logger.add(sys.stdout, format="{time:HH:mm:ss} | {level} | {message}", level="INFO")


def _infer_ttps(event: dict) -> list[str]:
    eid = event.get("eventid", "")
    ttps = []
    if "login" in eid:       ttps.append("T1110")       # Brute Force
    if "command" in eid:     ttps.append("T1059")       # Command & Scripting Interpreter
    if "file_upload" in eid: ttps.append("T1105")       # Ingress Tool Transfer
    if "download" in eid:    ttps.append("T1105")
    if "tcpip" in eid:       ttps.append("T1021.004")   # SSH Lateral Movement
    return list(set(ttps))


def _build_context(event: dict) -> str:
    parts = [
        f"event={event.get('eventid', '')}",
        f"ts={event.get('timestamp', '')}",
    ]
    if event.get("username"): parts.append(f"user={event['username']}")
    if event.get("password"): parts.append(f"pass={event['password']}")
    if event.get("input"):    parts.append(f"cmd={event['input'][:80]}")
    if event.get("url"):      parts.append(f"url={event['url']}")
    return "Cowrie honeypot | " + " | ".join(parts)


HOSTILE_EVENTS = {
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.command.failed",
    "cowrie.session.file_upload",
    "cowrie.session.file_download",
    "cowrie.direct-tcpip.request",
}


async def push_to_specter(ioc: dict):
    """POST IOC directly to SPECTER API."""
    import httpx
    payload = {
        "text": (
            f"Cowrie honeypot: {ioc['ioc_type']} {ioc['value']} "
            f"scored={ioc['confidence_score']} | {ioc['raw_context']}"
        ),
        "source_label": f"cowrie:honeypot",
    }
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.post(f"{SPECTER_API}/api/ingest/text", json=payload)
            if r.status_code == 200:
                logger.success(f"✓ Pushed honeypot IOC: {ioc['value']}")
            else:
                logger.warning(f"Push failed {r.status_code}: {r.text[:100]}")
        except Exception as e:
            logger.error(f"Push error: {e}")


async def tail_and_ingest():
    seen_ips: set[str] = set()
    file_position = 0

    logger.info(f"Cowrie watcher started — watching {LOG_PATH}")
    logger.info(f"SPECTER API: {SPECTER_API}")

    while True:
        await asyncio.sleep(POLL_INTERVAL)

        if not LOG_PATH.exists():
            logger.debug(f"Waiting for {LOG_PATH} to appear...")
            continue

        stat = LOG_PATH.stat()
        if stat.st_size <= file_position:
            continue    # no new data

        with open(LOG_PATH, "r", errors="replace") as f:
            f.seek(file_position)
            new_lines = f.readlines()
            file_position = f.tell()

        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("eventid") not in HOSTILE_EVENTS:
                continue

            src_ip = event.get("src_ip", "")
            if not src_ip or src_ip in seen_ips:
                continue

            seen_ips.add(src_ip)
            ctx = _build_context(event)
            ttps = _infer_ttps(event)

            logger.warning(f"🔴 HONEYPOT HIT from {src_ip} | {event.get('eventid')}")

            ioc = {
                "value": src_ip,
                "ioc_type": "ip",
                "confidence_score": 100.0,
                "source": "cowrie:honeypot",
                "raw_context": ctx,
                "ttp_tags": ttps,
            }

            await push_to_specter(ioc)

            # Also fire Discord alert directly from here
            try:
                from soar.webhooks import send_critical_alert
                await send_critical_alert(ioc)
            except Exception as e:
                logger.warning(f"Discord alert failed: {e}")


if __name__ == "__main__":
    asyncio.run(tail_and_ingest())
