"""
Cowrie Honeypot Ingestor
Reads Cowrie SSH honeypot JSON logs and ingests attacker IPs as
SPECTER IOCs with confidence score = 100 (actively hostile).

Cowrie log path (default): /var/log/cowrie/cowrie.json
Or via API polling if Cowrie is on another host.

Setup Cowrie: https://github.com/cowrie/cowrie
  docker run -p 2222:2222 cowrie/cowrie
"""
import json
from pathlib import Path
from datetime import datetime, timezone
from loguru import logger

from ingestion.nlp_parser import IOC
from graph.models import upsert_ioc


def parse_cowrie_log_file(log_path: str | Path) -> list[IOC]:
    """
    Parse a Cowrie JSON log file and extract attacker IPs.
    Each line in cowrie.json is a separate JSON event.
    """
    log_path = Path(log_path)
    if not log_path.exists():
        logger.warning(f"Cowrie log not found: {log_path}")
        return []

    iocs: dict[str, IOC] = {}

    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_id = event.get("eventid", "")
            src_ip = event.get("src_ip", "")

            if not src_ip or src_ip in iocs:
                continue

            # Only ingest events that indicate active hostile behavior
            hostile_events = {
                "cowrie.login.failed",
                "cowrie.login.success",
                "cowrie.command.input",
                "cowrie.command.failed",
                "cowrie.session.file_upload",
                "cowrie.session.file_download",
                "cowrie.direct-tcpip.request",
            }

            if event_id not in hostile_events:
                continue

            context = (
                f"Cowrie honeypot hit | event={event_id} "
                f"| timestamp={event.get('timestamp', '')} "
                f"| username={event.get('username', '')} "
                f"| input={event.get('input', '')[:100]}"
            )

            iocs[src_ip] = IOC(
                value=src_ip,
                ioc_type="ip",
                confidence_score=100.0,     # Honeypot hit = maximum confidence
                source=f"cowrie:honeypot:{log_path.name}",
                raw_context=context,
                ttp_tags=_infer_ttps_from_cowrie(event),
            )

    logger.info(f"Cowrie ingestor: found {len(iocs)} unique attacker IPs")
    return list(iocs.values())


def _infer_ttps_from_cowrie(event: dict) -> list[str]:
    """
    Automatically infer MITRE ATT&CK TTPs from Cowrie event type.
    """
    event_id = event.get("eventid", "")
    ttps = []

    if "login" in event_id:
        ttps.append("T1110")    # Brute Force
    if "command" in event_id:
        ttps.append("T1059")    # Command and Scripting Interpreter
    if "file_upload" in event_id or "file_download" in event_id:
        ttps.append("T1105")    # Ingress Tool Transfer
    if "direct-tcpip" in event_id:
        ttps.append("T1021.004")  # SSH lateral movement

    return ttps


async def ingest_cowrie_log(log_path: str | Path):
    """Parse Cowrie log and push all hostile IPs into Neo4j."""
    iocs = parse_cowrie_log_file(log_path)
    for ioc in iocs:
        await upsert_ioc(ioc)
    logger.info(f"Ingested {len(iocs)} Cowrie IOCs into graph")
    return len(iocs)


def tail_cowrie_log(log_path: str | Path, callback):
    """
    Tail a Cowrie log file in real-time using inotify-style polling.
    Calls callback(ioc) for each new hostile IP discovered.
    Use in a background thread/task for live ingestion.
    """
    import time
    log_path = Path(log_path)
    seen_positions = {}

    while True:
        if log_path.exists():
            stat = log_path.stat()
            last_pos = seen_positions.get(str(log_path), 0)

            if stat.st_size > last_pos:
                with open(log_path) as f:
                    f.seek(last_pos)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                            src_ip = event.get("src_ip", "")
                            if src_ip:
                                ioc = IOC(
                                    value=src_ip,
                                    ioc_type="ip",
                                    confidence_score=100.0,
                                    source="cowrie:live",
                                    raw_context=f"Live honeypot: {event.get('eventid')}",
                                    ttp_tags=_infer_ttps_from_cowrie(event),
                                )
                                callback(ioc)
                        except json.JSONDecodeError:
                            pass
                seen_positions[str(log_path)] = stat.st_size

        time.sleep(5)  # poll every 5 seconds
