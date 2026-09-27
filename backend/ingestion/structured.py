"""
Structured Ingestion — Engine 1
Pulls clean IOCs from threat intel APIs:
  - AlienVault OTX (pulses)
  - VirusTotal (IP / file reports)
"""
import httpx
from loguru import logger
from config import get_settings
from ingestion.nlp_parser import IOC


settings = get_settings()


# ── AlienVault OTX ────────────────────────────────────────────────────────────

OTX_BASE = "https://otx.alienvault.com/api/v1"


async def pull_otx_pulses(limit: int = 50) -> list[IOC]:
    """Pull the latest threat pulses from AlienVault OTX."""
    if not settings.otx_api_key:
        logger.warning("OTX_API_KEY not set, skipping OTX pull")
        return []

    headers = {"X-OTX-API-KEY": settings.otx_api_key}
    iocs: list[IOC] = []

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(
                f"{OTX_BASE}/pulses/subscribed",
                headers=headers,
                params={"limit": limit},
            )
            resp.raise_for_status()
            data = resp.json()

            for pulse in data.get("results", []):
                source_label = f"otx:pulse:{pulse.get('id', 'unknown')}"
                pulse_name = pulse.get("name", "")
                tags = pulse.get("tags", [])

                for indicator in pulse.get("indicators", []):
                    ioc_type = _otx_type_map(indicator.get("type", ""))
                    if not ioc_type:
                        continue

                    iocs.append(IOC(
                        value=indicator.get("indicator", ""),
                        ioc_type=ioc_type,
                        confidence_score=100.0,
                        source=source_label,
                        raw_context=f"OTX Pulse: {pulse_name} | tags: {', '.join(tags)}",
                        ttp_tags=[],
                    ))

        except httpx.HTTPError as e:
            logger.error(f"OTX API error: {e}")

    logger.info(f"OTX pulled {len(iocs)} IOCs")
    return iocs


def _otx_type_map(otx_type: str) -> str | None:
    mapping = {
        "IPv4": "ip",
        "IPv6": "ip",
        "domain": "domain",
        "hostname": "domain",
        "FileHash-SHA256": "sha256",
        "FileHash-MD5": "md5",
        "URL": "url",
    }
    return mapping.get(otx_type)


# ── VirusTotal ────────────────────────────────────────────────────────────────

VT_BASE = "https://www.virustotal.com/api/v3"


async def vt_lookup_ip(ip: str) -> dict:
    """
    Look up an IP address on VirusTotal.
    Returns detection stats and malicious flag.
    """
    if not settings.virustotal_api_key:
        return {}

    headers = {"x-apikey": settings.virustotal_api_key}

    async with httpx.AsyncClient(timeout=20) as client:
        try:
            resp = await client.get(f"{VT_BASE}/ip_addresses/{ip}", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "reputation": data["data"]["attributes"].get("reputation", 0),
                "country": data["data"]["attributes"].get("country", ""),
                "asn": data["data"]["attributes"].get("asn", ""),
                "as_owner": data["data"]["attributes"].get("as_owner", ""),
            }
        except Exception as e:
            logger.warning(f"VT lookup failed for {ip}: {e}")
            return {}


async def vt_lookup_hash(file_hash: str) -> dict:
    """Look up a file hash on VirusTotal."""
    if not settings.virustotal_api_key:
        return {}

    headers = {"x-apikey": settings.virustotal_api_key}

    async with httpx.AsyncClient(timeout=20) as client:
        try:
            resp = await client.get(f"{VT_BASE}/files/{file_hash}", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            attrs = data["data"]["attributes"]
            stats = attrs["last_analysis_stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "name": attrs.get("meaningful_name", ""),
                "type": attrs.get("type_description", ""),
                "size": attrs.get("size", 0),
                "first_seen": attrs.get("first_submission_date", ""),
                "tags": attrs.get("tags", []),
                "threat_names": list(attrs.get("popular_threat_classification", {})
                                         .get("suggested_threat_label", "").split("/")),
            }
        except Exception as e:
            logger.warning(f"VT hash lookup failed for {file_hash}: {e}")
            return {}


async def enrich_ioc_with_vt(ioc: IOC) -> IOC:
    """
    Enrich an IOC's confidence score based on VT detection ratio.
    Malicious ratio > 0.5 → boost to 100, harmless → reduce to 40.
    """
    vt_data: dict = {}

    if ioc.ioc_type == "ip":
        vt_data = await vt_lookup_ip(ioc.value)
    elif ioc.ioc_type in ("sha256", "md5"):
        vt_data = await vt_lookup_hash(ioc.value)

    if vt_data:
        total = vt_data.get("total", 1) or 1
        malicious = vt_data.get("malicious", 0)
        ratio = malicious / total

        if ratio > 0.5:
            ioc.confidence_score = 100.0
        elif ratio > 0.2:
            ioc.confidence_score = max(ioc.confidence_score, 75.0)
        elif ratio == 0 and vt_data.get("harmless", 0) > 10:
            ioc.confidence_score = min(ioc.confidence_score, 40.0)

        # Embed ASN/country into context for graph
        if ioc.ioc_type == "ip":
            ioc.raw_context += (
                f" | VT: {malicious}/{total} detections"
                f" | ASN: {vt_data.get('asn', '')} {vt_data.get('as_owner', '')}"
                f" | Country: {vt_data.get('country', '')}"
            )

    return ioc
