"""
VirusTotal IOC Enrichment
Queries VT v3 API for IPs, domains, hashes, and URLs.
Returns detection ratio, vendor tags, sandbox behavior, reputation.
"""
import httpx
import hashlib
import base64
from loguru import logger
from config import get_settings

settings = get_settings()
VT_BASE = "https://www.virustotal.com/api/v3"


def _vt_headers():
    return {"x-apikey": settings.virustotal_api_key}


def _url_id(url: str) -> str:
    """VT v3 requires URLs to be base64url-encoded without padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _detect_type(value: str) -> str:
    v = value.strip()
    if len(v) == 64 and all(c in "0123456789abcdefABCDEF" for c in v):
        return "sha256"
    if len(v) == 32 and all(c in "0123456789abcdefABCDEF" for c in v):
        return "md5"
    import re
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", v):
        return "ip"
    if v.startswith("http://") or v.startswith("https://") or v.startswith("hxxp"):
        return "url"
    return "domain"


async def enrich_virustotal(ioc_value: str) -> dict:
    if not settings.virustotal_api_key:
        return {"error": "VIRUSTOTAL_API_KEY not set in .env"}

    ioc_type = _detect_type(ioc_value)
    headers  = _vt_headers()

    # Route to correct VT endpoint
    if ioc_type == "ip":
        url = f"{VT_BASE}/ip_addresses/{ioc_value}"
    elif ioc_type == "domain":
        url = f"{VT_BASE}/domains/{ioc_value}"
    elif ioc_type == "sha256":
        url = f"{VT_BASE}/files/{ioc_value}"
    elif ioc_type == "md5":
        url = f"{VT_BASE}/files/{ioc_value}"
    elif ioc_type == "url":
        url = f"{VT_BASE}/urls/{_url_id(ioc_value)}"
    else:
        return {"error": f"Unsupported IOC type: {ioc_type}"}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(url, headers=headers)

            if r.status_code == 404:
                return {"ioc": ioc_value, "type": ioc_type, "found": False,
                        "message": "Not found in VirusTotal database"}
            if r.status_code == 401:
                return {"error": "Invalid VirusTotal API key"}
            if r.status_code == 429:
                return {"error": "VirusTotal rate limit hit — free tier is 4 req/min"}
            r.raise_for_status()

            data   = r.json()
            attrs  = data.get("data", {}).get("attributes", {})
            stats  = attrs.get("last_analysis_stats", {})
            mal    = stats.get("malicious", 0)
            sus    = stats.get("suspicious", 0)
            total  = sum(stats.values()) if stats else 0

            # Extract vendor names that flagged it
            analysis = attrs.get("last_analysis_results", {})
            flagging_vendors = [
                v for v, r in analysis.items()
                if r.get("category") in ("malicious", "suspicious")
            ][:10]

            result = {
                "ioc":              ioc_value,
                "type":             ioc_type,
                "found":            True,
                "malicious":        mal,
                "suspicious":       sus,
                "harmless":         stats.get("harmless", 0),
                "undetected":       stats.get("undetected", 0),
                "total_engines":    total,
                "detection_ratio":  f"{mal}/{total}" if total else "0/0",
                "reputation":       attrs.get("reputation", 0),
                "last_analysis_date": attrs.get("last_analysis_date", ""),
                "categories":       attrs.get("categories", {}),
                "flagging_vendors": flagging_vendors,
                "tags":             attrs.get("tags", []),
            }

            # IP-specific extras
            if ioc_type == "ip":
                result["country"]          = attrs.get("country", "")
                result["as_owner"]         = attrs.get("as_owner", "")
                result["asn"]              = attrs.get("asn", "")
                result["network"]          = attrs.get("network", "")
                result["regional_internet_registry"] = attrs.get("regional_internet_registry", "")

            # Domain-specific extras
            if ioc_type == "domain":
                result["registrar"]        = attrs.get("registrar", "")
                result["creation_date"]    = attrs.get("creation_date", "")
                result["whois"]            = attrs.get("whois", "")[:300] if attrs.get("whois") else ""

            # File-specific extras
            if ioc_type in ("sha256", "md5"):
                result["meaningful_name"]  = attrs.get("meaningful_name", "")
                result["file_type"]        = attrs.get("type_description", "")
                result["size"]             = attrs.get("size", 0)
                result["magic"]            = attrs.get("magic", "")
                result["names"]            = attrs.get("names", [])[:5]
                # Sandbox behavior summary
                sandbox = attrs.get("sandbox_verdicts", {})
                result["sandbox_verdicts"] = {k: v.get("category","") for k, v in list(sandbox.items())[:5]}

            logger.info(f"VT enrichment: {ioc_value} → {mal}/{total} malicious")
            return result

        except httpx.HTTPStatusError as e:
            logger.error(f"VT HTTP error for {ioc_value}: {e.response.status_code}")
            return {"error": f"VT error {e.response.status_code}", "ioc": ioc_value}
        except Exception as e:
            logger.error(f"VT enrichment failed for {ioc_value}: {e}")
            return {"error": str(e)[:200], "ioc": ioc_value}
