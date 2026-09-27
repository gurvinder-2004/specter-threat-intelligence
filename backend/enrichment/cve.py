"""
CVE Correlation — maps MITRE ATT&CK technique IDs to CVEs via NVD API.
Free, no key needed.
"""
import httpx
import asyncio
from loguru import logger

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ATT&CK → keyword mappings for NVD search
# NVD doesn't have a direct TTP→CVE index, so we search by technique name
TECHNIQUE_KEYWORDS = {
    "T1190": "exploit public-facing application",
    "T1059": "command injection scripting",
    "T1059.001": "powershell execution",
    "T1059.003": "windows command shell",
    "T1078": "valid accounts credential",
    "T1110": "brute force authentication",
    "T1566": "phishing attachment",
    "T1566.001": "spearphishing attachment",
    "T1203": "client execution exploit",
    "T1210": "remote services exploit",
    "T1133": "external remote services VPN",
    "T1574": "DLL hijacking side-loading",
    "T1574.001": "DLL search order hijacking",
    "T1055": "process injection",
    "T1486": "data encryption ransomware",
    "T1195": "supply chain compromise",
    "T1195.002": "compromise software supply chain",
    "T1190": "exploit public-facing application",
    "T1071": "application layer protocol C2",
    "T1021": "remote services lateral movement",
    "T1021.001": "remote desktop protocol RDP",
    "T1021.004": "SSH remote services",
}


async def correlate_cves(technique_ids: list[str]) -> list[dict]:
    """
    For each ATT&CK technique ID, search NVD for related CVEs.
    Returns up to 3 CVEs per technique, deduped.
    """
    if not technique_ids:
        return []

    results = []
    seen_cves = set()

    # Process max 5 techniques to avoid rate limits
    for tid in technique_ids[:5]:
        keyword = TECHNIQUE_KEYWORDS.get(tid)
        if not keyword:
            # Try to search by technique ID directly
            keyword = tid

        try:
            cves = await _search_nvd(keyword, tid)
            for cve in cves:
                if cve["id"] not in seen_cves:
                    seen_cves.add(cve["id"])
                    results.append(cve)
        except Exception as e:
            logger.warning(f"CVE lookup failed for {tid}: {e}")

        await asyncio.sleep(0.7)  # NVD rate limit: 5 req/30s without API key

    results.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
    return results[:20]


async def _search_nvd(keyword: str, technique_id: str) -> list[dict]:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(NVD_BASE, params={
            "keywordSearch": keyword,
            "resultsPerPage": 3,
            "startIndex": 0,
        })
        if r.status_code != 200:
            return []

        data = r.json()
        out  = []
        for vuln in data.get("vulnerabilities", []):
            cve  = vuln.get("cve", {})
            cid  = cve.get("id", "")
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "No description"
            )
            # Get CVSS score (try v3.1 then v3.0 then v2)
            metrics  = cve.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])
            cvss_v2  = metrics.get("cvssMetricV2", [])

            score = 0.0
            severity = "UNKNOWN"
            if cvss_v31:
                score    = cvss_v31[0]["cvssData"]["baseScore"]
                severity = cvss_v31[0]["cvssData"]["baseSeverity"]
            elif cvss_v30:
                score    = cvss_v30[0]["cvssData"]["baseScore"]
                severity = cvss_v30[0]["cvssData"]["baseSeverity"]
            elif cvss_v2:
                score    = cvss_v2[0]["cvssData"]["baseScore"]
                severity = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"

            out.append({
                "id":            cid,
                "technique_id":  technique_id,
                "description":   desc[:300],
                "cvss_score":    score,
                "severity":      severity,
                "published":     cve.get("published", ""),
                "url":           f"https://nvd.nist.gov/vuln/detail/{cid}",
            })
        return out
