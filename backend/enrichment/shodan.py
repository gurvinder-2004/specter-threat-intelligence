"""
Shodan IP Enrichment
Returns open ports, services, ISP, geo, VPN/proxy/TOR tags.
Free Shodan API has no streaming — single host lookup only.
"""
import httpx
from loguru import logger
from config import get_settings

settings = get_settings()
SHODAN_BASE = "https://api.shodan.io"

# ISP patterns that indicate VPS / hosting providers (attackers love these)
HOSTING_ISPS = {
    "digitalocean", "linode", "vultr", "hetzner", "ovh", "scaleway",
    "amazon", "microsoft azure", "google cloud", "alibaba", "tencent",
    "choopa", "peg tech", "m247", "serverius", "frantech", "buyvm",
    "sharktech", "psychz", "velia", "multacom", "quadranet",
}

# Port-to-service mapping for display
PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1080: "SOCKS", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 5900: "VNC", 6379: "Redis", 7474: "Neo4j",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB", 50050: "CobaltStrike-C2",
}

# Ports that are inherently suspicious on internet-facing hosts
SUSPICIOUS_PORTS = {4444, 50050, 31337, 1337, 8888, 9999, 12345}


def _classify_ip(data: dict) -> str:
    """
    Determine if the IP is likely a VPS/hosting node (attacker infra)
    vs residential/ISP (compromised victim).
    """
    org  = (data.get("org", "") or "").lower()
    isp  = (data.get("isp", "") or "").lower()
    tags = data.get("tags", [])

    if any(h in org or h in isp for h in HOSTING_ISPS):
        return "HOSTING_VPS"
    if "tor" in tags:
        return "TOR_EXIT_NODE"
    if "vpn" in tags:
        return "VPN_EXIT"
    if "cloud" in org or "cloud" in isp:
        return "CLOUD_PROVIDER"
    return "RESIDENTIAL_ISP"


async def enrich_shodan(ip: str) -> dict:
    if not getattr(settings, "shodan_api_key", None):
        # Try free no-key endpoint for basic info
        return await _shodan_no_key_fallback(ip)

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(
                f"{SHODAN_BASE}/shodan/host/{ip}",
                params={"key": settings.shodan_api_key},
            )
            if r.status_code == 404:
                return {"ip": ip, "found": False, "message": "IP not in Shodan database"}
            if r.status_code == 401:
                return {"error": "Invalid Shodan API key"}
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            logger.error(f"Shodan error for {ip}: {e}")
            return await _shodan_no_key_fallback(ip)

    ports = data.get("ports", [])
    services = []
    for item in data.get("data", []):
        port = item.get("port", 0)
        service = {
            "port":    port,
            "service": PORT_NAMES.get(port, item.get("_shodan", {}).get("module", "unknown")),
            "banner":  (item.get("data", "") or "")[:120],
            "suspicious": port in SUSPICIOUS_PORTS,
        }
        services.append(service)

    suspicious_ports_found = [p for p in ports if p in SUSPICIOUS_PORTS]
    ip_class = _classify_ip(data)

    result = {
        "ip":             ip,
        "found":          True,
        "country_name":   data.get("country_name", ""),
        "country_code":   data.get("country_code", ""),
        "city":           data.get("city", ""),
        "org":            data.get("org", ""),
        "isp":            data.get("isp", ""),
        "asn":            data.get("asn", ""),
        "ports":          ports[:20],
        "services":       services[:15],
        "hostnames":      data.get("hostnames", [])[:5],
        "domains":        data.get("domains", [])[:5],
        "tags":           data.get("tags", []),
        "last_update":    data.get("last_update", ""),
        "vulns":          list(data.get("vulns", {}).keys())[:10],
        # Analyst-friendly extras
        "ip_classification": ip_class,
        "suspicious_ports":  suspicious_ports_found,
        "verdict": _shodan_verdict(ip_class, suspicious_ports_found, data.get("tags", [])),
    }

    logger.info(f"Shodan: {ip} → {len(ports)} ports, class={ip_class}")
    return result


def _shodan_verdict(ip_class: str, sus_ports: list, tags: list) -> str:
    if sus_ports:
        return f"HIGH RISK — Open ports {sus_ports} suggest active C2/RAT infrastructure"
    if ip_class == "TOR_EXIT_NODE":
        return "TOR EXIT NODE — Attacker anonymizing through Tor network"
    if ip_class == "VPN_EXIT":
        return "VPN EXIT — Attacker using VPN for anonymization"
    if ip_class == "HOSTING_VPS":
        return "VPS/HOSTING — Typical attacker-controlled server infrastructure"
    return "RESIDENTIAL — Possibly compromised end-user device"


async def _shodan_no_key_fallback(ip: str) -> dict:
    """
    Uses ip-api.com (free, no key) for basic geo/ASN when Shodan key is absent.
    Limited but better than nothing.
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,org,isp,as,hosting,proxy,mobile")
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    ip_class = "HOSTING_VPS" if d.get("hosting") else ("VPN_EXIT" if d.get("proxy") else "RESIDENTIAL_ISP")
                    return {
                        "ip": ip, "found": True,
                        "country_name": d.get("country", ""),
                        "city": d.get("city", ""),
                        "org": d.get("org", ""),
                        "isp": d.get("isp", ""),
                        "asn": d.get("as", ""),
                        "ports": [], "services": [], "tags": [],
                        "ip_classification": ip_class,
                        "suspicious_ports": [],
                        "verdict": _shodan_verdict(ip_class, [], []),
                        "note": "Basic data from ip-api.com — add SHODAN_API_KEY for full port scan",
                    }
    except Exception as e:
        logger.debug(f"ip-api fallback failed: {e}")
    return {"ip": ip, "found": False, "error": "No Shodan key configured and geo fallback failed"}
