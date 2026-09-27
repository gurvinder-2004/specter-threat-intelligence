"""
NLP Parser — Engine 1 core
Extracts IPs, domains, SHA256/MD5 hashes from raw text using
regex + context-aware scoring. Returns structured IOC objects.

FIXES in this version:
- Benign domain allowlist (github, microsoft, cisa, etc. won't be flagged)
- Context-aware scoring: lowers score when domain appears in benign sentence context
- refang() is now called BEFORE extraction in all paths
- Defanged IPs like 45.227.254[.]124 are properly handled
"""
import re
import spacy
from dataclasses import dataclass, field
from typing import Literal
from loguru import logger

# ── IOC Types ────────────────────────────────────────────────────────────────

IOCType = Literal["ip", "domain", "sha256", "md5", "url", "email"]


@dataclass
class IOC:
    value: str
    ioc_type: IOCType
    confidence_score: float = 100.0
    source: str = "unknown"
    raw_context: str = ""
    ttp_tags: list[str] = field(default_factory=list)


# ── Benign Domain Allowlist ───────────────────────────────────────────────────
# These are well-known legitimate services that appear in threat reports
# as references, sources, or tools — NOT as malicious indicators.
# Add more as needed.

BENIGN_DOMAINS = {
    # Security organizations & references
    "cisa.gov", "us-cert.gov", "nist.gov", "dhs.gov", "fbi.gov",
    "cisa.cisa.gov", "nvd.nist.gov",
    # Research & threat intel sources
    "virustotal.com", "shodan.io", "abuse.ch", "malwarebytes.com",
    "mandiant.com", "crowdstrike.com", "fireeye.com", "secureworks.com",
    "trendmicro.com", "checkpoint.com", "paloaltonetworks.com",
    "recordedfuture.com", "threatpost.com", "krebsonsecurity.com",
    "bleepingcomputer.com", "darkreading.com", "sans.org", "isc.sans.edu",
    # MITRE ATT&CK
    "attack.mitre.org", "mitre.org",
    # Code / dev platforms (mentioned as attack vectors or tool downloads)
    "github.com", "raw.githubusercontent.com", "gitlab.com",
    "pypi.org", "npmjs.com", "nuget.org",
    # Microsoft (mentioned constantly in reports about Windows TTPs)
    "microsoft.com", "learn.microsoft.com", "docs.microsoft.com",
    "windowsupdate.com", "microsoftstore.com", "azure.com",
    "office.com", "office365.com", "sharepoint.com", "outlook.com",
    # Google infrastructure
    "google.com", "googleapis.com", "googledrive.com", "gstatic.com",
    "googletagmanager.com", "doubleclick.net",
    # Cloudflare / CDN (often mentioned in infra descriptions)
    "cloudflare.com", "cloudflare.net",
    # AWS / cloud
    "amazonaws.com", "awsstatic.com",
    # Vulnerability databases
    "cve.mitre.org", "nvd.nist.gov", "exploit-db.com", "vuldb.com",
    # Common legitimate file-sharing referenced in reports
    "dropbox.com", "onedrive.live.com",
    # Apple
    "apple.com", "icloud.com",
    # Threat intel reports often mention these as examples
    "poetpages.com", "cisecurity.org",
    # Social / messaging
    "twitter.com", "x.com", "telegram.org",
    # Certificates / OSCP
    "ocsp.digicert.com", "crl.verisign.com",
}

# ── Context keywords that indicate a BENIGN mention ──────────────────────────
# If these words appear near an IOC, lower its confidence score significantly
BENIGN_CONTEXT_KEYWORDS = [
    "according to", "source:", "reference", "reported by", "see also",
    "visit", "download from", "available at", "published by", "via",
    "as documented", "from the", "indicator platform", "threat intel",
    "information shared", "see reference", "for more information",
    "guidance", "advisory", "https://cisa", "https://github",
    "https://microsoft", "as described in", "as mentioned in",
    "similar to", "documented by", "blog post", "vulnerability database",
    "mitre att&ck", "cve-", "nvd",
]

# ── Malicious Context keywords that INCREASE confidence ──────────────────────
MALICIOUS_CONTEXT_KEYWORDS = [
    "c2", "c&c", "command and control", "backdoor", "exfiltrat",
    "malware", "ransomware", "trojan", "botnet", "dropper", "loader",
    "beacon", "payload", "shellcode", "exploit", "phishing",
    "lateral movement", "persistence", "privilege escalation",
    "compromised", "attacker", "threat actor", "ioc", "indicator",
    "malicious", "suspicious", "blocked", "detected", "infected",
]


# ── Regex Patterns ────────────────────────────────────────────────────────────

_PATTERNS: dict[IOCType, re.Pattern] = {
    # IPv4 — standard form (defanging handled by refang() before this runs)
    "ip": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    # Domains — common TLDs, avoids matching version numbers
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+?"
        r"(?:com|net|org|io|gov|edu|ru|cn|cc|xyz|info|biz|onion|top|club|"
        r"site|online|store|shop|live|tech|click|icu|pw|tk|ml|ga|cf)\b",
        re.IGNORECASE,
    ),
    # SHA-256 (64 hex chars)
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    # MD5 (32 hex chars) — applied carefully, skip if embedded in sha256
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    # Defanged URLs: hxxp[s]?://... (refang() converts these to real URLs first,
    # but we keep this pattern to catch any that slip through in context fields)
    "url": re.compile(
        r"hxxps?://[^\s\"'<>\]]+",
        re.IGNORECASE,
    ),
}

# ── Private / Special IPs — filter these out ──────────────────────────────────
_PRIVATE_PREFIXES = (
    "10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.2", "172.3", "0.0.0.0", "255.", "169.254.",
)


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


# ── Context-Aware Confidence Scoring ─────────────────────────────────────────

def _score_from_context(context: str, ioc_type: IOCType) -> float:
    """
    Return a confidence score (0–100) based on surrounding text context.
    Hashes always stay at 100 (their mere presence is suspicious).
    Domains and IPs are scored by context signals.
    """
    ctx = context.lower()

    # Hashes are always meaningful — no context downgrade
    if ioc_type in ("sha256", "md5"):
        return 100.0

    # Count signals
    benign_hits = sum(1 for kw in BENIGN_CONTEXT_KEYWORDS if kw in ctx)
    malicious_hits = sum(1 for kw in MALICIOUS_CONTEXT_KEYWORDS if kw in ctx)

    if malicious_hits >= 2:
        return 100.0
    if malicious_hits == 1:
        return 85.0
    if benign_hits >= 2:
        return 15.0   # Almost certainly a reference, not an IOC
    if benign_hits == 1:
        return 40.0   # Possibly benign — low confidence
    # No strong signal either way
    return 65.0


# ── Load spaCy model (lazy) ───────────────────────────────────────────────────
_nlp = None


def _get_nlp():
    global _nlp
    if _nlp is None:
        try:
            _nlp = spacy.load("en_core_web_trf")
            logger.info("spaCy model loaded: en_core_web_trf")
        except OSError:
            logger.warning("en_core_web_trf not found, falling back to en_core_web_sm")
            try:
                _nlp = spacy.load("en_core_web_sm")
            except OSError:
                logger.warning("No spaCy model found, NER disabled")
                _nlp = None
    return _nlp


# ── Core Extraction ───────────────────────────────────────────────────────────

def extract_iocs(text: str, source: str = "unknown") -> list[IOC]:
    """
    Extract all IOCs from a raw text blob.
    - Always refangs the text first
    - Filters benign domains via allowlist
    - Scores confidence based on surrounding context
    - Returns deduplicated IOC objects
    """
    # Always refang before extraction — handles defanged IPs and URLs
    text = refang(text)

    iocs: dict[str, IOC] = {}   # value → IOC (dedup by value)

    # 1. Regex sweep
    for ioc_type, pattern in _PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)

            # --- Filters ---
            if ioc_type == "ip" and _is_private_ip(value):
                continue
            if ioc_type == "md5" and len(value) == 32:
                # Skip if it's actually embedded inside a sha256
                start_pos = match.start()
                if start_pos > 0 and len(text) > match.end():
                    char_before = text[start_pos - 1] if start_pos > 0 else " "
                    char_after = text[match.end()] if match.end() < len(text) else " "
                    if char_before in "0123456789abcdefABCDEF" or char_after in "0123456789abcdefABCDEF":
                        continue

            # --- Domain allowlist ---
            if ioc_type == "domain":
                value_lower = value.lower()
                if value_lower in BENIGN_DOMAINS:
                    logger.debug(f"Skipping allowlisted domain: {value}")
                    continue
                # Also skip subdomains of benign domains
                if any(value_lower.endswith("." + bd) for bd in BENIGN_DOMAINS):
                    logger.debug(f"Skipping subdomain of allowlisted domain: {value}")
                    continue

            # --- Grab context ---
            start = max(0, match.start() - 80)
            end = min(len(text), match.end() + 80)
            context = text[start:end].replace("\n", " ").strip()

            # --- Context-based confidence scoring ---
            score = _score_from_context(context, ioc_type)

            # Skip very low confidence IOCs entirely (likely references)
            if score < 20:
                logger.debug(f"Skipping low-confidence IOC {value} (score={score})")
                continue

            if value not in iocs:
                iocs[value] = IOC(
                    value=value,
                    ioc_type=ioc_type,
                    confidence_score=score,
                    source=source,
                    raw_context=context,
                )
            else:
                # If we've seen it before, keep the higher score
                if score > iocs[value].confidence_score:
                    iocs[value].confidence_score = score
                    iocs[value].raw_context = context

    # 2. spaCy NER sweep — actor / organization hints
    nlp = _get_nlp()
    if nlp:
        try:
            doc = nlp(text[:100_000])   # cap at 100k chars
            actor_hints = {ent.text for ent in doc.ents if ent.label_ in ("ORG", "GPE", "PERSON")}
            logger.debug(f"Actor hints from NER: {len(actor_hints)}")
        except Exception as e:
            logger.warning(f"spaCy NER failed: {e}")

    result = list(iocs.values())
    logger.info(f"Extracted {len(result)} IOCs from source={source!r}")
    return result


def _looks_like_sha256_fragment(value: str) -> bool:
    return len(value) == 32


def refang(text: str) -> str:
    """
    Convert ALL known defanging patterns back to normal form.
    This runs BEFORE regex extraction so patterns like 45[.]227[.]254[.]124
    are properly matched by the IP regex.
    """
    return (
        text
        # URL defanging
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("HXXPS://", "https://")
        .replace("HXXP://", "http://")
        # Dot defanging variants
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[dot]", ".")
        .replace("(dot)", ".")
        .replace("[d0t]", ".")
        .replace("{.}", ".")
        # At-sign defanging (emails)
        .replace("[@]", "@")
        .replace("[at]", "@")
        .replace("(at)", "@")
        # Slash defanging (URLs)
        .replace("[/]", "/")
        # Port brackets (less common)
        .replace("[:]", ":")
    )


def defang(value: str) -> str:
    """Sanitize IOC so it can't be accidentally clicked/resolved."""
    return (
        value.replace("http", "hxxp")
             .replace(".", "[.]", 1)
    )
