"""
Unstructured Ingestion — Engine 1
Handles PDF reports, blog RSS feeds, and raw text paste ingestion.
Extracts text and passes to NLP parser + MITRE mapper.
"""
import io
import httpx
import feedparser
import pdfplumber
from pathlib import Path
from loguru import logger

from ingestion.nlp_parser import extract_iocs, refang, IOC
from ingestion.mitre_mapper import map_ttps, TTPMatch


# ── Data class for an ingestion result ───────────────────────────────────────

class IngestionResult:
    def __init__(self, source: str, raw_text: str, iocs: list[IOC], ttps: list[TTPMatch]):
        self.source = source
        self.raw_text = raw_text
        self.iocs = iocs
        self.ttps = ttps
        self.ioc_count = len(iocs)
        self.ttp_count = len(ttps)

    def __repr__(self):
        return f"<IngestionResult source={self.source!r} iocs={self.ioc_count} ttps={self.ttp_count}>"


# ── PDF Ingestion ─────────────────────────────────────────────────────────────

def ingest_pdf(file_path: str | Path | bytes, source_label: str = "pdf") -> IngestionResult:
    """
    Parse a PDF file (path or raw bytes) and extract all IOCs + TTPs.
    Uses pdfplumber for accurate text extraction including tables.
    """
    text_chunks: list[str] = []

    if isinstance(file_path, (str, Path)):
        pdf_source = open(file_path, "rb")
    else:
        pdf_source = io.BytesIO(file_path)

    try:
        with pdfplumber.open(pdf_source) as pdf:
            logger.info(f"Parsing PDF: {len(pdf.pages)} pages")
            for i, page in enumerate(pdf.pages):
                page_text = page.extract_text()
                if page_text:
                    text_chunks.append(page_text)

                # Also extract text from any tables on the page
                tables = page.extract_tables()
                for table in tables:
                    for row in table:
                        row_text = " ".join(str(cell) for cell in row if cell)
                        text_chunks.append(row_text)

    except Exception as e:
        logger.error(f"PDF parse error: {e}")
        raise

    full_text = "\n".join(text_chunks)
    logger.info(f"PDF extracted {len(full_text)} characters")

    return _process_text(full_text, source_label)


# ── Raw Text / Paste Ingestion ────────────────────────────────────────────────

def ingest_text(raw_text: str, source_label: str = "manual_paste") -> IngestionResult:
    """
    Process a raw block of text (e.g. pasted blog post, forum dump).
    Refangs defanged IOCs before processing.
    """
    clean_text = refang(raw_text)
    return _process_text(clean_text, source_label)


# ── RSS Feed Ingestion ────────────────────────────────────────────────────────

def ingest_rss_feed(feed_url: str, max_entries: int = 20) -> list[IngestionResult]:
    """
    Pull a threat intel RSS/Atom feed and ingest each entry.
    Works with feeds from: Krebs on Security, Threatpost, SANS ISC, etc.
    """
    logger.info(f"Fetching RSS feed: {feed_url}")
    results: list[IngestionResult] = []

    try:
        feed = feedparser.parse(feed_url)
        entries = feed.entries[:max_entries]
        logger.info(f"Feed has {len(entries)} entries")

        for entry in entries:
            # Combine title + summary + content
            parts = [entry.get("title", ""), entry.get("summary", "")]
            if hasattr(entry, "content"):
                for content_block in entry.content:
                    parts.append(content_block.get("value", ""))

            combined = " ".join(parts)
            source_label = f"rss:{feed_url}:{entry.get('link', '')[:60]}"
            results.append(_process_text(refang(combined), source_label))

    except Exception as e:
        logger.error(f"RSS ingest error for {feed_url}: {e}")

    return results


# ── URL Ingestion (fetch + parse) ─────────────────────────────────────────────

async def ingest_url(url: str) -> IngestionResult:
    """
    Fetch a web page and extract IOCs from its text content.
    """
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        resp = await client.get(url, headers={"User-Agent": "SPECTER-TIP/1.0"})
        resp.raise_for_status()

    # Strip HTML tags with a simple regex (avoid heavy BeautifulSoup dep)
    import re
    text = re.sub(r"<[^>]+>", " ", resp.text)
    text = re.sub(r"\s+", " ", text)
    return _process_text(refang(text), source_label=f"url:{url}")


# ── Shared Processing ─────────────────────────────────────────────────────────

def _process_text(text: str, source_label: str) -> IngestionResult:
    iocs = extract_iocs(text, source=source_label)
    ttps = map_ttps(text)

    # Attach TTP tags to IOCs for graph enrichment
    ttp_ids = [t.technique_id for t in ttps]
    for ioc in iocs:
        ioc.ttp_tags = ttp_ids

    logger.info(
        f"Processed source={source_label!r} → "
        f"{len(iocs)} IOCs, {len(ttps)} TTPs"
    )
    return IngestionResult(
        source=source_label,
        raw_text=text[:2000],  # store a snippet, not the whole thing
        iocs=iocs,
        ttps=ttps,
    )


# ── Known Threat Intel RSS Feeds ─────────────────────────────────────────────

KNOWN_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://krebsonsecurity.com/feed/",
    "https://isc.sans.edu/rssfeed_full.xml",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
]
