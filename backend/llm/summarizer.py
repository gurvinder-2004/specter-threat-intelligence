"""
LLM Layer — Groq (cloud, fast) + Ollama (local, offline)
Falls back gracefully when no key is configured.

FIX: Updated GROQ_MODELS to current non-deprecated models.
     The old list had llama3-70b-8192 etc. which are all deprecated
     and return 400. llama-3.3-70b-versatile is the correct name.
"""
import httpx
from loguru import logger
from config import get_settings

settings = get_settings()

GROQ_BASE = "https://api.groq.com/openai/v1"

# Current valid Groq models (as of 2025-2026)
# The old names (llama3-70b-8192, llama3-8b-8192, mixtral-8x7b-32768)
# are ALL deprecated. Use these instead:
GROQ_MODELS = [
    "llama-3.3-70b-versatile",   # Best quality — use this as primary
    "llama-3.1-70b-versatile",   # Fallback
    "llama-3.1-8b-instant",      # Fast/cheap fallback
    "llama3-groq-70b-8192-tool-use-preview",
    "gemma2-9b-it",              # Google Gemma (still works)
    "mixtral-8x7b-32768",        # May still work but check availability
]

GROQ_DEFAULT_FALLBACK = "llama-3.3-70b-versatile"


async def _groq_complete(system: str, user: str) -> str:
    if not settings.groq_api_key or settings.groq_api_key in ("your_groq_key_here", ""):
        return "[LLM offline — add GROQ_API_KEY to .env and restart Docker]"

    # Use configured model if valid, otherwise use the correct fallback
    model = settings.groq_model
    if model not in GROQ_MODELS:
        logger.warning(
            f"GROQ_MODEL='{model}' not in known valid models. "
            f"Using fallback: {GROQ_DEFAULT_FALLBACK}"
        )
        model = GROQ_DEFAULT_FALLBACK

    headers = {
        "Authorization": f"Bearer {settings.groq_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.3,
        "max_tokens": 512,
    }
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{GROQ_BASE}/chat/completions",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
    except httpx.HTTPStatusError as e:
        logger.error(f"Groq HTTP error {e.response.status_code}: {e.response.text[:200]}")
        return f"[LLM error {e.response.status_code}: {e.response.text[:100]}]"
    except Exception as e:
        logger.error(f"Groq call failed: {e}")
        return f"[LLM unavailable: {str(e)[:120]}]"


async def _ollama_complete(system: str, user: str) -> str:
    payload = {
        "model": settings.ollama_model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 512},
    }
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"{settings.ollama_base_url}/api/chat",
            json=payload,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"].strip()


async def _complete(system: str, user: str) -> str:
    try:
        if settings.llm_provider.lower() == "ollama":
            return await _ollama_complete(system, user)
        return await _groq_complete(system, user)
    except Exception as e:
        logger.error(f"LLM error: {e}")
        return f"[LLM unavailable: {str(e)[:120]}]"


# ── Prompts ───────────────────────────────────────────────────────────────────

BRIEF_SYSTEM = """You are a senior threat intelligence analyst briefing a CISO.
Write exactly 3 clear sentences. No bullet points. No markdown.
Sentence 1: What the threat is and who is behind it (based on the TTPs and IOC types).
Sentence 2: What they target and how they attack (reference specific TTPs from the list).
Sentence 3: Recommended immediate action for the security team.
Be specific — mention technique names, not just IDs."""

NARRATIVE_SYSTEM = """You are a cybersecurity analyst reconstructing an attack campaign.
Given MITRE ATT&CK techniques, describe the full attack chain as a 4-6 sentence story.
Use plain English technique descriptions, not T-numbers. Tell the story chronologically:
initial access → execution → persistence → privilege escalation → exfiltration."""

XAI_SYSTEM = """You are a threat scoring engine. Given an IOC and its metadata,
write exactly 2-3 bullet points explaining WHY it has this confidence score.
Be specific: reference the source, context words, or TTPs that drove the score.
Keep each bullet under 20 words."""

INGESTION_SUMMARY_SYSTEM = """You are a threat intelligence platform summarizing a newly ingested report.
Write a 2-sentence alert summary in plain English.
Sentence 1: What the report is about (threat actor, malware, or campaign if identifiable).
Sentence 2: The most dangerous finding (top TTP or IOC type and count)."""


async def generate_executive_brief(
    ioc_summary: str, ttp_summary: str, source: str = "threat report"
) -> str:
    return await _complete(
        BRIEF_SYSTEM,
        f"Source: {source}\nIOCs: {ioc_summary}\nTTPs: {ttp_summary}\n\nWrite the 3-sentence brief.",
    )


async def generate_ttp_narrative(ttps: list[dict]) -> str:
    if not ttps:
        return "No ATT&CK techniques detected in current IOC set."
    ttp_list = "\n".join(
        f"- {t.get('technique_id','')}: {t.get('name','')} [{t.get('tactic','')}]"
        for t in ttps[:15]
    )
    return await _complete(
        NARRATIVE_SYSTEM,
        f"Techniques:\n{ttp_list}\n\nDescribe the attack campaign as a narrative.",
    )


async def explain_confidence_score(ioc: dict) -> str:
    score  = ioc.get("confidence_score", 0)
    seen   = ioc.get("seen_count", 1)
    ttps   = ioc.get("ttp_tags", [])
    source = ioc.get("source", "")
    ctx    = ioc.get("raw_context", "")
    prompt = f"""IOC: {ioc.get('value')} ({ioc.get('ioc_type')})
Confidence score: {score:.1f}/100
Times seen: {seen}
Source: {source}
MITRE TTPs: {', '.join(ttps[:5]) if ttps else 'none'}
Context snippet: {ctx[:200]}

Explain the score in 2-3 bullet points. Be specific about what drove the score."""
    return await _complete(XAI_SYSTEM, prompt)


async def generate_ingestion_summary(
    source: str, ioc_count: int, ttp_count: int,
    top_ttps: list[str], ioc_breakdown: dict,
) -> str:
    breakdown_str = ", ".join(f"{v} {k}" for k, v in ioc_breakdown.items() if v > 0)
    prompt = f"""Report source: {source}
Total IOCs extracted: {ioc_count} ({breakdown_str})
ATT&CK techniques detected: {ttp_count}
Top techniques: {', '.join(top_ttps[:5]) if top_ttps else 'none'}

Write the 2-sentence alert summary."""
    return await _complete(INGESTION_SUMMARY_SYSTEM, prompt)


async def enrich_ioc_context(ioc_value: str, ioc_type: str, raw_context: str) -> str:
    return await _complete(
        "You are a threat intel researcher. Give a 2-sentence threat assessment. Be factual and specific.",
        f"IOC: {ioc_value} ({ioc_type})\nContext: {raw_context[:600]}",
    )
