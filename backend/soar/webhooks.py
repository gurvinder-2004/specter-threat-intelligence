"""
SPECTER — Discord Interactive Alerts v2
ONE summary message per ingestion, not 500 individual IOC alerts.
Message has action buttons — user clicks to get enrichment on demand.

Flow:
  1. PDF ingested → one "ingestion summary" embed with 4 buttons
  2. User clicks "🔬 VT Enrich" → bot responds with VirusTotal data
  3. User clicks "🌐 Shodan" → bot responds with port/geo data
  4. User clicks "🧠 AI Brief" → bot responds with LLM analysis
  5. User clicks "🛡️ Block Now" → bot responds with firewall rule

For INDIVIDUAL critical IOC alerts (honeypot hits etc.):
  Same pattern — one embed per IOC with 4 buttons.

Requirements:
  - DISCORD_WEBHOOK_URL in .env for sending messages
  - DISCORD_BOT_TOKEN in .env for slash commands (optional)
  - DISCORD_PUBLIC_KEY in .env to verify button click signatures
  - Your FastAPI must be publicly accessible for Discord to POST interactions to it
    → Use ngrok: ngrok http 8000, then set interactions URL in Discord dev portal
"""
import httpx
from datetime import datetime, timezone
from loguru import logger
from config import get_settings
from soar.defanger import defang_ioc

settings = get_settings()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _severity_label(score: float) -> str:
    if score >= 90: return "🔴 CRITICAL"
    if score >= 70: return "🟠 HIGH"
    if score >= 50: return "🟡 MEDIUM"
    return "🟢 LOW"

def _severity_color(score: float) -> int:
    if score >= 90: return 0xFF0000
    if score >= 70: return 0xFF6600
    if score >= 50: return 0xFFCC00
    return 0x39FF14

def _score_bar(score: float) -> str:
    filled = int(score / 10)
    return "█" * filled + "░" * (10 - filled)

def _type_icon(t: str) -> str:
    return {"ip":"🌐","domain":"🔗","sha256":"#️⃣","md5":"#️⃣","url":"↗️","email":"✉️"}.get(t,"◆")

def _ttp_links(tags: list) -> str:
    if not tags:
        return "None detected"
    parts = [f"[{t}](https://attack.mitre.org/techniques/{t.replace('.','/')})" for t in tags[:6]]
    s = " · ".join(parts)
    if len(tags) > 6:
        s += f" *(+{len(tags)-6} more)*"
    return s


# ── Action buttons ────────────────────────────────────────────────────────────
# Discord component structure for message action rows

def _ioc_buttons(ioc_value: str, ioc_type: str) -> list[dict]:
    """
    Returns the Discord message components (buttons) for an IOC alert.
    custom_id format: "action:ioc_value" — parsed in main.py interactions handler.
    """
    safe = ioc_value[:80]  # Discord custom_id limit is 100 chars
    buttons = [
        {
            "type": 2,
            "style": 1,  # PRIMARY (blue)
            "label": "🔬 VirusTotal",
            "custom_id": f"vt:{safe}",
        },
        {
            "type": 2,
            "style": 1,
            "label": "🧠 AI Analysis",
            "custom_id": f"explain:{safe}",
        },
    ]

    # Shodan only makes sense for IPs
    if ioc_type == "ip":
        buttons.append({
            "type": 2,
            "style": 2,  # SECONDARY (grey)
            "label": "🌐 Shodan",
            "custom_id": f"shodan:{safe}",
        })

    buttons.append({
        "type": 2,
        "style": 4,  # DANGER (red)
        "label": "🛡️ Block Now",
        "custom_id": f"block:{safe}",
    })

    return [{"type": 1, "components": buttons}]  # ActionRow wrapping


async def _post_discord(payload: dict) -> bool:
    if not settings.discord_webhook_url or "discord.com" not in settings.discord_webhook_url:
        logger.debug("Discord webhook not configured — skipping alert")
        return False
    async with httpx.AsyncClient(timeout=12) as client:
        try:
            r = await client.post(
                settings.discord_webhook_url + "?wait=true",  # wait=true returns message ID
                json=payload,
            )
            if r.status_code in (200, 204):
                logger.info(f"Discord alert sent → {r.status_code}")
                return True
            logger.warning(f"Discord returned {r.status_code}: {r.text[:200]}")
            return False
        except Exception as e:
            logger.error(f"Discord post failed: {e}")
            return False


# ── Ingestion summary alert (one per PDF/OTX pull) ───────────────────────────

async def send_ingestion_summary_alert(
    source: str, ioc_count: int, critical_count: int,
    ttp_count: int, ai_summary: str, ioc_breakdown: dict,
):
    breakdown_str = " | ".join(f"**{v}** {k}" for k, v in ioc_breakdown.items() if v > 0)
    color = 0xFF0000 if critical_count > 10 else 0xFF8800 if critical_count > 0 else 0x39FF14

    fields = []
    if ai_summary and not ai_summary.startswith("[LLM"):
        fields.append({
            "name": "🧠 Threat Intelligence Summary",
            "value": ai_summary,
            "inline": False,
        })

    fields += [
        {"name": "📄 Source",        "value": f"`{source}`",       "inline": True},
        {"name": "☣️ Total IOCs",    "value": str(ioc_count),      "inline": True},
        {"name": "🔴 Critical",      "value": str(critical_count), "inline": True},
        {"name": "🎯 ATT&CK TTPs",  "value": str(ttp_count),      "inline": True},
        {"name": "📊 Breakdown",     "value": breakdown_str or "—","inline": False},
        {
            "name": "⚡ What to do",
            "value": "Click **View Dashboard** or use the buttons below to enrich critical indicators.",
            "inline": False,
        },
    ]

    payload = {
        "username": "SPECTER TIP",
        "embeds": [{
            "title": "📥 Intelligence Ingested — SPECTER",
            "description": f"New threat data processed from **{source}**. {critical_count} indicators require immediate attention.",
            "color": color,
            "fields": fields,
            "footer": {"text": "SPECTER Threat Intelligence Platform"},
            "timestamp": _utc_now(),
        }],
        "components": [{
            "type": 1,
            "components": [
                {
                    "type": 2, "style": 5,  # LINK button
                    "label": "🖥️ View Dashboard",
                    "url": "http://localhost:3000",
                },
                {
                    "type": 2, "style": 5,
                    "label": "📊 Threat Map",
                    "url": "http://localhost:3000/graph",
                },
                {
                    "type": 2, "style": 5,
                    "label": "📋 Reports",
                    "url": "http://localhost:3000/reports",
                },
            ],
        }],
    }
    await _post_discord(payload)


# ── Individual critical IOC alert (honeypot hits, single-IOC events) ─────────

async def send_critical_alert(ioc: dict):
    """
    Sends ONE embed for a specific IOC with enrichment buttons.
    Used for honeypot hits and manually triggered alerts.
    Not used for bulk PDF ingestion (use send_ingestion_summary_alert instead).
    """
    score     = ioc.get("confidence_score", 0)
    ioc_type  = ioc.get("ioc_type", "unknown")
    raw_value = ioc.get("value", "")
    safe_val  = defang_ioc(raw_value, ioc_type)
    ttps      = ioc.get("ttp_tags", []) or []
    source    = ioc.get("source", "unknown")
    ctx       = (ioc.get("raw_context") or "No context captured")[:280]

    # Get AI summary
    ai_summary = await _get_ai_summary(ioc)

    fields = []
    if ai_summary:
        fields.append({
            "name": "🧠 Executive Summary",
            "value": ai_summary,
            "inline": False,
        })

    fields += [
        {
            "name": f"{_type_icon(ioc_type)} Indicator",
            "value": f"```{safe_val}```",
            "inline": False,
        },
        {"name": "Type",     "value": ioc_type.upper(),                          "inline": True},
        {"name": "Score",    "value": f"`{_score_bar(score)}` **{score:.0f}**",  "inline": True},
        {"name": "Severity", "value": _severity_label(score),                    "inline": True},
        {"name": "Source",   "value": f"`{source}`",                             "inline": True},
        {"name": "MITRE ATT&CK", "value": _ttp_links(ttps),                     "inline": False},
        {"name": "Context",  "value": f"*{ctx}*",                                "inline": False},
        {
            "name": "🚨 Respond",
            "value": "Use the buttons below to enrich this IOC, get AI analysis, or generate a firewall block rule.",
            "inline": False,
        },
    ]

    payload = {
        "username": "SPECTER TIP",
        "embeds": [{
            "title": f"⚠️ SPECTER Alert — {_severity_label(score)}",
            "description": (
                f"A **{ioc_type.upper()}** indicator has triggered a **{_severity_label(score)}** alert."
            ),
            "color": _severity_color(score),
            "fields": fields,
            "footer": {"text": "SPECTER Threat Intelligence Platform · Click buttons to investigate"},
            "timestamp": _utc_now(),
        }],
        "components": _ioc_buttons(raw_value, ioc_type),
    }

    await _post_discord(payload)


# ── LLM summary helper ────────────────────────────────────────────────────────

async def _get_ai_summary(ioc: dict) -> str:
    try:
        from llm.summarizer import _complete
        score = ioc.get("confidence_score", 0)
        system = (
            "You are a threat intelligence analyst. Write exactly 2 sentences. "
            "Sentence 1: What this IOC is and why it is dangerous. "
            "Sentence 2: What the SOC team should do right now. "
            "Be specific. Reference TTPs and context. No bullets."
        )
        prompt = (
            f"IOC: {ioc.get('value')} ({ioc.get('ioc_type')})\n"
            f"Score: {score:.0f}/100\nSource: {ioc.get('source','')}\n"
            f"TTPs: {', '.join((ioc.get('ttp_tags') or [])[:5]) or 'none'}\n"
            f"Context: {(ioc.get('raw_context') or '')[:250]}"
        )
        result = await _complete(system, prompt)
        return "" if result.startswith("[LLM") else result
    except Exception:
        return ""


# ── Slack (kept for completeness) ────────────────────────────────────────────

async def send_slack_alert(ioc: dict):
    if not getattr(settings, "slack_webhook_url", "") or "hooks.slack.com" not in settings.slack_webhook_url:
        return
    score     = ioc.get("confidence_score", 0)
    safe_val  = defang_ioc(ioc.get("value", ""), ioc.get("ioc_type", ""))
    ttps      = ioc.get("ttp_tags", []) or []

    payload = {
        "text": f"SPECTER {_severity_label(score)} — `{safe_val}`",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f"⚠️ SPECTER Alert — {_severity_label(score)}"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*IOC:*\n`{safe_val}`"},
                {"type": "mrkdwn", "text": f"*Score:*\n`{_score_bar(score)}` {score:.0f}/100"},
                {"type": "mrkdwn", "text": f"*Type:*\n{ioc.get('ioc_type','').upper()}"},
                {"type": "mrkdwn", "text": f"*Source:*\n{ioc.get('source','')}"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn",
                "text": f"*TTPs:* {', '.join(ttps[:6]) or 'none'}\n*Context:* {(ioc.get('raw_context') or '')[:200]}"}},
            {"type": "divider"},
        ],
    }
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            await client.post(settings.slack_webhook_url, json=payload)
        except Exception as e:
            logger.error(f"Slack alert failed: {e}")
