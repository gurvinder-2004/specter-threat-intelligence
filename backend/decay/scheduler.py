"""
Half-Life Decay Engine — Engine 3
Celery background tasks that degrade IOC confidence scores daily.
"""
from celery.schedules import crontab
from loguru import logger
from decay.celery_app import celery_app
from config import get_settings

settings = get_settings()

# Schedule decay daily at 02:00 UTC, critical check every hour
celery_app.conf.beat_schedule = {
    "daily-decay": {
        "task": "decay.scheduler.run_decay_cycle",
        "schedule": crontab(hour=2, minute=0),
    },
    "hourly-critical-check": {
        "task": "decay.scheduler.check_critical_alerts",
        "schedule": crontab(minute=0),
    },
}


@celery_app.task(name="decay.scheduler.run_decay_cycle")
def run_decay_cycle():
    import asyncio
    from graph.neo4j_client import run_query

    async def _run():
        logger.info("Starting decay cycle...")
        decay_rules = [
            ("ip",       settings.ip_decay_rate,
             "MATCH (n:IOC {ioc_type:'ip', archived:false}) SET n.confidence_score = n.confidence_score * (1 - $rate) RETURN count(n) AS updated"),
            ("domain",   settings.domain_decay_rate,
             "MATCH (n:IOC {ioc_type:'domain', archived:false}) SET n.confidence_score = n.confidence_score * (1 - $rate) RETURN count(n) AS updated"),
            ("hash/url", settings.hash_decay_rate,
             "MATCH (n:IOC) WHERE n.ioc_type IN ['sha256','md5','url'] AND n.archived=false SET n.confidence_score = n.confidence_score * (1 - $rate) RETURN count(n) AS updated"),
        ]
        total = 0
        for label, rate, cypher in decay_rules:
            r = await run_query(cypher, {"rate": rate})
            c = r[0]["updated"] if r else 0
            total += c
            logger.info(f"Decayed {c} {label} IOCs at rate {rate}")

        archive = await run_query(
            "MATCH (n:IOC {archived:false}) WHERE n.confidence_score < $t SET n.archived=true RETURN count(n) AS archived",
            {"t": settings.archive_threshold}
        )
        archived = archive[0]["archived"] if archive else 0
        logger.info(f"Cycle complete: {total} decayed, {archived} archived")
        return {"decayed": total, "archived": archived}

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_run())
    finally:
        loop.close()


@celery_app.task(name="decay.scheduler.check_critical_alerts")
def check_critical_alerts():
    import asyncio
    from graph.neo4j_client import run_query
    from soar.webhooks import send_critical_alert

    async def _run():
        results = await run_query(
            "MATCH (n:IOC {archived:false}) WHERE n.confidence_score >= 90 AND n.created_at >= datetime() - duration('PT1H') RETURN n"
        )
        iocs = [dict(r["n"]) for r in results]
        for ioc in iocs:
            await send_critical_alert(ioc)
        return len(iocs)

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_run())
    finally:
        loop.close()
