"""
Neo4j Client — connection pool + session manager.
All graph operations go through this module.
"""
from neo4j import AsyncGraphDatabase, AsyncDriver
from loguru import logger
from config import get_settings

_driver: AsyncDriver | None = None


async def get_driver() -> AsyncDriver:
    global _driver
    if _driver is None:
        s = get_settings()
        _driver = AsyncGraphDatabase.driver(
            s.neo4j_uri,
            auth=(s.neo4j_user, s.neo4j_password),
            max_connection_lifetime=3600,
            max_connection_pool_size=50,
        )
        logger.info(f"Neo4j driver created → {s.neo4j_uri}")
    return _driver


async def close_driver():
    global _driver
    if _driver:
        await _driver.close()
        _driver = None


async def run_query(cypher: str, params: dict = None) -> list[dict]:
    """Execute a read/write query and return list of record dicts."""
    driver = await get_driver()
    async with driver.session() as session:
        result = await session.run(cypher, params or {})
        records = await result.data()
        return records


async def initialize_schema():
    """
    Create uniqueness constraints and indexes on first run.
    Call this at app startup.
    """
    constraints = [
        # Node uniqueness
        "CREATE CONSTRAINT ioc_value IF NOT EXISTS FOR (n:IOC) REQUIRE n.value IS UNIQUE",
        "CREATE CONSTRAINT actor_name IF NOT EXISTS FOR (n:Actor) REQUIRE n.name IS UNIQUE",
        "CREATE CONSTRAINT campaign_id IF NOT EXISTS FOR (n:Campaign) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT ttp_id IF NOT EXISTS FOR (n:TTP) REQUIRE n.technique_id IS UNIQUE",

        # Indexes for frequent lookups
        "CREATE INDEX ioc_type IF NOT EXISTS FOR (n:IOC) ON (n.ioc_type)",
        "CREATE INDEX ioc_score IF NOT EXISTS FOR (n:IOC) ON (n.confidence_score)",
        "CREATE INDEX ioc_source IF NOT EXISTS FOR (n:IOC) ON (n.source)",
        "CREATE INDEX ioc_created IF NOT EXISTS FOR (n:IOC) ON (n.created_at)",
    ]

    for stmt in constraints:
        try:
            await run_query(stmt)
        except Exception as e:
            logger.warning(f"Schema stmt skipped (may already exist): {e}")

    logger.info("Neo4j schema initialized")
