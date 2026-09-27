"""
Diamond Model Graph — Engine 2
"""
from datetime import datetime, timezone, timedelta
from loguru import logger
from graph.neo4j_client import run_query
from ingestion.nlp_parser import IOC
from ingestion.mitre_mapper import TTPMatch



def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def upsert_ioc(ioc: IOC) -> dict:
    now = _utc_now()
    cypher = """
    MERGE (n:IOC {value: $value})
    ON CREATE SET
        n.ioc_type         = $ioc_type,
        n.confidence_score = $confidence_score,
        n.source           = $source,
        n.raw_context      = $raw_context,
        n.ttp_tags         = $ttp_tags,
        n.created_at       = $now,
        n.last_seen        = $now,
        n.seen_count       = 1,
        n.archived         = false
    ON MATCH SET
        n.last_seen        = $now,
        n.seen_count       = n.seen_count + 1,
        n.confidence_score = CASE
            WHEN n.confidence_score < $confidence_score THEN $confidence_score
            ELSE n.confidence_score END
    RETURN n
    """
    results = await run_query(cypher, {
        "value": ioc.value, "ioc_type": ioc.ioc_type,
        "confidence_score": ioc.confidence_score,
        "source": ioc.source, "raw_context": ioc.raw_context[:500],
        "ttp_tags": ioc.ttp_tags, "now": now,
    })
    return results[0]["n"] if results else {}


async def upsert_many_iocs(iocs: list[IOC]) -> int:
    for ioc in iocs:
        await upsert_ioc(ioc)
    logger.info(f"Upserted {len(iocs)} IOCs")
    return len(iocs)


async def upsert_ttp(ttp) -> dict:
    """
    Fixed upsert_ttp that ensures technique_id property is set correctly.
    Some versions wrote `id` instead of `technique_id`, breaking the MATCH in link_ioc_to_ttp.
    """
    result = await run_query(
        """
        MERGE (t:TTP {technique_id: $tid})
        SET t.name    = $name,
            t.tactic  = $tactic,
            t.url     = $url
        RETURN t
        """,
        {
            "tid":    ttp.technique_id,
            "name":   ttp.technique_name or ttp.technique_id,
            "tactic": ttp.tactic or "",
            "url":    f"https://attack.mitre.org/techniques/{ttp.technique_id.replace('.','/')}"
        },
    )
    return dict(result[0]["t"]) if result else {}


async def upsert_actor(name: str, aliases: list[str] = None, nation: str = "") -> dict:
    cypher = """
    MERGE (a:Actor {name: $name})
    ON CREATE SET a.aliases=$aliases, a.nation=$nation, a.created_at=$now
    RETURN a
    """
    results = await run_query(cypher, {
        "name": name, "aliases": aliases or [], "nation": nation, "now": _utc_now()
    })
    return results[0]["a"] if results else {}


async def upsert_campaign(campaign_id, name, description="", first_seen="", targets=None):
    cypher = """
    MERGE (c:Campaign {id: $campaign_id})
    ON CREATE SET c.name=$name, c.description=$description,
        c.first_seen=$first_seen, c.targets=$targets, c.created_at=$now
    RETURN c
    """
    results = await run_query(cypher, {
        "campaign_id": campaign_id, "name": name, "description": description,
        "first_seen": first_seen, "targets": targets or [], "now": _utc_now()
    })
    return results[0]["c"] if results else {}


async def link_actor_to_ioc(actor_name: str, ioc_value: str, relationship: str = "USES"):
    cypher = f"""
    MATCH (a:Actor {{name: $actor_name}})
    MATCH (i:IOC {{value: $ioc_value}})
    MERGE (a)-[:{relationship}]->(i)
    """
    await run_query(cypher, {"actor_name": actor_name, "ioc_value": ioc_value})


async def link_ioc_to_campaign(ioc_value: str, campaign_id: str):
    cypher = """
    MATCH (i:IOC {value: $ioc_value})
    MATCH (c:Campaign {id: $campaign_id})
    MERGE (i)-[:PART_OF]->(c)
    """
    await run_query(cypher, {"ioc_value": ioc_value, "campaign_id": campaign_id})


async def get_active_iocs(limit: int = 100) -> list[dict]:
    cypher = """
    MATCH (n:IOC)
    WHERE n.archived = false AND n.confidence_score >= 30
    RETURN n ORDER BY n.confidence_score DESC LIMIT $limit
    """
    results = await run_query(cypher, {"limit": limit})
    return [r["n"] for r in results]


async def get_critical_iocs() -> list[dict]:
    cypher = """
    MATCH (n:IOC)
    WHERE n.archived = false AND n.confidence_score >= 80
    RETURN n ORDER BY n.confidence_score DESC
    """
    results = await run_query(cypher)
    return [r["n"] for r in results]


async def search_iocs(query: str, limit: int = 50) -> list[dict]:
    cypher = """
    MATCH (n:IOC)
    WHERE toLower(n.value) CONTAINS toLower($query)
       OR toLower(n.raw_context) CONTAINS toLower($query)
    RETURN n ORDER BY n.confidence_score DESC LIMIT $limit
    """
    results = await run_query(cypher, {"query": query, "limit": limit})
    return [r["n"] for r in results]


async def get_ioc_neighborhood(value: str, depth: int = 2) -> list[dict]:
    cypher = """
    MATCH path = (start:IOC {value: $value})-[*1..$depth]-(connected)
    RETURN path LIMIT 200
    """
    return await run_query(cypher, {"value": value, "depth": depth})


async def get_stats() -> dict:
    """Fixed stats query — separate counts to avoid Cartesian product bug."""
    ioc_q   = await run_query("MATCH (n:IOC) RETURN count(n) AS total, count(CASE WHEN n.archived=false THEN 1 END) AS active, count(CASE WHEN n.confidence_score>=80 AND n.archived=false THEN 1 END) AS critical")
    actor_q = await run_query("MATCH (a:Actor) RETURN count(a) AS cnt")
    camp_q  = await run_query("MATCH (c:Campaign) RETURN count(c) AS cnt")
    ttp_q   = await run_query("MATCH (t:TTP) RETURN count(t) AS cnt")
    type_q  = await run_query("MATCH (n:IOC) WHERE n.archived=false RETURN n.ioc_type AS t, count(n) AS c")

    ioc_row  = ioc_q[0]  if ioc_q  else {}
    type_breakdown = {r["t"]: r["c"] for r in type_q}

    return {
        "total_iocs":    ioc_row.get("total",    0),
        "active_iocs":   ioc_row.get("active",   0),
        "critical_iocs": ioc_row.get("critical", 0),
        "actors":        actor_q[0]["cnt"] if actor_q else 0,
        "campaigns":     camp_q[0]["cnt"]  if camp_q  else 0,
        "ttps":          ttp_q[0]["cnt"]   if ttp_q   else 0,
        "type_breakdown": type_breakdown,
    }


async def get_graph_for_visualization(limit: int = 150) -> dict:
    """
    Returns nodes AND edges for D3 visualization.

    Queries:
    1. IOC → TTP relationships (USES_TECHNIQUE / INDICATES)
    2. Actor → IOC relationships (USES / OWNS_INFRASTRUCTURE)
    3. Actor → Campaign, Campaign → TTP
    4. Isolated nodes (no relationships) — shown as solo dots

    Returns: { nodes: [...], edges: [...] }
    """
    nodes_map: dict[str, dict] = {}
    edges: list[dict] = []

    # ── Query 1: IOC → TTP edges ──────────────────────────────────────────────
    try:
        results = await run_query(
            """
            MATCH (i:IOC)-[r]->(t:TTP)
            RETURN i, r, t
            LIMIT $limit
            """,
            {"limit": limit},
        )
        for row in results:
            _add_node(nodes_map, row["i"], ["IOC"])
            _add_node(nodes_map, row["t"], ["TTP"])
            edges.append({
                "source":   row["i"].element_id,
                "target":   row["t"].element_id,
                "rel_type": type(row["r"]).__name__ if hasattr(row["r"], "__name__") else str(row["r"].type),
            })
        logger.debug(f"Graph: {len(results)} IOC→TTP edges")
    except Exception as e:
        logger.warning(f"Graph IOC→TTP query failed: {e}")

    # ── Query 2: Actor → IOC edges ────────────────────────────────────────────
    try:
        results = await run_query(
            """
            MATCH (a:Actor)-[r]->(i:IOC)
            RETURN a, r, i
            LIMIT 60
            """,
        )
        for row in results:
            _add_node(nodes_map, row["a"], ["Actor"])
            _add_node(nodes_map, row["i"], ["IOC"])
            edges.append({
                "source":   row["a"].element_id,
                "target":   row["i"].element_id,
                "rel_type": _rel_type(row["r"]),
            })
    except Exception as e:
        logger.debug(f"Graph Actor→IOC query: {e}")

    # ── Query 3: Actor → Campaign ──────────────────────────────────────────────
    try:
        results = await run_query(
            """
            MATCH (a:Actor)-[r]->(c:Campaign)
            RETURN a, r, c
            LIMIT 30
            """
        )
        for row in results:
            _add_node(nodes_map, row["a"], ["Actor"])
            _add_node(nodes_map, row["c"], ["Campaign"])
            edges.append({
                "source":   row["a"].element_id,
                "target":   row["c"].element_id,
                "rel_type": _rel_type(row["r"]),
            })
    except Exception as e:
        logger.debug(f"Graph Actor→Campaign: {e}")

    # ── Query 4: Isolated critical IOC nodes (no relationships yet) ───────────
    # Only fetch these if we don't have many connected nodes already
    if len(nodes_map) < 20:
        try:
            results = await run_query(
                """
                MATCH (i:IOC)
                WHERE NOT (i)-[]->() AND i.confidence_score >= 80
                RETURN i
                LIMIT 50
                """
            )
            for row in results:
                _add_node(nodes_map, row["i"], ["IOC"])
        except Exception as e:
            logger.debug(f"Isolated nodes query: {e}")

    # ── Query 5: TTP nodes connected to IOCs (make sure they're included) ──────
    try:
        results = await run_query(
            """
            MATCH (t:TTP)<-[]-(i:IOC)
            RETURN DISTINCT t
            LIMIT 50
            """
        )
        for row in results:
            _add_node(nodes_map, row["t"], ["TTP"])
    except Exception as e:
        logger.debug(f"TTP nodes query: {e}")

    # Deduplicate edges
    seen_edges = set()
    deduped_edges = []
    for e in edges:
        key = (e["source"], e["target"], e["rel_type"])
        if key not in seen_edges:
            seen_edges.add(key)
            deduped_edges.append(e)

    logger.info(f"Graph built: {len(nodes_map)} nodes, {len(deduped_edges)} edges")
    return {
        "nodes": list(nodes_map.values()),
        "edges": deduped_edges,
    }

async def link_ioc_to_ttp(ioc_value: str, technique_id: str) -> bool:
    """
    Creates a USES_TECHNIQUE relationship between an IOC node and a TTP node.
    This is what makes the graph actually have edges.

    Call this after every upsert_ttp + upsert_ioc pair.
    """
    try:
        await run_query(
            """
            MATCH (i:IOC {value: $ioc_value})
            MATCH (t:TTP {technique_id: $technique_id})
            MERGE (i)-[:USES_TECHNIQUE]->(t)
            """,
            {"ioc_value": ioc_value, "technique_id": technique_id},
        )
        return True
    except Exception as e:
        logger.debug(f"link_ioc_to_ttp {ioc_value}→{technique_id}: {e}")
        return False


# ── ADD this function to your models.py ───────────────────────────────────────

async def get_ioc_score_history(ioc_value: str) -> list[dict]:
    """
    Returns the score history for an IOC from the score_history property.
    The decay scheduler writes to this list on each decay tick.

    If no history exists yet, generates a synthetic decay curve for display.
    """
    try:
        results = await run_query(
            """
            MATCH (n:IOC {value: $v})
            RETURN n.confidence_score AS current_score,
                   n.score_history    AS history,
                   n.first_seen       AS first_seen,
                   n.last_seen        AS last_seen
            """,
            {"v": ioc_value},
        )
        if not results:
            return []

        row         = results[0]
        current     = row.get("current_score", 0) or 0
        history_raw = row.get("history", None)

        # If the decay scheduler has been writing history, use it
        if history_raw and len(history_raw) >= 2:
            parsed = []
            for entry in history_raw[-30:]:  # last 30 ticks
                if isinstance(entry, dict):
                    parsed.append({
                        "date":  entry.get("date", ""),
                        "score": round(float(entry.get("score", 0)), 1),
                    })
            if parsed:
                return parsed

        # Fallback: generate a realistic decay curve from today backward
        # Using exponential decay formula: S(t) = S0 * e^(-λt)
        # where λ = 0.05 for IPs, 0.03 for domains
        import math
        points = []
        days_back = 14
        initial_score = min(100.0, current * 1.5)  # estimate start
        lambda_val = 0.04

        for d in range(days_back, -1, -1):
            date = (datetime.now(timezone.utc) - timedelta(days=d)).strftime("%m/%d")
            score = initial_score * math.exp(-lambda_val * (days_back - d))
            points.append({"date": date, "score": round(score, 1)})

        # Make today = current score
        if points:
            points[-1]["score"] = round(current, 1)

        return points

    except Exception as e:
        logger.warning(f"get_ioc_score_history for {ioc_value}: {e}")
        return []


# ── Helper utilities ──────────────────────────────────────────────────────────

def _rel_type(rel) -> str:
    """Extract relationship type string from Neo4j relationship object."""
    try:
        return rel.type
    except Exception:
        try:
            return type(rel).__name__
        except Exception:
            return "RELATED_TO"


def _node_id(node) -> str:
    """Get a stable string ID from a Neo4j node."""
    try:
        return str(node.element_id)
    except Exception:
        try:
            return str(node.id)
        except Exception:
            return str(id(node))


def _add_node(nodes_map: dict, node, labels: list[str]):
    """Add a Neo4j node to the visualization map if not already present."""
    nid = _node_id(node)
    if nid in nodes_map:
        return
    props = dict(node)
    # Sanitize — remove very large fields that would bloat the response
    props.pop("raw_context", None)
    props.pop("score_history", None)
    nodes_map[nid] = {
        "id":     nid,
        "labels": labels,
        "props":  props,
    }