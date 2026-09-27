#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SPECTER — Full database reset
# Wipes ALL IOCs, TTPs, Actors, Campaigns from Neo4j and Redis.
# Run this before a presentation to start completely clean.
#
# Usage:
#   ./scripts/reset_db.sh              # wipes everything, keeps docker running
#   ./scripts/reset_db.sh --hard       # destroys neo4j volume + rebuilds from scratch
# ─────────────────────────────────────────────────────────────────────────────

set -e
COMPOSE_FILE="$(dirname "$0")/../docker-compose.yml"
HARD=false
[[ "$1" == "--hard" ]] && HARD=true

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}╔══════════════════════════════════════╗${NC}"
echo -e "${RED}║   SPECTER DATABASE RESET UTILITY     ║${NC}"
echo -e "${RED}╚══════════════════════════════════════╝${NC}"
echo ""

if $HARD; then
    echo -e "${YLW}[HARD RESET] This will DESTROY all data and rebuild Neo4j from scratch.${NC}"
    read -p "Type 'RESET' to confirm: " confirm
    [[ "$confirm" != "RESET" ]] && echo "Aborted." && exit 1

    echo -e "${YLW}→ Stopping containers...${NC}"
    docker-compose -f "$COMPOSE_FILE" down -v

    echo -e "${YLW}→ Removing Neo4j data volume...${NC}"
    docker volume rm specter_v5_neo4j_data 2>/dev/null || \
    docker volume rm specter_final_neo4j_data 2>/dev/null || \
    docker volume ls | grep neo4j | awk '{print $2}' | xargs docker volume rm 2>/dev/null || true

    echo -e "${YLW}→ Rebuilding containers...${NC}"
    docker-compose -f "$COMPOSE_FILE" up -d --build

    echo -e "${GRN}✓ Hard reset complete. Fresh Neo4j schema will be created on first API call.${NC}"
    exit 0
fi

# ── Soft reset: wipe graph data, keep containers running ─────────────────────
echo -e "${YLW}→ Soft reset — wiping graph data, containers stay running...${NC}"

# Wait for Neo4j to be available
echo -e "${YLW}→ Checking Neo4j connection...${NC}"
for i in {1..20}; do
    if docker exec $(docker-compose -f "$COMPOSE_FILE" ps -q neo4j) \
        wget -q --spider http://localhost:7474 2>/dev/null; then
        break
    fi
    echo "   Waiting for Neo4j... ($i/20)"
    sleep 3
done

# Run Cypher to delete all nodes
echo -e "${YLW}→ Deleting all nodes and relationships...${NC}"
docker exec $(docker-compose -f "$COMPOSE_FILE" ps -q neo4j) \
    cypher-shell -u neo4j -p specter_pass \
    "MATCH (n) DETACH DELETE n; RETURN 'Graph cleared' AS status;" 2>/dev/null || \
docker-compose -f "$COMPOSE_FILE" exec neo4j \
    cypher-shell -u neo4j -p specter_pass \
    "MATCH (n) DETACH DELETE n; RETURN 'Graph cleared' AS status;"

echo -e "${GRN}✓ Neo4j graph cleared${NC}"

# Flush Redis
echo -e "${YLW}→ Flushing Redis cache...${NC}"
docker-compose -f "$COMPOSE_FILE" exec redis redis-cli FLUSHALL > /dev/null
echo -e "${GRN}✓ Redis cleared${NC}"

echo ""
echo -e "${GRN}╔══════════════════════════════════════╗${NC}"
echo -e "${GRN}║   SPECTER IS CLEAN — DEMO READY ✓   ║${NC}"
echo -e "${GRN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "  Dashboard: ${YLW}http://localhost:3000${NC}"
echo -e "  To ingest demo data: open ${YLW}Ingest → PDF${NC} and upload a threat report"
echo -e "  Or pull live OTX feed: ${YLW}Ingest → Live Feeds → OTX → PULL NOW${NC}"
echo ""
