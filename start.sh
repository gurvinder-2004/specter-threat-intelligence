#!/bin/bash
# SPECTER — One-command startup script
# Usage: chmod +x start.sh && ./start.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${RED}${BOLD}⚡ SPECTER Threat Intelligence Platform${NC}"
echo -e "${CYAN}Starting all services...${NC}"
echo ""

# ── 1. Check Docker ───────────────────────────────────────────────────────────
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker not found. Install from https://docker.com${NC}"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${RED}✗ Docker daemon not running. Start Docker Desktop first.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker is running${NC}"

# ── 2. Check .env ─────────────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}⚠ .env not found, copying from .env.example${NC}"
    cp .env.example .env 2>/dev/null || true
fi

if grep -q "your_groq_key_here" .env 2>/dev/null; then
    echo -e "${YELLOW}⚠ GROQ_API_KEY not set in .env${NC}"
    echo -e "  Get a free key at ${CYAN}https://console.groq.com${NC}"
    echo -e "  LLM features will be disabled until key is added."
    echo ""
fi

# ── 3. Start Docker services ──────────────────────────────────────────────────
echo -e "${CYAN}Starting Neo4j, Redis, FastAPI, Celery...${NC}"
docker-compose up -d

echo -e "${CYAN}Waiting for Neo4j to be ready...${NC}"
for i in $(seq 1 30); do
    if docker-compose exec -T neo4j neo4j status &>/dev/null; then
        echo -e "${GREEN}✓ Neo4j ready${NC}"
        break
    fi
    sleep 2
    echo -n "."
done

# Quick API health check
sleep 3
if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ FastAPI backend is live at http://localhost:8000${NC}"
else
    echo -e "${YELLOW}⚠ FastAPI still starting... check: docker-compose logs api${NC}"
fi

# ── 4. Frontend ───────────────────────────────────────────────────────────────
if [ -d "frontend" ]; then
    echo ""
    echo -e "${CYAN}Starting React frontend...${NC}"
    cd frontend

    if [ ! -d "node_modules" ]; then
        echo "Installing npm packages..."
        npm install
    fi

    echo -e "${GREEN}✓ Frontend starting at http://localhost:3000${NC}"
    echo ""
    echo -e "${BOLD}════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD} SPECTER is ready!${NC}"
    echo -e "${BOLD}════════════════════════════════════════════${NC}"
    echo -e " Dashboard:  ${CYAN}http://localhost:3000${NC}"
    echo -e " API docs:   ${CYAN}http://localhost:8000/docs${NC}"
    echo -e " Neo4j UI:   ${CYAN}http://localhost:7474${NC}"
    echo -e "${BOLD}════════════════════════════════════════════${NC}"
    echo ""

    npm run dev
fi
