"""
SPECTER — Settings (pydantic-settings)
Add new fields here, then update .env with values.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Neo4j ────────────────────────────────────────
    neo4j_uri:      str = "bolt://neo4j:7687"
    neo4j_user:     str = "neo4j"
    neo4j_password: str = "specter_pass"

    # ── Redis ────────────────────────────────────────
    redis_url: str = "redis://redis:6379/0"

    # ── Threat Intel APIs ─────────────────────────────
    otx_api_key:          str = ""
    virustotal_api_key:   str = ""
    shodan_api_key:       str = ""   # free at account.shodan.io → "My Account"

    # ── LLM ──────────────────────────────────────────
    llm_provider:    str = "groq"
    groq_api_key:    str = ""
    groq_model:      str = "llama-3.3-70b-versatile"
    ollama_base_url: str = "http://host.docker.internal:11434"
    ollama_model:    str = "mistral:7b"

    # ── SOAR / Alerts ─────────────────────────────────
    discord_webhook_url: str = ""
    discord_public_key:  str = ""   # from Discord dev portal → your app → General Info
    slack_webhook_url:   str = ""

    # ── Decay rates ───────────────────────────────────
    ip_decay_rate:     float = 0.05   # 5% per day
    domain_decay_rate: float = 0.03
    hash_decay_rate:   float = 0.01   # hashes decay slowest
    archive_threshold: float = 30.0   # score below which IOC is archived

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
