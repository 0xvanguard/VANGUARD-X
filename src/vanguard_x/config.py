"""Runtime configuration for VANGUARD-X.

All settings are loaded from environment variables (and a ``.env`` file when
present). Secrets are never read from anywhere else — no hardcoded fallbacks,
no implicit defaults for credentials.

Usage::

    from vanguard_x.config import get_settings
    settings = get_settings()
    db_url = settings.database_url
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Deployment environment label."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class ToolRunnerKind(StrEnum):
    """Strategy for invoking external tools.

    - ``LOCAL``       : ``asyncio.create_subprocess_exec`` on the host / container.
    - ``DOCKER_EXEC`` : ``docker exec`` into a named, long-running tool container.
    """

    LOCAL = "local"
    DOCKER_EXEC = "docker_exec"


class Settings(BaseSettings):
    """Strongly-typed runtime settings.

    Field names match ``VANGUARDX_<UPPER_SNAKE>`` env vars (case-insensitive).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="VANGUARDX_",
        extra="ignore",
        case_sensitive=False,
    )

    # -- Runtime -------------------------------------------------------------
    environment: Environment = Field(default=Environment.DEVELOPMENT)
    log_level: str = Field(default="INFO")
    data_dir: Path = Field(default=Path("./data"))

    # -- Database ------------------------------------------------------------
    database_url: str = Field(
        default="sqlite+aiosqlite:///./data/vanguard.db",
        description="SQLAlchemy async URL. Use postgresql+asyncpg://... in production.",
    )

    # -- Scope (CRITICAL safety boundary) -----------------------------------
    authorized_targets: str = Field(
        default="",
        description=(
            "Comma-separated list of domains / IPs / CIDRs that VANGUARD-X is "
            "authorized to scan. Subdomains of listed hosts are auto-permitted."
        ),
    )

    # -- Tool runner ---------------------------------------------------------
    tool_runner: ToolRunnerKind = Field(default=ToolRunnerKind.LOCAL)
    nmap_container: str = Field(default="vanguardx-nmap")
    harvester_container: str = Field(default="vanguardx-harvester")
    tool_timeout_seconds: int = Field(default=600, ge=1, le=7200)

    # -- Telegram ------------------------------------------------------------
    telegram_bot_token: str | None = Field(default=None)
    telegram_chat_id: str | None = Field(default=None)

    # -- LLM (Phase 3 placeholders) -----------------------------------------
    anthropic_api_key: str | None = Field(default=None)
    llm_model: str = Field(default="claude-opus-4-5")
    ollama_base_url: str = Field(default="http://localhost:11434")

    # -- Continuous monitoring (Phase 1 Month 2) ----------------------------
    recon_interval_hours: int = Field(default=24, ge=1, le=24 * 30)

    # ----- Validators / derived properties ---------------------------------
    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        upper = value.upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got {value!r}")
        return upper

    @property
    def authorized_targets_list(self) -> list[str]:
        """Parsed authorized targets, stripped and lowercased, empty entries removed."""
        return [t.strip().lower() for t in self.authorized_targets.split(",") if t.strip()]

    @property
    def telegram_enabled(self) -> bool:
        """True iff a usable Telegram bot configuration is present."""
        return bool(self.telegram_bot_token and self.telegram_chat_id)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide :class:`Settings` instance (cached)."""
    return Settings()


def reset_settings_cache() -> None:
    """Clear the cached settings — used by tests that mutate env vars."""
    get_settings.cache_clear()
