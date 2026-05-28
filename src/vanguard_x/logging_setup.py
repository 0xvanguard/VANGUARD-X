"""Centralised structured logging.

We use :mod:`structlog` with a JSON renderer in production and a coloured
console renderer in development. A single :func:`configure_logging` call
wires everything up; modules just call ``structlog.get_logger(__name__)``.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from vanguard_x.config import Environment, Settings


def configure_logging(settings: Settings) -> None:
    """Configure structlog and the stdlib :mod:`logging` module.

    Idempotent — safe to call multiple times (e.g. from tests).
    """
    level = getattr(logging, settings.log_level, logging.INFO)

    # Tame stdlib loggers -> route them through structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
        force=True,
    )

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]

    if settings.environment is Environment.DEVELOPMENT:
        renderer: Any = structlog.dev.ConsoleRenderer(colors=True)
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[*shared_processors, structlog.processors.format_exc_info, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Convenience wrapper returning a bound structlog logger."""
    return structlog.get_logger(name)  # type: ignore[no-any-return]
