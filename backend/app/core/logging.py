"""Structured logging with request correlation."""

import logging
import sys

import structlog

from app.core.config import get_settings

_SENSITIVE = ("password", "secret", "token", "authorization", "api_key", "credential", "cookie")


def _redact(_logger, _name, event_dict):
    for key in list(event_dict):
        if any(s in key.lower() for s in _SENSITIVE):
            event_dict[key] = "[redacted]"
    return event_dict


def configure_logging() -> None:
    settings = get_settings()
    renderer = structlog.processors.JSONRenderer() if settings.log_json else structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _redact,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(settings.log_level.upper())),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(level=settings.log_level.upper(), stream=sys.stdout, format="%(message)s")


def get_logger(name: str):
    return structlog.get_logger(name)
