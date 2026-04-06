"""Structured logging configuration with secret redaction.

Uses structlog for structured key-value logging. Automatically redacts
fields that look like passwords, tokens, or secrets from log output.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import structlog


# Patterns to redact from log output — matches common secret field names
_REDACT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(password|passwd|secret|token|auth_token|api_key|private_pin)", re.IGNORECASE),
]

_REDACT_PLACEHOLDER = "***REDACTED***"


def _redact_value(key: str, value: Any) -> Any:
    """Replace secret-looking values with a placeholder."""
    if isinstance(value, str) and any(p.search(key) for p in _REDACT_PATTERNS):
        return _REDACT_PLACEHOLDER
    return value


def _redact_processor(
    _logger: Any, _method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Structlog processor that scrubs sensitive keys from log events."""
    return {k: _redact_value(k, v) for k, v in event_dict.items()}


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Utility for manually redacting HTTP headers before logging."""
    sensitive = {"authorization", "x-auth-token", "cookie", "set-cookie"}
    return {
        k: (_REDACT_PLACEHOLDER if k.lower() in sensitive else v)
        for k, v in headers.items()
    }


def configure_logging(*, level: str = "INFO", debug: bool = False) -> None:
    """Set up structlog + stdlib logging with redaction.

    Call once at startup. After this, use ``structlog.get_logger()``
    everywhere.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        _redact_processor,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if debug:
        renderer: structlog.types.Processor = structlog.dev.ConsoleRenderer(
            colors=True,
        )
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)

    # Quiet noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a bound structlog logger, optionally namespaced."""
    return structlog.get_logger(name)  # type: ignore[return-value]


# Re-export for convenience
redact_headers = _redact_headers
