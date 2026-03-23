"""Audit logging service for security events."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AuditService:
    """Append-only audit logger for authentication and authorization events."""

    __slots__ = ("_log_path",)

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(
        self,
        event_type: str,
        actor: str,
        ip_address: str,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Write an audit log entry. Never logs sensitive data."""
        entry = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "event_type": event_type,
            "actor": actor,
            "ip_address": ip_address,
            "result": result,
            "details": details or {},
        }
        with self._log_path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        logger.debug("Audit: %s %s %s", event_type, actor, result)
