"""Base model utilities."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime


def generate_id() -> str:
    """Generate a UUID4 string."""
    return str(uuid.uuid4())


def utc_now() -> datetime:
    """Return current UTC datetime."""
    return datetime.now(tz=UTC)
