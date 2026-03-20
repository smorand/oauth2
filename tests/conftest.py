"""Shared test fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_name() -> str:
    """Sample name for testing."""
    return "Test User"
