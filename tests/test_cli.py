"""Tests for CLI module."""

from __future__ import annotations

from typer.testing import CliRunner

from src.cli import app

runner = CliRunner()


def test_hello_default(sample_name: str) -> None:
    """Test hello command with default name."""
    result = runner.invoke(app, ["hello"])
    assert result.exit_code == 0
    assert "Hello, World!" in result.stdout


def test_hello_with_name(sample_name: str) -> None:
    """Test hello command with custom name."""
    result = runner.invoke(app, ["hello", "--name", sample_name])
    assert result.exit_code == 0
    assert f"Hello, {sample_name}!" in result.stdout
