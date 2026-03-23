"""Tests for CLI module."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from cli import app

runner = CliRunner()


def test_serve_help() -> None:
    """Test serve command shows help."""
    result = runner.invoke(app, ["serve", "--help"])
    assert result.exit_code == 0
    assert "Start the OAuth2 authorization server" in result.stdout


def test_generate_keys_help() -> None:
    """Test generate-keys command shows help."""
    result = runner.invoke(app, ["generate-keys", "--help"])
    assert result.exit_code == 0
    assert "Generate RSA key pair" in result.stdout


def test_create_admin_help() -> None:
    """Test create-admin command shows help."""
    result = runner.invoke(app, ["create-admin", "--help"])
    assert result.exit_code == 0
    assert "Create an admin user" in result.stdout


def test_generate_keys_runs(tmp_path: Path) -> None:
    """Test generate-keys command creates key files."""
    output_dir = tmp_path / "test-keys"
    result = runner.invoke(app, ["generate-keys", "--output-dir", str(output_dir)])
    assert result.exit_code == 0
    assert (output_dir / "private.pem").exists()
    assert (output_dir / "public.pem").exists()
    assert "Keys generated" in result.stdout
