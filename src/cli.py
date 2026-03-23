"""OAuth2 authorization server CLI entry point."""

from __future__ import annotations

import logging
from pathlib import Path

import typer
from rich.console import Console

from logging_config import setup_logging

app = typer.Typer(help="OAuth2 authorization server")
console = Console()
logger = logging.getLogger(__name__)

verbose_option = typer.Option(0, "--verbose", "-v", count=True, help="Increase verbosity")
quiet_option = typer.Option(False, "--quiet", "-q", help="Suppress output")


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Bind host"),
    port: int = typer.Option(8000, help="Bind port"),
    reload: bool = typer.Option(False, help="Enable auto-reload"),
    verbose: int = verbose_option,
    quiet: bool = quiet_option,
) -> None:
    """Start the OAuth2 authorization server."""
    import uvicorn

    verbosity = -1 if quiet else verbose
    setup_logging(verbosity=verbosity)
    logger.info("Starting OAuth2 server on %s:%d", host, port)
    uvicorn.run(
        "app:create_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
    )


@app.command()
def generate_keys(
    output_dir: Path = typer.Option(Path("keys"), help="Output directory for keys"),
    key_size: int = typer.Option(2048, help="RSA key size in bits"),
) -> None:
    """Generate RSA key pair for JWT signing."""
    from crypto.keys import generate_rsa_key_pair

    setup_logging()
    output_dir.mkdir(parents=True, exist_ok=True)
    private_path = output_dir / "private.pem"
    public_path = output_dir / "public.pem"
    generate_rsa_key_pair(private_path, public_path, key_size)
    console.print(f"Keys generated: {private_path}, {public_path}")


@app.command()
def create_admin(
    email: str = typer.Option(..., help="Admin email"),
    password: str = typer.Option(..., prompt=True, hide_input=True, help="Admin password"),
    name: str = typer.Option("Admin", help="Admin display name"),
) -> None:
    """Create an admin user for initial setup."""
    import asyncio

    from config import Settings
    from services.bootstrap import create_admin_user

    setup_logging()
    settings = Settings()
    user = asyncio.run(create_admin_user(settings, email, password, name))
    console.print(f"Admin user created: {user.email} (id: {user.id})")


if __name__ == "__main__":
    app()
