"""OAuth2 authentication and authorization service."""

from __future__ import annotations

import logging

import typer
from rich.console import Console
from rich.logging import RichHandler

from src.logging_config import configure_logging

app = typer.Typer(help="OAuth2 authentication and authorization service")
console = Console()
logger = logging.getLogger(__name__)


@app.command()
def hello(name: str = typer.Option("World", help="Name to greet")) -> None:
    """Greet someone."""
    configure_logging()
    logger.info("Greeting %s", name)
    console.print(f"Hello, {name}!")


if __name__ == "__main__":
    app()
