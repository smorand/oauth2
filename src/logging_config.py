"""Logging configuration with rich support."""

from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler


def configure_logging(verbosity: int = 0) -> None:
    """Configure logging with rich handler.

    Args:
        verbosity: Verbosity level (-1=quiet, 0=info, 1=debug)
    """
    log_level = logging.INFO

    if verbosity < 0:
        log_level = logging.WARNING
    elif verbosity > 0:
        log_level = logging.DEBUG

    console = Console()
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console)],
    )
