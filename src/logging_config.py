"""Logging configuration with rich console and file output."""

from __future__ import annotations

import logging
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler


def setup_logging(verbosity: int = 0, log_file: str = "oauth2.log") -> None:
    """Configure logging with rich handler and file output.

    Args:
        verbosity: Verbosity level (-1=quiet, 0=info, 1=debug)
        log_file: Path to log file
    """
    log_level = logging.INFO

    if verbosity < 0:
        log_level = logging.WARNING
    elif verbosity > 0:
        log_level = logging.DEBUG

    console = Console()
    handlers: list[logging.Handler] = [
        RichHandler(rich_tracebacks=True, console=console),
    ]

    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    handlers.append(file_handler)

    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
        force=True,
    )
