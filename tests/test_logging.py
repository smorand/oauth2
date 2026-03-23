"""Tests for logging configuration."""

from __future__ import annotations

import logging
from pathlib import Path

from logging_config import setup_logging


class TestSetupLogging:
    def test_default_info_level(self, tmp_path: Path) -> None:
        log_file = str(tmp_path / "test.log")
        setup_logging(verbosity=0, log_file=log_file)
        root = logging.getLogger()
        assert root.level == logging.INFO

    def test_debug_level(self, tmp_path: Path) -> None:
        log_file = str(tmp_path / "debug.log")
        setup_logging(verbosity=1, log_file=log_file)
        root = logging.getLogger()
        assert root.level == logging.DEBUG

    def test_quiet_level(self, tmp_path: Path) -> None:
        log_file = str(tmp_path / "quiet.log")
        setup_logging(verbosity=-1, log_file=log_file)
        root = logging.getLogger()
        assert root.level == logging.WARNING

    def test_creates_log_file(self, tmp_path: Path) -> None:
        log_file = str(tmp_path / "subdir" / "test.log")
        setup_logging(verbosity=0, log_file=log_file)
        logger = logging.getLogger("test_creates_log")
        logger.info("hello")
        assert Path(log_file).exists()
