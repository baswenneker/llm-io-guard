"""Pytest configuration and fixtures."""

import logging
from collections.abc import Generator
from pathlib import Path

import pytest
from _pytest.logging import LogCaptureFixture

from llm_io_guard.utils import configure_logging


@pytest.fixture(scope="session", autouse=True)
def setup_test_logging() -> None:
    """Configure logging for tests."""
    configure_logging(level="DEBUG", format="console")


@pytest.fixture
def log_capture(caplog: LogCaptureFixture) -> Generator[LogCaptureFixture, None, None]:
    """Capture log messages during tests."""
    with caplog.at_level(logging.DEBUG):
        yield caplog


@pytest.fixture
def sample_data() -> dict[str, str]:
    """Provide sample test data."""
    return {
        "short": "test",
        "medium": "This is a test string",
        "long": "Lorem ipsum dolor sit amet, consectetur adipiscing elit",
        "empty": "",
        "with_numbers": "Test123",
        "with_special": "Test!@#$%",
    }


@pytest.fixture
def temp_file(tmp_path: Path) -> Path:
    """Create a temporary file for testing."""
    file_path = tmp_path / "test_file.txt"
    file_path.write_text("Test content")
    return file_path
