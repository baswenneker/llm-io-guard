"""Exceptions for the LLM IO Guard filter API."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import FilterResult


class ContentBlocked(Exception):  # noqa: N818 - intentional name per API design
    """Raised when content is blocked by a filter in 'raise' mode."""

    def __init__(self, result: FilterResult) -> None:
        """Initialize with the FilterResult that caused the block."""
        self.result = result
        super().__init__(f"Content blocked by: {[r.scanner_name for r in result.blocked_by]}")
