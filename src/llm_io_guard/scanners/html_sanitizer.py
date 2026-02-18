"""Tier 1 scanner that strips HTML to plain text.

Uses the ``html-sanitizer`` library (lxml-based) to remove all tags and
attributes, keeping only visible text. Flags content where >80% is stripped,
which may indicate a hidden-content attack (e.g. invisible ``<div>`` payloads).
"""

from html_sanitizer import Sanitizer as HtmlSanitizerLib

from ..models import Action, ScanResult
from ..scanner import Scanner

# Configure to strip ALL HTML, keeping only text content.
# A made-up tag is required because lxml cleaner doesn't support an empty tag set.
SANITIZER = HtmlSanitizerLib(
    settings={
        "tags": {"__nonexistent__"},
        "attributes": {},
        "empty": set(),
        "separate": set(),
        "whitespace": set(),
    }
)


class HtmlSanitizer(Scanner):
    """Tier 1 input scanner that strips HTML to plain text.

    Produces ``sanitized_content`` in result details. Flags content when
    stripping removes more than 80% of the original length, indicating
    the HTML was mostly non-visible markup (potential hidden payload).
    """

    @property
    def name(self) -> str:
        """Scanner identifier: ``html_sanitizer``."""
        return "html_sanitizer"

    @property
    def tier(self) -> int:
        """Tier 1 — deterministic, sub-millisecond."""
        return 1

    @property
    def supported_directions(self) -> frozenset[str]:
        """Only supports input direction."""
        return frozenset({"input"})

    async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
        """Strip HTML tags and flag content with excessive markup.

        Args:
            content: The text content to scan.
            metadata: Optional dict; uses ``content_type`` key to decide
                whether to sanitize (defaults to ``"text/plain"``).

        Returns:
            ScanResult with ``sanitized_content`` in details. Action is FLAG
            when >80% of content was stripped, PASS otherwise.
        """
        content_type = (metadata or {}).get("content_type", "text/plain")

        # Only sanitize HTML content
        if content_type not in ("text/html", "text/xml") and "<" not in content:
            return ScanResult(
                scanner_name=self.name,
                action=Action.PASS,
                confidence=0.0,
                description="Content is plain text, no HTML sanitization needed",
                details={"sanitized_content": content},
            )

        sanitized = SANITIZER.sanitize(content)

        # Check if significant content was removed (possible hidden content)
        original_len = len(content)
        sanitized_len = len(sanitized)
        reduction_ratio = 1 - (sanitized_len / original_len) if original_len > 0 else 0

        # >80% reduction means the HTML was mostly invisible markup — likely a
        # hidden-content attack embedding payloads in tags/attributes.
        if reduction_ratio > 0.8:
            return ScanResult(
                scanner_name=self.name,
                action=Action.FLAG,
                confidence=reduction_ratio,
                description=f"HTML sanitization removed {reduction_ratio:.0%} of content "
                f"(possible hidden content attack)",
                details={
                    "sanitized_content": sanitized,
                    "original_length": original_len,
                    "sanitized_length": sanitized_len,
                },
            )

        return ScanResult(
            scanner_name=self.name,
            action=Action.PASS,
            confidence=0.0,
            description="HTML sanitized to plain text",
            details={"sanitized_content": sanitized},
        )
