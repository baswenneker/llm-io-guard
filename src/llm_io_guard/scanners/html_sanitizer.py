"""Scanner that strips HTML to plain text."""

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
    """Strips HTML to plain text, preserving readable structure."""

    @property
    def name(self) -> str:
        return "html_sanitizer"

    @property
    def tier(self) -> int:
        return 1

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
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
