"""Tier 2 URL safety scanner with Google Safe Browsing and homoglyph detection.

Extracts URLs from both plain text and HTML, then runs two checks:

1. **Homoglyph detection** (local, fast): Uses ``confusable_homoglyphs`` to detect
   domain names with mixed-script characters that look like Latin letters (IDN
   homograph attacks, e.g. ``gοοgle.com`` using Greek omicron).
2. **Google Safe Browsing** (network): Checks URLs against Google's threat lists
   for malware, phishing, and unwanted software. Requires ``GOOGLE_SAFE_BROWSING_API_KEY``.
"""

import asyncio
import os
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

import structlog
from confusable_homoglyphs import confusables

from ..models import Action, ScanResult
from ..scanner import Scanner

logger = structlog.get_logger()

# URL regex for plain text extraction
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"')\]]+|"  # Standard URLs
    r"www\.[^\s<>\"')\]]+|"  # www. prefixed
    r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s<>\"')\]]*"  # domain/path
)


class LinkExtractor(HTMLParser):
    """Extract URLs from href, src, and action attributes in HTML."""

    def __init__(self) -> None:
        """Initialize the HTML parser and URL collection list."""
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Collect URL-bearing attributes from HTML start tags."""
        for attr, value in attrs:
            if attr in ("href", "src", "action") and value:
                self.urls.append(value)


def extract_urls(content: str, content_type: str = "text/plain") -> list[str]:
    """Extract all URLs from content using regex and HTML parsing."""
    urls = set()

    # Extract from plain text
    for match in URL_PATTERN.finditer(content):
        urls.add(match.group())

    # Extract from HTML attributes
    if content_type == "text/html" or "<a " in content.lower():
        try:
            extractor = LinkExtractor()
            extractor.feed(content)
            urls.update(extractor.urls)
        except Exception:
            logger.debug("html_parse_error", msg="Malformed HTML, using regex results only")

    return list(urls)


class UrlScanner(Scanner):
    """Tier 2 scanner for URL safety using Safe Browsing and homoglyph detection.

    Supports both input and output directions (default). Combines a fast local
    homoglyph check with an optional Google Safe Browsing API lookup.
    """

    def __init__(self) -> None:
        """Initialize the URL scanner. Safe Browsing client is set up in ``ainitialize``."""
        self._safe_browsing = None

    @property
    def name(self) -> str:
        """Scanner identifier: ``url_scanner``."""
        return "url_scanner"

    @property
    def tier(self) -> int:
        """Tier 2 — local regex + optional network API call."""
        return 2

    async def ainitialize(self) -> None:
        """Initialize the Google Safe Browsing client if API key is available."""
        api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
        if api_key:
            from pysafebrowsing import SafeBrowsing

            self._safe_browsing = SafeBrowsing(api_key)
            logger.info("safe_browsing_initialized")
        else:
            logger.warning(
                "safe_browsing_no_api_key", msg="URL scanning will use local checks only"
            )

    async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
        """Scan content for malicious or spoofed URLs.

        Args:
            content: The text content to scan.
            metadata: Optional dict; uses ``content_type`` key for HTML-aware
                URL extraction (defaults to ``"text/plain"``).

        Returns:
            ScanResult with BLOCK for Safe Browsing threats, FLAG for
            homoglyph spoofing, PASS when all URLs are safe.
        """
        content_type = (metadata or {}).get("content_type", "text/plain")
        urls = extract_urls(content, content_type)

        if not urls:
            return ScanResult(
                scanner_name=self.name,
                action=Action.PASS,
                confidence=0.0,
                description="No URLs found in content",
                details={},
            )

        threats: list[dict] = []

        # Check homoglyphs (local, fast)
        for url in urls:
            homoglyph_result = self._check_homoglyphs(url)
            if homoglyph_result:
                threats.append(homoglyph_result)

        # Check Google Safe Browsing API (network, slower)
        if self._safe_browsing:
            try:
                sb_threats = await self._check_safe_browsing(urls)
                threats.extend(sb_threats)
            except Exception as e:
                logger.warning("safe_browsing_error", error=str(e))
                # Fallback: continue without Safe Browsing results

        if threats:
            max_confidence = max(t["confidence"] for t in threats)
            has_block = any(t.get("action") == "block" for t in threats)

            return ScanResult(
                scanner_name=self.name,
                action=Action.BLOCK if has_block else Action.FLAG,
                confidence=max_confidence,
                description=f"Suspicious URLs detected: {len(threats)} threat(s)",
                details={
                    "threats": threats,
                    "urls_scanned": len(urls),
                },
            )

        return ScanResult(
            scanner_name=self.name,
            action=Action.PASS,
            confidence=0.0,
            description=f"All {len(urls)} URLs are safe",
            details={"urls_scanned": len(urls)},
        )

    async def _check_safe_browsing(self, urls: list[str]) -> list[dict]:
        """Check URLs against Google Safe Browsing API.

        Runs the synchronous ``pysafebrowsing`` lookup in a thread executor
        to avoid blocking the event loop.
        """
        if self._safe_browsing is None:
            return []
        threats = []
        # pysafebrowsing supports batch lookup — run in executor to avoid blocking
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, self._safe_browsing.lookup_urls, urls)

        for url, info in result.items():
            if info.get("malicious"):
                threats.append(
                    {
                        "url": url,
                        "type": "safe_browsing",
                        "threat_type": info.get("threats", ["UNKNOWN"]),
                        "confidence": 0.99,  # Near-certain: Google's threat list is authoritative
                        "action": "block",
                    }
                )

        return threats

    def _check_homoglyphs(self, url: str) -> dict | None:
        """Check URL domain for homoglyph (IDN homograph) spoofing.

        Uses ``confusable_homoglyphs`` with ``greedy=True`` to catch all confusable
        characters, and ``preferred_aliases=["LATIN"]`` to only flag non-Latin
        characters that visually resemble Latin letters.
        """
        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            domain = parsed.hostname
            if not domain:
                return None

            # greedy=True: check all characters, not just the first confusable.
            # preferred_aliases=["LATIN"]: only flag non-Latin chars that look Latin.
            is_confusable = confusables.is_confusable(
                domain, greedy=True, preferred_aliases=["LATIN"]
            )

            if is_confusable:
                return {
                    "url": url,
                    "type": "homoglyph",
                    "domain": domain,
                    "confusables": [
                        {
                            "character": item["character"],
                            "alias": item["alias"],
                            "homoglyphs": [h["c"] for h in item["homoglyphs"]],
                        }
                        for item in is_confusable
                    ],
                    "confidence": 0.85,  # High but not blocking — false positives possible with legitimate IDN domains
                    "action": "flag",
                }
        except Exception as e:
            logger.warning("homoglyph_check_error", url=url, error=str(e))

        return None
