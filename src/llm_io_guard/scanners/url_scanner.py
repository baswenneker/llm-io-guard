"""URL safety scanner with Google Safe Browsing and homoglyph detection."""

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
    """Extract URLs from href and src attributes in HTML."""

    def __init__(self):
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for attr, value in attrs:
            if attr in ("href", "src", "action") and value:
                self.urls.append(value)


def extract_urls(content: str, content_type: str = "text/plain") -> list[str]:
    """Extract all URLs from content."""
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
    """URL safety scanner with Google Safe Browsing and homoglyph detection."""

    def __init__(self) -> None:
        self._safe_browsing = None

    @property
    def name(self) -> str:
        return "url_scanner"

    @property
    def tier(self) -> int:
        return 2

    async def ainitialize(self) -> None:
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
        """Check URLs against Google Safe Browsing API."""
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
                        "confidence": 0.99,
                        "action": "block",
                    }
                )

        return threats

    def _check_homoglyphs(self, url: str) -> dict | None:
        """Check URL domain for homoglyph spoofing."""
        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            domain = parsed.hostname
            if not domain:
                return None

            # Check for mixed-script confusables (only flag non-Latin chars that look Latin)
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
                    "confidence": 0.85,
                    "action": "flag",
                }
        except Exception as e:
            logger.warning("homoglyph_check_error", url=url, error=str(e))

        return None
