# Phase 5: URL & Phishing Protection (Tier 2)

> **Goal**: Detect malicious URLs, phishing links, and Unicode domain spoofing in content.
>
> **Depends on**: [Phase 1: Project Setup](./01-project-setup.md)
> **Tier**: 2 — Medium (<200ms, network-bound)
> **OWASP**: LLM01 (Prompt Injection via URLs), LLM04 (Data Poisoning via malicious links)

## Overview

URLs in untrusted content can lead to:
- **Phishing pages** that steal credentials
- **Malware downloads** that compromise systems
- **Homoglyph domains** that impersonate legitimate sites (e.g., `gοοgle.com` using Greek omicron)
- **Data exfiltration** endpoints that the agent might be tricked into calling

The URL scanner combines local analysis with the Google Safe Browsing API for real-time threat intelligence.

## Components

### 1. URL Extraction

Extract URLs from both plain text and HTML content.

```python
# src/llm_io_guard/scanners/url_scanner.py
import re
from urllib.parse import urlparse
from html.parser import HTMLParser
import structlog

from ..scanner import Scanner
from ..models import Action, ScanResult
from ..config import PipelineConfig

logger = structlog.get_logger()

# URL regex for plain text extraction
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"')\]]+|"    # Standard URLs
    r"www\.[^\s<>\"')\]]+|"         # www. prefixed
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
            pass  # Malformed HTML, continue with regex results

    return list(urls)
```

### 2. Google Safe Browsing API

```python
from pysafebrowsing import SafeBrowsing
import os


class UrlScanner(Scanner):
    """URL safety scanner with Google Safe Browsing and homoglyph detection."""

    def __init__(self, config: PipelineConfig):
        self._config = config
        self._safe_browsing: SafeBrowsing | None = None

    @property
    def name(self) -> str:
        return "url_scanner"

    @property
    def tier(self) -> int:
        return 2

    async def initialize(self) -> None:
        api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
        if api_key:
            self._safe_browsing = SafeBrowsing(api_key)
            logger.info("safe_browsing_initialized")
        else:
            logger.warning("safe_browsing_no_api_key", msg="URL scanning will use local checks only")

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
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
        threats = []
        # pysafebrowsing supports batch lookup
        result = self._safe_browsing.lookup_urls(urls)

        for url, info in result.items():
            if info.get("malicious"):
                threats.append({
                    "url": url,
                    "type": "safe_browsing",
                    "threat_type": info.get("threats", ["UNKNOWN"]),
                    "confidence": 0.99,
                    "action": "block",
                })

        return threats

    def _check_homoglyphs(self, url: str) -> dict | None:
        """Check URL domain for homoglyph spoofing."""
        from confusable_homoglyphs import confusables

        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            domain = parsed.hostname
            if not domain:
                return None

            # Check for mixed-script confusables
            is_confusable = confusables.is_confusable(domain, greedy=True)

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
```

### 3. API Key Management & Rate Limits

Google Safe Browsing API v4 limits:

| Metric | Limit |
|--------|-------|
| Requests per minute | 600 (free tier) |
| URLs per request | 500 |
| Daily queries | 10,000 (free tier) |

Implementation considerations:
- Store API key in environment variable: `GOOGLE_SAFE_BROWSING_API_KEY`
- Batch URL lookups (max 500 per request)
- Cache results for 5 minutes to reduce API calls
- Graceful degradation: if API is unavailable, fall back to local-only checks

## Fallback Behavior

When the Google Safe Browsing API is unavailable (no API key, rate limit, network error):

1. Log a warning
2. Continue with local-only checks:
   - Homoglyph detection (always available)
   - IP-address URLs (suspicious)
   - Very long URLs (>2048 chars, suspicious)
   - Known suspicious TLDs
3. Return results with reduced confidence

The scanner should **never block pipeline execution** due to API unavailability.

## Performance

| Operation | Target Latency |
|-----------|---------------|
| URL extraction (regex) | <2ms |
| Homoglyph check (local) | <5ms per URL |
| Safe Browsing API | ~100-200ms (network) |
| **Total** | **<200ms** |

Since URL scanning runs in parallel with other Tier 2 scanners, its latency doesn't block the pipeline unless it's the slowest Tier 2 scanner.

## Implementation Checklist

- [ ] Implement URL extraction from plain text and HTML
- [ ] Integrate `pysafebrowsing` for Google Safe Browsing API v4
- [ ] Implement homoglyph detection with `confusable_homoglyphs`
- [ ] Add fallback behavior for API unavailability
- [ ] Add result caching (5-minute TTL)
- [ ] Write unit tests for URL extraction
- [ ] Write tests for homoglyph domains (Cyrillic, Greek lookalikes)
- [ ] Write integration tests with Safe Browsing API (mocked)
- [ ] Benchmark performance

## Next Phase

→ [Phase 6: Claude Haiku Judge](./06-llm-judge.md)
