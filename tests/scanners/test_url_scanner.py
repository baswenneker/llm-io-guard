"""Tests for the URL safety scanner."""

from unittest.mock import MagicMock, patch

import pytest

from llm_io_guard.config import PipelineConfig
from llm_io_guard.models import Action
from llm_io_guard.scanners.url_scanner import UrlScanner, extract_urls

# ---------------------------------------------------------------------------
# URL extraction tests
# ---------------------------------------------------------------------------


class TestExtractUrls:
    def test_extract_urls_plain_text(self):
        content = "Visit https://example.com and http://test.org/path for details."
        urls = extract_urls(content)
        assert "https://example.com" in urls
        assert "http://test.org/path" in urls

    def test_extract_urls_html(self):
        content = '<a href="https://link.com/page">click</a> <img src="https://img.com/x.png">'
        urls = extract_urls(content, content_type="text/html")
        assert "https://link.com/page" in urls
        assert "https://img.com/x.png" in urls

    def test_extract_no_urls(self):
        urls = extract_urls("No links here, just plain text.")
        assert urls == []

    def test_extract_mixed(self):
        content = 'Check https://plain.com and <a href="https://html.com/page">link</a> for info.'
        urls = extract_urls(content)
        assert "https://plain.com" in urls
        assert "https://html.com/page" in urls


# ---------------------------------------------------------------------------
# UrlScanner tests
# ---------------------------------------------------------------------------


class TestUrlScanner:
    @pytest.fixture
    def config(self):
        return PipelineConfig()

    @pytest.fixture
    def scanner(self, config):
        return UrlScanner(config)

    async def test_no_urls_passes(self, scanner):
        result = await scanner.scan("Hello, no URLs here.")
        assert result.action == Action.PASS
        assert result.confidence == 0.0

    async def test_safe_urls_pass(self, scanner):
        mock_sb = MagicMock()
        mock_sb.lookup_urls.return_value = {
            "https://google.com": {"malicious": False},
        }
        scanner._safe_browsing = mock_sb

        result = await scanner.scan("Visit https://google.com for search.")
        assert result.action == Action.PASS
        assert result.details["urls_scanned"] >= 1

    async def test_malicious_url_blocked(self, scanner):
        mock_sb = MagicMock()
        mock_sb.lookup_urls.return_value = {
            "https://evil-site.com": {
                "malicious": True,
                "threats": ["MALWARE"],
            },
        }
        scanner._safe_browsing = mock_sb

        result = await scanner.scan("Go to https://evil-site.com now.")
        assert result.action == Action.BLOCK
        assert result.confidence == 0.99
        assert len(result.details["threats"]) >= 1

    async def test_homoglyph_detected(self, scanner):
        # Cyrillic 'а' (U+0430) looks like Latin 'a'
        result = await scanner.scan("Visit https://\u0430pple.com today.")
        assert result.action == Action.FLAG
        assert result.confidence == 0.85
        threats = result.details["threats"]
        assert any(t["type"] == "homoglyph" for t in threats)

    async def test_no_api_key_local_only(self, scanner):
        with patch.dict("os.environ", {}, clear=True):
            await scanner.initialize()
        assert scanner._safe_browsing is None

        # Homoglyph check should still work
        result = await scanner.scan("Visit https://\u0430pple.com today.")
        assert result.action == Action.FLAG

    async def test_api_error_fallback(self, scanner):
        mock_sb = MagicMock()
        mock_sb.lookup_urls.side_effect = RuntimeError("API timeout")
        scanner._safe_browsing = mock_sb

        result = await scanner.scan("Visit https://example.com now.")
        # Should not raise; falls back to local results
        assert result.action == Action.PASS

    async def test_multiple_urls_checked(self, scanner):
        mock_sb = MagicMock()
        mock_sb.lookup_urls.return_value = {
            "https://safe.com": {"malicious": False},
            "https://also-safe.com": {"malicious": False},
        }
        scanner._safe_browsing = mock_sb

        result = await scanner.scan("Visit https://safe.com and https://also-safe.com for info.")
        assert result.action == Action.PASS
        assert result.details["urls_scanned"] == 2
        mock_sb.lookup_urls.assert_called_once()
        called_urls = mock_sb.lookup_urls.call_args[0][0]
        assert len(called_urls) == 2


# ---------------------------------------------------------------------------
# Homoglyph detection tests
# ---------------------------------------------------------------------------


class TestHomoglyphDetection:
    @pytest.fixture
    def scanner(self):
        return UrlScanner(PipelineConfig())

    def test_cyrillic_a_detected(self, scanner):
        # Cyrillic 'а' (U+0430) in "аpple.com"
        result = scanner._check_homoglyphs("https://\u0430pple.com")
        assert result is not None
        assert result["type"] == "homoglyph"
        assert result["confidence"] == 0.85

    def test_greek_omicron_detected(self, scanner):
        # Greek 'ο' (U+03BF) in "gοοgle.com"
        result = scanner._check_homoglyphs("https://g\u03bf\u03bfgle.com")
        assert result is not None
        assert result["type"] == "homoglyph"

    def test_normal_domain_passes(self, scanner):
        result = scanner._check_homoglyphs("https://google.com")
        assert result is None
