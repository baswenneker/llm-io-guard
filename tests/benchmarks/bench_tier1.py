"""Benchmark tests for Tier 1 scanner latency."""

import time

import pytest

from llm_io_guard.scanners.html_sanitizer import HtmlSanitizer
from llm_io_guard.scanners.invisible_text import InvisibleTextScanner
from llm_io_guard.scanners.xml_safe_parser import XmlSafeParser


@pytest.mark.benchmark
class TestTier1Benchmarks:
    """Benchmark Tier 1 scanners to verify they meet latency targets."""

    async def test_invisible_text_latency(self):
        """InvisibleTextScanner should process content in <5ms per scan."""
        scanner = InvisibleTextScanner()
        content = "Normal text with some content " * 100
        start = time.perf_counter()
        for _ in range(100):
            await scanner.scan(content)
        elapsed = (time.perf_counter() - start) / 100
        assert elapsed < 0.005, f"InvisibleTextScanner too slow: {elapsed*1000:.2f}ms"

    async def test_html_sanitizer_latency(self):
        """HtmlSanitizer should process content in <5ms per scan."""
        scanner = HtmlSanitizer()
        content = "<p>Hello</p><div>World</div>" * 50
        start = time.perf_counter()
        for _ in range(100):
            await scanner.scan(content)
        elapsed = (time.perf_counter() - start) / 100
        assert elapsed < 0.005, f"HtmlSanitizer too slow: {elapsed*1000:.2f}ms"

    async def test_xml_safe_parser_latency(self):
        """XmlSafeParser should process content in <5ms per scan."""
        scanner = XmlSafeParser()
        content = "Normal text content without XML"
        start = time.perf_counter()
        for _ in range(100):
            await scanner.scan(content)
        elapsed = (time.perf_counter() - start) / 100
        assert elapsed < 0.005, f"XmlSafeParser too slow: {elapsed*1000:.2f}ms"

    async def test_tier1_total_latency(self):
        """All Tier 1 scanners combined should process in <5ms."""
        scanners = [InvisibleTextScanner(), HtmlSanitizer(), XmlSafeParser()]
        content = "Normal text content"
        start = time.perf_counter()
        for _ in range(100):
            for scanner in scanners:
                await scanner.scan(content)
        elapsed = (time.perf_counter() - start) / 100
        assert elapsed < 0.005, f"Combined Tier 1 too slow: {elapsed*1000:.2f}ms"

    async def test_invisible_text_with_many_invisible_chars(self):
        """InvisibleTextScanner with many invisible chars should still be fast."""
        scanner = InvisibleTextScanner()
        content = "Normal" + "\u200b" * 500 + "text" + "\u200c" * 500
        start = time.perf_counter()
        for _ in range(100):
            await scanner.scan(content)
        elapsed = (time.perf_counter() - start) / 100
        assert elapsed < 0.005, f"InvisibleTextScanner (heavy) too slow: {elapsed*1000:.2f}ms"

    async def test_html_sanitizer_large_html(self):
        """HtmlSanitizer with large HTML should complete in reasonable time."""
        scanner = HtmlSanitizer()
        content = "<div>" + "<p>Content paragraph</p>" * 100 + "</div>"
        start = time.perf_counter()
        for _ in range(50):
            await scanner.scan(content, metadata={"content_type": "text/html"})
        elapsed = (time.perf_counter() - start) / 50
        assert elapsed < 0.050, f"HtmlSanitizer (large) too slow: {elapsed*1000:.2f}ms"
