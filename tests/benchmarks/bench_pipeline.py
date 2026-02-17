"""Benchmark tests for full pipeline with Tier 1 scanners."""

import time

import pytest

from llm_io_guard import InputFilter
from llm_io_guard.scanners.html_sanitizer import HtmlSanitizer
from llm_io_guard.scanners.invisible_text import InvisibleTextScanner
from llm_io_guard.scanners.xml_safe_parser import XmlSafeParser


def _create_tier1_filter() -> InputFilter:
    """Create an input filter with only Tier 1 scanners."""
    f = InputFilter()
    f.add(InvisibleTextScanner())
    f.add(HtmlSanitizer())
    f.add(XmlSafeParser())
    return f


@pytest.mark.benchmark
class TestPipelineBenchmarks:
    """Benchmark the full pipeline with Tier 1 scanners."""

    async def test_pipeline_plain_text_latency(self):
        """Pipeline with plain text should complete in <10ms."""
        f = _create_tier1_filter()
        content = "This is a normal email with regular text content."
        start = time.perf_counter()
        for _ in range(100):
            await f.afilter(content)
        elapsed = (time.perf_counter() - start) / 100
        assert elapsed < 0.010, f"Pipeline (plain text) too slow: {elapsed * 1000:.2f}ms"

    async def test_pipeline_html_content_latency(self):
        """Pipeline with HTML content should complete in <20ms."""
        f = _create_tier1_filter()
        content = (
            "<html><body>"
            "<h1>Welcome</h1>"
            "<p>This is a normal web page with some content.</p>"
            "<ul><li>Item 1</li><li>Item 2</li></ul>"
            "</body></html>"
        )
        start = time.perf_counter()
        for _ in range(50):
            await f.afilter(content, metadata={"content_type": "text/html"})
        elapsed = (time.perf_counter() - start) / 50
        assert elapsed < 0.020, f"Pipeline (HTML) too slow: {elapsed * 1000:.2f}ms"

    async def test_pipeline_email_metadata_latency(self):
        """Pipeline with email metadata should complete in <10ms."""
        f = _create_tier1_filter()
        content = "From: sender@example.com\nSubject: Test\n\nHello, please review."
        metadata = {
            "source": "email",
            "source_risk": "low",
            "sender": "sender@example.com",
            "content_type": "text/plain",
        }
        start = time.perf_counter()
        for _ in range(100):
            await f.afilter(content, metadata=metadata)
        elapsed = (time.perf_counter() - start) / 100
        assert elapsed < 0.010, f"Pipeline (email) too slow: {elapsed * 1000:.2f}ms"

    async def test_pipeline_throughput(self):
        """Pipeline should handle at least 100 scans per second."""
        f = _create_tier1_filter()
        content = "Standard content for throughput test."
        count = 200
        start = time.perf_counter()
        for _ in range(count):
            await f.afilter(content)
        total = time.perf_counter() - start
        throughput = count / total
        assert throughput > 100, f"Pipeline throughput too low: {throughput:.0f} scans/sec"
