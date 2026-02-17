"""Tests for the HtmlSanitizer."""

from llm_io_guard.models import Action
from llm_io_guard.scanners.html_sanitizer import HtmlSanitizer


async def test_plain_text_passes_through():
    scanner = HtmlSanitizer()
    result = await scanner.scan("Just plain text, no HTML here.")
    assert result.action == Action.PASS
    assert result.details["sanitized_content"] == "Just plain text, no HTML here."
    assert "plain text" in result.description


async def test_html_stripped():
    scanner = HtmlSanitizer()
    result = await scanner.scan("<p>Hello <b>World</b></p>")
    assert result.action == Action.PASS
    assert "Hello" in result.details["sanitized_content"]
    assert "World" in result.details["sanitized_content"]
    assert "<p>" not in result.details["sanitized_content"]
    assert "<b>" not in result.details["sanitized_content"]


async def test_script_tags_removed():
    scanner = HtmlSanitizer()
    html = '<p>Safe text</p><script>alert("xss")</script>'
    result = await scanner.scan(html)
    assert "script" not in result.details["sanitized_content"].lower()
    assert "alert" not in result.details["sanitized_content"]
    assert "Safe text" in result.details["sanitized_content"]


async def test_high_reduction_flagged():
    scanner = HtmlSanitizer()
    # Content that is mostly HTML with very little text
    html = (
        "<div><script>var x = 'a'.repeat(1000);</script>"
        "<style>.x{display:none}</style>"
        "<div hidden>secret</div>"
        "</div>"
    )
    result = await scanner.scan(html)
    # The sanitizer should remove most of this, triggering a flag
    assert result.action == Action.FLAG
    assert result.confidence > 0.8


async def test_content_type_html_triggers_sanitization():
    scanner = HtmlSanitizer()
    # Even without '<' in content, content_type text/html triggers sanitization
    result = await scanner.scan("no angle brackets", metadata={"content_type": "text/html"})
    assert result.action == Action.PASS
    assert result.details["sanitized_content"] is not None


async def test_scanner_name_and_tier():
    scanner = HtmlSanitizer()
    assert scanner.name == "html_sanitizer"
    assert scanner.tier == 1
