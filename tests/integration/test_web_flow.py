"""Integration tests for end-to-end web content scanning flow."""

from unittest.mock import AsyncMock

from llm_io_guard.config import PipelineConfig
from llm_io_guard.integration import safe_fetch_webpage
from llm_io_guard.models import Action, FilterResult
from llm_io_guard.pipeline import ContentSafetyPipeline
from llm_io_guard.scanners.html_sanitizer import HtmlSanitizer
from llm_io_guard.scanners.invisible_text import InvisibleTextScanner
from llm_io_guard.scanners.xml_safe_parser import XmlSafeParser


def _create_tier1_pipeline() -> ContentSafetyPipeline:
    """Create a pipeline with only Tier 1 scanners (no model dependencies)."""
    pipeline = ContentSafetyPipeline(config=PipelineConfig())
    pipeline.register_scanner(InvisibleTextScanner())
    pipeline.register_scanner(HtmlSanitizer())
    pipeline.register_scanner(XmlSafeParser())
    return pipeline


class TestWebFlowTier1:
    """End-to-end web content scanning with Tier 1 scanners only."""

    async def test_clean_webpage_passes(self):
        """Clean HTML page should pass all Tier 1 scanners."""
        pipeline = _create_tier1_pipeline()
        html = "<html><body><h1>Welcome</h1><p>This is a normal page.</p></body></html>"
        result = await safe_fetch_webpage(
            pipeline=pipeline,
            url="https://example.com",
            html_content=html,
        )
        assert result.action == Action.PASS

    async def test_webpage_with_script_stripped(self):
        """Web page with script tags should have them stripped."""
        pipeline = _create_tier1_pipeline()
        html = (
            "<html><body>"
            "<p>Content</p>"
            '<script>document.location="https://evil.com"</script>'
            "</body></html>"
        )
        result = await safe_fetch_webpage(
            pipeline=pipeline,
            url="https://example.com",
            html_content=html,
        )
        assert result.action in (Action.PASS, Action.FLAG)
        if result.sanitized_content:
            assert "<script>" not in result.sanitized_content

    async def test_webpage_with_invisible_text_attack(self):
        """Web page with invisible text injection should be detected by Tier 1.

        Note: Tier 1 FLAG does not propagate to top-level action (only BLOCK does).
        The FLAG is recorded in scan_results for downstream decision-making.
        """
        pipeline = _create_tier1_pipeline()
        hidden = "\u200b" * 50
        html = f"<html><body><p>Visible content{hidden}hidden instructions</p></body></html>"
        result = await safe_fetch_webpage(
            pipeline=pipeline,
            url="https://example.com",
            html_content=html,
        )
        # Tier 1 flags are in scan_results but don't propagate to top-level action
        assert len(result.flagged_by) > 0
        assert result.flagged_by[0].scanner_name == "invisible_text"

    async def test_webpage_metadata_set_correctly(self):
        """Web page scanning should set metadata correctly."""
        pipeline = AsyncMock()
        pipeline.scan.return_value = FilterResult(action=Action.PASS, original_content="test")
        await safe_fetch_webpage(
            pipeline=pipeline,
            url="https://example.com/page",
            html_content="<p>Content</p>",
        )
        call_kwargs = pipeline.scan.call_args[1]
        assert call_kwargs["metadata"]["source"] == "web"
        assert call_kwargs["metadata"]["source_risk"] == "unknown"
        assert call_kwargs["metadata"]["url"] == "https://example.com/page"
        assert call_kwargs["metadata"]["content_type"] == "text/html"
        assert call_kwargs["direction"] == "input"

    async def test_large_webpage_content(self):
        """Large web page content should be processed without errors."""
        pipeline = _create_tier1_pipeline()
        paragraphs = "<p>Normal paragraph content. </p>" * 200
        html = f"<html><body>{paragraphs}</body></html>"
        result = await safe_fetch_webpage(
            pipeline=pipeline,
            url="https://example.com/large",
            html_content=html,
        )
        assert result.action in (Action.PASS, Action.FLAG)

    async def test_webpage_with_mixed_attacks(self):
        """Web page combining HTML injection and invisible chars."""
        pipeline = _create_tier1_pipeline()
        html = (
            "<html><body>"
            '<div style="display:none">' + "\u200b" * 30 + "</div>"
            "<p>Visible content</p>"
            '<script>alert("xss")</script>'
            "</body></html>"
        )
        result = await safe_fetch_webpage(
            pipeline=pipeline,
            url="https://suspicious.com",
            html_content=html,
        )
        # Should at minimum strip dangerous HTML; invisible chars may trigger FLAG
        assert result.action in (Action.PASS, Action.FLAG)
        if result.sanitized_content:
            assert "<script>" not in result.sanitized_content

    async def test_webpage_dutch_content(self):
        """Dutch language web page should pass."""
        pipeline = _create_tier1_pipeline()
        html = (
            "<html><body>"
            "<h1>Welkom bij ons bedrijf</h1>"
            "<p>Wij bieden professionele diensten aan voor het MKB.</p>"
            "</body></html>"
        )
        result = await safe_fetch_webpage(
            pipeline=pipeline,
            url="https://example.nl",
            html_content=html,
        )
        assert result.action == Action.PASS
