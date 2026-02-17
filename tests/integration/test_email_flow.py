"""Integration tests for end-to-end email scanning flow."""

from unittest.mock import AsyncMock

from llm_io_guard.config import PipelineConfig
from llm_io_guard.integration import safe_fetch_email
from llm_io_guard.models import Action
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


class TestEmailFlowTier1:
    """End-to-end email scanning with Tier 1 scanners only."""

    async def test_clean_plain_text_email(self):
        """Clean plain text email should pass all Tier 1 scanners."""
        pipeline = _create_tier1_pipeline()
        result = await safe_fetch_email(
            pipeline=pipeline,
            email_body="Hello, please find the report attached. Best regards.",
            sender="colleague@company.com",
            subject="Monthly Report",
        )
        assert result.action == Action.PASS

    async def test_clean_html_email(self):
        """Clean HTML email should pass after sanitization."""
        pipeline = _create_tier1_pipeline()
        result = await safe_fetch_email(
            pipeline=pipeline,
            email_body="<html><body><p>Hello,</p><p>Please review.</p></body></html>",
            sender="colleague@company.com",
            subject="Review request",
        )
        assert result.action == Action.PASS

    async def test_email_with_script_tag(self):
        """Email with script tags should have them stripped by HtmlSanitizer."""
        pipeline = _create_tier1_pipeline()
        result = await safe_fetch_email(
            pipeline=pipeline,
            email_body='<html><body><p>Hello</p><script>alert("xss")</script></body></html>',
            sender="attacker@unknown.org",
            subject="Urgent",
        )
        # Script tags stripped, but content should pass since "Hello" remains
        assert result.action in (Action.PASS, Action.FLAG)
        if result.sanitized_content:
            assert "<script>" not in result.sanitized_content

    async def test_email_with_invisible_chars(self):
        """Email body with many invisible characters should be detected by Tier 1.

        Note: Tier 1 FLAG does not propagate to top-level action (only BLOCK does).
        The FLAG is recorded in scan_results for downstream decision-making.
        """
        pipeline = _create_tier1_pipeline()
        hidden = "\u200b" * 50
        result = await safe_fetch_email(
            pipeline=pipeline,
            email_body=f"Normal text{hidden}more text",
            sender="user@unknown.org",
            subject="Test",
        )
        # Tier 1 flags are in scan_results but don't propagate to top-level action
        assert len(result.flagged_by) > 0
        assert result.flagged_by[0].scanner_name == "invisible_text"

    async def test_email_metadata_propagated(self):
        """Email metadata should be passed to the pipeline correctly."""
        pipeline = AsyncMock()
        from llm_io_guard.models import FilterResult

        pipeline.scan.return_value = FilterResult(action=Action.PASS, original_content="test")
        await safe_fetch_email(
            pipeline=pipeline,
            email_body="Test body",
            sender="user@partner.com",
            subject="Test Subject",
        )
        call_kwargs = pipeline.scan.call_args[1]
        assert call_kwargs["metadata"]["source"] == "email"
        assert call_kwargs["metadata"]["sender"] == "user@partner.com"
        assert call_kwargs["metadata"]["subject"] == "Test Subject"
        assert call_kwargs["metadata"]["source_risk"] == "low"  # partner.com is trusted

    async def test_email_from_untrusted_domain(self):
        """Email from untrusted domain should have unknown risk."""
        pipeline = AsyncMock()
        from llm_io_guard.models import FilterResult

        pipeline.scan.return_value = FilterResult(action=Action.PASS, original_content="test")
        await safe_fetch_email(
            pipeline=pipeline,
            email_body="Check this out",
            sender="user@suspicious.org",
            subject="Important",
        )
        call_kwargs = pipeline.scan.call_args[1]
        assert call_kwargs["metadata"]["source_risk"] == "unknown"

    async def test_email_dutch_content_passes(self):
        """Dutch language email should pass Tier 1 scanners."""
        pipeline = _create_tier1_pipeline()
        result = await safe_fetch_email(
            pipeline=pipeline,
            email_body="Beste klant, hierbij sturen wij u de factuur voor november. Met vriendelijke groet.",
            sender="admin@company.com",
            subject="Factuur november",
        )
        assert result.action == Action.PASS
