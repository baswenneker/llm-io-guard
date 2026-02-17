"""Tests for the agent integration layer."""

from unittest.mock import AsyncMock, patch

from llm_io_guard.integration import safe_fetch_email, safe_fetch_webpage
from llm_io_guard.models import Action, FilterResult


def _mock_pipeline(action: Action = Action.PASS) -> AsyncMock:
    """Create a mock pipeline that returns a FilterResult."""
    pipeline = AsyncMock()
    pipeline.scan.return_value = FilterResult(action=action, original_content="test")
    return pipeline


class TestSafeFetchEmail:
    """Tests for safe_fetch_email."""

    async def test_safe_email_scanned(self):
        pipeline = _mock_pipeline()
        result = await safe_fetch_email(
            pipeline=pipeline,
            email_body="Hello world",
            sender="user@example.com",
            subject="Test",
        )
        assert result.action == Action.PASS
        pipeline.scan.assert_called_once()

    async def test_email_known_domain_low_risk(self):
        pipeline = _mock_pipeline()
        await safe_fetch_email(
            pipeline=pipeline,
            email_body="Hello",
            sender="user@company.com",
            subject="Test",
        )
        call_kwargs = pipeline.scan.call_args[1]
        assert call_kwargs["metadata"]["source_risk"] == "low"

    async def test_email_unknown_domain_unknown_risk(self):
        pipeline = _mock_pipeline()
        await safe_fetch_email(
            pipeline=pipeline,
            email_body="Hello",
            sender="user@random.org",
            subject="Test",
        )
        call_kwargs = pipeline.scan.call_args[1]
        assert call_kwargs["metadata"]["source_risk"] == "unknown"

    async def test_email_html_content_type(self):
        pipeline = _mock_pipeline()
        await safe_fetch_email(
            pipeline=pipeline,
            email_body="<html><body>Hello</body></html>",
            sender="user@example.com",
            subject="Test",
        )
        call_kwargs = pipeline.scan.call_args[1]
        assert call_kwargs["metadata"]["content_type"] == "text/html"

    async def test_email_plain_text_content_type(self):
        pipeline = _mock_pipeline()
        await safe_fetch_email(
            pipeline=pipeline,
            email_body="Just plain text",
            sender="user@example.com",
            subject="Test",
        )
        call_kwargs = pipeline.scan.call_args[1]
        assert call_kwargs["metadata"]["content_type"] == "text/plain"

    async def test_email_attachments_logged(self):
        pipeline = _mock_pipeline()
        with patch("llm_io_guard.integration.logger") as mock_logger:
            await safe_fetch_email(
                pipeline=pipeline,
                email_body="See attached",
                sender="user@example.com",
                subject="Files",
                attachments=["doc.pdf", "image.png"],
            )
            mock_logger.info.assert_called_once_with(
                "email_attachments_noted",
                count=2,
                filenames=["doc.pdf", "image.png"],
            )


class TestSafeFetchWebpage:
    """Tests for safe_fetch_webpage."""

    async def test_webpage_scanned(self):
        pipeline = _mock_pipeline()
        result = await safe_fetch_webpage(
            pipeline=pipeline,
            url="https://example.com",
            html_content="<html><body>Hello</body></html>",
        )
        assert result.action == Action.PASS
        pipeline.scan.assert_called_once()

    async def test_webpage_metadata(self):
        pipeline = _mock_pipeline()
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
