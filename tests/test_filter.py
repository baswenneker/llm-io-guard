"""Tests for InputFilter and OutputFilter."""

import pytest

from llm_io_guard import Action, ContentBlocked, FilterResult, InputFilter, OutputFilter
from tests.helpers import (
    BlockScanner,
    ErrorScanner,
    PassScanner,
    SanitizingScanner,
)

# ---------------------------------------------------------------------------
# InputFilter
# ---------------------------------------------------------------------------


class TestInputFilter:
    """Tests for InputFilter."""

    def test_add_scanner(self):
        """Can add a scanner that supports input."""
        f = InputFilter()
        f.add(PassScanner(tier=2))
        assert len(f._scanners[2]) == 1

    def test_reject_output_only_scanner(self):
        """Adding a scanner that only supports output raises ValueError."""
        from llm_io_guard.scanners.pii_detector import PiiDetector

        f = InputFilter()
        with pytest.raises(ValueError, match="does not support direction 'input'"):
            f.add(PiiDetector())

    def test_add_chaining(self):
        """add() returns self for method chaining."""
        f = InputFilter()
        result = f.add(PassScanner(tier=1))
        assert result is f

    async def test_filter_safe_content(self):
        """Safe content returns PASS."""
        f = InputFilter()
        f.add(PassScanner(tier=2))
        result = await f.filter("safe content")
        assert isinstance(result, FilterResult)
        assert result.is_safe

    async def test_filter_blocked_content(self):
        """Blocked content returns BLOCK."""
        f = InputFilter()
        f.add(BlockScanner(tier=2))
        result = await f.filter("bad content")
        assert isinstance(result, FilterResult)
        assert result.action == Action.BLOCK

    async def test_auto_initialize(self):
        """Filter auto-initializes on first filter() call."""
        f = InputFilter()
        f.add(PassScanner(tier=2))
        assert f._initialized is False
        await f.filter("test")
        assert f._initialized is True

    async def test_tier_ordering(self):
        """Tier 1 runs before Tier 2."""
        f = InputFilter()
        f.add(SanitizingScanner())  # Tier 1
        f.add(PassScanner(tier=2))
        result = await f.filter("<script>alert('xss')</script> hello")
        assert isinstance(result, FilterResult)
        assert result.sanitized_content is not None
        assert "<script>" not in result.sanitized_content

    async def test_metadata_has_direction(self):
        """Metadata passed to scanners includes direction='input'."""
        received_metadata = {}

        class MetadataCapture(PassScanner):
            async def scan(self, content, metadata=None):
                received_metadata.update(metadata or {})
                return await super().scan(content, metadata)

        f = InputFilter()
        f.add(MetadataCapture(tier=2))
        await f.filter("test")
        assert received_metadata.get("direction") == "input"

    async def test_max_content_length(self):
        """Content exceeding max_content_length is blocked."""
        f = InputFilter(max_content_length=10)
        f.add(PassScanner(tier=2))
        result = await f.filter("this content is too long for the filter")
        assert isinstance(result, FilterResult)
        assert result.action == Action.BLOCK

    async def test_error_scanner_produces_flag(self):
        """Scanner that raises an exception produces FLAG result."""
        f = InputFilter()
        f.add(ErrorScanner(tier=2))
        result = await f.filter("test")
        assert isinstance(result, FilterResult)
        assert result.action == Action.FLAG


# ---------------------------------------------------------------------------
# OutputFilter
# ---------------------------------------------------------------------------


class TestOutputFilter:
    """Tests for OutputFilter."""

    def test_add_scanner(self):
        """Can add a scanner that supports output."""
        f = OutputFilter()
        f.add(PassScanner(tier=2))
        assert len(f._scanners[2]) == 1

    def test_reject_input_only_scanner(self):
        """Adding a scanner that only supports input raises ValueError."""
        from llm_io_guard.scanners.invisible_text import InvisibleTextScanner

        f = OutputFilter()
        with pytest.raises(ValueError, match="does not support direction 'output'"):
            f.add(InvisibleTextScanner())

    async def test_metadata_has_direction(self):
        """Metadata passed to scanners includes direction='output'."""
        received_metadata = {}

        class MetadataCapture(PassScanner):
            async def scan(self, content, metadata=None):
                received_metadata.update(metadata or {})
                return await super().scan(content, metadata)

        f = OutputFilter()
        f.add(MetadataCapture(tier=2))
        await f.filter("test")
        assert received_metadata.get("direction") == "output"

    async def test_filter_safe_content(self):
        """Safe content returns PASS."""
        f = OutputFilter()
        f.add(PassScanner(tier=2))
        result = await f.filter("safe output")
        assert isinstance(result, FilterResult)
        assert result.is_safe


# ---------------------------------------------------------------------------
# on_block modes
# ---------------------------------------------------------------------------


class TestOnBlockModes:
    """Tests for different on_block behaviors."""

    async def test_result_mode_returns_filter_result(self):
        """on_block='result' always returns FilterResult."""
        f = InputFilter(on_block="result")
        f.add(PassScanner(tier=2))
        result = await f.filter("safe")
        assert isinstance(result, FilterResult)

    async def test_result_mode_returns_filter_result_on_block(self):
        """on_block='result' returns FilterResult even when blocked."""
        f = InputFilter(on_block="result")
        f.add(BlockScanner(tier=2))
        result = await f.filter("bad")
        assert isinstance(result, FilterResult)
        assert result.action == Action.BLOCK

    async def test_raise_mode_returns_str_on_pass(self):
        """on_block='raise' returns str on safe content."""
        f = InputFilter(on_block="raise")
        f.add(PassScanner(tier=2))
        result = await f.filter("safe content")
        assert isinstance(result, str)
        assert result == "safe content"

    async def test_raise_mode_raises_on_block(self):
        """on_block='raise' raises ContentBlocked on blocked content."""
        f = InputFilter(on_block="raise")
        f.add(BlockScanner(tier=2))
        with pytest.raises(ContentBlocked) as exc_info:
            await f.filter("bad content")
        assert exc_info.value.result.action == Action.BLOCK

    async def test_none_mode_returns_str_on_pass(self):
        """on_block='none' returns str on safe content."""
        f = InputFilter(on_block="none")
        f.add(PassScanner(tier=2))
        result = await f.filter("safe content")
        assert isinstance(result, str)
        assert result == "safe content"

    async def test_none_mode_returns_none_on_block(self):
        """on_block='none' returns None on blocked content."""
        f = InputFilter(on_block="none")
        f.add(BlockScanner(tier=2))
        result = await f.filter("bad content")
        assert result is None

    def test_invalid_on_block_raises(self):
        """Invalid on_block value raises ValueError."""
        with pytest.raises(ValueError, match="on_block must be"):
            InputFilter(on_block="invalid")


# ---------------------------------------------------------------------------
# FilterResult.text property
# ---------------------------------------------------------------------------


class TestFilterResult:
    """Tests for FilterResult.text property."""

    def test_text_returns_sanitized_when_set(self):
        """text property returns sanitized_content when available."""
        result = FilterResult(
            action=Action.PASS,
            original_content="original",
            sanitized_content="sanitized",
        )
        assert result.text == "sanitized"

    def test_text_returns_original_when_no_sanitized(self):
        """text property returns original_content when sanitized_content is None."""
        result = FilterResult(
            action=Action.PASS,
            original_content="original",
        )
        assert result.text == "original"
