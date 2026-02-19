"""Tests for InputFilter and OutputFilter."""

import asyncio

import pytest

from llm_io_guard import Action, ContentBlocked, FilterResult, InputFilter, OutputFilter
from tests.helpers import (
    BlockScanner,
    ErrorScanner,
    FlagScanner,
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
        result = await f.afilter("safe content")
        assert isinstance(result, FilterResult)
        assert result.is_safe

    async def test_filter_blocked_content(self):
        """Blocked content returns BLOCK."""
        f = InputFilter()
        f.add(BlockScanner(tier=2))
        result = await f.afilter("bad content")
        assert isinstance(result, FilterResult)
        assert result.action == Action.BLOCK

    async def test_auto_initialize(self):
        """Filter auto-initializes on first afilter() call."""
        f = InputFilter()
        f.add(PassScanner(tier=2))
        assert f._initialized is False
        await f.afilter("test")
        assert f._initialized is True

    async def test_tier_ordering(self):
        """Tier 1 runs before Tier 2."""
        f = InputFilter()
        f.add(SanitizingScanner())  # Tier 1
        f.add(PassScanner(tier=2))
        result = await f.afilter("<script>alert('xss')</script> hello")
        assert isinstance(result, FilterResult)
        assert result.sanitized_content is not None
        assert "<script>" not in result.sanitized_content

    async def test_metadata_has_direction(self):
        """Metadata passed to scanners includes direction='input'."""
        received_metadata = {}

        class MetadataCapture(PassScanner):
            async def ascan(self, content, metadata=None):
                received_metadata.update(metadata or {})
                return await super().ascan(content, metadata)

        f = InputFilter()
        f.add(MetadataCapture(tier=2))
        await f.afilter("test")
        assert received_metadata.get("direction") == "input"

    async def test_max_content_length(self):
        """Content exceeding max_content_length is blocked."""
        f = InputFilter(max_content_length=10)
        f.add(PassScanner(tier=2))
        result = await f.afilter("this content is too long for the filter")
        assert isinstance(result, FilterResult)
        assert result.action == Action.BLOCK

    async def test_error_scanner_produces_block(self):
        """Scanner that raises an exception produces BLOCK result (fail-closed)."""
        f = InputFilter()
        f.add(ErrorScanner(tier=2))
        result = await f.afilter("test")
        assert isinstance(result, FilterResult)
        assert result.action == Action.BLOCK
        assert "fail-closed" in result.scan_results[0].description

    async def test_tier1_error_scanner_produces_block(self):
        """Tier 1 scanner error produces BLOCK (fail-closed), not FLAG."""
        f = InputFilter()
        f.add(ErrorScanner(tier=1))
        result = await f.afilter("test")
        assert isinstance(result, FilterResult)
        assert result.action == Action.BLOCK
        assert "fail-closed" in result.scan_results[0].description

    async def test_tier3_error_scanner_produces_block(self):
        """Tier 3 scanner error produces BLOCK (fail-closed), not FLAG."""
        f = InputFilter()
        f.add(FlagScanner(tier=2))  # FLAG triggers Tier 3 for InputFilter
        f.add(ErrorScanner(tier=3))
        result = await f.afilter("test")
        assert isinstance(result, FilterResult)
        assert result.action == Action.BLOCK
        block_results = [r for r in result.scan_results if r.action == Action.BLOCK]
        assert any("fail-closed" in r.description for r in block_results)

    async def test_tier2_cancelled_error_propagates(self):
        """CancelledError in Tier 2 is re-raised, not swallowed."""
        from llm_io_guard.models import ScanResult
        from llm_io_guard.scanner import Scanner

        class CancelScanner(Scanner):
            """Scanner that raises CancelledError."""

            name = "cancel_scanner"
            tier = 2

            async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
                raise asyncio.CancelledError()

        f = InputFilter()
        f.add(CancelScanner())
        with pytest.raises(asyncio.CancelledError):
            await f.afilter("test")


# ---------------------------------------------------------------------------
# Tier 3 conditional logic
# ---------------------------------------------------------------------------


class TestTier3ConditionalLogic:
    """Tests for InputFilter._should_run_tier3 conditions."""

    async def test_tier3_runs_on_flag(self):
        """Tier 3 runs when a Tier 2 scanner flags content."""
        tier3_ran = False

        class TrackingPassScanner(PassScanner):
            async def ascan(self, content, metadata=None):
                nonlocal tier3_ran
                tier3_ran = True
                return await super().ascan(content, metadata)

        f = InputFilter()
        f.add(FlagScanner(tier=2))  # Tier 2 produces FLAG
        f.add(TrackingPassScanner(tier=3))  # Tier 3 should run
        await f.afilter("test")
        assert tier3_ran is True

    async def test_tier3_skipped_on_pass_low_risk(self):
        """Tier 3 is skipped when Tier 2 passes and source_risk is low."""
        tier3_ran = False

        class TrackingPassScanner(PassScanner):
            async def ascan(self, content, metadata=None):
                nonlocal tier3_ran
                tier3_ran = True
                return await super().ascan(content, metadata)

        f = InputFilter()
        f.add(PassScanner(tier=2))  # Tier 2 passes
        f.add(TrackingPassScanner(tier=3))
        await f.afilter("test", metadata={"source_risk": "low"})
        assert tier3_ran is False

    async def test_tier3_runs_on_high_risk(self):
        """Tier 3 runs when source_risk is 'high' even if Tier 2 passes."""
        tier3_ran = False

        class TrackingPassScanner(PassScanner):
            async def ascan(self, content, metadata=None):
                nonlocal tier3_ran
                tier3_ran = True
                return await super().ascan(content, metadata)

        f = InputFilter()
        f.add(PassScanner(tier=2))  # Tier 2 passes
        f.add(TrackingPassScanner(tier=3))
        await f.afilter("test", metadata={"source_risk": "high"})
        assert tier3_ran is True

    async def test_tier3_runs_on_unknown_risk(self):
        """Tier 3 runs when source_risk is 'unknown' even if Tier 2 passes."""
        tier3_ran = False

        class TrackingPassScanner(PassScanner):
            async def ascan(self, content, metadata=None):
                nonlocal tier3_ran
                tier3_ran = True
                return await super().ascan(content, metadata)

        f = InputFilter()
        f.add(PassScanner(tier=2))
        f.add(TrackingPassScanner(tier=3))
        await f.afilter("test", metadata={"source_risk": "unknown"})
        assert tier3_ran is True

    async def test_output_filter_always_runs_tier3(self):
        """OutputFilter always runs Tier 3 regardless of Tier 2 result."""
        tier3_ran = False

        class TrackingPassScanner(PassScanner):
            async def ascan(self, content, metadata=None):
                nonlocal tier3_ran
                tier3_ran = True
                return await super().ascan(content, metadata)

        f = OutputFilter()
        f.add(PassScanner(tier=2))
        f.add(TrackingPassScanner(tier=3))
        await f.afilter("safe content")
        assert tier3_ran is True


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
            async def ascan(self, content, metadata=None):
                received_metadata.update(metadata or {})
                return await super().ascan(content, metadata)

        f = OutputFilter()
        f.add(MetadataCapture(tier=2))
        await f.afilter("test")
        assert received_metadata.get("direction") == "output"

    async def test_filter_safe_content(self):
        """Safe content returns PASS."""
        f = OutputFilter()
        f.add(PassScanner(tier=2))
        result = await f.afilter("safe output")
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
        result = await f.afilter("safe")
        assert isinstance(result, FilterResult)

    async def test_result_mode_returns_filter_result_on_block(self):
        """on_block='result' returns FilterResult even when blocked."""
        f = InputFilter(on_block="result")
        f.add(BlockScanner(tier=2))
        result = await f.afilter("bad")
        assert isinstance(result, FilterResult)
        assert result.action == Action.BLOCK

    async def test_raise_mode_returns_str_on_pass(self):
        """on_block='raise' returns str on safe content."""
        f = InputFilter(on_block="raise")
        f.add(PassScanner(tier=2))
        result = await f.afilter("safe content")
        assert isinstance(result, str)
        assert result == "safe content"

    async def test_raise_mode_raises_on_block(self):
        """on_block='raise' raises ContentBlocked on blocked content."""
        f = InputFilter(on_block="raise")
        f.add(BlockScanner(tier=2))
        with pytest.raises(ContentBlocked) as exc_info:
            await f.afilter("bad content")
        assert exc_info.value.result.action == Action.BLOCK

    async def test_none_mode_returns_str_on_pass(self):
        """on_block='none' returns str on safe content."""
        f = InputFilter(on_block="none")
        f.add(PassScanner(tier=2))
        result = await f.afilter("safe content")
        assert isinstance(result, str)
        assert result == "safe content"

    async def test_none_mode_returns_none_on_block(self):
        """on_block='none' returns None on blocked content."""
        f = InputFilter(on_block="none")
        f.add(BlockScanner(tier=2))
        result = await f.afilter("bad content")
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
