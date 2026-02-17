"""Integration tests for multi-tier filter pipeline using mock scanners."""

from llm_io_guard import Action, FilterResult, InputFilter, OutputFilter
from tests.helpers import (
    BlockScanner,
    ErrorScanner,
    FlagScanner,
    PassScanner,
    SanitizingScanner,
)


class TestInputFilterPipeline:
    """Integration tests for InputFilter with multi-tier scanner chains."""

    async def test_tier1_sanitize_then_tier2_pass(self):
        """Tier 1 sanitizes content, Tier 2 passes sanitized content."""
        f = InputFilter()
        f.add(SanitizingScanner())  # Tier 1 — removes <script> tags
        f.add(PassScanner(tier=2))
        result = await f.filter("<script>alert('xss')</script> Hello world")

        assert isinstance(result, FilterResult)
        assert result.is_safe
        assert result.sanitized_content is not None
        assert "<script>" not in result.sanitized_content
        assert "Hello world" in result.text
        assert len(result.scan_results) == 2

    async def test_tier1_sanitize_tier2_flag_tier3_pass(self):
        """Full 3-tier flow: sanitize → flag → tier 3 runs and passes."""
        f = InputFilter()
        f.add(SanitizingScanner())  # Tier 1
        f.add(FlagScanner(tier=2))  # Tier 2 flags → triggers Tier 3
        f.add(PassScanner(tier=3))  # Tier 3 passes

        result = await f.filter("<script>bad</script> normal content")

        assert isinstance(result, FilterResult)
        # Final action is FLAG (from Tier 2), not BLOCK
        assert result.action == Action.FLAG
        assert len(result.scan_results) == 3
        assert result.scan_results[0].scanner_name == "sanitizing_scanner"
        assert result.scan_results[1].scanner_name == "flag_scanner"
        assert result.scan_results[2].scanner_name == "pass_scanner"

    async def test_tier2_block_short_circuits_tier3(self):
        """Tier 2 BLOCK prevents Tier 3 from running."""
        tier3_ran = False

        class TrackingScanner(PassScanner):
            async def scan(self, content, metadata=None):
                nonlocal tier3_ran
                tier3_ran = True
                return await super().scan(content, metadata)

        f = InputFilter()
        f.add(BlockScanner(tier=2))
        f.add(TrackingScanner(tier=3))
        result = await f.filter("test")

        assert result.action == Action.BLOCK
        assert tier3_ran is False

    async def test_tier1_block_short_circuits_remaining(self):
        """Tier 1 BLOCK prevents Tier 2 and Tier 3 from running."""
        f = InputFilter()
        f.add(BlockScanner(tier=1))
        f.add(PassScanner(tier=2))
        f.add(PassScanner(tier=3))
        result = await f.filter("test")

        assert result.action == Action.BLOCK
        assert len(result.scan_results) == 1

    async def test_multiple_tier2_scanners_run_concurrently(self):
        """Multiple Tier 2 scanners all run even if one flags."""
        f = InputFilter()
        f.add(PassScanner(tier=2))
        f.add(FlagScanner(tier=2))
        result = await f.filter("test")

        assert result.action == Action.FLAG
        assert len(result.scan_results) == 2

    async def test_tier2_error_blocks_pipeline(self):
        """Tier 2 scanner error produces BLOCK (fail-closed)."""
        f = InputFilter()
        f.add(ErrorScanner(tier=2))
        f.add(PassScanner(tier=2))
        result = await f.filter("test")

        assert result.action == Action.BLOCK
        error_results = [r for r in result.scan_results if "fail-closed" in r.description]
        assert len(error_results) == 1


class TestOutputFilterPipeline:
    """Integration tests for OutputFilter multi-tier pipeline."""

    async def test_output_filter_always_runs_tier3(self):
        """OutputFilter runs Tier 3 even when Tier 2 passes."""
        tier3_ran = False

        class TrackingScanner(PassScanner):
            async def scan(self, content, metadata=None):
                nonlocal tier3_ran
                tier3_ran = True
                return await super().scan(content, metadata)

        f = OutputFilter()
        f.add(PassScanner(tier=2))
        f.add(TrackingScanner(tier=3))
        result = await f.filter("safe output content")

        assert result.is_safe
        assert tier3_ran is True

    async def test_output_tier3_block_overrides_tier2_pass(self):
        """Tier 3 BLOCK on output overrides Tier 2 PASS."""
        f = OutputFilter()
        f.add(PassScanner(tier=2))
        f.add(BlockScanner(tier=3))
        result = await f.filter("output with hidden issue")

        assert result.action == Action.BLOCK
