"""Tests for the ContentSafetyPipeline."""

import pytest
from helpers import BlockScanner, FlagScanner, PassScanner, SanitizingScanner

from llm_io_guard import Action
from llm_io_guard.config import PipelineConfig, ScannerConfig
from llm_io_guard.pipeline import ContentSafetyPipeline


class TestPipelineRegistration:
    """Tests for scanner registration."""

    def test_register_scanner(self, pipeline: ContentSafetyPipeline):
        scanner = PassScanner(tier=2)
        pipeline.register_scanner(scanner)
        assert scanner in pipeline._scanners[2]

    def test_register_invalid_tier(self, pipeline: ContentSafetyPipeline):
        class BadTier(PassScanner):
            @property
            def tier(self) -> int:
                return 99

        with pytest.raises(ValueError, match="Invalid tier"):
            pipeline.register_scanner(BadTier())


class TestPipelineExecution:
    """Tests for pipeline scan execution."""

    async def test_empty_pipeline_passes(self, pipeline: ContentSafetyPipeline):
        result = await pipeline.scan("hello world")
        assert result.action == Action.PASS
        assert result.scan_results == []

    async def test_pass_scanner(self, pipeline: ContentSafetyPipeline):
        pipeline.register_scanner(PassScanner(tier=2))
        result = await pipeline.scan("hello world")
        assert result.action == Action.PASS
        assert len(result.scan_results) == 1

    async def test_block_scanner(self, pipeline: ContentSafetyPipeline):
        pipeline.register_scanner(BlockScanner(tier=2))
        result = await pipeline.scan("bad content")
        assert result.action == Action.BLOCK
        assert len(result.blocked_by) == 1

    async def test_flag_scanner(self, pipeline: ContentSafetyPipeline):
        pipeline.register_scanner(FlagScanner(tier=2))
        result = await pipeline.scan("suspicious content")
        assert result.action == Action.FLAG
        assert len(result.flagged_by) == 1

    async def test_processing_time_recorded(self, pipeline: ContentSafetyPipeline):
        pipeline.register_scanner(PassScanner(tier=2))
        result = await pipeline.scan("test")
        assert result.processing_time_ms > 0


class TestTierExecution:
    """Tests for tiered execution behavior."""

    async def test_tier1_sequential_sanitization(self, pipeline: ContentSafetyPipeline):
        pipeline.register_scanner(SanitizingScanner())
        result = await pipeline.scan("<script>alert('xss')</script>")
        assert result.action == Action.PASS
        assert result.sanitized_content == "alert('xss')"

    async def test_tier1_block_stops_pipeline(self, pipeline: ContentSafetyPipeline):
        pipeline.register_scanner(BlockScanner(tier=1))
        pipeline.register_scanner(PassScanner(tier=2))
        result = await pipeline.scan("bad content")
        assert result.action == Action.BLOCK
        # Tier 2 scanner should not have run
        assert len(result.scan_results) == 1
        assert result.scan_results[0].scanner_name == "block_scanner"

    async def test_tier2_parallel_execution(self, pipeline: ContentSafetyPipeline):
        pipeline.register_scanner(PassScanner(tier=2))
        pipeline.register_scanner(FlagScanner(tier=2))
        result = await pipeline.scan("test content")
        assert result.action == Action.FLAG
        assert len(result.scan_results) == 2

    async def test_tier2_block_stops_before_tier3(self, pipeline: ContentSafetyPipeline):
        pipeline.register_scanner(BlockScanner(tier=2))
        pipeline.register_scanner(PassScanner(tier=3))
        result = await pipeline.scan("test", metadata={"source_risk": "high"})
        assert result.action == Action.BLOCK
        # Tier 3 should not have run
        assert len(result.scan_results) == 1

    async def test_tier_execution_order(self, pipeline: ContentSafetyPipeline):
        """Verify scanners run in tier order: 1, 2, 3."""
        execution_order: list[str] = []

        class OrderTracker(PassScanner):
            def __init__(self, tier: int, label: str) -> None:
                super().__init__(tier=tier)
                self._label = label

            @property
            def name(self) -> str:
                return self._label

            async def scan(self, content, metadata=None):
                execution_order.append(self._label)
                return await super().scan(content, metadata)

        pipeline.register_scanner(OrderTracker(tier=2, label="tier2"))
        pipeline.register_scanner(OrderTracker(tier=1, label="tier1"))
        pipeline.register_scanner(OrderTracker(tier=3, label="tier3"))

        await pipeline.scan("test", metadata={"source_risk": "high"})

        assert execution_order[0] == "tier1"
        assert execution_order[1] == "tier2"
        assert execution_order[2] == "tier3"


class TestTier3Conditional:
    """Tests for conditional Tier 3 execution."""

    async def test_tier3_skipped_when_safe(self, pipeline: ContentSafetyPipeline):
        """Tier 3 should not run when content is safe and source is low-risk."""
        pipeline.register_scanner(PassScanner(tier=2))
        pipeline.register_scanner(PassScanner(tier=3))
        result = await pipeline.scan("safe content")
        # Only tier 2 scanner should have run
        assert len(result.scan_results) == 1

    async def test_tier3_runs_when_flagged(self, pipeline: ContentSafetyPipeline):
        """Tier 3 should run when content is flagged by earlier tiers."""
        pipeline.register_scanner(FlagScanner(tier=2))
        pipeline.register_scanner(PassScanner(tier=3))
        result = await pipeline.scan("flagged content")
        assert len(result.scan_results) == 2

    async def test_tier3_runs_for_high_risk_source(self, pipeline: ContentSafetyPipeline):
        """Tier 3 should run for high-risk sources even if content is safe."""
        pipeline.register_scanner(PassScanner(tier=2))
        pipeline.register_scanner(PassScanner(tier=3))
        result = await pipeline.scan("test", metadata={"source_risk": "high"})
        assert len(result.scan_results) == 2

    async def test_tier3_runs_for_unknown_source(self, pipeline: ContentSafetyPipeline):
        """Tier 3 should run for unknown source risk."""
        pipeline.register_scanner(PassScanner(tier=2))
        pipeline.register_scanner(PassScanner(tier=3))
        result = await pipeline.scan("test", metadata={"source_risk": "unknown"})
        assert len(result.scan_results) == 2


class TestDisabledScanners:
    """Tests for disabled scanner handling."""

    async def test_disabled_scanner_skipped(self):
        config = PipelineConfig(
            scanners={"pass_scanner": ScannerConfig(enabled=False)},
        )
        pipeline = ContentSafetyPipeline(config=config)
        pipeline.register_scanner(PassScanner(tier=2))
        result = await pipeline.scan("test")
        assert len(result.scan_results) == 0
        assert result.action == Action.PASS

    async def test_mixed_enabled_disabled(self):
        config = PipelineConfig(
            scanners={"pass_scanner": ScannerConfig(enabled=False)},
        )
        pipeline = ContentSafetyPipeline(config=config)
        pipeline.register_scanner(PassScanner(tier=2))
        pipeline.register_scanner(FlagScanner(tier=2))
        result = await pipeline.scan("test")
        # Only FlagScanner should run
        assert len(result.scan_results) == 1
        assert result.scan_results[0].scanner_name == "flag_scanner"


class TestPipelineInitialize:
    """Tests for pipeline initialization."""

    async def test_initialize_calls_scanners(self, pipeline: ContentSafetyPipeline):
        initialized = []

        class TrackingScanner(PassScanner):
            async def initialize(self) -> None:
                initialized.append(self.name)

        pipeline.register_scanner(TrackingScanner(tier=1))
        pipeline.register_scanner(TrackingScanner(tier=2))
        await pipeline.initialize()
        assert len(initialized) == 2

    async def test_original_content_preserved(self, pipeline: ContentSafetyPipeline):
        pipeline.register_scanner(SanitizingScanner())
        result = await pipeline.scan("<script>test</script>")
        assert result.original_content == "<script>test</script>"
        assert result.sanitized_content == "test"
