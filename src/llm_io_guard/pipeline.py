"""Content safety pipeline orchestrator."""

import asyncio
import time

import structlog

from .config import PipelineConfig
from .models import Action, FilterResult, ScanResult
from .scanner import Scanner

logger = structlog.get_logger()

PIPELINE_TIERS: tuple[int, ...] = (1, 2, 3)


class ContentSafetyPipeline:
    """Tiered content safety pipeline with fail-fast behavior."""

    def __init__(self, config: PipelineConfig) -> None:
        self.config = config
        self._scanners: dict[int, list[Scanner]] = {tier: [] for tier in PIPELINE_TIERS}

    def register_scanner(self, scanner: Scanner) -> None:
        """Register a scanner in the appropriate tier."""
        if scanner.tier not in self._scanners:
            raise ValueError(f"Invalid tier: {scanner.tier}. Must be one of {PIPELINE_TIERS}.")
        self._scanners[scanner.tier].append(scanner)
        logger.info("scanner_registered", scanner=scanner.name, tier=scanner.tier)

    async def initialize(self) -> None:
        """Initialize all registered scanners."""
        for tier_scanners in self._scanners.values():
            await asyncio.gather(*(s.initialize() for s in tier_scanners))

    async def scan(
        self,
        content: str,
        metadata: dict | None = None,
        direction: str = "input",
    ) -> FilterResult:
        """Run content through the tiered pipeline.

        Args:
            content: The text content to scan.
            metadata: Optional metadata (source, sender, content_type, etc.)
            direction: "input" or "output"

        Returns:
            FilterResult with aggregated action and all scan results.
        """
        start_time = time.perf_counter()

        if len(content) > self.config.max_content_length:
            return FilterResult(
                action=Action.BLOCK,
                original_content=content,
                processing_time_ms=0.0,
                scan_results=[],
            )

        result = FilterResult(action=Action.PASS, original_content=content)
        scan_metadata = {**(metadata or {}), "direction": direction}

        current_content = content

        for tier in PIPELINE_TIERS:
            tier_scanners = [
                s for s in self._scanners[tier] if self.config.is_scanner_enabled(s.name)
            ]

            if not tier_scanners:
                continue

            # Tier 1: sequential (sanitizers modify content)
            if tier == 1:
                for scanner in tier_scanners:
                    try:
                        scan_result = await scanner.scan(current_content, scan_metadata)
                    except Exception as e:
                        logger.error("scanner_error", scanner=scanner.name, tier=tier, error=str(e))
                        scan_result = ScanResult(
                            scanner_name=scanner.name,
                            action=Action.FLAG,
                            confidence=0.0,
                            description=f"Scanner error: {e}",
                            details={"error": str(e)},
                        )
                    result.scan_results.append(scan_result)
                    if scan_result.action == Action.BLOCK:
                        result.action = Action.BLOCK
                        result.processing_time_ms = (time.perf_counter() - start_time) * 1000
                        return result
                    if scan_result.action == Action.FLAG:
                        result.action = Action.FLAG
                    # Tier 1 scanners may sanitize content
                    if "sanitized_content" in scan_result.details:
                        current_content = str(scan_result.details["sanitized_content"])

                result.sanitized_content = current_content

            # Tier 2: parallel execution
            elif tier == 2:
                tier_results_raw = await asyncio.gather(
                    *(s.scan(current_content, scan_metadata) for s in tier_scanners),
                    return_exceptions=True,
                )
                tier_results = []
                for i, raw_result in enumerate(tier_results_raw):
                    if isinstance(raw_result, BaseException):
                        logger.error(
                            "scanner_error",
                            scanner=tier_scanners[i].name,
                            tier=tier,
                            error=str(raw_result),
                        )
                        tier_results.append(
                            ScanResult(
                                scanner_name=tier_scanners[i].name,
                                action=Action.FLAG,
                                confidence=0.0,
                                description=f"Scanner error: {raw_result}",
                                details={"error": str(raw_result)},
                            )
                        )
                    else:
                        tier_results.append(raw_result)
                for scan_result in tier_results:
                    result.scan_results.append(scan_result)

                # Check for blocks after all Tier 2 scanners complete
                if any(r.action == Action.BLOCK for r in tier_results):
                    result.action = Action.BLOCK
                    result.processing_time_ms = (time.perf_counter() - start_time) * 1000
                    return result

                # Propagate flags
                if any(r.action == Action.FLAG for r in tier_results):
                    result.action = Action.FLAG

            # Tier 3: conditional, sequential
            elif tier == 3:
                if not self._should_run_tier3(result, scan_metadata):
                    continue

                for scanner in tier_scanners:
                    try:
                        scan_result = await scanner.scan(current_content, scan_metadata)
                    except Exception as e:
                        logger.error("scanner_error", scanner=scanner.name, tier=tier, error=str(e))
                        scan_result = ScanResult(
                            scanner_name=scanner.name,
                            action=Action.FLAG,
                            confidence=0.0,
                            description=f"Scanner error: {e}",
                            details={"error": str(e)},
                        )
                    result.scan_results.append(scan_result)
                    if scan_result.action == Action.BLOCK:
                        result.action = Action.BLOCK
                        break

        result.processing_time_ms = (time.perf_counter() - start_time) * 1000
        logger.info(
            "pipeline_complete",
            action=result.action.value,
            duration_ms=round(result.processing_time_ms, 2),
            scanners_run=len(result.scan_results),
        )
        return result

    def _should_run_tier3(self, result: FilterResult, metadata: dict) -> bool:
        """Determine if Tier 3 (LLM judge) should run."""
        if result.action == Action.FLAG:
            return True
        source_risk = metadata.get("source_risk", "low")
        return source_risk in ("high", "unknown")
