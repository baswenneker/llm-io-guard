"""Input and output content safety filters."""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Literal, Self

import structlog

from .exceptions import ContentBlocked
from .models import Action, FilterResult, ScanResult
from .scanner import Scanner  # noqa: TC001 - used at runtime in dict construction
from .utils.sync import run_sync

logger = structlog.get_logger()

PIPELINE_TIERS: tuple[int, ...] = (1, 2, 3)

OnBlockMode = Literal["result", "raise", "none"]


class BaseFilter(ABC):
    """Base class for input/output content filters."""

    def __init__(
        self,
        *,
        on_block: OnBlockMode = "result",
        max_content_length: int = 100_000,
    ) -> None:
        """Initialize the filter with on_block behavior and content length limit.

        Args:
            on_block: Behavior when content is blocked.
                ``"result"`` — always return a ``FilterResult`` (default).
                ``"raise"``  — return ``str`` on pass, raise ``ContentBlocked`` on block.
                ``"none"``   — return ``str`` on pass, ``None`` on block.
            max_content_length: Maximum allowed content length in characters.
                Content exceeding this limit is immediately blocked.
        """
        if on_block not in ("result", "raise", "none"):
            raise ValueError(f"on_block must be 'result', 'raise', or 'none', got '{on_block}'")
        self._on_block = on_block
        self._scanners: dict[int, list[Scanner]] = {tier: [] for tier in PIPELINE_TIERS}
        self._max_content_length = max_content_length
        self._initialized = False

    def add(self, scanner: Scanner) -> Self:
        """Add a scanner to this filter.

        Validates that the scanner supports this filter's direction and
        groups it by tier. Returns self for chaining.
        """
        if self._direction() not in scanner.supported_directions:
            raise ValueError(
                f"Scanner '{scanner.name}' does not support direction '{self._direction()}'. "
                f"Supported: {scanner.supported_directions}"
            )
        if scanner.tier not in self._scanners:
            raise ValueError(f"Invalid tier: {scanner.tier}. Must be one of {PIPELINE_TIERS}.")
        self._scanners[scanner.tier].append(scanner)
        logger.info("scanner_added", scanner=scanner.name, tier=scanner.tier)
        return self

    async def ainitialize(self) -> None:
        """Initialize all registered scanners (async)."""
        for tier_scanners in self._scanners.values():
            await asyncio.gather(*(s.ainitialize() for s in tier_scanners))
        self._initialized = True

    def initialize(self) -> None:
        """Initialize all registered scanners (sync)."""
        run_sync(self.ainitialize())

    async def afilter(
        self, content: str, metadata: dict | None = None
    ) -> FilterResult | str | None:
        """Run content through the filter pipeline (async).

        Returns based on on_block mode:
          - "result": always returns FilterResult
          - "raise": returns str on pass, raises ContentBlocked on block
          - "none": returns str on pass, None on block
        """
        if not self._initialized:
            await self.ainitialize()

        result = await self._run_pipeline(content, metadata)

        if self._on_block == "result":
            return result
        elif self._on_block == "raise":
            if result.action == Action.BLOCK:
                raise ContentBlocked(result)
            return result.text
        else:  # "none"
            if result.action == Action.BLOCK:
                return None
            return result.text

    def filter(self, content: str, metadata: dict | None = None) -> FilterResult | str | None:
        """Run content through the filter pipeline (sync).

        Returns based on on_block mode:
          - "result": always returns FilterResult
          - "raise": returns str on pass, raises ContentBlocked on block
          - "none": returns str on pass, None on block
        """
        return run_sync(self.afilter(content, metadata))

    async def _run_pipeline(self, content: str, metadata: dict | None = None) -> FilterResult:
        """Execute the tiered scanning pipeline."""
        start_time = time.perf_counter()

        if len(content) > self._max_content_length:
            return FilterResult(
                action=Action.BLOCK,
                original_content=content,
                processing_time_ms=0.0,
                scan_results=[],
            )

        result = FilterResult(action=Action.PASS, original_content=content)
        scan_metadata = {**(metadata or {}), "direction": self._direction()}

        current_content = content

        for tier in PIPELINE_TIERS:
            tier_scanners = self._scanners[tier]

            if not tier_scanners:
                continue

            # Tier 1: sequential (sanitizers modify content)
            if tier == 1:
                for scanner in tier_scanners:
                    try:
                        scan_result = await scanner.ascan(current_content, scan_metadata)
                    except Exception as e:
                        logger.error("scanner_error", scanner=scanner.name, tier=tier, error=str(e))
                        scan_result = ScanResult(
                            scanner_name=scanner.name,
                            action=Action.BLOCK,
                            confidence=0.0,
                            description=f"Scanner error (fail-closed): {e}",
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
                    *(s.ascan(current_content, scan_metadata) for s in tier_scanners),
                    return_exceptions=True,
                )
                tier_results = []
                for i, raw_result in enumerate(tier_results_raw):
                    if isinstance(raw_result, BaseException):
                        if not isinstance(raw_result, Exception):
                            raise raw_result  # propagate CancelledError, KeyboardInterrupt
                        logger.error(
                            "scanner_error",
                            scanner=tier_scanners[i].name,
                            tier=tier,
                            error=str(raw_result),
                        )
                        tier_results.append(
                            ScanResult(
                                scanner_name=tier_scanners[i].name,
                                action=Action.BLOCK,
                                confidence=0.0,
                                description=f"Scanner error (fail-closed): {raw_result}",
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
                        scan_result = await scanner.ascan(current_content, scan_metadata)
                    except Exception as e:
                        logger.error("scanner_error", scanner=scanner.name, tier=tier, error=str(e))
                        scan_result = ScanResult(
                            scanner_name=scanner.name,
                            action=Action.BLOCK,
                            confidence=0.0,
                            description=f"Scanner error (fail-closed): {e}",
                            details={"error": str(e)},
                        )
                    result.scan_results.append(scan_result)
                    if scan_result.action == Action.BLOCK:
                        result.action = Action.BLOCK
                        break

        result.processing_time_ms = (time.perf_counter() - start_time) * 1000
        logger.info(
            "filter_complete",
            action=result.action.value,
            duration_ms=round(result.processing_time_ms, 2),
            scanners_run=len(result.scan_results),
        )
        return result

    @abstractmethod
    def _direction(self) -> str:
        """Return the direction this filter operates on."""
        ...

    @abstractmethod
    def _should_run_tier3(self, result: FilterResult, metadata: dict) -> bool:
        """Determine if Tier 3 scanners should run."""
        ...


class InputFilter(BaseFilter):
    """Filter for untrusted input content (emails, web pages, etc.)."""

    def _direction(self) -> str:
        """Return 'input' direction."""
        return "input"

    def _should_run_tier3(self, result: FilterResult, metadata: dict) -> bool:
        """Run tier 3 if content was flagged or source risk is high/unknown."""
        if result.action == Action.FLAG:
            return True
        source_risk = metadata.get("source_risk", "low")
        return source_risk in ("high", "unknown")


class OutputFilter(BaseFilter):
    """Filter for LLM output content."""

    def _direction(self) -> str:
        """Return 'output' direction."""
        return "output"

    def _should_run_tier3(self, result: FilterResult, metadata: dict) -> bool:
        """Always run tier 3 on output if scanners are registered."""
        return True
