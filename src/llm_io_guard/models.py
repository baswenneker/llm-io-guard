"""Core data classes for the LLM IO Guard pipeline."""

from dataclasses import dataclass, field
from enum import Enum


class Action(Enum):
    """Action to take based on scan results."""

    PASS = "pass"  # noqa: S105  # nosec B105
    FLAG = "flag"
    BLOCK = "block"


@dataclass(frozen=True)
class ScanResult:
    """Result from a single scanner."""

    scanner_name: str
    action: Action
    confidence: float
    description: str
    details: dict[str, object] = field(default_factory=dict)


@dataclass
class FilterResult:
    """Aggregated result from the full pipeline.

    Note: Unlike ``ScanResult``, this dataclass is intentionally mutable so the
    pipeline can accumulate scan results and update the action as tiers execute.
    """

    action: Action
    scan_results: list[ScanResult] = field(default_factory=list)
    sanitized_content: str | None = None
    original_content: str = ""
    processing_time_ms: float = 0.0

    @property
    def text(self) -> str:
        """Return sanitized content if available, otherwise original."""
        return (
            self.sanitized_content if self.sanitized_content is not None else self.original_content
        )

    @property
    def is_safe(self) -> bool:
        """Whether the content passed all scanners without a BLOCK action."""
        return self.action == Action.PASS

    @property
    def blocked_by(self) -> list[ScanResult]:
        """Scan results that produced a BLOCK action."""
        return [r for r in self.scan_results if r.action == Action.BLOCK]

    @property
    def flagged_by(self) -> list[ScanResult]:
        """Scan results that produced a FLAG action."""
        return [r for r in self.scan_results if r.action == Action.FLAG]
