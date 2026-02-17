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
    details: dict = field(default_factory=dict)


@dataclass
class FilterResult:
    """Aggregated result from the full pipeline."""

    action: Action
    scan_results: list[ScanResult] = field(default_factory=list)
    sanitized_content: str | None = None
    original_content: str = ""
    processing_time_ms: float = 0.0

    @property
    def is_safe(self) -> bool:
        return self.action == Action.PASS

    @property
    def blocked_by(self) -> list[ScanResult]:
        return [r for r in self.scan_results if r.action == Action.BLOCK]

    @property
    def flagged_by(self) -> list[ScanResult]:
        return [r for r in self.scan_results if r.action == Action.FLAG]
