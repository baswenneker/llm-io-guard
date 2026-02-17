"""Abstract base class for content scanners."""

from abc import ABC, abstractmethod

from .models import ScanResult


class Scanner(ABC):
    """Abstract base class for all content scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this scanner."""
        ...

    @property
    @abstractmethod
    def tier(self) -> int:
        """Execution tier (1=fast, 2=medium, 3=slow)."""
        ...

    @abstractmethod
    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        """Scan content and return a result.

        Args:
            content: The text content to scan.
            metadata: Optional metadata (source type, sender, etc.)

        Returns:
            ScanResult with action, confidence, and description.
        """
        ...

    @property
    def supported_directions(self) -> frozenset[str]:
        """Directions this scanner supports. Default: both."""
        return frozenset({"input", "output"})

    async def initialize(self) -> None:  # noqa: B027
        """Optional async initialization (model loading, etc.)."""
