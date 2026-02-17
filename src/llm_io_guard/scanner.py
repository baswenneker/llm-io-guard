"""Abstract base class for content scanners."""

from abc import ABC, abstractmethod

from .models import ScanResult
from .utils.sync import run_sync


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
    async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
        """Scan content and return a result (async).

        Args:
            content: The text content to scan.
            metadata: Optional metadata (source type, sender, etc.)

        Returns:
            ScanResult with action, confidence, and description.
        """
        ...

    def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        """Scan content and return a result (sync).

        Args:
            content: The text content to scan.
            metadata: Optional metadata (source type, sender, etc.)

        Returns:
            ScanResult with action, confidence, and description.
        """
        return run_sync(self.ascan(content, metadata))

    @property
    def supported_directions(self) -> frozenset[str]:
        """Directions this scanner supports. Default: both."""
        return frozenset({"input", "output"})

    async def ainitialize(self) -> None:  # noqa: B027
        """Optional async initialization (model loading, etc.)."""

    def initialize(self) -> None:
        """Optional sync initialization (model loading, etc.)."""
        run_sync(self.ainitialize())
