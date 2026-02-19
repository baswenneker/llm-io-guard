"""Abstract base class for content scanners.

All scanners in the pipeline extend ``Scanner`` and implement ``ascan()``.
The base class provides sync wrappers (``scan``, ``initialize``) that call
``asyncio.run()`` internally, so callers can use either the sync or async API.
"""

from abc import ABC, abstractmethod

from .models import ScanResult
from .utils.sync import run_sync


class Scanner(ABC):
    """Abstract base class for all content scanners.

    Subclasses must define ``name``, ``tier`` as class attributes and implement
    ``ascan()``.  Optionally override ``supported_directions`` to restrict to
    ``"input"`` or ``"output"`` only, and ``ainitialize()`` for lazy resource
    loading (models, API clients, etc.).

    Sync wrappers ``scan()`` and ``initialize()`` are provided automatically.
    """

    name: str
    """Unique identifier for this scanner."""

    tier: int
    """Execution tier (1=fast deterministic, 2=ML/pattern, 3=LLM judge)."""

    supported_directions: frozenset[str] = frozenset({"input", "output"})
    """Directions this scanner supports. Override to restrict to a single direction."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Enforce that concrete scanners define ``name`` and ``tier``."""
        super().__init_subclass__(**kwargs)
        if getattr(cls, "__abstractmethods__", frozenset()):
            return  # abstract subclass, skip check
        for attr in ("name", "tier"):
            if not hasattr(cls, attr):
                raise TypeError(
                    f"Concrete scanner {cls.__name__} must define class attribute '{attr}'"
                )

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

        Convenience wrapper that calls ``ascan()`` via ``asyncio.run()``.

        Args:
            content: The text content to scan.
            metadata: Optional metadata (source type, sender, etc.)

        Returns:
            ScanResult with action, confidence, and description.
        """
        return run_sync(self.ascan(content, metadata))

    async def ainitialize(self) -> None:  # noqa: B027
        """Optional async initialization hook for loading models, API clients, etc.

        Called once by the filter before the first scan. Subclasses that need
        heavy setup (downloading ML models, creating API connections) should
        override this rather than doing work in ``__init__``.
        """

    def initialize(self) -> None:
        """Sync wrapper for ``ainitialize()``, calls ``asyncio.run()`` internally."""
        run_sync(self.ainitialize())
