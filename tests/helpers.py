"""Shared mock scanners for pipeline tests."""

from llm_io_guard import Action, ScanResult
from llm_io_guard.scanner import Scanner


class PassScanner(Scanner):
    """Scanner that always passes."""

    @property
    def name(self) -> str:
        return "pass_scanner"

    @property
    def tier(self) -> int:
        return self._tier

    def __init__(self, tier: int = 2) -> None:
        self._tier = tier

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        return ScanResult(
            scanner_name=self.name,
            action=Action.PASS,
            confidence=1.0,
            description="Content is safe",
        )


class BlockScanner(Scanner):
    """Scanner that always blocks."""

    @property
    def name(self) -> str:
        return "block_scanner"

    @property
    def tier(self) -> int:
        return self._tier

    def __init__(self, tier: int = 2) -> None:
        self._tier = tier

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        return ScanResult(
            scanner_name=self.name,
            action=Action.BLOCK,
            confidence=0.95,
            description="Content is blocked",
        )


class FlagScanner(Scanner):
    """Scanner that always flags."""

    @property
    def name(self) -> str:
        return "flag_scanner"

    @property
    def tier(self) -> int:
        return self._tier

    def __init__(self, tier: int = 2) -> None:
        self._tier = tier

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        return ScanResult(
            scanner_name=self.name,
            action=Action.FLAG,
            confidence=0.8,
            description="Content is flagged",
        )


class ErrorScanner(Scanner):
    """Scanner that raises an exception on scan() for testing error handling."""

    def __init__(self, tier: int = 2, error: Exception | None = None):
        self._tier = tier
        self._error = error or RuntimeError("Test scanner error")

    @property
    def name(self) -> str:
        return "error_scanner"

    @property
    def tier(self) -> int:
        return self._tier

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        raise self._error


class SanitizingScanner(Scanner):
    """Tier 1 scanner that sanitizes content."""

    @property
    def name(self) -> str:
        return "sanitizing_scanner"

    @property
    def tier(self) -> int:
        return 1

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        sanitized = content.replace("<script>", "").replace("</script>", "")
        return ScanResult(
            scanner_name=self.name,
            action=Action.PASS,
            confidence=1.0,
            description="Content sanitized",
            details={"sanitized_content": sanitized},
        )
