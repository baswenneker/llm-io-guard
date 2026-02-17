"""Tests for the Scanner ABC."""

import pytest

from llm_io_guard.models import Action, ScanResult
from llm_io_guard.scanner import Scanner


class TestScannerABC:
    """Tests for Scanner abstract base class."""

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            Scanner()  # type: ignore[abstract]

    def test_must_implement_name(self):
        class NoName(Scanner):
            @property
            def tier(self) -> int:
                return 1

            async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
                return ScanResult(
                    scanner_name="no_name",
                    action=Action.PASS,
                    confidence=1.0,
                    description="ok",
                )

        with pytest.raises(TypeError):
            NoName()  # type: ignore[abstract]

    def test_must_implement_tier(self):
        class NoTier(Scanner):
            @property
            def name(self) -> str:
                return "no_tier"

            async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
                return ScanResult(
                    scanner_name=self.name,
                    action=Action.PASS,
                    confidence=1.0,
                    description="ok",
                )

        with pytest.raises(TypeError):
            NoTier()  # type: ignore[abstract]

    def test_must_implement_scan(self):
        class NoScan(Scanner):
            @property
            def name(self) -> str:
                return "no_scan"

            @property
            def tier(self) -> int:
                return 1

        with pytest.raises(TypeError):
            NoScan()  # type: ignore[abstract]

    def test_concrete_subclass(self):
        class ConcreteScanner(Scanner):
            @property
            def name(self) -> str:
                return "concrete"

            @property
            def tier(self) -> int:
                return 2

            async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
                return ScanResult(
                    scanner_name=self.name,
                    action=Action.PASS,
                    confidence=1.0,
                    description="ok",
                )

        scanner = ConcreteScanner()
        assert scanner.name == "concrete"
        assert scanner.tier == 2

    async def test_concrete_scan(self):
        class ConcreteScanner(Scanner):
            @property
            def name(self) -> str:
                return "concrete"

            @property
            def tier(self) -> int:
                return 1

            async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
                return ScanResult(
                    scanner_name=self.name,
                    action=Action.PASS,
                    confidence=1.0,
                    description="ok",
                )

        scanner = ConcreteScanner()
        result = await scanner.scan("test content")
        assert result.action == Action.PASS
        assert result.scanner_name == "concrete"

    async def test_initialize_noop(self):
        class ConcreteScanner(Scanner):
            @property
            def name(self) -> str:
                return "concrete"

            @property
            def tier(self) -> int:
                return 1

            async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
                return ScanResult(
                    scanner_name=self.name,
                    action=Action.PASS,
                    confidence=1.0,
                    description="ok",
                )

        scanner = ConcreteScanner()
        # Should not raise
        await scanner.initialize()
