"""Tests for the Scanner ABC."""

import pytest

from llm_io_guard.models import Action, ScanResult
from llm_io_guard.scanner import Scanner


class TestScannerABC:
    """Tests for Scanner abstract base class."""

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            Scanner()  # type: ignore[abstract]

    def test_must_define_name(self):
        with pytest.raises(TypeError, match="must define class attribute 'name'"):

            class NoName(Scanner):
                tier = 1

                async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
                    return ScanResult(
                        scanner_name="no_name",
                        action=Action.PASS,
                        confidence=1.0,
                        description="ok",
                    )

    def test_must_define_tier(self):
        with pytest.raises(TypeError, match="must define class attribute 'tier'"):

            class NoTier(Scanner):
                name = "no_tier"

                async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
                    return ScanResult(
                        scanner_name="no_tier",
                        action=Action.PASS,
                        confidence=1.0,
                        description="ok",
                    )

    def test_must_implement_ascan(self):
        with pytest.raises(TypeError):

            class NoScan(Scanner):
                name = "no_scan"
                tier = 1

            NoScan()  # type: ignore[abstract]

    def test_concrete_subclass(self):
        class ConcreteScanner(Scanner):
            name = "concrete"
            tier = 2

            async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
                return ScanResult(
                    scanner_name=self.name,
                    action=Action.PASS,
                    confidence=1.0,
                    description="ok",
                )

        scanner = ConcreteScanner()
        assert scanner.name == "concrete"
        assert scanner.tier == 2

    async def test_concrete_ascan(self):
        class ConcreteScanner(Scanner):
            name = "concrete"
            tier = 1

            async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
                return ScanResult(
                    scanner_name=self.name,
                    action=Action.PASS,
                    confidence=1.0,
                    description="ok",
                )

        scanner = ConcreteScanner()
        result = await scanner.ascan("test content")
        assert result.action == Action.PASS
        assert result.scanner_name == "concrete"

    async def test_ainitialize_noop(self):
        class ConcreteScanner(Scanner):
            name = "concrete"
            tier = 1

            async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
                return ScanResult(
                    scanner_name=self.name,
                    action=Action.PASS,
                    confidence=1.0,
                    description="ok",
                )

        scanner = ConcreteScanner()
        # Should not raise
        await scanner.ainitialize()

    def test_supported_directions_default(self):
        """Default supported_directions includes both input and output."""

        class ConcreteScanner(Scanner):
            name = "concrete"
            tier = 1

            async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
                return ScanResult(
                    scanner_name=self.name,
                    action=Action.PASS,
                    confidence=1.0,
                    description="ok",
                )

        scanner = ConcreteScanner()
        assert scanner.supported_directions == frozenset({"input", "output"})
