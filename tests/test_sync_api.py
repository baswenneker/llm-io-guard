"""Tests for the synchronous API wrappers.

These tests are NOT async — they verify that the sync wrappers
(filter, scan, initialize) work without asyncio.run() boilerplate.
"""

from llm_io_guard import Action, FilterResult, InputFilter, OutputFilter
from llm_io_guard.models import ScanResult
from llm_io_guard.scanner import Scanner


class _PassScanner(Scanner):
    """Minimal scanner for sync tests."""

    name = "sync_pass"
    tier = 2

    async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
        return ScanResult(
            scanner_name=self.name,
            action=Action.PASS,
            confidence=1.0,
            description="Content is safe",
        )


class _BlockScanner(Scanner):
    """Minimal blocking scanner for sync tests."""

    name = "sync_block"
    tier = 2

    async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
        return ScanResult(
            scanner_name=self.name,
            action=Action.BLOCK,
            confidence=0.99,
            description="Content is blocked",
        )


class TestSyncFilter:
    """Tests for synchronous filter() method."""

    def test_sync_filter_pass(self):
        """Sync filter() returns FilterResult for safe content."""
        f = InputFilter()
        f.add(_PassScanner())
        result = f.filter("safe content")
        assert isinstance(result, FilterResult)
        assert result.is_safe

    def test_sync_filter_block(self):
        """Sync filter() returns FilterResult for blocked content."""
        f = InputFilter()
        f.add(_BlockScanner())
        result = f.filter("bad content")
        assert isinstance(result, FilterResult)
        assert result.action == Action.BLOCK

    def test_sync_output_filter(self):
        """Sync filter() works on OutputFilter."""
        f = OutputFilter()
        f.add(_PassScanner())
        result = f.filter("output content")
        assert isinstance(result, FilterResult)
        assert result.is_safe


class TestSyncInitialize:
    """Tests for synchronous initialize() method."""

    def test_sync_initialize(self):
        """Sync initialize() sets _initialized flag."""
        f = InputFilter()
        f.add(_PassScanner())
        assert f._initialized is False
        f.initialize()
        assert f._initialized is True


class TestSyncScan:
    """Tests for synchronous scan() method on Scanner."""

    def test_sync_scan(self):
        """Sync scan() returns ScanResult."""
        scanner = _PassScanner()
        result = scanner.scan("test content")
        assert isinstance(result, ScanResult)
        assert result.action == Action.PASS
        assert result.scanner_name == "sync_pass"

    def test_sync_scan_block(self):
        """Sync scan() works for blocking scanners."""
        scanner = _BlockScanner()
        result = scanner.scan("bad content")
        assert isinstance(result, ScanResult)
        assert result.action == Action.BLOCK
