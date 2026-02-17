"""Tests for core data models."""

import pytest

from llm_io_guard.models import Action, FilterResult, ScanResult


class TestAction:
    """Tests for the Action enum."""

    def test_action_values(self):
        assert Action.PASS.value == "pass"
        assert Action.FLAG.value == "flag"
        assert Action.BLOCK.value == "block"

    def test_action_members(self):
        assert set(Action) == {Action.PASS, Action.FLAG, Action.BLOCK}


class TestScanResult:
    """Tests for the ScanResult dataclass."""

    def test_creation(self):
        result = ScanResult(
            scanner_name="test",
            action=Action.PASS,
            confidence=0.95,
            description="All clear",
        )
        assert result.scanner_name == "test"
        assert result.action == Action.PASS
        assert result.confidence == 0.95
        assert result.description == "All clear"
        assert result.details == {}

    def test_with_details(self):
        result = ScanResult(
            scanner_name="test",
            action=Action.FLAG,
            confidence=0.8,
            description="Suspicious",
            details={"pattern": "injection"},
        )
        assert result.details == {"pattern": "injection"}

    def test_immutability(self):
        result = ScanResult(
            scanner_name="test",
            action=Action.PASS,
            confidence=1.0,
            description="Safe",
        )
        with pytest.raises(AttributeError):
            result.action = Action.BLOCK  # type: ignore[misc]

    def test_default_details(self):
        r1 = ScanResult(scanner_name="a", action=Action.PASS, confidence=1.0, description="ok")
        r2 = ScanResult(scanner_name="b", action=Action.PASS, confidence=1.0, description="ok")
        assert r1.details is not r2.details


class TestFilterResult:
    """Tests for the FilterResult dataclass."""

    def test_defaults(self):
        result = FilterResult(action=Action.PASS)
        assert result.action == Action.PASS
        assert result.scan_results == []
        assert result.sanitized_content is None
        assert result.original_content == ""
        assert result.processing_time_ms == 0.0

    def test_is_safe_when_pass(self):
        result = FilterResult(action=Action.PASS)
        assert result.is_safe is True

    def test_is_safe_when_block(self):
        result = FilterResult(action=Action.BLOCK)
        assert result.is_safe is False

    def test_is_safe_when_flag(self):
        result = FilterResult(action=Action.FLAG)
        assert result.is_safe is False

    def test_blocked_by(self):
        block_result = ScanResult(
            scanner_name="blocker",
            action=Action.BLOCK,
            confidence=0.95,
            description="Blocked",
        )
        pass_result = ScanResult(
            scanner_name="passer",
            action=Action.PASS,
            confidence=1.0,
            description="Safe",
        )
        result = FilterResult(
            action=Action.BLOCK,
            scan_results=[block_result, pass_result],
        )
        assert result.blocked_by == [block_result]

    def test_flagged_by(self):
        flag_result = ScanResult(
            scanner_name="flagger",
            action=Action.FLAG,
            confidence=0.8,
            description="Flagged",
        )
        pass_result = ScanResult(
            scanner_name="passer",
            action=Action.PASS,
            confidence=1.0,
            description="Safe",
        )
        result = FilterResult(
            action=Action.FLAG,
            scan_results=[flag_result, pass_result],
        )
        assert result.flagged_by == [flag_result]

    def test_no_blocked_or_flagged(self):
        result = FilterResult(action=Action.PASS, scan_results=[])
        assert result.blocked_by == []
        assert result.flagged_by == []
