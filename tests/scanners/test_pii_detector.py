"""Tests for the PII detector scanner."""

import pytest

pytest.importorskip("presidio_analyzer")

import re
from unittest.mock import MagicMock, patch

from llm_io_guard.models import Action
from llm_io_guard.scanners.pii_detector import (
    BsnRecognizer,
    PiiDetector,
    SecretRecognizer,
)

# ---------------------------------------------------------------------------
# BsnRecognizer tests (no mocking needed -- pure validation logic)
# ---------------------------------------------------------------------------


class TestBsnRecognizer:
    def setup_method(self):
        self.recognizer = BsnRecognizer()

    def test_valid_bsn(self):
        assert self.recognizer.validate_result("111222333") is True

    def test_invalid_bsn(self):
        assert self.recognizer.validate_result("123456789") is False

    def test_bsn_with_dots(self):
        assert self.recognizer.validate_result("111.22.2333") is True

    def test_bsn_too_short(self):
        assert self.recognizer.validate_result("12345678") is False

    def test_bsn_too_long(self):
        assert self.recognizer.validate_result("1234567890") is False

    def test_bsn_zero_result(self):
        assert self.recognizer.validate_result("000000000") is False


# ---------------------------------------------------------------------------
# SecretRecognizer tests (regex patterns tested directly)
# ---------------------------------------------------------------------------


class TestSecretRecognizer:
    def setup_method(self):
        self.recognizer = SecretRecognizer()
        self._patterns = {p.name: p.regex for p in self.recognizer.patterns}

    def test_openai_key_pattern(self):
        pattern = self._patterns["openai_key"]
        assert re.search(pattern, "sk-abc123def456ghi789jkl012mno345p")

    def test_anthropic_key_pattern(self):
        pattern = self._patterns["anthropic_key"]
        assert re.search(pattern, "sk-ant-abc123-def456ghi789jkl012mno")

    def test_github_pat_pattern(self):
        pattern = self._patterns["github_pat"]
        assert re.search(pattern, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")

    def test_aws_key_pattern(self):
        pattern = self._patterns["aws_key"]
        assert re.search(pattern, "AKIAIOSFODNN7EXAMPLE")

    def test_pem_key_pattern(self):
        pattern = self._patterns["pem_key"]
        assert re.search(pattern, "-----BEGIN RSA PRIVATE KEY-----")
        assert re.search(pattern, "-----BEGIN PRIVATE KEY-----")


# ---------------------------------------------------------------------------
# PiiDetector tests (mock Presidio to avoid spaCy model downloads)
# ---------------------------------------------------------------------------


def _make_analyzer_result(entity_type: str, start: int, end: int, score: float):
    """Create a mock Presidio RecognizerResult."""
    mock = MagicMock()
    mock.entity_type = entity_type
    mock.start = start
    mock.end = end
    mock.score = score
    return mock


class TestPiiDetector:
    def setup_method(self):
        self.detector = PiiDetector(threshold_block=0.9, threshold_flag=0.7)

    async def test_not_initialized_raises(self):
        with pytest.raises(RuntimeError, match="not initialized"):
            await self.detector.scan("hello")

    @patch("llm_io_guard.scanners.pii_detector.AnonymizerEngine")
    @patch("llm_io_guard.scanners.pii_detector.AnalyzerEngine")
    @patch("llm_io_guard.scanners.pii_detector.RecognizerRegistry")
    @patch("llm_io_guard.scanners.pii_detector.SpacyNlpEngine")
    async def test_no_pii_passes(self, mock_spacy, mock_registry, mock_analyzer_cls, mock_anon_cls):
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = []
        mock_analyzer_cls.return_value = mock_analyzer
        mock_anon_cls.return_value = MagicMock()

        await self.detector.initialize()
        result = await self.detector.scan("Hello world, no PII here.")

        assert result.action == Action.PASS
        assert result.confidence == 0.0

    @patch("llm_io_guard.scanners.pii_detector.AnonymizerEngine")
    @patch("llm_io_guard.scanners.pii_detector.AnalyzerEngine")
    @patch("llm_io_guard.scanners.pii_detector.RecognizerRegistry")
    @patch("llm_io_guard.scanners.pii_detector.SpacyNlpEngine")
    async def test_secret_detected_blocks(
        self, mock_spacy, mock_registry, mock_analyzer_cls, mock_anon_cls
    ):
        secret_result = _make_analyzer_result("SECRET_API_KEY", 0, 30, 0.95)

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = [secret_result]
        mock_analyzer_cls.return_value = mock_analyzer
        mock_anon_cls.return_value = MagicMock()

        await self.detector.initialize()
        result = await self.detector.scan("sk-abc123def456ghi789jkl012mno345p")

        assert result.action == Action.BLOCK
        assert result.confidence == 0.95
        assert "SECRET_API_KEY" in result.details["secret_types"]

    @patch("llm_io_guard.scanners.pii_detector.AnonymizerEngine")
    @patch("llm_io_guard.scanners.pii_detector.AnalyzerEngine")
    @patch("llm_io_guard.scanners.pii_detector.RecognizerRegistry")
    @patch("llm_io_guard.scanners.pii_detector.SpacyNlpEngine")
    async def test_pii_input_flags(
        self, mock_spacy, mock_registry, mock_analyzer_cls, mock_anon_cls
    ):
        pii_result = _make_analyzer_result("PERSON", 0, 10, 0.85)

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = [pii_result]
        mock_analyzer_cls.return_value = mock_analyzer
        mock_anon_cls.return_value = MagicMock()

        await self.detector.initialize()
        result = await self.detector.scan("Jan de Vries is here", metadata={"direction": "input"})

        assert result.action == Action.FLAG
        assert result.details["redacted"] is False

    @patch("llm_io_guard.scanners.pii_detector.AnonymizerEngine")
    @patch("llm_io_guard.scanners.pii_detector.AnalyzerEngine")
    @patch("llm_io_guard.scanners.pii_detector.RecognizerRegistry")
    @patch("llm_io_guard.scanners.pii_detector.SpacyNlpEngine")
    async def test_pii_output_redacts(
        self, mock_spacy, mock_registry, mock_analyzer_cls, mock_anon_cls
    ):
        pii_result = _make_analyzer_result("PERSON", 0, 10, 0.85)

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = [pii_result]
        mock_analyzer_cls.return_value = mock_analyzer

        mock_anonymizer = MagicMock()
        mock_anon_result = MagicMock()
        mock_anon_result.text = "<PERSON> is here"
        mock_anonymizer.anonymize.return_value = mock_anon_result
        mock_anon_cls.return_value = mock_anonymizer

        await self.detector.initialize()
        result = await self.detector.scan("Jan de Vries is here", metadata={"direction": "output"})

        assert result.action == Action.FLAG
        assert result.details["redacted"] is True
        assert result.details["sanitized_content"] == "<PERSON> is here"

    @patch("llm_io_guard.scanners.pii_detector.AnonymizerEngine")
    @patch("llm_io_guard.scanners.pii_detector.AnalyzerEngine")
    @patch("llm_io_guard.scanners.pii_detector.RecognizerRegistry")
    @patch("llm_io_guard.scanners.pii_detector.SpacyNlpEngine")
    async def test_low_confidence_passes(
        self, mock_spacy, mock_registry, mock_analyzer_cls, mock_anon_cls
    ):
        pii_result = _make_analyzer_result("PERSON", 0, 10, 0.3)

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = [pii_result]
        mock_analyzer_cls.return_value = mock_analyzer
        mock_anon_cls.return_value = MagicMock()

        await self.detector.initialize()
        result = await self.detector.scan("Maybe a name here")

        assert result.action == Action.PASS
        assert result.confidence == 0.3
        assert "below threshold" in result.description

    @patch("llm_io_guard.scanners.pii_detector.AnonymizerEngine")
    @patch("llm_io_guard.scanners.pii_detector.AnalyzerEngine")
    @patch("llm_io_guard.scanners.pii_detector.RecognizerRegistry")
    @patch("llm_io_guard.scanners.pii_detector.SpacyNlpEngine")
    async def test_analysis_error_returns_flag(
        self, mock_spacy, mock_registry, mock_analyzer_cls, mock_anon_cls
    ):
        """analyzer.analyze() raising an exception returns FLAG."""
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.side_effect = RuntimeError("spaCy model error")
        mock_analyzer_cls.return_value = mock_analyzer
        mock_anon_cls.return_value = MagicMock()

        await self.detector.initialize()
        result = await self.detector.scan("some content")

        assert result.action == Action.FLAG
        assert "PII detection error" in result.description


class TestImportGuard:
    def test_raises_without_pii_deps(self):
        """PiiDetector() raises ImportError when presidio is missing."""
        with (
            patch("llm_io_guard.scanners.pii_detector._HAS_PII_DEPS", False),
            pytest.raises(ImportError, match="pip install llm-io-guard\\[pii\\]"),
        ):
            PiiDetector()
