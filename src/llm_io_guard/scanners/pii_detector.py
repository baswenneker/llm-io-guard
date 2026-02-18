"""Tier 2 PII and secret detection scanner using Microsoft Presidio.

Runs Presidio analysis in both Dutch (``nl``) and English (``en``) to support
bilingual content common in Dutch business environments. Results from both
languages are merged and deduplicated. Secrets (API keys, tokens) trigger BLOCK;
PII (names, emails, BSN) triggers FLAG with optional anonymization on output.
"""

import asyncio

import structlog

from ..models import Action, ScanResult
from ..scanner import Scanner

try:
    from presidio_analyzer import (
        AnalyzerEngine,
        Pattern,
        PatternRecognizer,
        RecognizerRegistry,
        RecognizerResult,
    )
    from presidio_analyzer.nlp_engine import SpacyNlpEngine
    from presidio_anonymizer import AnonymizerEngine

    _HAS_PII_DEPS = True
except ImportError:
    _HAS_PII_DEPS = False

logger = structlog.get_logger()

# Entity types that represent leaked secrets rather than personal data.
# These always trigger BLOCK because secrets in LLM output are a critical risk.
SECRET_ENTITY_TYPES = {
    "SECRET_API_KEY",
    "SECRET_TOKEN",
    "SECRET_PRIVATE_KEY",
}


if _HAS_PII_DEPS:

    class BsnRecognizer(PatternRecognizer):
        """Dutch BSN (burgerservicenummer) recognizer with 11-proef validation.

        The BSN is a 9-digit Dutch citizen service number. The 11-proef (mod-11
        check) validates the checksum: multiply each digit by its position weight
        (9 down to 1, with the last digit subtracted), and verify the total is
        divisible by 11 (and non-zero).
        """

        def __init__(self) -> None:
            """Initialize with BSN digit patterns."""
            patterns = [
                Pattern(
                    name="bsn_pattern",
                    regex=r"\b(\d{9})\b",
                    score=0.3,
                ),
                Pattern(
                    name="bsn_with_dots",
                    regex=r"\b(\d{3}\.\d{2}\.\d{4})\b",
                    score=0.5,
                ),
            ]
            super().__init__(
                supported_entity="NL_BSN",
                supported_language="nl",
                patterns=patterns,
                context=["bsn", "burgerservicenummer", "sofinummer", "sofi"],
            )

        def validate_result(self, pattern_text: str) -> bool:
            """Validate BSN using the 11-proef (mod-11) checksum.

            Weights: positions 0-7 use (9-i), position 8 uses -1.
            The total must be divisible by 11 and non-zero.
            """
            digits = pattern_text.replace(".", "")
            if len(digits) != 9 or not digits.isdigit():
                return False
            # 11-proef: weight 9,8,7,...,2 for first 8 digits, -1 for the last
            total = sum((9 - i) * int(d) if i < 8 else -1 * int(d) for i, d in enumerate(digits))
            return total % 11 == 0 and total != 0

    class DutchPhoneRecognizer(PatternRecognizer):
        """Dutch phone number recognizer."""

        def __init__(self) -> None:
            """Initialize with Dutch phone number patterns."""
            patterns = [
                Pattern(
                    name="nl_phone_international",
                    regex=r"\+31\s?[1-9][\s.-]?\d{1,3}[\s.-]?\d{4,7}",
                    score=0.7,
                ),
                Pattern(
                    name="nl_phone_national",
                    regex=r"0[1-9][\s.-]?\d{1,3}[\s.-]?\d{4,7}",
                    score=0.4,
                ),
            ]
            super().__init__(
                supported_entity="NL_PHONE",
                supported_language="nl",
                patterns=patterns,
                context=["telefoon", "telefoonnummer", "bel", "mobiel", "phone", "tel"],
            )

    class DutchPostalCodeRecognizer(PatternRecognizer):
        """Dutch postal code recognizer (4 digits + 2 letters)."""

        def __init__(self) -> None:
            """Initialize with Dutch postal code pattern."""
            patterns = [
                Pattern(
                    name="nl_postal_code",
                    regex=r"\b[1-9]\d{3}\s?[A-Z]{2}\b",
                    score=0.6,
                ),
            ]
            super().__init__(
                supported_entity="NL_POSTAL_CODE",
                supported_language="nl",
                patterns=patterns,
                context=["postcode", "adres", "woonplaats", "postal"],
            )

    class SecretRecognizer(PatternRecognizer):
        """Detects API keys, tokens, and other secrets."""

        def __init__(self) -> None:
            """Initialize with secret detection patterns."""
            patterns = [
                Pattern(name="openai_key", regex=r"sk-[a-zA-Z0-9]{20,}", score=0.95),
                Pattern(name="anthropic_key", regex=r"sk-ant-[a-zA-Z0-9\-]{20,}", score=0.95),
                Pattern(name="github_pat", regex=r"ghp_[a-zA-Z0-9]{36,}", score=0.95),
                Pattern(name="github_fine", regex=r"github_pat_[a-zA-Z0-9_]{20,}", score=0.95),
                Pattern(name="slack_bot", regex=r"xoxb-[a-zA-Z0-9-]+", score=0.90),
                Pattern(name="slack_user", regex=r"xoxp-[a-zA-Z0-9-]+", score=0.90),
                Pattern(name="aws_key", regex=r"AKIA[0-9A-Z]{16}", score=0.95),
                Pattern(
                    name="bearer_token",
                    regex=r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*",
                    score=0.80,
                ),
                Pattern(
                    name="pem_key",
                    regex=r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
                    score=0.99,
                ),
                Pattern(
                    name="generic_secret",
                    regex=r"(?:key|secret|token|password|passwd|pwd)\s*[=:]\s*['\"]?[a-zA-Z0-9+/]{40,}['\"]?",
                    score=0.70,
                ),
            ]
            super().__init__(
                supported_entity="SECRET_API_KEY",
                supported_language="en",
                patterns=patterns,
                context=["api", "key", "secret", "token", "credential", "auth"],
            )


class PiiDetector(Scanner):
    """Tier 2 output scanner for PII and secret detection.

    Uses Microsoft Presidio with spaCy NLP engines for both Dutch and English.
    Includes custom recognizers for Dutch-specific PII (BSN, phone numbers,
    postal codes) and common secret patterns (API keys, tokens, PEM keys).
    """

    def __init__(
        self,
        *,
        threshold_block: float = 0.9,
        threshold_flag: float = 0.7,
    ) -> None:
        """Initialize the PII detector scanner.

        Args:
            threshold_block: Minimum confidence score to BLOCK content (default: 0.9).
                Applied to secret detection (API keys, tokens, etc.).
            threshold_flag: Minimum confidence score to FLAG PII (default: 0.7).
                PII above this threshold is flagged and optionally redacted on output.

        Raises:
            ImportError: If presidio-analyzer/presidio-anonymizer are not installed.
        """
        if not _HAS_PII_DEPS:
            raise ImportError(
                "PiiDetector requires presidio-analyzer and presidio-anonymizer. "
                "Install with: pip install llm-io-guard[pii]"
            )
        self._threshold_block = threshold_block
        self._threshold_flag = threshold_flag
        self._analyzer: AnalyzerEngine | None = None
        self._anonymizer: AnonymizerEngine | None = None
        self._init_lock = asyncio.Lock()

    @property
    def name(self) -> str:
        """Scanner identifier: ``pii_detector``."""
        return "pii_detector"

    @property
    def tier(self) -> int:
        """Tier 2 — spaCy NLP + regex patterns, ~20-50ms."""
        return 2

    @property
    def supported_directions(self) -> frozenset[str]:
        """Only supports output direction."""
        return frozenset({"output"})

    async def ainitialize(self) -> None:
        """Initialize Presidio with Dutch spaCy model and custom recognizers."""
        async with self._init_lock:
            if self._analyzer is not None:
                return

            nlp_engine = SpacyNlpEngine(
                models=[
                    {"lang_code": "nl", "model_name": "nl_core_news_lg"},
                    {"lang_code": "en", "model_name": "en_core_web_lg"},
                ]
            )

            registry = RecognizerRegistry()
            registry.load_predefined_recognizers(nlp_engine=nlp_engine)

            registry.add_recognizer(BsnRecognizer())
            registry.add_recognizer(DutchPhoneRecognizer())
            registry.add_recognizer(DutchPostalCodeRecognizer())
            registry.add_recognizer(SecretRecognizer())

            self._analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                registry=registry,
            )
            self._anonymizer = AnonymizerEngine()

            logger.info("pii_detector_initialized")

    async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
        """Scan content for PII and secrets.

        Runs Presidio analysis in both Dutch and English, merges results, and
        separates secrets (BLOCK) from PII (FLAG). On output direction,
        high-confidence PII is anonymized via ``presidio-anonymizer``.

        Args:
            content: The text content to scan.
            metadata: Optional dict; uses ``direction`` key (default ``"output"``).

        Returns:
            ScanResult with BLOCK for secrets, FLAG for PII, PASS otherwise.
        """
        if self._analyzer is None or self._anonymizer is None:
            raise RuntimeError("PiiDetector not initialized. Call initialize() first.")

        direction = (metadata or {}).get("direction", "output")
        try:
            results_nl = self._analyzer.analyze(text=content, language="nl", entities=None)
            results_en = self._analyzer.analyze(text=content, language="en", entities=None)
        except Exception as e:
            logger.error("pii_detector_analysis_error", error=str(e))
            return ScanResult(
                scanner_name=self.name,
                action=Action.FLAG,
                confidence=0.0,
                description=f"PII detection error: {e}",
                details={"error": str(e)},
            )

        # Run both languages because Dutch business content often mixes languages
        # (e.g. English API docs with Dutch names/addresses).
        all_results = self._merge_results(results_nl, results_en)

        secrets = [r for r in all_results if r.entity_type in SECRET_ENTITY_TYPES]
        pii = [r for r in all_results if r.entity_type not in SECRET_ENTITY_TYPES]

        if secrets:
            return ScanResult(
                scanner_name=self.name,
                action=Action.BLOCK,
                confidence=max(s.score for s in secrets),
                description=f"Secret(s) detected: {', '.join(s.entity_type for s in secrets)}",
                details={
                    "secret_types": [s.entity_type for s in secrets],
                    "secret_count": len(secrets),
                },
            )

        if not pii:
            return ScanResult(
                scanner_name=self.name,
                action=Action.PASS,
                confidence=0.0,
                description="No PII detected",
                details={},
            )

        high_confidence_pii = [p for p in pii if p.score >= self._threshold_flag]

        if direction == "output" and high_confidence_pii:
            anonymized = self._anonymizer.anonymize(
                text=content,
                analyzer_results=high_confidence_pii,  # type: ignore[arg-type]
            )
            return ScanResult(
                scanner_name=self.name,
                action=Action.FLAG,
                confidence=max(p.score for p in high_confidence_pii),
                description=f"PII redacted for output: {', '.join({p.entity_type for p in high_confidence_pii})}",
                details={
                    "sanitized_content": anonymized.text,
                    "pii_types": list({p.entity_type for p in high_confidence_pii}),
                    "pii_count": len(high_confidence_pii),
                    "redacted": True,
                },
            )
        elif high_confidence_pii:
            return ScanResult(
                scanner_name=self.name,
                action=Action.FLAG,
                confidence=max(p.score for p in high_confidence_pii),
                description=f"PII detected: {', '.join({p.entity_type for p in high_confidence_pii})}",
                details={
                    "pii_types": list({p.entity_type for p in high_confidence_pii}),
                    "pii_count": len(high_confidence_pii),
                    "redacted": False,
                },
            )

        return ScanResult(
            scanner_name=self.name,
            action=Action.PASS,
            confidence=max(p.score for p in pii),
            description="PII detected but below threshold",
            details={
                "pii_types": list({p.entity_type for p in pii}),
                "pii_count": len(pii),
            },
        )

    def _merge_results(
        self, results_nl: list[RecognizerResult], results_en: list[RecognizerResult]
    ) -> list[RecognizerResult]:
        """Merge and deduplicate results from multiple language analyses.

        Results are sorted by score (descending) then start position. A result
        is dropped if its span is fully contained within an already-accepted
        higher-scoring result, preventing duplicate detections for the same
        text region across languages.

        Args:
            results_nl: Recognizer results from Dutch analysis.
            results_en: Recognizer results from English analysis.

        Returns:
            Deduplicated list of recognizer results, highest-scoring first.
        """
        all_results = list(results_nl) + list(results_en)
        all_results.sort(key=lambda r: (-r.score, r.start))
        merged: list[RecognizerResult] = []
        for result in all_results:
            # Skip if this span is fully contained within an existing higher-scored match
            if not any(
                existing.start <= result.start and existing.end >= result.end for existing in merged
            ):
                merged.append(result)
        return merged
