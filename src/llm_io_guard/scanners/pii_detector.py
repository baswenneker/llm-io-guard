"""PII and secret detection scanner using Microsoft Presidio."""

import structlog
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_anonymizer import AnonymizerEngine

from ..config import PipelineConfig
from ..models import Action, ScanResult
from ..scanner import Scanner

logger = structlog.get_logger()

SECRET_ENTITY_TYPES = {
    "SECRET_API_KEY",
    "SECRET_TOKEN",
    "SECRET_PRIVATE_KEY",
}


class BsnRecognizer(PatternRecognizer):
    """Dutch BSN (burgerservicenummer) recognizer with 11-proef validation."""

    def __init__(self):
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
        """Validate BSN using the 11-proef checksum."""
        digits = pattern_text.replace(".", "")
        if len(digits) != 9:
            return False
        total = sum(
            (9 - i) * int(d) if i < 8 else -1 * int(d) for i, d in enumerate(digits)
        )
        return total % 11 == 0 and total != 0


class DutchPhoneRecognizer(PatternRecognizer):
    """Dutch phone number recognizer."""

    def __init__(self):
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

    def __init__(self):
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

    def __init__(self):
        patterns = [
            Pattern(name="openai_key", regex=r"sk-[a-zA-Z0-9]{20,}", score=0.95),
            Pattern(name="anthropic_key", regex=r"sk-ant-[a-zA-Z0-9\-]{20,}", score=0.95),
            Pattern(name="github_pat", regex=r"ghp_[a-zA-Z0-9]{36,}", score=0.95),
            Pattern(
                name="github_fine", regex=r"github_pat_[a-zA-Z0-9_]{20,}", score=0.95
            ),
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
    """PII and secret detection using Microsoft Presidio with Dutch support."""

    def __init__(self, config: PipelineConfig):
        self._config = config
        self._analyzer: AnalyzerEngine | None = None
        self._anonymizer: AnonymizerEngine | None = None

    @property
    def name(self) -> str:
        return "pii_detector"

    @property
    def tier(self) -> int:
        return 2

    async def initialize(self) -> None:
        """Initialize Presidio with Dutch spaCy model and custom recognizers."""
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

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        if self._analyzer is None:
            raise RuntimeError("PiiDetector not initialized. Call initialize() first.")

        direction = (metadata or {}).get("direction", "input")
        scanner_config = self._config.get_scanner_config(self.name)

        results_nl = self._analyzer.analyze(text=content, language="nl", entities=None)
        results_en = self._analyzer.analyze(text=content, language="en", entities=None)

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

        high_confidence_pii = [p for p in pii if p.score >= scanner_config.threshold_flag]

        if direction == "output" and high_confidence_pii:
            anonymized = self._anonymizer.anonymize(
                text=content,
                analyzer_results=high_confidence_pii,
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

    def _merge_results(self, results_nl, results_en):
        """Merge and deduplicate results from multiple language analyses."""
        all_results = list(results_nl) + list(results_en)
        all_results.sort(key=lambda r: (-r.score, r.start))
        merged = []
        for result in all_results:
            if not any(
                existing.start <= result.start and existing.end >= result.end
                for existing in merged
            ):
                merged.append(result)
        return merged
