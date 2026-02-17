# Phase 4: PII & Secret Detection (Tier 2)

> **Goal**: Detect personally identifiable information (PII) and secrets in content, with special support for Dutch PII formats.
>
> **Depends on**: [Phase 1: Project Setup](./01-project-setup.md)
> **Tier**: 2 — Medium (<100ms)
> **OWASP**: LLM02 (Sensitive Information Disclosure), LLM05 (Improper Output Handling)

## Overview

PII detection serves two purposes:

1. **Input scanning**: Detect PII in incoming content and flag it (e.g., an email containing a BSN number)
2. **Output scanning**: Redact PII before sending content to third-party services

The scanner uses Microsoft Presidio for entity recognition, supplemented with custom Dutch recognizers and secret detection patterns.

## Bidirectional Handling

| Direction | PII Type | Action | Rationale |
|-----------|----------|--------|-----------|
| **Input** (incoming) | Personal PII | FLAG + log | Don't modify incoming content; log for audit |
| **Output** (to 3rd party) | Personal PII | REDACT if confidence >0.7 | Prevent PII leakage to external services |
| **Any direction** | Secrets (API keys, tokens) | BLOCK immediately | Secrets must never pass through |

## Microsoft Presidio Setup

### Analyzer Configuration

```python
# src/llm_io_guard/scanners/pii_detector.py
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_anonymizer import AnonymizerEngine
import re
import structlog

from ..scanner import Scanner
from ..models import Action, ScanResult
from ..config import PipelineConfig

logger = structlog.get_logger()


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

        # Configure spaCy NLP engine with Dutch model
        nlp_engine = SpacyNlpEngine(
            models=[
                {"lang_code": "nl", "model_name": "nl_core_news_lg"},
                {"lang_code": "en", "model_name": "en_core_web_lg"},
            ]
        )

        # Create registry with custom recognizers
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers(nlp_engine=nlp_engine)

        # Add Dutch-specific recognizers
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

        # Analyze for PII in both Dutch and English
        results_nl = self._analyzer.analyze(
            text=content, language="nl", entities=None
        )
        results_en = self._analyzer.analyze(
            text=content, language="en", entities=None
        )

        # Merge and deduplicate results
        all_results = self._merge_results(results_nl, results_en)

        # Separate secrets from PII
        secrets = [r for r in all_results if r.entity_type in SECRET_ENTITY_TYPES]
        pii = [r for r in all_results if r.entity_type not in SECRET_ENTITY_TYPES]

        # Secrets: always BLOCK
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

        # PII found — behavior depends on direction
        high_confidence_pii = [p for p in pii if p.score >= scanner_config.threshold_flag]

        if direction == "output" and high_confidence_pii:
            # Output direction: redact PII above threshold
            anonymized = self._anonymizer.anonymize(
                text=content,
                analyzer_results=high_confidence_pii,
            )
            return ScanResult(
                scanner_name=self.name,
                action=Action.FLAG,
                confidence=max(p.score for p in high_confidence_pii),
                description=f"PII redacted for output: {', '.join(set(p.entity_type for p in high_confidence_pii))}",
                details={
                    "sanitized_content": anonymized.text,
                    "pii_types": list(set(p.entity_type for p in high_confidence_pii)),
                    "pii_count": len(high_confidence_pii),
                    "redacted": True,
                },
            )
        elif high_confidence_pii:
            # Input direction: flag but don't modify
            return ScanResult(
                scanner_name=self.name,
                action=Action.FLAG,
                confidence=max(p.score for p in high_confidence_pii),
                description=f"PII detected: {', '.join(set(p.entity_type for p in high_confidence_pii))}",
                details={
                    "pii_types": list(set(p.entity_type for p in high_confidence_pii)),
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
                "pii_types": list(set(p.entity_type for p in pii)),
                "pii_count": len(pii),
            },
        )

    def _merge_results(self, results_nl, results_en):
        """Merge and deduplicate results from multiple language analyses."""
        all_results = list(results_nl) + list(results_en)
        # Deduplicate by keeping highest score for overlapping spans
        all_results.sort(key=lambda r: (-r.score, r.start))
        merged = []
        for result in all_results:
            if not any(
                existing.start <= result.start and existing.end >= result.end
                for existing in merged
            ):
                merged.append(result)
        return merged
```

## Custom Dutch Recognizers

### BSN (Burgerservicenummer) Recognizer

The BSN is the Dutch citizen service number. It must pass the **11-proef** (eleven-test) checksum.

```python
class BsnRecognizer(PatternRecognizer):
    """Dutch BSN (burgerservicenummer) recognizer with 11-proef validation."""

    def __init__(self):
        patterns = [
            Pattern(
                name="bsn_pattern",
                regex=r"\b(\d{9})\b",
                score=0.3,  # Low initial score, boosted by validation
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
        # 11-proef: 9*d1 + 8*d2 + 7*d3 + 6*d4 + 5*d5 + 4*d6 + 3*d7 + 2*d8 - 1*d9
        # Result must be divisible by 11 and not 0
        total = sum(
            (9 - i) * int(d) if i < 8 else -1 * int(d)
            for i, d in enumerate(digits)
        )
        return total % 11 == 0 and total != 0
```

### Dutch Phone Number Recognizer

```python
class DutchPhoneRecognizer(PatternRecognizer):
    """Dutch phone number recognizer."""

    def __init__(self):
        patterns = [
            # International format: +31 6 12345678
            Pattern(
                name="nl_phone_international",
                regex=r"\+31\s?[1-9][\s.-]?\d{1,3}[\s.-]?\d{4,7}",
                score=0.7,
            ),
            # National format: 06-12345678, 020-1234567
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
```

### Dutch Postal Code Recognizer

```python
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
```

## Secret Detection

### Secret Types and Patterns

```python
SECRET_ENTITY_TYPES = {
    "SECRET_API_KEY",
    "SECRET_TOKEN",
    "SECRET_PRIVATE_KEY",
}


class SecretRecognizer(PatternRecognizer):
    """Detects API keys, tokens, and other secrets."""

    def __init__(self):
        patterns = [
            # OpenAI API key
            Pattern(name="openai_key", regex=r"sk-[a-zA-Z0-9]{20,}", score=0.95),
            # Anthropic API key
            Pattern(name="anthropic_key", regex=r"sk-ant-[a-zA-Z0-9-]{20,}", score=0.95),
            # GitHub personal access token
            Pattern(name="github_pat", regex=r"ghp_[a-zA-Z0-9]{36,}", score=0.95),
            # GitHub fine-grained token
            Pattern(name="github_fine", regex=r"github_pat_[a-zA-Z0-9_]{20,}", score=0.95),
            # Slack bot token
            Pattern(name="slack_bot", regex=r"xoxb-[a-zA-Z0-9-]+", score=0.90),
            # Slack user token
            Pattern(name="slack_user", regex=r"xoxp-[a-zA-Z0-9-]+", score=0.90),
            # AWS access key
            Pattern(name="aws_key", regex=r"AKIA[0-9A-Z]{16}", score=0.95),
            # Bearer token in headers
            Pattern(name="bearer_token", regex=r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*", score=0.80),
            # PEM private key
            Pattern(name="pem_key", regex=r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", score=0.99),
            # Generic high-entropy secret (40+ char base64)
            Pattern(name="generic_secret", regex=r"(?:key|secret|token|password|passwd|pwd)\s*[=:]\s*['\"]?[a-zA-Z0-9+/]{40,}['\"]?", score=0.70),
        ]
        super().__init__(
            supported_entity="SECRET_API_KEY",
            supported_language="en",
            patterns=patterns,
            context=["api", "key", "secret", "token", "credential", "auth"],
        )
```

## IBAN Detection

Presidio has built-in IBAN detection. The Dutch IBAN format is `NL` + 2 check digits + 4 bank code + 10 account number:

```
NL91 ABNA 0417 1643 00
```

No custom recognizer needed — Presidio's built-in `IBAN_CODE` entity handles this, including checksum validation.

## Performance

| Operation | Target Latency |
|-----------|---------------|
| Presidio analysis (NL) | ~50ms |
| Presidio analysis (EN) | ~50ms |
| Both languages (parallel possible) | ~60ms |
| Anonymization | ~5ms |
| **Total** | **<100ms** |

## Implementation Checklist

- [ ] Implement `PiiDetector` scanner with Presidio
- [ ] Add Dutch spaCy model (`nl_core_news_lg`) integration
- [ ] Implement `BsnRecognizer` with 11-proef validation
- [ ] Implement `DutchPhoneRecognizer` with +31 format support
- [ ] Implement `DutchPostalCodeRecognizer`
- [ ] Implement `SecretRecognizer` with API key patterns
- [ ] Add bidirectional handling (flag input, redact output, block secrets)
- [ ] Write unit tests with valid Dutch PII samples
- [ ] Write tests for BSN 11-proef edge cases
- [ ] Write tests for secret detection patterns
- [ ] Benchmark performance (<100ms)

## Next Phase

→ [Phase 5: URL & Phishing Protection](./05-url-phishing.md)
