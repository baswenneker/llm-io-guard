# Phase 1: Project Setup & Core Architecture

> **Goal**: Establish the Python project structure, core data classes, pipeline orchestrator, and configuration system.
>
> **Depends on**: Nothing (first phase)
> **Blocks**: All subsequent phases

## Project Structure

```
llm_io_guard/
├── src/
│   └── llm_io_guard/
│       ├── __init__.py              # Public API exports
│       ├── pipeline.py              # ContentSafetyPipeline orchestrator
│       ├── models.py                # Data classes: Action, ScanResult, FilterResult
│       ├── scanner.py               # Scanner ABC
│       ├── config.py                # Configuration loading (YAML + env vars)
│       ├── scanners/
│       │   ├── __init__.py
│       │   ├── invisible_text.py    # Tier 1: Zero-width char detection
│       │   ├── html_sanitizer.py    # Tier 1: HTML stripping
│       │   ├── xml_safe_parser.py   # Tier 1: XXE prevention
│       │   ├── prompt_guard.py      # Tier 2: Meta Prompt Guard 2
│       │   ├── pii_detector.py      # Tier 2: Presidio + Dutch NER
│       │   ├── url_scanner.py       # Tier 2: URL & phishing
│       │   └── llm_judge.py         # Tier 3: Claude Haiku judge
│       └── utils/
│           ├── __init__.py
│           ├── chunking.py          # Text chunking for model input
│           └── logging.py           # Structured logging setup
├── tests/
│   ├── __init__.py
│   ├── conftest.py                  # Shared fixtures
│   ├── test_pipeline.py             # Integration tests
│   ├── test_invisible_text.py
│   ├── test_html_sanitizer.py
│   ├── test_xml_safe_parser.py
│   ├── test_prompt_guard.py
│   ├── test_pii_detector.py
│   ├── test_url_scanner.py
│   ├── test_llm_judge.py
│   └── adversarial/
│       ├── __init__.py
│       ├── test_prompt_injection.py
│       └── test_unicode_attacks.py
├── config/
│   └── default.yaml                 # Default configuration
├── pyproject.toml
├── README.md
├── LICENSE
└── .github/
    └── workflows/
        └── ci.yml
```

## pyproject.toml

```toml
[project]
name = "llm-io-guard"
version = "0.1.0"
description = "Layered content safety pipeline for LLM agents"
requires-python = ">=3.11"
license = { text = "MIT" }

dependencies = [
    "presidio-analyzer>=2.2,<3",
    "presidio-anonymizer>=2.2,<3",
    "spacy>=3.7,<4",
    "transformers>=4.40,<5",
    "torch>=2.2,<3",
    "defusedxml>=0.7,<1",
    "html-sanitizer>=2.3,<3",
    "pysafebrowsing>=0.1,<1",
    "confusable-homoglyphs>=3.3,<4",
    "detect-secrets>=1.4,<2",
    "anthropic>=0.40,<1",
    "pyyaml>=6.0,<7",
    "pydantic>=2.5,<3",
    "structlog>=24.1,<25",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0,<9",
    "pytest-asyncio>=0.23,<1",
    "pytest-cov>=5.0,<6",
    "pytest-benchmark>=4.0,<5",
    "ruff>=0.4,<1",
    "mypy>=1.10,<2",
    "pre-commit>=3.7,<4",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/llm_io_guard"]

[tool.ruff]
target-version = "py311"
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "I", "N", "UP", "S", "B", "A", "C4", "SIM", "TCH"]

[tool.mypy]
python_version = "3.11"
strict = true

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "adversarial: adversarial test cases",
]
```

## Core Data Classes

```python
# src/llm_io_guard/models.py
from dataclasses import dataclass, field
from enum import Enum


class Action(Enum):
    """Action to take based on scan results."""
    PASS = "pass"       # Content is safe, proceed
    FLAG = "flag"       # Content is suspicious, log and proceed with caution
    BLOCK = "block"     # Content is unsafe, stop processing


@dataclass(frozen=True)
class ScanResult:
    """Result from a single scanner."""
    scanner_name: str
    action: Action
    confidence: float          # 0.0 to 1.0
    description: str           # Human-readable explanation
    details: dict = field(default_factory=dict)  # Scanner-specific metadata


@dataclass
class FilterResult:
    """Aggregated result from the full pipeline."""
    action: Action
    scan_results: list[ScanResult] = field(default_factory=list)
    sanitized_content: str | None = None  # Content after Tier 1 sanitization
    original_content: str = ""
    processing_time_ms: float = 0.0

    @property
    def is_safe(self) -> bool:
        return self.action == Action.PASS

    @property
    def blocked_by(self) -> list[ScanResult]:
        return [r for r in self.scan_results if r.action == Action.BLOCK]

    @property
    def flagged_by(self) -> list[ScanResult]:
        return [r for r in self.scan_results if r.action == Action.FLAG]
```

## Scanner ABC

```python
# src/llm_io_guard/scanner.py
from abc import ABC, abstractmethod
from .models import ScanResult


class Scanner(ABC):
    """Abstract base class for all content scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this scanner."""
        ...

    @property
    @abstractmethod
    def tier(self) -> int:
        """Execution tier (1=fast, 2=medium, 3=slow)."""
        ...

    @abstractmethod
    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        """
        Scan content and return a result.

        Args:
            content: The text content to scan.
            metadata: Optional metadata (source type, sender, etc.)

        Returns:
            ScanResult with action, confidence, and description.
        """
        ...

    async def initialize(self) -> None:
        """Optional async initialization (model loading, etc.)."""
        pass
```

## Pipeline Orchestrator

```python
# src/llm_io_guard/pipeline.py
import asyncio
import time
import structlog
from .models import Action, FilterResult, ScanResult
from .scanner import Scanner
from .config import PipelineConfig

logger = structlog.get_logger()


class ContentSafetyPipeline:
    """Tiered content safety pipeline with fail-fast behavior."""

    def __init__(self, config: PipelineConfig):
        self.config = config
        self._scanners: dict[int, list[Scanner]] = {1: [], 2: [], 3: []}

    def register_scanner(self, scanner: Scanner) -> None:
        """Register a scanner in the appropriate tier."""
        if scanner.tier not in self._scanners:
            raise ValueError(f"Invalid tier: {scanner.tier}. Must be 1, 2, or 3.")
        self._scanners[scanner.tier].append(scanner)
        logger.info("scanner_registered", scanner=scanner.name, tier=scanner.tier)

    async def initialize(self) -> None:
        """Initialize all registered scanners."""
        for tier_scanners in self._scanners.values():
            await asyncio.gather(*(s.initialize() for s in tier_scanners))

    async def scan(
        self,
        content: str,
        metadata: dict | None = None,
        direction: str = "input",
    ) -> FilterResult:
        """
        Run content through the tiered pipeline.

        Args:
            content: The text content to scan.
            metadata: Optional metadata (source, sender, content_type, etc.)
            direction: "input" or "output"

        Returns:
            FilterResult with aggregated action and all scan results.
        """
        start_time = time.perf_counter()
        result = FilterResult(action=Action.PASS, original_content=content)
        scan_metadata = {**(metadata or {}), "direction": direction}

        current_content = content

        for tier in [1, 2, 3]:
            tier_scanners = [
                s for s in self._scanners[tier]
                if self.config.is_scanner_enabled(s.name)
            ]

            if not tier_scanners:
                continue

            # Tier 1: sequential (sanitizers modify content)
            if tier == 1:
                for scanner in tier_scanners:
                    scan_result = await scanner.scan(current_content, scan_metadata)
                    result.scan_results.append(scan_result)
                    if scan_result.action == Action.BLOCK:
                        result.action = Action.BLOCK
                        result.processing_time_ms = (time.perf_counter() - start_time) * 1000
                        return result
                    # Tier 1 scanners may sanitize content
                    if "sanitized_content" in scan_result.details:
                        current_content = scan_result.details["sanitized_content"]

                result.sanitized_content = current_content

            # Tier 2: parallel execution
            elif tier == 2:
                tier_results = await asyncio.gather(
                    *(s.scan(current_content, scan_metadata) for s in tier_scanners)
                )
                for scan_result in tier_results:
                    result.scan_results.append(scan_result)

                # Check for blocks after all Tier 2 scanners complete
                if any(r.action == Action.BLOCK for r in tier_results):
                    result.action = Action.BLOCK
                    result.processing_time_ms = (time.perf_counter() - start_time) * 1000
                    return result

                # Propagate flags
                if any(r.action == Action.FLAG for r in tier_results):
                    result.action = Action.FLAG

            # Tier 3: conditional, sequential
            elif tier == 3:
                # Only run Tier 3 if source is high-risk or content was flagged
                if not self._should_run_tier3(result, scan_metadata):
                    continue

                for scanner in tier_scanners:
                    scan_result = await scanner.scan(current_content, scan_metadata)
                    result.scan_results.append(scan_result)
                    if scan_result.action == Action.BLOCK:
                        result.action = Action.BLOCK
                        break

        result.processing_time_ms = (time.perf_counter() - start_time) * 1000
        logger.info(
            "pipeline_complete",
            action=result.action.value,
            duration_ms=round(result.processing_time_ms, 2),
            scanners_run=len(result.scan_results),
        )
        return result

    def _should_run_tier3(self, result: FilterResult, metadata: dict) -> bool:
        """Determine if Tier 3 (LLM judge) should run."""
        # Run if content was flagged by earlier tiers
        if result.action == Action.FLAG:
            return True
        # Run if source is marked as high-risk
        source_risk = metadata.get("source_risk", "low")
        return source_risk in ("high", "unknown")
```

## Configuration System

```python
# src/llm_io_guard/config.py
from pathlib import Path
from pydantic import BaseModel, Field
import yaml
import os


class ScannerConfig(BaseModel):
    """Configuration for a single scanner."""
    enabled: bool = True
    threshold_block: float = 0.9
    threshold_flag: float = 0.7


class PipelineConfig(BaseModel):
    """Root configuration for the content safety pipeline."""
    scanners: dict[str, ScannerConfig] = Field(default_factory=dict)
    tier3_sources: list[str] = Field(
        default_factory=lambda: ["email", "web", "unknown"]
    )
    log_level: str = "INFO"
    max_content_length: int = 100_000  # chars
    model_cache_dir: str = Field(
        default_factory=lambda: os.environ.get(
            "LLM_IO_GUARD_MODEL_DIR", str(Path.home() / ".cache" / "llm_io_guard")
        )
    )

    def is_scanner_enabled(self, scanner_name: str) -> bool:
        """Check if a scanner is enabled (default: True)."""
        if scanner_name not in self.scanners:
            return True
        return self.scanners[scanner_name].enabled

    def get_scanner_config(self, scanner_name: str) -> ScannerConfig:
        """Get configuration for a scanner (returns defaults if not configured)."""
        return self.scanners.get(scanner_name, ScannerConfig())

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PipelineConfig":
        """Load configuration from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls(**data)

    @classmethod
    def from_env(cls) -> "PipelineConfig":
        """Load configuration from environment variables."""
        config = cls()
        if log_level := os.environ.get("LLM_IO_GUARD_LOG_LEVEL"):
            config.log_level = log_level
        if max_length := os.environ.get("LLM_IO_GUARD_MAX_CONTENT_LENGTH"):
            config.max_content_length = int(max_length)
        return config
```

## Default Configuration (YAML)

```yaml
# config/default.yaml
log_level: INFO
max_content_length: 100000

scanners:
  invisible_text:
    enabled: true
  html_sanitizer:
    enabled: true
  xml_safe_parser:
    enabled: true
  prompt_guard:
    enabled: true
    threshold_block: 0.9
    threshold_flag: 0.7
  pii_detector:
    enabled: true
    threshold_block: 0.9
    threshold_flag: 0.7
  url_scanner:
    enabled: true
  llm_judge:
    enabled: true
    threshold_block: 0.8
    threshold_flag: 0.5

tier3_sources:
  - email
  - web
  - unknown
```

## Model Download & Caching Strategy

Models are downloaded on first use and cached locally:

```python
# src/llm_io_guard/utils/model_cache.py
import hashlib
from pathlib import Path
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import structlog

logger = structlog.get_logger()

# Expected SHA-256 hashes for model integrity verification
MODEL_HASHES = {
    "meta-llama/Prompt-Guard-2-86M": {
        "model.safetensors": "expected_sha256_hash_here",
    }
}


def verify_model_integrity(model_dir: Path, model_name: str) -> bool:
    """Verify downloaded model files match expected hashes."""
    expected = MODEL_HASHES.get(model_name, {})
    for filename, expected_hash in expected.items():
        filepath = model_dir / filename
        if not filepath.exists():
            return False
        actual_hash = hashlib.sha256(filepath.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            logger.error(
                "model_integrity_check_failed",
                model=model_name,
                file=filename,
                expected=expected_hash,
                actual=actual_hash,
            )
            return False
    return True


def load_prompt_guard(cache_dir: str) -> tuple:
    """Load Prompt Guard 2 model with caching and integrity check."""
    model_name = "meta-llama/Prompt-Guard-2-86M"
    model_dir = Path(cache_dir) / model_name.replace("/", "--")

    tokenizer = AutoTokenizer.from_pretrained(
        model_name, cache_dir=cache_dir
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name, cache_dir=cache_dir
    )

    if model_dir.exists():
        verify_model_integrity(model_dir, model_name)

    return tokenizer, model
```

## Supply Chain Security

- **Dependency pinning**: All dependencies have upper-bound version constraints in `pyproject.toml`
- **Lock file**: Use `pip-compile` or `uv` to generate a lock file with exact versions and hashes
- **Model verification**: SHA-256 hash verification of downloaded model files
- **Minimal permissions**: The library does not require network access at runtime (except for URL scanning and LLM judge)
- **No dynamic code execution**: No `eval()`, `exec()`, or dynamic imports from user content

## Implementation Checklist

- [ ] Create project directory structure
- [ ] Write `pyproject.toml` with all dependencies
- [ ] Implement `Action`, `ScanResult`, `FilterResult` in `models.py`
- [ ] Implement `Scanner` ABC in `scanner.py`
- [ ] Implement `ContentSafetyPipeline` in `pipeline.py`
- [ ] Implement `PipelineConfig` in `config.py`
- [ ] Create `default.yaml` configuration
- [ ] Set up model download and caching utilities
- [ ] Write unit tests for core classes
- [ ] Set up ruff and mypy configuration

## Next Phase

→ [Phase 2: Input Sanitization](./02-input-sanitization.md)
