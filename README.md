# llm_io_guard

**Layered content safety pipeline for LLM agents.**

Built with Llama

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## The Problem

AI agents increasingly operate with access to private data, process untrusted external content, and execute real-world actions (send emails, modify databases, call APIs). This creates what Simon Willison calls the **"lethal trifecta"**:

1. **Private data** -- the agent has access to confidential information
2. **Untrusted content** -- the agent processes input from external sources (emails, web pages, documents)
3. **External actions** -- the agent can take actions that affect the real world

Without a content safety pipeline, a single prompt injection in an incoming email could instruct the agent to exfiltrate private data, send unauthorized emails, or modify critical records. Every piece of external content the agent touches is an attack surface.

`llm_io_guard` is a Python library that provides a layered, fail-fast content safety pipeline for scanning both **input** (before the LLM sees it) and **output** (before the agent acts on LLM responses). It combines fast deterministic sanitization, ML-based detection, and LLM-based judgment into a single pipeline that runs in under 600ms.

## Quick Start

```python
from llm_io_guard import ContentSafetyPipeline, PipelineConfig

# Create pipeline with default config
config = PipelineConfig.from_yaml("config/default.yaml")
pipeline = ContentSafetyPipeline(config)
await pipeline.initialize()

# Scan incoming email content
result = await pipeline.scan(
    content=email_body,
    metadata={"source": "email", "sender": "unknown@example.com"},
    direction="input",
)

if result.is_safe:
    # Process the sanitized content
    process(result.sanitized_content)
elif result.action == Action.FLAG:
    # Content flagged -- proceed with caution
    log_warning(result.flagged_by)
    process_with_caution(result.sanitized_content)
else:
    # Content blocked
    log_block(result.blocked_by)
    reject(result)
```

## Architecture

The pipeline uses a tiered architecture where fast, deterministic checks run first. If content fails any tier, processing stops immediately (fail-fast).

```
+---------------------------------------------------------+
|                  INCOMING CONTENT                        |
|            (email, web page, document)                   |
+-----------------------+---------------------------------+
                        |
                        v
+---------------------------------------------------------+
|  TIER 1: Fast Sanitization (<5ms, deterministic)        |
|  +---------------+ +----------------+ +----------------+ |
|  | Invisible     | | HTML           | | XML Safe       | |
|  | Text Strip    | | Sanitizer      | | Parser         | |
|  +---------------+ +----------------+ +----------------+ |
+-----------------------+---------------------------------+
                        | PASS
                        v
+---------------------------------------------------------+
|  TIER 2: ML & Pattern Detection (<50ms, parallel)       |
|  +---------------+ +----------------+ +----------------+ |
|  | Prompt        | | PII &          | | URL &          | |
|  | Guard 2       | | Presidio       | | Phishing       | |
|  +---------------+ +----------------+ +----------------+ |
+-----------------------+---------------------------------+
                        | PASS
                        v
+---------------------------------------------------------+
|  TIER 3: LLM Judge (<500ms, conditional)                |
|  +--------------------------------------------------+   |
|  | Claude Haiku 4.5 -- content safety classifier    |   |
|  | (only for high-risk sources)                      |   |
|  +--------------------------------------------------+   |
+-----------------------+---------------------------------+
                        | PASS
                        v
+---------------------------------------------------------+
|              SAFE CONTENT -> LLM / Agent                |
+---------------------------------------------------------+
```

| Tier | Latency Target | Type | Scanners |
|------|---------------|------|----------|
| 1 -- Fast | <5ms | Deterministic, regex-based | Invisible text, HTML sanitization, XML safe parsing |
| 2 -- Medium | <50ms | ML models, pattern matching | Prompt Guard 2, Presidio PII, URL/phishing detection |
| 3 -- Slow | <500ms | LLM-based | Claude Haiku judge (conditional) |

Tier 1 scanners run **sequentially** because they sanitize content for downstream tiers. Tier 2 scanners run **in parallel** via `asyncio.gather()`. Tier 3 runs **conditionally** -- only for high-risk sources (email, web, unknown) or when Tier 2 flags content.

Total pipeline latency target: **<600ms** (worst case, with Tier 3). Typical case (Tier 1 + 2 only): **<60ms**.

## Installation

```bash
# Install the package
pip install llm-io-guard

# Or install from source with uv
uv sync --all-extras

# Download required spaCy model for Dutch NER
python -m spacy download nl_core_news_lg

# Prompt Guard 2 is downloaded automatically on first use
```

## Scanners

| Scanner | Tier | Description | OWASP Coverage |
|---------|------|-------------|----------------|
| `InvisibleTextScanner` | 1 | Strips zero-width characters, invisible Unicode, and homoglyph obfuscation | LLM01, LLM04 |
| `HtmlSanitizer` | 1 | Sanitizes HTML to plain text, removes scripts and dangerous elements | LLM01, LLM04 |
| `XmlSafeParser` | 1 | Prevents XXE (XML External Entity) attacks using defusedxml | LLM01, LLM04 |
| `PromptGuardScanner` | 2 | Meta Prompt Guard 2 (86M params) for prompt injection detection | LLM01 |
| `PiiDetector` | 2 | Microsoft Presidio with Dutch NER (BSN, phone, postal codes) + secret detection | LLM02, LLM05 |
| `UrlScanner` | 2 | Google Safe Browsing API + homoglyph detection for phishing URLs | LLM01, LLM02 |
| `LlmJudgeScanner` | 3 | Claude Haiku 4.5 content safety classifier for high-risk sources | LLM01, LLM07, LLM09 |

## Configuration Reference

Full reference for `config/default.yaml`:

```yaml
# config/default.yaml -- full reference
log_level: INFO                    # DEBUG, INFO, WARNING, ERROR
max_content_length: 100000         # Maximum input length in characters

scanners:
  invisible_text:
    enabled: true                  # Strip invisible Unicode characters
  html_sanitizer:
    enabled: true                  # Strip HTML to plain text
  xml_safe_parser:
    enabled: true                  # Prevent XXE attacks
  prompt_guard:
    enabled: true
    threshold_block: 0.9           # Block above this confidence
    threshold_flag: 0.7            # Flag above this confidence
  pii_detector:
    enabled: true
    threshold_block: 0.9           # Block above this PII confidence
    threshold_flag: 0.7            # Flag above this PII confidence
  url_scanner:
    enabled: true
  llm_judge:
    enabled: true
    threshold_block: 0.8           # Block above this judge confidence
    threshold_flag: 0.5            # Flag above this judge confidence

tier3_sources:                     # Sources that trigger Tier 3 (LLM judge)
  - email
  - web
  - unknown
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_IO_GUARD_LOG_LEVEL` | Log level | `INFO` |
| `LLM_IO_GUARD_MAX_CONTENT_LENGTH` | Max input chars | `100000` |
| `LLM_IO_GUARD_MODEL_DIR` | Model cache directory | `~/.cache/llm_io_guard` |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing API key | -- |
| `ANTHROPIC_API_KEY` | Anthropic API key (for LLM judge) | -- |

## OWASP Top 10 for LLM Applications (2025)

| # | OWASP Risk | Direction | Filter | Status |
|---|-----------|-----------|--------|--------|
| LLM01 | Prompt Injection | Input | Prompt Guard 2 + Haiku Judge | Covered |
| LLM02 | Sensitive Information Disclosure | Input + Output | Presidio PII + Secret detection | Covered |
| LLM03 | Supply Chain Vulnerabilities | N/A | Dependency pinning, model hash verification | Partially covered |
| LLM04 | Data and Model Poisoning | Input | Content filtering pipeline | Partially covered |
| LLM05 | Improper Output Handling | Output | PII redaction + output scanning | Covered |
| LLM06 | Excessive Agency | Output | Human-in-the-loop, action allowlisting | Covered |
| LLM07 | System Prompt Leakage | Output | Output scanning for system prompt fragments | Covered |
| LLM08 | Vector and Embedding Weaknesses | -- | -- | Not in scope |
| LLM09 | Misinformation | Output | Haiku judge (limited) | Partially covered |
| LLM10 | Unbounded Consumption | Both | Rate limiting, cost controls | Covered |

## Licenses

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

### Third-Party Licenses

This project uses Meta Prompt Guard 2, which is licensed under the **Llama 4 Community License**.

> Llama 4 is licensed under the Llama 4 Community License, Copyright Meta Platforms, Inc. All Rights Reserved.

**Requirements for using Prompt Guard 2:**
- Display "Built with Llama" in your application or documentation
- Usage is limited to organizations with fewer than 700 million monthly active users
- Derived model names must include "Llama"
- Must comply with Meta's [Acceptable Use Policy](https://llama.meta.com/llama3/use-policy/)

| Dependency | License | Link |
|-----------|---------|------|
| Meta Prompt Guard 2 | Llama 4 Community License | [License](https://llama.meta.com/llama3/license/) |
| Microsoft Presidio | MIT | [License](https://github.com/microsoft/presidio/blob/main/LICENSE) |
| spaCy | MIT | [License](https://github.com/explosion/spaCy/blob/master/LICENSE) |
| html-sanitizer | BSD-3-Clause | [License](https://github.com/matthiask/html-sanitizer/blob/main/LICENSE) |
| defusedxml | PSF License | [License](https://github.com/tiran/defusedxml/blob/main/LICENSE) |
| pysafebrowsing | MIT | [License](https://github.com/pysafebrowsing/pysafebrowsing/blob/main/LICENSE) |
| confusable_homoglyphs | MIT | [License](https://github.com/vhf/confusable_homoglyphs/blob/master/LICENSE) |
| detect-secrets | Apache 2.0 | [License](https://github.com/Yelp/detect-secrets/blob/master/LICENSE) |

## Development

```bash
# Install with dev dependencies
make install
# or
uv sync --all-extras

# Run tests
make test

# Run tests with coverage
make test-cov

# Run adversarial tests
uv run pytest -m adversarial

# Format code
make fmt

# Run all linters (ruff, mypy, bandit, pyright)
make lint

# Type checking
make typecheck

# Check docstring coverage
make docs

# Run all development checks
make dev

# Clean temporary files
make clean
```

## API Reference

### `ContentSafetyPipeline`
Main pipeline class. Orchestrates tiered scanning with fail-fast behavior.
- `__init__(config: PipelineConfig)` -- create a pipeline from configuration
- `register_scanner(scanner: Scanner)` -- register a scanner in the appropriate tier
- `async initialize()` -- initialize all registered scanners (load models, etc.)
- `async scan(content, metadata, direction)` -- run content through the tiered pipeline

### `PipelineConfig`
Configuration class backed by Pydantic.
- `from_yaml(path)` -- load configuration from a YAML file
- `from_env()` -- load configuration from environment variables
- `is_scanner_enabled(name)` -- check if a scanner is enabled
- `get_scanner_config(name)` -- get scanner-specific configuration

### `Scanner`
Abstract base class for all content scanners. Extend this to add custom scanners.
- `name: str` -- unique identifier (abstract property)
- `tier: int` -- execution tier 1/2/3 (abstract property)
- `async scan(content, metadata) -> ScanResult` -- perform the scan (abstract)
- `async initialize()` -- optional async initialization

### Data Classes
- `Action` -- enum: `PASS`, `FLAG`, `BLOCK`
- `ScanResult` -- result from a single scanner (scanner_name, action, confidence, description, details)
- `FilterResult` -- aggregated pipeline result with `is_safe`, `blocked_by`, `flagged_by` properties
- `ScannerConfig` -- per-scanner configuration (enabled, threshold_block, threshold_flag)

### Integration Helpers
- `async safe_fetch_email(pipeline, email_body, sender, subject, ...)` -- scan email content with appropriate metadata
- `async safe_fetch_webpage(pipeline, url, html_content)` -- scan web page content with appropriate metadata

### Action Validation
- `ActionRequest` -- represents an agent action request with category and risk level
- `ActionCategory` -- enum: `READ`, `NOTIFY`, `CREATE`, `MODIFY`, `DELETE`, `SEND`, `EXECUTE`
- `async validate_action(action, confirm_callback)` -- validate whether an agent action should be executed

### Rate Limiting
- `RateLimiter` -- token-bucket rate limiter with `max_requests_per_minute` and `max_cost_per_day_usd`

## Author

**Bas Wenneker** -- bas@headingfwd.com
