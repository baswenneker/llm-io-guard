# Phase 9: Documentation Plan

> **Goal**: Create comprehensive documentation including README, OWASP coverage table, license compliance section, and configuration reference.
>
> **Depends on**: All previous phases
> **Output**: README.md, inline docstrings, configuration docs

## README.md Structure

The README should follow this structure:

### 1. Header & Badges

```markdown
# llm_io_guard

**Layered content safety pipeline for LLM agents.**

Built with Llama

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/github/actions/workflow/status/headingfwd/llm-io-guard/ci.yml)](https://github.com/headingfwd/llm-io-guard/actions)
```

Note: The "Built with Llama" text is a requirement of the Llama 4 Community License for using Meta Prompt Guard 2.

### 2. Problem Statement

Brief description of the "lethal trifecta" problem and why content safety matters for AI agents. 2-3 paragraphs max.

### 3. Quick Start

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
    # Content flagged — proceed with caution
    log_warning(result.flagged_by)
    process_with_caution(result.sanitized_content)
else:
    # Content blocked
    log_block(result.blocked_by)
    reject(result)
```

### 4. Architecture

Include the ASCII pipeline diagram from the overview document, plus a brief explanation of the tiered approach.

### 5. Installation

```bash
# Install the package
pip install llm-io-guard

# Download required models
python -m spacy download nl_core_news_lg

# Prompt Guard 2 is downloaded automatically on first use
```

### 6. Configuration Reference

Document all configuration options with examples:

```yaml
# config/default.yaml — full reference
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
    threshold_block: 0.9
    threshold_flag: 0.7
  url_scanner:
    enabled: true
  llm_judge:
    enabled: true
    threshold_block: 0.8
    threshold_flag: 0.5

tier3_sources:                     # Sources that trigger Tier 3 (LLM judge)
  - email
  - web
  - unknown
```

Environment variable overrides:

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_IO_GUARD_LOG_LEVEL` | Log level | `INFO` |
| `LLM_IO_GUARD_MAX_CONTENT_LENGTH` | Max input chars | `100000` |
| `LLM_IO_GUARD_MODEL_DIR` | Model cache directory | `~/.cache/llm_io_guard` |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing API key | — |
| `ANTHROPIC_API_KEY` | Anthropic API key (for LLM judge) | — |

### 7. OWASP Top 10 for LLM Applications (2025)

| # | OWASP Risk | Direction | Filter | Status |
|---|-----------|-----------|--------|--------|
| LLM01 | Prompt Injection | Input | Prompt Guard 2 + Haiku Judge | ✅ Covered |
| LLM02 | Sensitive Info Disclosure | Input + Output | Presidio PII + Secret detection | ✅ Covered |
| LLM03 | Supply Chain Vulnerabilities | N/A | Dependency pinning, model hash verification | ⚠️ Partially covered |
| LLM04 | Data and Model Poisoning | Input | Content filtering pipeline | ⚠️ Partially covered |
| LLM05 | Improper Output Handling | Output | PII redaction + output scanning | ✅ Covered |
| LLM06 | Excessive Agency | Output | Human-in-the-loop, action allowlisting | ✅ Covered |
| LLM07 | System Prompt Leakage | Output | Output scanning | ✅ Covered |
| LLM08 | Vector & Embedding Weaknesses | — | — | ❌ Not in scope |
| LLM09 | Misinformation | Output | Haiku judge (limited) | ⚠️ Partially covered |
| LLM10 | Unbounded Consumption | Both | Rate limiting, cost controls | ✅ Covered |

### 8. License Section

```markdown
## Licenses

This project is licensed under the MIT License.

### Third-Party Licenses

This project uses Meta Prompt Guard 2, which is licensed under the
**Llama 4 Community License**.

> Llama 4 is licensed under the Llama 4 Community License,
> Copyright Meta Platforms, Inc. All Rights Reserved.

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
```

### 9. Development

```markdown
## Development

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=llm_io_guard --cov-report=html

# Run adversarial tests
pytest -m adversarial

# Run benchmarks
pytest --benchmark-only

# Lint
ruff check src/ tests/
ruff format src/ tests/

# Type check
mypy src/
```

### 10. API Reference

Document the main public API:

- `ContentSafetyPipeline` — main pipeline class
- `PipelineConfig` — configuration class
- `Action` — enum (PASS, FLAG, BLOCK)
- `FilterResult` — pipeline result
- `ScanResult` — individual scanner result
- `Scanner` — ABC for custom scanners

## Inline Documentation Standards

- All public classes and methods must have docstrings
- Use Google-style docstrings
- Include type hints on all public APIs
- Add usage examples in docstrings for main entry points

## Implementation Checklist

- [ ] Write README.md with all sections listed above
- [ ] Add "Built with Llama" notice (Llama 4 Community License requirement)
- [ ] Include OWASP Top 10 coverage table
- [ ] Include complete license section
- [ ] Add inline docstrings to all public APIs
- [ ] Write configuration reference with all options
- [ ] Create CONTRIBUTING.md (basic guidelines)
- [ ] Create CHANGELOG.md (initial release)
- [ ] Verify all cross-references between documents

## Cross-References

- Architecture diagram: [00-overview.md](./00-overview.md)
- API details: [01-project-setup.md](./01-project-setup.md)
- Scanner details: phases [02](./02-input-sanitization.md)–[06](./06-llm-judge.md)
- Integration guide: [07-agent-integration.md](./07-agent-integration.md)
- Test suite: [08-testing.md](./08-testing.md)
