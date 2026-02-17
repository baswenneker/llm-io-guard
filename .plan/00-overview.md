# Phase 0: Overview — LLM I/O Guard

## Problem Statement

AI agents increasingly operate with access to private data, process untrusted external content, and execute real-world actions (send emails, modify databases, call APIs). This creates what Simon Willison calls the **"lethal trifecta"**:

1. **Private data** — the agent has access to confidential information
2. **Untrusted content** — the agent processes input from external sources (emails, web pages, documents)
3. **External actions** — the agent can take actions that affect the real world

Without a content safety pipeline, a single prompt injection in an incoming email could instruct the agent to exfiltrate private data, send unauthorized emails, or modify critical records.

`llm_io_guard` is a Python library that provides a layered, fail-fast content safety pipeline for scanning both input (before the LLM sees it) and output (before the agent acts on LLM responses).

## Architecture: Layered Pipeline

The pipeline uses a tiered architecture where fast, deterministic checks run first. If content fails any tier, processing stops immediately (fail-fast).

```
┌─────────────────────────────────────────────────────────┐
│                  INCOMING CONTENT                        │
│            (email, web page, document)                   │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  TIER 1: Fast Sanitization (<5ms, deterministic)        │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────────┐  │
│  │ Invisible   │ │ HTML         │ │ XML Safe         │  │
│  │ Text Strip  │ │ Sanitizer    │ │ Parser           │  │
│  └─────────────┘ └──────────────┘ └──────────────────┘  │
└─────────────────┬───────────────────────────────────────┘
                  │ PASS
                  ▼
┌─────────────────────────────────────────────────────────┐
│  TIER 2: ML & Pattern Detection (<50ms, parallel)       │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────────┐  │
│  │ Prompt      │ │ PII &        │ │ URL &            │  │
│  │ Guard 2     │ │ Presidio     │ │ Phishing         │  │
│  └─────────────┘ └──────────────┘ └──────────────────┘  │
└─────────────────┬───────────────────────────────────────┘
                  │ PASS
                  ▼
┌─────────────────────────────────────────────────────────┐
│  TIER 3: LLM Judge (<500ms, conditional)                │
│  ┌──────────────────────────────────────────────────┐   │
│  │ Claude Haiku 4.5 — content safety classifier     │   │
│  │ (only for high-risk sources)                     │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────┬───────────────────────────────────────┘
                  │ PASS
                  ▼
┌─────────────────────────────────────────────────────────┐
│              SAFE CONTENT → LLM / Agent                  │
└─────────────────────────────────────────────────────────┘
```

## Tier Breakdown

| Tier | Latency Target | Type | Scanners |
|------|---------------|------|----------|
| 1 — Fast | <5ms | Deterministic, regex-based | Invisible text, HTML sanitization, XML safe parsing |
| 2 — Medium | <50ms | ML models, pattern matching | Prompt Guard 2, Presidio PII, URL/phishing detection |
| 3 — Slow | <500ms | LLM-based | Claude Haiku judge (conditional) |

## Tech Stack

| Component | Library | Version | License |
|-----------|---------|---------|---------|
| Prompt injection detection | Meta Prompt Guard 2 | 86M params | Llama 4 Community License |
| PII detection | Microsoft Presidio | ≥2.2 | MIT |
| Dutch NER | spaCy `nl_core_news_lg` | ≥3.7 | MIT |
| HTML sanitization | html-sanitizer | ≥2.3 | BSD-3-Clause |
| XML protection | defusedxml | ≥0.7 | PSF License |
| URL safety | pysafebrowsing | ≥0.1 | MIT |
| Homoglyph detection | confusable_homoglyphs | ≥3.3 | MIT |
| Secret detection | detect-secrets (Yelp) | ≥1.4 | Apache 2.0 |
| LLM judge | Claude Haiku 4.5 (API) | — | Anthropic API ToS |
| Agent framework | Claude Agent SDK | ≥0.1 | Anthropic |

## OWASP Top 10 for LLM Applications (2025) Coverage

| # | OWASP Risk | Direction | Filter | Phase | Status |
|---|-----------|-----------|--------|-------|--------|
| LLM01 | Prompt Injection | Input | Prompt Guard 2 + Haiku Judge | 03, 06 | ✅ Covered |
| LLM02 | Sensitive Information Disclosure | Input + Output | Presidio PII + Secret detection | 04 | ✅ Covered |
| LLM03 | Supply Chain Vulnerabilities | N/A | Dependency pinning, model hash verification | 01 | ⚠️ Partially covered |
| LLM04 | Data and Model Poisoning | Input | Content filtering pipeline | 02, 03 | ⚠️ Partially covered |
| LLM05 | Improper Output Handling | Output | PII redaction + output scanning | 04, 07 | ✅ Covered |
| LLM06 | Excessive Agency | Output | Human-in-the-loop, action allowlisting | 07 | ✅ Covered |
| LLM07 | System Prompt Leakage | Output | Output scanning for system prompt fragments | 03, 06 | ✅ Covered |
| LLM08 | Vector and Embedding Weaknesses | — | — | — | ❌ Not in scope |
| LLM09 | Misinformation | Output | Haiku judge (limited) | 06 | ⚠️ Partially covered |
| LLM10 | Unbounded Consumption | Both | Rate limiting, cost controls | 07 | ✅ Covered |

## License Overview

| Library | License | Key Requirements |
|---------|---------|-----------------|
| Meta Prompt Guard 2 | Llama 4 Community License | Must display "Built with Llama"; <700M MAU threshold; must include "Llama" in derived model names; attribution: "Llama 4 is licensed under the Llama 4 Community License, Copyright Meta Platforms, Inc."; comply with Acceptable Use Policy |
| Presidio | MIT | Include copyright notice |
| spaCy | MIT | Include copyright notice |
| html-sanitizer | BSD-3-Clause | Include copyright + no endorsement clause |
| defusedxml | PSF License | Include license |
| pysafebrowsing | MIT | Include copyright notice |
| confusable_homoglyphs | MIT | Include copyright notice |
| detect-secrets | Apache 2.0 | Include license + NOTICE file |

## Phase Documents

| Phase | Document | Description |
|-------|----------|-------------|
| 0 | [00-overview.md](./00-overview.md) | This document — overview, OWASP mapping, licenses |
| 1 | [01-project-setup.md](./01-project-setup.md) | Project structure, core architecture, configuration |
| 2 | [02-input-sanitization.md](./02-input-sanitization.md) | Tier 1: HTML/XML/Unicode sanitization |
| 3 | [03-prompt-injection.md](./03-prompt-injection.md) | Tier 2: Meta Prompt Guard 2 integration |
| 4 | [04-pii-detection.md](./04-pii-detection.md) | Tier 2: Presidio + Dutch PII detection |
| 5 | [05-url-phishing.md](./05-url-phishing.md) | Tier 2: URL safety & homoglyph detection |
| 6 | [06-llm-judge.md](./06-llm-judge.md) | Tier 3: Claude Haiku judge |
| 7 | [07-agent-integration.md](./07-agent-integration.md) | Integration with Claude Agent SDK |
| 8 | [08-testing.md](./08-testing.md) | Test suite & adversarial testing |
| 9 | [09-documentation.md](./09-documentation.md) | README structure, OWASP table, licenses |

## Latency Budget

Total pipeline latency target: **<600ms** (worst case, with Tier 3).

Typical case (Tier 1 + 2 only): **<60ms**.

Tier 2 scanners run in parallel via `asyncio.gather()`, so the tier latency is determined by the slowest scanner, not the sum.

```
Tier 1 (sequential):  ~5ms
Tier 2 (parallel):   ~50ms  (Prompt Guard ~30ms, PII ~50ms, URL ~200ms*)
Tier 3 (conditional): ~300ms (only for high-risk sources)

* URL scanning runs in parallel; its higher latency doesn't block other Tier 2 scanners
```
