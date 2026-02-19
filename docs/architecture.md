# Architecture

This document describes the internal pipeline architecture of `llm_io_guard`. For a high-level overview, see the [README](../README.md#architecture).

## Pipeline overview

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

## Pipeline execution

The pipeline is implemented in `BaseFilter._run_pipeline()` (`src/llm_io_guard/filter.py`). It iterates over tiers 1, 2, and 3 in order. A BLOCK result at any tier short-circuits the pipeline immediately.

```python
result = FilterResult(action=Action.PASS, original_content=content)

for tier in (1, 2, 3):
    # skip tiers with no registered scanners
    # run scanners for this tier
    # short-circuit on BLOCK
```

Before any scanning starts, content length is checked against `max_content_length` (default 100,000 characters). Oversized content is immediately blocked.

## Tier 1: Sequential sanitization

Tier 1 scanners run **sequentially** because each one may transform the content for downstream scanners. After a Tier 1 scanner returns, the pipeline checks for a `sanitized_content` key in `scan_result.details`:

```python
if "sanitized_content" in scan_result.details:
    current_content = str(scan_result.details["sanitized_content"])
```

This means Tier 1 scanners form a chain: the output of one becomes the input to the next. After all Tier 1 scanners complete, the final sanitized content is stored on the `FilterResult` and passed to Tier 2.

Built-in Tier 1 scanners:

| Scanner | What it does |
|---------|-------------|
| `InvisibleTextScanner` | Strips zero-width characters, invisible Unicode, homoglyph obfuscation |
| `HtmlSanitizer` | Strips HTML tags, scripts, event handlers; extracts readable text |
| `XmlSafeParser` | Prevents XXE (XML External Entity) attacks via defusedxml |

### Content mutation convention

Any Tier 1 scanner can mutate content by including `"sanitized_content"` in its `details` dict. The pipeline picks this up automatically. Tier 2 and Tier 3 scanners should **not** mutate content -- they only detect and report.

## Tier 2: Parallel detection

Tier 2 scanners run **concurrently** via `asyncio.gather()` with `return_exceptions=True`:

```python
tier_results_raw = await asyncio.gather(
    *(s.ascan(current_content, scan_metadata) for s in tier_scanners),
    return_exceptions=True,
)
```

After all Tier 2 scanners complete, results are checked for BLOCKs. If any scanner blocked, the pipeline stops. If any scanner flagged, the overall result is upgraded to FLAG.

Built-in Tier 2 scanners:

| Scanner | What it does |
|---------|-------------|
| `PromptGuardScanner` | Meta Prompt Guard 2 model for prompt injection detection |
| `PiiDetector` | Microsoft Presidio with Dutch NER + secret/API key detection |
| `UrlScanner` | Google Safe Browsing API + homoglyph-based phishing detection |

## Tier 3: Conditional LLM judge

Tier 3 scanners run **sequentially** and **conditionally**. Whether Tier 3 runs depends on the filter type:

| Filter | Tier 3 runs when |
|--------|-----------------|
| `InputFilter` | Content was flagged by Tier 1/2, **or** `source_risk` metadata is `"high"` or `"unknown"` |
| `OutputFilter` | Always (if Tier 3 scanners are registered) |

The rationale: input from known-safe sources that passed Tier 1 and 2 without flags doesn't need expensive LLM review. But LLM output should always be checked for policy violations, data leakage, etc.

Built-in Tier 3 scanner:

| Scanner | What it does |
|---------|-------------|
| `LLMJudgeScanner` | Claude Haiku 4.5 content safety classifier |

## InputFilter vs OutputFilter

Both extend `BaseFilter` and share the same pipeline. They differ in two ways:

| | `InputFilter` | `OutputFilter` |
|---|---|---|
| **Direction** | `"input"` | `"output"` |
| **Tier 3 trigger** | Conditional (flagged or high-risk source) | Always |
| **Typical use** | Scan untrusted content before passing to LLM | Scan LLM responses before acting on them |
| **Scanner validation** | Only accepts scanners with `"input"` in `supported_directions` | Only accepts scanners with `"output"` in `supported_directions` |

## `on_block` modes

The `on_block` parameter controls what happens when the pipeline produces a BLOCK:

| Mode | On PASS/FLAG | On BLOCK |
|------|-------------|----------|
| `"result"` (default) | Returns `FilterResult` | Returns `FilterResult` |
| `"raise"` | Returns `str` (sanitized text) | Raises `ContentBlocked` |
| `"none"` | Returns `str` (sanitized text) | Returns `None` |

The `"result"` mode is the default and gives full access to scan results, flagged/blocked scanners, and processing time. The `"raise"` and `"none"` modes are convenience modes for simpler integration patterns.

## Error handling

The pipeline uses a **fail-closed** design: if a scanner raises an exception, the pipeline converts it to a BLOCK result rather than allowing potentially unsafe content through.

For Tier 1 and 3 (sequential execution):

```python
try:
    scan_result = await scanner.ascan(current_content, scan_metadata)
except Exception as e:
    scan_result = ScanResult(
        scanner_name=scanner.name,
        action=Action.BLOCK,
        confidence=0.0,
        description=f"Scanner error (fail-closed): {e}",
        details={"error": str(e)},
    )
```

For Tier 2, `asyncio.gather(return_exceptions=True)` captures exceptions without cancelling other scanners. After gathering, exceptions are converted to BLOCK results.

Non-Exception `BaseException` subclasses (`CancelledError`, `KeyboardInterrupt`) are re-raised rather than converted, since these represent cancellation or system-level signals.

## Latency targets

| Scope | Target |
|-------|--------|
| Tier 1 only | < 5ms |
| Tier 1 + Tier 2 | < 60ms |
| Full pipeline (Tier 1 + 2 + 3) | < 600ms |

Tier 3 dominates latency because it makes an LLM API call. The conditional trigger on `InputFilter` avoids this cost for low-risk, clean content.
