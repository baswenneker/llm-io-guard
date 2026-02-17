# Custom Scanners

This guide walks through building your own scanner for `llm_io_guard`.

## The Scanner ABC

Every scanner extends the `Scanner` abstract base class from `src/llm_io_guard/scanner.py`:

```python
from abc import ABC, abstractmethod
from llm_io_guard.models import ScanResult

class Scanner(ABC):

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
        """Scan content and return a result."""
        ...

    @property
    def supported_directions(self) -> frozenset[str]:
        """Directions this scanner supports. Default: both."""
        return frozenset({"input", "output"})

    async def initialize(self) -> None:
        """Optional async initialization (model loading, etc.)."""
```

### Members

| Member | Required | Description |
|--------|----------|-------------|
| `name` | Yes | Unique snake_case identifier (e.g. `"keyword_blocklist"`). Used in scan results and logs. |
| `tier` | Yes | Which tier this scanner runs in: `1`, `2`, or `3`. See [tier selection guide](#tier-selection-guide) below. |
| `scan()` | Yes | Async method that receives content and optional metadata, returns a `ScanResult`. Should never raise -- see [error handling](#error-handling). |
| `supported_directions` | No | `frozenset` of `"input"`, `"output"`, or both. Defaults to both. The filter rejects scanners that don't match its direction. |
| `initialize()` | No | Async setup hook called once before the first scan. Use for loading ML models, warming caches, etc. |

## Worked example: KeywordBlocklistScanner

A Tier 2 scanner that blocks content containing any of a set of banned keywords.

```python
import re

from llm_io_guard.models import Action, ScanResult
from llm_io_guard.scanner import Scanner


class KeywordBlocklistScanner(Scanner):
    """Block content that contains banned keywords."""

    def __init__(self, keywords: list[str], case_sensitive: bool = False) -> None:
        self._keywords = keywords
        flags = 0 if case_sensitive else re.IGNORECASE
        self._pattern = re.compile("|".join(re.escape(k) for k in keywords), flags)

    @property
    def name(self) -> str:
        return "keyword_blocklist"

    @property
    def tier(self) -> int:
        return 2

    @property
    def supported_directions(self) -> frozenset[str]:
        return frozenset({"input", "output"})

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        matches = self._pattern.findall(content)
        if matches:
            return ScanResult(
                scanner_name=self.name,
                action=Action.BLOCK,
                confidence=1.0,
                description=f"Blocked keyword(s) found: {', '.join(set(matches))}",
                details={"matched_keywords": list(set(matches))},
            )
        return ScanResult(
            scanner_name=self.name,
            action=Action.PASS,
            confidence=1.0,
            description="No blocked keywords found",
        )
```

## Using it

```python
from llm_io_guard import InputFilter

input_filter = InputFilter()
input_filter.add(KeywordBlocklistScanner(keywords=["DROP TABLE", "rm -rf"]))

result = await input_filter.filter("Please run: DROP TABLE users;")
print(result.action)       # Action.BLOCK
print(result.blocked_by)   # [ScanResult(scanner_name='keyword_blocklist', ...)]
```

Scanners can also be chained with the builder pattern:

```python
input_filter = (
    InputFilter()
    .add(HtmlSanitizer())
    .add(KeywordBlocklistScanner(keywords=["DROP TABLE"]))
)
```

## Content mutation (Tier 1 only)

Tier 1 scanners can transform content by including a `"sanitized_content"` key in their `ScanResult.details`. The pipeline replaces the current content with this value before passing it to the next scanner.

```python
class CensorScanner(Scanner):
    """Replace banned words with asterisks."""

    @property
    def name(self) -> str:
        return "censor"

    @property
    def tier(self) -> int:
        return 1  # Must be Tier 1 for content mutation

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        censored = content.replace("badword", "***")
        changed = censored != content
        return ScanResult(
            scanner_name=self.name,
            action=Action.FLAG if changed else Action.PASS,
            confidence=1.0,
            description="Content censored" if changed else "No changes needed",
            details={"sanitized_content": censored},
        )
```

Tier 2 and 3 scanners should **not** set `sanitized_content` -- they are detection-only.

## Testing

Tests follow a class-based async pattern. Since `asyncio_mode = "auto"` is configured, test methods are plain `async def` without extra decorators.

```python
import pytest

from llm_io_guard.models import Action


class TestKeywordBlocklistScanner:
    async def test_blocks_banned_keyword(self):
        scanner = KeywordBlocklistScanner(keywords=["DROP TABLE"])
        result = await scanner.scan("Please run: DROP TABLE users;")
        assert result.action == Action.BLOCK
        assert result.confidence == 1.0
        assert "DROP TABLE" in result.details["matched_keywords"]

    async def test_passes_clean_content(self):
        scanner = KeywordBlocklistScanner(keywords=["DROP TABLE"])
        result = await scanner.scan("SELECT * FROM users WHERE id = 1")
        assert result.action == Action.PASS

    async def test_case_insensitive_by_default(self):
        scanner = KeywordBlocklistScanner(keywords=["drop table"])
        result = await scanner.scan("DROP TABLE users")
        assert result.action == Action.BLOCK

    async def test_case_sensitive_mode(self):
        scanner = KeywordBlocklistScanner(keywords=["drop table"], case_sensitive=True)
        result = await scanner.scan("DROP TABLE users")
        assert result.action == Action.PASS
```

Key things to assert:

| Field | What to check |
|-------|--------------|
| `result.action` | `Action.PASS`, `Action.FLAG`, or `Action.BLOCK` |
| `result.confidence` | Float between 0.0 and 1.0 |
| `result.description` | Human-readable explanation |
| `result.details` | Scanner-specific data (matched keywords, sanitized content, etc.) |

## Error handling

The pipeline uses a **fail-closed** design: if your scanner raises an exception, the pipeline catches it and converts it to a BLOCK result. This means unsafe content never slips through due to a bug.

However, you should still handle expected errors within your scanner to provide better diagnostics:

```python
async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
    try:
        matches = self._check(content)
    except SomeExpectedError as e:
        return ScanResult(
            scanner_name=self.name,
            action=Action.BLOCK,
            confidence=0.0,
            description=f"Scanner error: {e}",
            details={"error": str(e)},
        )
    # ... normal logic
```

The pipeline's automatic error-to-BLOCK conversion is a safety net, not a substitute for proper error handling. A scanner that regularly throws exceptions will block all content and provide poor diagnostics.

## Tier selection guide

| Tier | When to use | Examples |
|------|------------|---------|
| **1** | Deterministic transforms that run in < 5ms. Regex, string operations, parsing. Use when you need to **modify** content before downstream scanners see it. | Strip invisible characters, sanitize HTML, censor keywords |
| **2** | ML models, API calls, or pattern matching that runs in < 50ms. Scanners that **detect** without modifying. These run in parallel, so multiple Tier 2 scanners don't add latency linearly. | Prompt injection detection, PII detection, URL checking |
| **3** | LLM-based judgment that runs in < 500ms. Use sparingly -- this tier is conditional on `InputFilter` and adds significant latency. | Content safety classification, policy compliance checking |

Rules of thumb:
- If your scanner transforms content, it **must** be Tier 1
- If your scanner is fast and deterministic, prefer Tier 1
- If your scanner uses ML or network calls, prefer Tier 2
- If your scanner needs an LLM, it must be Tier 3
- When in doubt, use Tier 2
