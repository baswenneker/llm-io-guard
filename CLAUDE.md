# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development

This project uses **uv** as the package manager and **hatchling** as the build backend. Python 3.12+ required.

```bash
make install          # Create venv + install all extras (editable)
make dev              # Full pipeline: install → fmt → lint → docs → test
make fmt              # Format with ruff (auto-fix enabled)
make lint             # Run ruff, mypy, bandit, pyright
make typecheck        # Run pyright only
make docs             # Check docstring coverage (≥90% required)
make test             # Run all tests in parallel (-n auto)
make test-serial      # Run only @pytest.mark.serial tests
make test-cov         # Tests with coverage report
```

Run a single test file or test:
```bash
uv run pytest tests/scanners/test_pii_detector.py
uv run pytest tests/scanners/test_pii_detector.py::TestPiiDetector::test_detect_email -n0
```

Test markers: `serial`, `slow`, `adversarial`, `benchmark`. Filter with `-m`, e.g. `uv run pytest -m "not slow"`.

All tests are async (`asyncio_mode = "auto"`). Use `-n0` to disable parallel execution when debugging.

## Architecture

**llm_io_guard** is a layered content safety filter for LLM agents. It uses separate `InputFilter` and `OutputFilter` classes with a builder-pattern API. Content is processed through a 3-tier fail-fast pipeline:

```
Tier 1 (< 5ms)  → Sequential deterministic sanitization
                   InvisibleTextScanner, HtmlSanitizer, XmlSafeParser
                   Tier 1 scanners mutate content via details["sanitized_content"]

Tier 2 (< 50ms) → Parallel ML/pattern detection (asyncio.gather)
                   PromptGuardScanner, PiiDetector, UrlScanner

Tier 3 (< 500ms)→ Conditional LLM judge
                   LlmJudgeScanner (Claude Haiku)
```

Usage:
```python
from llm_io_guard import InputFilter, OutputFilter, ContentBlocked

input_filter = InputFilter()
input_filter.add(InvisibleTextScanner())
input_filter.add(PromptGuardScanner(threshold_block=0.95))

result = await input_filter.filter("untrusted content")
if result.is_safe:
    llm_response = await call_llm(result.text)

output_filter = OutputFilter()
output_filter.add(PiiDetector())
result = await output_filter.filter(llm_response)
```

Any BLOCK result short-circuits the pipeline immediately. Tier 2 scanners run concurrently. InputFilter runs Tier 3 only if content was flagged or source risk is high/unknown. OutputFilter always runs Tier 3 if scanners are registered.

Scanners declare `supported_directions` (`"input"`, `"output"`, or both). Filters reject scanners that don't support their direction.

### Key modules

| Module | Purpose |
|--------|---------|
| `src/llm_io_guard/filter.py` | `InputFilter` / `OutputFilter` — builder-pattern filter API with tiered pipeline execution |
| `src/llm_io_guard/scanner.py` | `Scanner` ABC — all scanners implement `name`, `tier`, `supported_directions`, `scan()`, optionally `initialize()` |
| `src/llm_io_guard/models.py` | `Action` (PASS/FLAG/BLOCK), `ScanResult`, `FilterResult` dataclasses |
| `src/llm_io_guard/exceptions.py` | `ContentBlocked` exception for `on_block="raise"` mode |
| `src/llm_io_guard/actions.py` | `ActionRequest`, `ActionCategory` — agent action validation with confirmation callbacks |
| `src/llm_io_guard/rate_limiter.py` | Token bucket rate limiter for cost control |
| `src/llm_io_guard/scanners/` | All 7 scanner implementations |

### Adding a scanner

1. Extend `Scanner` ABC, set `name`, `tier`, `supported_directions`, implement `scan()` returning `ScanResult`
2. Add to a filter with `filter.add(MyScanner())`
3. Add tests in `tests/scanners/`

## Code Conventions

- **Type hints**: Modern Python 3.12 syntax — `dict[str, int]`, `str | None`, `list[T]`. Use `collections.abc` for `Callable`, `Awaitable`.
- **Async**: All scanner `scan()` methods and filter methods are async. Tests use `asyncio_mode = "auto"`.
- **Imports**: stdlib → third-party → local (relative with `..`). Enforced by ruff `I` rules.
- **Line length**: 100 chars (ruff). `E501` is ignored.
- **Docstrings**: Google-style. 90% coverage enforced by `interrogate`.
- **Logging**: `structlog` with `get_logger()`. Use `log_context()` context manager, `@log_execution_time`, `@log_exceptions` decorators from `utils/logging.py`.
- **Data models**: `@dataclass(frozen=True)` for immutable value objects (`ScanResult`). Pydantic for validated config.
- **Tests**: Class-based organization. Scanner constructors take direct keyword arguments (thresholds, model paths, etc.) — no config objects.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Required for LLM judge (Tier 3) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Required for URL scanner |
| `LLM_IO_GUARD_LOG_LEVEL` | Log level (default: INFO) |
| `LLM_IO_GUARD_MAX_CONTENT_LENGTH` | Max input chars (default: 100000) |
| `LLM_IO_GUARD_MODEL_DIR` | Model cache dir (default: ~/.cache/llm_io_guard) |
