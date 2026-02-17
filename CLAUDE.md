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

**llm_io_guard** is a layered content safety pipeline for LLM agents. It processes untrusted content through a 3-tier fail-fast pipeline:

```
Tier 1 (< 5ms)  → Sequential deterministic sanitization
                   InvisibleTextScanner, HtmlSanitizer, XmlSafeParser
                   Tier 1 scanners mutate content via details["sanitized_content"]

Tier 2 (< 50ms) → Parallel ML/pattern detection (asyncio.gather)
                   PromptGuardScanner, PiiDetector, UrlScanner

Tier 3 (< 500ms)→ Conditional LLM judge (only for high-risk sources or flagged content)
                   LlmJudgeScanner (Claude Haiku)
```

Any BLOCK result short-circuits the pipeline immediately. Tier 2 scanners run concurrently. Tier 3 only runs if content was flagged or the source is in `tier3_sources` (email, web, unknown).

### Key modules

| Module | Purpose |
|--------|---------|
| `src/llm_io_guard/pipeline.py` | `ContentSafetyPipeline` orchestrator — registers scanners by tier, runs fail-fast |
| `src/llm_io_guard/scanner.py` | `Scanner` ABC — all scanners implement `name`, `tier`, `scan()`, optionally `initialize()` |
| `src/llm_io_guard/models.py` | `Action` (PASS/FLAG/BLOCK), `ScanResult`, `FilterResult` dataclasses |
| `src/llm_io_guard/config.py` | `PipelineConfig` / `ScannerConfig` (Pydantic) — loads from YAML or env vars |
| `src/llm_io_guard/actions.py` | `ActionRequest`, `ActionCategory` — agent action validation with confirmation callbacks |
| `src/llm_io_guard/integration.py` | `safe_fetch_email()`, `safe_fetch_webpage()` — convenience wrappers |
| `src/llm_io_guard/rate_limiter.py` | Token bucket rate limiter for cost control |
| `src/llm_io_guard/scanners/` | All 7 scanner implementations |

### Adding a scanner

1. Extend `Scanner` ABC, set `name`, `tier`, implement `scan()` returning `ScanResult`
2. Register with `pipeline.register_scanner(MyScanner())`
3. Add config to `config/default.yaml`
4. Add tests in `tests/scanners/`

## Code Conventions

- **Type hints**: Modern Python 3.12 syntax — `dict[str, int]`, `str | None`, `list[T]`. Use `collections.abc` for `Callable`, `Awaitable`.
- **Async**: All scanner `scan()` methods and pipeline methods are async. Tests use `asyncio_mode = "auto"`.
- **Imports**: stdlib → third-party → local (relative with `..`). Enforced by ruff `I` rules.
- **Line length**: 100 chars (ruff). `E501` is ignored.
- **Docstrings**: Google-style. 90% coverage enforced by `interrogate`.
- **Logging**: `structlog` with `get_logger()`. Use `log_context()` context manager, `@log_execution_time`, `@log_exceptions` decorators from `utils/logging.py`.
- **Config**: Pydantic `BaseModel` with `from_yaml()` / `from_env()` factory methods.
- **Data models**: `@dataclass(frozen=True)` for immutable value objects (`ScanResult`). Pydantic for validated config.
- **Tests**: Class-based organization. Integration tests create pipelines with only Tier 1 scanners to avoid model dependencies.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Required for LLM judge (Tier 3) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Required for URL scanner |
| `LLM_IO_GUARD_LOG_LEVEL` | Log level (default: INFO) |
| `LLM_IO_GUARD_MAX_CONTENT_LENGTH` | Max input chars (default: 100000) |
| `LLM_IO_GUARD_MODEL_DIR` | Model cache dir (default: ~/.cache/llm_io_guard) |
