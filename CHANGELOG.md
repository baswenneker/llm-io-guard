# Changelog

### 2026-02-17 [UNRELEASED]

**Commit: 6105aac**
- [Documentation] Restructure README and add custom scanner guides

**Commit: 94a5da5**
- [Changed] Improve build process and PyPI publication workflow with CI enhancements

**Commit: 5c31b27**
- [Added] Add `pytest.importorskip` guards and `ImportError` test coverage for optional dependencies

**Commit: 08ee4e9**
- [Fixed] Implement fail-closed error handling in `PromptGuardScanner`

**Commit: 6e06642**
- [Changed] Cache lazy imports in scanners `__getattr__` for better performance

**Commit: ab80b46**
- [Changed] Restore type annotations in `LlmJudgeScanner` via `TYPE_CHECKING`

**Commit: 240a952**
- [Added] Prepare for PyPI publication with optional dependency groups (`ml`, `pii`, `url`, `llm`)

**Commit: 4a060ba**
- [Security] Implement fail-closed error handling and response validation across scanners

**Commit: c4fad47**
- [Changed] Replace `ContentSafetyPipeline` with `InputFilter`/`OutputFilter` builder-pattern API

**Commit: f2805f0**
- [Documentation] Add CLAUDE.md with development guide and architecture overview

**Commit: 5854cb0**
- [Changed] Comprehensive code review fixes and test updates

**Commit: 1a088e4**
- [Added] Implement comprehensive testing suite (Phase 08)

**Commit: 61bc727**
- [Documentation] Create comprehensive project documentation

**Commit: 192a9e6**
- [Fixed] Resolve mypy/pyright type errors and add scanner exports

**Commit: eea52db**
- [Added] Implement agent integration layer with action validation and rate limiting

## [0.1.0] - 2025-01-15

### Added
- Core pipeline orchestrator with 3-tier architecture
- Tier 1 scanners: InvisibleTextScanner, HtmlSanitizer, XmlSafeParser
- Tier 2 scanners: PromptGuardScanner (Meta Prompt Guard 2), PiiDetector (Presidio), UrlScanner
- Tier 3 scanner: LlmJudgeScanner (Claude Haiku 4.5)
- Agent integration layer with safe_fetch_email() and safe_fetch_webpage()
- Action validation with human-in-the-loop support
- Rate limiter with cost controls
- Dutch PII support (BSN, phone numbers, postal codes)
- Comprehensive test suite with adversarial tests
- OWASP Top 10 for LLM Applications coverage
