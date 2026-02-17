# Changelog

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
