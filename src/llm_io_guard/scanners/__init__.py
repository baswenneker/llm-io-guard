"""Scanner implementations for the content safety pipeline.

Tier 1 scanners (lightweight, no external deps) are imported eagerly.
Tier 2/3 scanners with heavy dependencies (torch, presidio, anthropic) are
lazy-loaded via ``__getattr__`` so that ``import llm_io_guard.scanners``
does not pull in ML libraries unless actually used.
"""

from .html_sanitizer import HtmlSanitizer
from .invisible_text import InvisibleTextScanner
from .xml_safe_parser import XmlSafeParser

# All public scanner classes — includes lazy-loaded names so that
# ``from llm_io_guard.scanners import PromptGuardScanner`` works.
__all__ = [
    "HtmlSanitizer",
    "InvisibleTextScanner",
    "LLMJudgeScanner",
    "PiiDetector",
    "PromptGuardScanner",
    "UrlScanner",
    "XmlSafeParser",
]

# Mapping of class name → relative module for lazy imports.
_LAZY_IMPORTS: dict[str, str] = {
    "LLMJudgeScanner": ".llm_judge",
    "PiiDetector": ".pii_detector",
    "PromptGuardScanner": ".prompt_guard",
    "UrlScanner": ".url_scanner",
}


def __getattr__(name: str) -> type:
    """Lazily import optional scanners to avoid pulling in heavy dependencies."""
    if name in _LAZY_IMPORTS:
        import importlib

        module = importlib.import_module(_LAZY_IMPORTS[name], __package__)
        obj = getattr(module, name)
        globals()[name] = obj  # Cache for subsequent access
        return obj
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
