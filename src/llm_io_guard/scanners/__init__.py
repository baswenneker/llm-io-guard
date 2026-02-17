"""Scanner implementations for the content safety pipeline."""

from .html_sanitizer import HtmlSanitizer
from .invisible_text import InvisibleTextScanner
from .xml_safe_parser import XmlSafeParser

__all__ = [
    "HtmlSanitizer",
    "InvisibleTextScanner",
    "LlmJudgeScanner",
    "PiiDetector",
    "PromptGuardScanner",
    "UrlScanner",
    "XmlSafeParser",
]

_LAZY_IMPORTS: dict[str, str] = {
    "LlmJudgeScanner": ".llm_judge",
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
