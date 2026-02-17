# Phase 2: Input Sanitization (Tier 1)

> **Goal**: Implement fast, deterministic sanitization scanners that strip potentially dangerous content before it reaches ML models or the LLM.
>
> **Depends on**: [Phase 1: Project Setup](./01-project-setup.md)
> **Tier**: 1 — Fast (<5ms, deterministic)
> **Position**: Always runs first in the pipeline

## Overview

Tier 1 scanners handle content sanitization — they clean and normalize input to prevent encoding-based attacks. These scanners are:

- **Deterministic**: No ML models, no probability thresholds
- **Fast**: Pure regex/string operations, <5ms total
- **Sequential**: They modify content in-place, so order matters

### Execution Order

1. `InvisibleTextScanner` — strip invisible/control characters
2. `HtmlSanitizer` — strip HTML to plain text
3. `XmlSafeParser` — prevent XXE and entity expansion attacks

## InvisibleTextScanner

Detects and removes invisible Unicode characters that can be used to hide prompt injections.

### Attack Vectors

- **Zero-width characters**: `\u200b` (zero-width space), `\u200c` (zero-width non-joiner), `\u200d` (zero-width joiner), `\ufeff` (BOM)
- **RTL overrides**: `\u202a`–`\u202e`, `\u2066`–`\u2069` — can visually reorder text
- **Tag characters**: `\U000e0001`–`\U000e007f` — Unicode tag characters used to hide text
- **Variation selectors**: `\ufe00`–`\ufe0f`, `\U000e0100`–`\U000e01ef`
- **Invisible separators**: `\u2028` (line separator), `\u2029` (paragraph separator)

### Implementation

```python
# src/llm_io_guard/scanners/invisible_text.py
import re
from ..scanner import Scanner
from ..models import Action, ScanResult

# Pattern matching invisible/dangerous Unicode characters
INVISIBLE_CHARS_PATTERN = re.compile(
    r"["
    r"\u200b-\u200f"    # Zero-width and directional marks
    r"\u202a-\u202e"    # Directional formatting
    r"\u2060-\u2064"    # Invisible operators
    r"\u2066-\u2069"    # Directional isolates
    r"\ufeff"           # BOM / zero-width no-break space
    r"\ufff9-\ufffb"    # Interlinear annotations
    r"\U000e0001-\U000e007f"  # Tag characters
    r"\u0000-\u0008"    # C0 control chars (except tab \t, newline \n, carriage return \r)
    r"\u000b"           # Vertical tab
    r"\u000e-\u001f"    # More C0 control chars
    r"\u007f"           # DEL
    r"\u0080-\u009f"    # C1 control chars
    r"]+"
)

# Variation selectors (less dangerous, but flag them)
VARIATION_SELECTORS = re.compile(
    r"[\ufe00-\ufe0f\U000e0100-\U000e01ef]+"
)


class InvisibleTextScanner(Scanner):
    """Detects and strips invisible Unicode characters."""

    @property
    def name(self) -> str:
        return "invisible_text"

    @property
    def tier(self) -> int:
        return 1

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        # Find all invisible characters
        invisible_matches = INVISIBLE_CHARS_PATTERN.findall(content)
        variation_matches = VARIATION_SELECTORS.findall(content)

        total_invisible = sum(len(m) for m in invisible_matches)
        total_variations = sum(len(m) for m in variation_matches)

        # Strip invisible characters
        sanitized = INVISIBLE_CHARS_PATTERN.sub("", content)
        sanitized = VARIATION_SELECTORS.sub("", sanitized)

        if total_invisible > 0:
            # High count of invisible chars is suspicious
            if total_invisible > 10:
                return ScanResult(
                    scanner_name=self.name,
                    action=Action.FLAG,
                    confidence=min(total_invisible / 50, 1.0),
                    description=f"Stripped {total_invisible} invisible characters "
                                f"(possible content hiding attack)",
                    details={
                        "sanitized_content": sanitized,
                        "invisible_char_count": total_invisible,
                        "variation_selector_count": total_variations,
                    },
                )
            return ScanResult(
                scanner_name=self.name,
                action=Action.PASS,
                confidence=0.0,
                description=f"Stripped {total_invisible} invisible characters (benign)",
                details={"sanitized_content": sanitized},
            )

        return ScanResult(
            scanner_name=self.name,
            action=Action.PASS,
            confidence=0.0,
            description="No invisible characters detected",
            details={"sanitized_content": sanitized},
        )
```

## HtmlSanitizer

Strips all HTML to plain text. This is critical for email content and web-scraped data.

### Implementation

```python
# src/llm_io_guard/scanners/html_sanitizer.py
from html_sanitizer import Sanitizer as HtmlSanitizerLib
from ..scanner import Scanner
from ..models import Action, ScanResult

# Configure to strip ALL HTML, keeping only text content
SANITIZER = HtmlSanitizerLib(
    tags=set(),              # No tags allowed
    attributes={},           # No attributes allowed
    empty=set(),             # No self-closing tags
    separate={"p", "br", "div", "li", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6"},
    whitespace={"br"},
)


class HtmlSanitizer(Scanner):
    """Strips HTML to plain text, preserving readable structure."""

    @property
    def name(self) -> str:
        return "html_sanitizer"

    @property
    def tier(self) -> int:
        return 1

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        content_type = (metadata or {}).get("content_type", "text/plain")

        # Only sanitize HTML content
        if content_type not in ("text/html", "text/xml") and "<" not in content:
            return ScanResult(
                scanner_name=self.name,
                action=Action.PASS,
                confidence=0.0,
                description="Content is plain text, no HTML sanitization needed",
                details={"sanitized_content": content},
            )

        sanitized = SANITIZER.sanitize(content)

        # Check if significant content was removed (possible hidden content)
        original_len = len(content)
        sanitized_len = len(sanitized)
        reduction_ratio = 1 - (sanitized_len / original_len) if original_len > 0 else 0

        if reduction_ratio > 0.8:
            return ScanResult(
                scanner_name=self.name,
                action=Action.FLAG,
                confidence=reduction_ratio,
                description=f"HTML sanitization removed {reduction_ratio:.0%} of content "
                            f"(possible hidden content attack)",
                details={
                    "sanitized_content": sanitized,
                    "original_length": original_len,
                    "sanitized_length": sanitized_len,
                },
            )

        return ScanResult(
            scanner_name=self.name,
            action=Action.PASS,
            confidence=0.0,
            description="HTML sanitized to plain text",
            details={"sanitized_content": sanitized},
        )
```

## XmlSafeParser

Prevents XML-based attacks (XXE, billion laughs, entity expansion).

### Attack Vectors

- **XXE (XML External Entity)**: Reading local files via entity declarations
- **Billion Laughs**: Exponential entity expansion causing DoS
- **DTD retrieval**: Network requests via external DTD references

### Implementation

```python
# src/llm_io_guard/scanners/xml_safe_parser.py
import defusedxml.ElementTree as ET
from defusedxml import DefusedXmlException
from ..scanner import Scanner
from ..models import Action, ScanResult


class XmlSafeParser(Scanner):
    """Validates and safely parses XML content to prevent XXE and entity attacks."""

    @property
    def name(self) -> str:
        return "xml_safe_parser"

    @property
    def tier(self) -> int:
        return 1

    async def scan(self, content: str, metadata: dict | None = None) -> ScanResult:
        content_type = (metadata or {}).get("content_type", "text/plain")

        # Only check content that looks like XML
        if content_type not in ("text/xml", "application/xml") and not content.lstrip().startswith("<?xml"):
            return ScanResult(
                scanner_name=self.name,
                action=Action.PASS,
                confidence=0.0,
                description="Content is not XML, skipping",
                details={"sanitized_content": content},
            )

        try:
            # defusedxml will raise on malicious XML
            ET.fromstring(content)
            return ScanResult(
                scanner_name=self.name,
                action=Action.PASS,
                confidence=0.0,
                description="XML parsed safely, no malicious entities detected",
                details={"sanitized_content": content},
            )
        except DefusedXmlException as e:
            return ScanResult(
                scanner_name=self.name,
                action=Action.BLOCK,
                confidence=1.0,
                description=f"Malicious XML detected: {type(e).__name__}",
                details={
                    "attack_type": type(e).__name__,
                    "error": str(e),
                },
            )
        except ET.ParseError:
            # Malformed XML — not necessarily malicious, pass through
            return ScanResult(
                scanner_name=self.name,
                action=Action.PASS,
                confidence=0.0,
                description="Malformed XML (not parseable), passing through",
                details={"sanitized_content": content},
            )
```

## Regex Patterns for Encoding Tricks

Additional regex patterns for detecting common encoding-based attacks:

```python
# src/llm_io_guard/scanners/invisible_text.py (additional patterns)

# Base64-encoded prompt injections
BASE64_PROMPT_PATTERN = re.compile(
    r"(?:data:text/[^;]+;base64,|atob\(|base64\.b64decode\()"
)

# Unicode escape sequences that might hide content
UNICODE_ESCAPE_PATTERN = re.compile(
    r"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|&#x?[0-9a-fA-F]+;){3,}"
)

# Homoglyph-heavy text (Latin mixed with Cyrillic/Greek lookalikes)
# Detected by checking for mixed-script content
MIXED_SCRIPT_PATTERN = re.compile(
    r"[\u0400-\u04ff].*[a-zA-Z]|[a-zA-Z].*[\u0400-\u04ff]"  # Latin + Cyrillic
)
```

## Performance Requirements

| Scanner | Target Latency | Method |
|---------|---------------|--------|
| InvisibleTextScanner | <1ms | Regex substitution |
| HtmlSanitizer | <3ms | html-sanitizer library |
| XmlSafeParser | <2ms | defusedxml parsing |
| **Total Tier 1** | **<5ms** | Sequential |

## Implementation Checklist

- [ ] Implement `InvisibleTextScanner` with comprehensive Unicode pattern
- [ ] Implement `HtmlSanitizer` with html-sanitizer library
- [ ] Implement `XmlSafeParser` with defusedxml
- [ ] Add encoding trick detection patterns
- [ ] Write unit tests for each scanner
- [ ] Write tests for known invisible text attacks
- [ ] Benchmark all scanners (must be <5ms total)

## Next Phase

→ [Phase 3: Prompt Injection Detection](./03-prompt-injection.md)
