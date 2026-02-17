"""Scanner that detects and strips invisible Unicode characters."""

import re

from ..models import Action, ScanResult
from ..scanner import Scanner

# Pattern matching invisible/dangerous Unicode characters
INVISIBLE_CHARS_PATTERN = re.compile(
    r"["
    r"\u200b-\u200f"  # Zero-width and directional marks
    r"\u202a-\u202e"  # Directional formatting
    r"\u2060-\u2064"  # Invisible operators
    r"\u2066-\u2069"  # Directional isolates
    r"\ufeff"  # BOM / zero-width no-break space
    r"\ufff9-\ufffb"  # Interlinear annotations
    r"\U000e0001-\U000e007f"  # Tag characters
    r"\u0000-\u0008"  # C0 control chars (except tab, newline, carriage return)
    r"\u000b"  # Vertical tab
    r"\u000e-\u001f"  # More C0 control chars
    r"\u007f"  # DEL
    r"\u0080-\u009f"  # C1 control chars
    r"]+"
)

VARIATION_SELECTORS = re.compile(r"[\ufe00-\ufe0f\U000e0100-\U000e01ef]+")


class InvisibleTextScanner(Scanner):
    """Detects and strips invisible Unicode characters."""

    @property
    def name(self) -> str:
        return "invisible_text"

    @property
    def tier(self) -> int:
        return 1

    @property
    def supported_directions(self) -> frozenset[str]:
        """Only supports input direction."""
        return frozenset({"input"})

    async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
        invisible_matches = INVISIBLE_CHARS_PATTERN.findall(content)
        variation_matches = VARIATION_SELECTORS.findall(content)

        total_invisible = sum(len(m) for m in invisible_matches)
        total_variations = sum(len(m) for m in variation_matches)

        sanitized = INVISIBLE_CHARS_PATTERN.sub("", content)
        sanitized = VARIATION_SELECTORS.sub("", sanitized)

        if total_invisible > 0:
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
