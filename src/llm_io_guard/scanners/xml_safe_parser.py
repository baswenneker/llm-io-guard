"""Scanner that safely parses XML to prevent XXE and entity attacks."""

import defusedxml.ElementTree as DefusedET
from defusedxml import DefusedXmlException

from ..models import Action, ScanResult
from ..scanner import Scanner


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
        if content_type not in ("text/xml", "application/xml") and not content.lstrip().startswith(
            "<?xml"
        ):
            return ScanResult(
                scanner_name=self.name,
                action=Action.PASS,
                confidence=0.0,
                description="Content is not XML, skipping",
                details={"sanitized_content": content},
            )

        try:
            DefusedET.fromstring(content)
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
        except DefusedET.ParseError:
            return ScanResult(
                scanner_name=self.name,
                action=Action.PASS,
                confidence=0.0,
                description="Malformed XML (not parseable), passing through",
                details={"sanitized_content": content},
            )
