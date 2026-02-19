"""Tier 1 scanner that safely parses XML to prevent XXE and entity attacks.

Uses ``defusedxml`` to detect XML eXternal Entity (XXE) injection, billion-laughs
entity expansion, and other XML-based attacks. Blocks only confirmed malicious
entities; malformed (unparseable) XML is passed through because it cannot carry
an entity-based payload.
"""

import defusedxml.ElementTree as DefusedET
from defusedxml import DefusedXmlException

from ..models import Action, ScanResult
from ..scanner import Scanner


class XmlSafeParser(Scanner):
    """Tier 1 input scanner that validates XML against XXE and entity attacks.

    Uses ``defusedxml`` to parse XML safely. Blocks content when a
    ``DefusedXmlException`` is raised (external entities, DTD processing, etc.).
    Malformed XML that cannot be parsed is passed through because unparseable
    XML cannot exploit entity-expansion vulnerabilities.
    """

    name = "xml_safe_parser"
    tier = 1
    supported_directions = frozenset({"input"})

    async def ascan(self, content: str, metadata: dict | None = None) -> ScanResult:
        """Parse XML safely and block content with malicious entities.

        Args:
            content: The text content to scan.
            metadata: Optional dict; uses ``content_type`` key to decide
                whether to parse (defaults to ``"text/plain"``).

        Returns:
            ScanResult with BLOCK for malicious XML entities, PASS otherwise.
        """
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
            # Malformed XML cannot carry entity-expansion attacks, so it's safe
            # to pass through. Downstream consumers will handle parse errors.
            return ScanResult(
                scanner_name=self.name,
                action=Action.PASS,
                confidence=0.0,
                description="Malformed XML (not parseable), passing through",
                details={"sanitized_content": content},
            )
