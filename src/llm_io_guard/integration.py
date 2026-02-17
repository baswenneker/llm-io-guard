"""Agent integration layer for content safety pipeline."""

import structlog

from .models import FilterResult
from .pipeline import ContentSafetyPipeline

logger = structlog.get_logger()


async def safe_fetch_email(
    pipeline: ContentSafetyPipeline,
    email_body: str,
    sender: str,
    subject: str,
    headers: dict | None = None,
    attachments: list[str] | None = None,
) -> FilterResult:
    """Scan email content through the safety pipeline before processing."""
    sender_domain = sender.split("@")[-1] if "@" in sender else "unknown"
    source_risk = "low" if _is_known_domain(sender_domain) else "unknown"

    metadata = {
        "source": "email",
        "source_risk": source_risk,
        "sender": sender,
        "subject": subject,
        "content_type": "text/html" if "<html" in email_body.lower() else "text/plain",
    }

    content = f"From: {sender}\nSubject: {subject}\n\n{email_body}"
    result = await pipeline.scan(content=content, metadata=metadata, direction="input")

    if attachments:
        logger.info("email_attachments_noted", count=len(attachments), filenames=attachments)

    return result


async def safe_fetch_webpage(
    pipeline: ContentSafetyPipeline,
    url: str,
    html_content: str,
) -> FilterResult:
    """Scan web page content through the safety pipeline before processing."""
    metadata = {
        "source": "web",
        "source_risk": "unknown",
        "url": url,
        "content_type": "text/html",
    }
    return await pipeline.scan(content=html_content, metadata=metadata, direction="input")


def _is_known_domain(domain: str) -> bool:
    """Check if sender domain is in the known/trusted list."""
    trusted_domains = {"company.com", "partner.com"}
    return domain in trusted_domains
