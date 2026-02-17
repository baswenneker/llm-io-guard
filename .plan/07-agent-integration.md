# Phase 7: Agent Integration

> **Goal**: Integrate the content safety pipeline with the Claude Agent SDK, providing safe wrappers for external content ingestion and action execution.
>
> **Depends on**: [Phase 1: Project Setup](./01-project-setup.md), Phases 2–6 (scanner implementations)
> **OWASP**: LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

## Overview

This phase covers how `llm_io_guard` integrates into an AI agent workflow built with the Claude Agent SDK. The integration happens at two critical boundaries:

1. **Tool-result boundary** (input): Scan content returned by tools (email fetch, web scrape) before the LLM processes it
2. **Action boundary** (output): Validate and gate agent actions before execution

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    AI AGENT                           │
│                                                      │
│  ┌──────────┐    ┌──────────────┐    ┌────────────┐  │
│  │  Tool     │───▶│ SAFETY      │───▶│ Claude     │  │
│  │  Results  │    │ PIPELINE    │    │ LLM        │  │
│  │ (input)   │    │ (input scan)│    │            │  │
│  └──────────┘    └──────────────┘    └─────┬──────┘  │
│                                            │         │
│                                      LLM Response    │
│                                            │         │
│  ┌──────────┐    ┌──────────────┐    ┌─────▼──────┐  │
│  │  Execute  │◀──│ SAFETY      │◀───│ Action     │  │
│  │  Action   │    │ PIPELINE    │    │ Parser     │  │
│  │ (output)  │    │(output scan)│    │            │  │
│  └──────────┘    └──────────────┘    └────────────┘  │
└──────────────────────────────────────────────────────┘
```

## Tool-Result Boundary Integration

### Safe Wrapper Functions

```python
# src/llm_io_guard/integration.py
from .pipeline import ContentSafetyPipeline
from .models import Action, FilterResult
import structlog

logger = structlog.get_logger()


async def safe_fetch_email(
    pipeline: ContentSafetyPipeline,
    email_body: str,
    sender: str,
    subject: str,
    headers: dict | None = None,
    attachments: list[str] | None = None,
) -> FilterResult:
    """
    Scan email content through the safety pipeline before processing.

    Args:
        pipeline: The configured ContentSafetyPipeline instance.
        email_body: The email body (HTML or plain text).
        sender: The sender email address.
        subject: The email subject line.
        headers: Optional email headers for analysis.
        attachments: Optional list of attachment filenames.

    Returns:
        FilterResult with sanitized content if safe.
    """
    # Determine source risk based on sender
    sender_domain = sender.split("@")[-1] if "@" in sender else "unknown"
    source_risk = "low" if _is_known_domain(sender_domain) else "unknown"

    metadata = {
        "source": "email",
        "source_risk": source_risk,
        "sender": sender,
        "subject": subject,
        "content_type": "text/html" if "<html" in email_body.lower() else "text/plain",
    }

    # Scan the combined content
    content = f"From: {sender}\nSubject: {subject}\n\n{email_body}"

    result = await pipeline.scan(content=content, metadata=metadata, direction="input")

    if attachments:
        logger.info(
            "email_attachments_noted",
            count=len(attachments),
            filenames=attachments,
        )
        # Attachment content scanning would go here

    return result


async def safe_fetch_webpage(
    pipeline: ContentSafetyPipeline,
    url: str,
    html_content: str,
) -> FilterResult:
    """
    Scan web page content through the safety pipeline before processing.

    Args:
        pipeline: The configured ContentSafetyPipeline instance.
        url: The URL of the web page.
        html_content: The raw HTML content of the page.

    Returns:
        FilterResult with sanitized content if safe.
    """
    metadata = {
        "source": "web",
        "source_risk": "unknown",
        "url": url,
        "content_type": "text/html",
    }

    return await pipeline.scan(content=html_content, metadata=metadata, direction="input")


def _is_known_domain(domain: str) -> bool:
    """Check if sender domain is in the known/trusted list."""
    # This should be configurable
    trusted_domains = {
        "company.com",
        "partner.com",
    }
    return domain in trusted_domains
```

### Source-Specific Preprocessing

#### Email Preprocessing

| Step | Action | Rationale |
|------|--------|-----------|
| 1. Header analysis | Extract sender, reply-to, SPF/DKIM status | Identify spoofed senders |
| 2. HTML sanitization | Strip HTML to plain text (Tier 1) | Remove script injection |
| 3. Attachment handling | Log filenames, scan text attachments | Identify dangerous files |
| 4. Encoding normalization | Decode quoted-printable, base64 | Prevent encoding bypass |

#### Web Preprocessing

| Step | Action | Rationale |
|------|--------|-----------|
| 1. HTML stripping | Remove all tags, keep text (Tier 1) | Remove embedded scripts/styles |
| 2. URL extraction | Extract all links (Tier 2) | Check for phishing URLs |
| 3. Encoding normalization | Decode HTML entities, Unicode | Prevent encoding bypass |
| 4. Content truncation | Limit to max_content_length | Prevent resource exhaustion |

## Action Boundary: Human-in-the-Loop

### Destructive Action Confirmation

```python
# src/llm_io_guard/actions.py
from dataclasses import dataclass, field
from enum import Enum


class ActionCategory(Enum):
    """Categories of agent actions by risk level."""
    READ = "read"           # Read-only operations (safe)
    NOTIFY = "notify"       # Notifications to the user (safe)
    CREATE = "create"       # Creating new resources (moderate)
    MODIFY = "modify"       # Modifying existing resources (risky)
    DELETE = "delete"       # Deleting resources (dangerous)
    SEND = "send"           # Sending to external parties (dangerous)
    EXECUTE = "execute"     # Executing code/commands (critical)


# Actions that ALWAYS require human confirmation
REQUIRES_CONFIRMATION = {
    ActionCategory.DELETE,
    ActionCategory.SEND,
    ActionCategory.EXECUTE,
}

# Actions that are allowed without confirmation
AUTO_ALLOWED = {
    ActionCategory.READ,
    ActionCategory.NOTIFY,
}


@dataclass
class ActionRequest:
    """Represents an agent action request that needs safety validation."""
    category: ActionCategory
    tool_name: str
    description: str
    parameters: dict = field(default_factory=dict)
    requires_confirmation: bool = False

    def __post_init__(self):
        self.requires_confirmation = self.category in REQUIRES_CONFIRMATION


async def validate_action(
    action: ActionRequest,
    confirm_callback=None,
) -> bool:
    """
    Validate whether an agent action should be executed.

    Args:
        action: The action to validate.
        confirm_callback: Async callback for human confirmation.
            Receives the action description and returns True/False.

    Returns:
        True if the action is allowed, False if rejected.
    """
    # Auto-allow safe actions
    if action.category in AUTO_ALLOWED:
        return True

    # Require confirmation for dangerous actions
    if action.requires_confirmation:
        if confirm_callback is None:
            logger.warning("action_blocked_no_confirmation", action=action.description)
            return False

        confirmed = await confirm_callback(
            f"The agent wants to: {action.description}\n"
            f"Tool: {action.tool_name}\n"
            f"Category: {action.category.value}\n"
            f"Allow this action?"
        )
        return confirmed

    # Default: allow with logging
    logger.info("action_auto_allowed", action=action.description, category=action.category.value)
    return True
```

### Action Allowlisting

Define which tool actions are permitted without confirmation:

```yaml
# config/default.yaml (additions)
action_policy:
  auto_allow:
    - read_email          # Reading emails
    - search_calendar     # Searching calendar
    - get_document        # Fetching documents
  require_confirmation:
    - send_email          # Sending emails to external recipients
    - delete_email        # Deleting emails
    - modify_calendar     # Changing calendar events
    - execute_code        # Running code
  always_block:
    - delete_database     # Never allow database deletion
    - modify_permissions  # Never allow permission changes
```

## Dual LLM / CaMeL Pattern

For highest-security operations, consider the **CaMeL (Capability-Mediated Language) pattern**:

1. **Primary LLM**: Processes content and generates action proposals
2. **Safety LLM**: Independently validates proposed actions against policy
3. The safety LLM has NO access to the untrusted content, only the proposed action

```
Untrusted Content ──▶ Primary LLM ──▶ Proposed Action ──▶ Safety LLM ──▶ Execute/Reject
                                                              │
                                                     (only sees the action,
                                                      not the original content)
```

This prevents an attacker from crafting content that simultaneously fools both the primary LLM and the safety classifier.

### When to Use Dual LLM

| Scenario | Pattern |
|----------|---------|
| Reading emails | Single LLM + pipeline |
| Summarizing content | Single LLM + pipeline |
| Replying to known contacts | Single LLM + pipeline |
| Sending email to new contact | Dual LLM |
| Modifying shared data | Dual LLM |
| Executing API calls | Dual LLM + human confirmation |

## Logging and Audit Trail

```python
# All safety decisions are logged with structured logging
{
    "event": "content_scanned",
    "timestamp": "2025-01-15T10:30:00Z",
    "direction": "input",
    "source": "email",
    "sender": "unknown@example.com",
    "action": "flag",
    "scanners": [
        {"name": "invisible_text", "action": "pass", "confidence": 0.0},
        {"name": "prompt_guard", "action": "flag", "confidence": 0.75},
        {"name": "pii_detector", "action": "pass", "confidence": 0.0},
    ],
    "processing_time_ms": 45.2,
}
```

Audit trail requirements:
- Log every scan decision with all scanner results
- Log every action request with approval/rejection
- Log human confirmation decisions
- Retain logs for compliance review
- Never log the full content of blocked messages (privacy)

## Rate Limiting and Cost Controls

```python
# src/llm_io_guard/rate_limiter.py
import time
from dataclasses import dataclass


@dataclass
class RateLimiter:
    """Simple token-bucket rate limiter."""
    max_requests_per_minute: int = 60
    max_cost_per_day_usd: float = 50.0
    _request_times: list[float] = None
    _daily_cost: float = 0.0
    _cost_reset_time: float = 0.0

    def __post_init__(self):
        self._request_times = []
        self._cost_reset_time = time.time()

    def check_rate_limit(self) -> bool:
        """Check if we're within rate limits."""
        now = time.time()

        # Clean old request times
        self._request_times = [t for t in self._request_times if now - t < 60]

        return len(self._request_times) < self.max_requests_per_minute

    def check_cost_limit(self, estimated_cost: float) -> bool:
        """Check if we're within daily cost limits."""
        now = time.time()

        # Reset daily cost at midnight
        if now - self._cost_reset_time > 86400:
            self._daily_cost = 0.0
            self._cost_reset_time = now

        return self._daily_cost + estimated_cost <= self.max_cost_per_day_usd

    def record_request(self, cost: float = 0.0) -> None:
        """Record a request for rate limiting."""
        self._request_times.append(time.time())
        self._daily_cost += cost
```

## Implementation Checklist

- [ ] Implement `safe_fetch_email()` wrapper
- [ ] Implement `safe_fetch_webpage()` wrapper
- [ ] Add source-specific preprocessing (email headers, HTML stripping)
- [ ] Implement `ActionRequest` and `validate_action()` for human-in-the-loop
- [ ] Define action allowlist/blocklist in configuration
- [ ] Document Dual LLM / CaMeL pattern (implementation deferred)
- [ ] Set up structured logging for audit trail
- [ ] Implement rate limiter with cost controls
- [ ] Write integration tests with mock agent workflow
- [ ] Write tests for action validation logic

## Next Phase

→ [Phase 8: Testing](./08-testing.md)
