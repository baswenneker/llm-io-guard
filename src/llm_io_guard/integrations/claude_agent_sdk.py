"""Hook factories for the Claude Agent SDK.

Provides factory functions that build async hook callbacks from llm_io_guard
scanners and filters.  The returned callbacks conform to the Agent SDK hook
signature ``(input_data, tool_use_id, context) -> dict`` and return plain
dicts — no dependency on ``claude_agent_sdk`` at import time.

Two generic hooks cover all use cases:

- **pre_tool_use_hook**: Filters an input field (URL, prompt, …) through a
  ``BaseFilter`` before the tool executes.
- **post_tool_use_hook**: Filters the tool response through a ``BaseFilter``
  after execution, with an optional *only_skills* list to skip irrelevant
  invocations.

Example usage::

    from llm_io_guard.integrations.claude_agent_sdk import (
        post_tool_use_hook,
        pre_tool_use_hook,
    )

    hooks = {
        "PreToolUse": [
            HookMatcher(matcher="WebFetch", hooks=[
                pre_tool_use_hook(url_filter),
            ]),
        ],
        "PostToolUse": [
            HookMatcher(matcher="WebFetch", hooks=[
                post_tool_use_hook(webfetch_filter),
            ]),
            HookMatcher(matcher="Skill", hooks=[
                post_tool_use_hook(email_filter, only_skills=["read-email"], source_risk="high"),
            ]),
        ],
    }
"""

from __future__ import annotations

import json
from functools import wraps
from typing import TYPE_CHECKING, Any, Literal, cast

import structlog

from ..models import Action

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from claude_agent_sdk.types import HookCallback

    from ..filter import BaseFilter

logger = structlog.get_logger()

"""Async hook callback signature expected by the Claude Agent SDK.

The ``HookCallback`` type is re-exported from ``claude_agent_sdk.types``
at type-checking time so that factories return the exact same type the SDK
expects.  At runtime the type is not needed — the functions are plain
``async def`` callables.
"""

_DEFAULT_MAX_CONTENT_LENGTH = 50_000


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def extract_text(tool_response: object) -> str:
    """Extract scannable text content from a tool response.

    Handles strings, dicts (tries common text keys, falls back to JSON),
    lists (joins elements), and arbitrary objects (``str()``).

    Args:
        tool_response: The raw tool response from the Agent SDK.

    Returns:
        A string suitable for scanning.
    """
    if isinstance(tool_response, str):
        return tool_response
    if isinstance(tool_response, dict):
        for key in ("text", "content", "result", "body", "output"):
            if key in tool_response and isinstance(tool_response[key], str):
                return tool_response[key]
        return json.dumps(tool_response, default=str)
    if isinstance(tool_response, list):
        return "\n".join(str(item) for item in tool_response)
    return str(tool_response)


def _extract_nested(data: dict[str, Any], path: str) -> str:
    """Traverse nested dict keys separated by dots.

    Args:
        data: The dict to traverse.
        path: Dot-separated key path (e.g. ``"tool_input.url"``).

    Returns:
        The leaf value as a string, or ``""`` if any key is missing or
        an intermediate value is not a dict.
    """
    current: Any = data
    for key in path.split("."):
        if not isinstance(current, dict):
            return ""
        current = current.get(key, "")
    return str(current) if current else ""


def _fail_open(error_event: str) -> Callable:
    """Decorator that catches exceptions and returns ``{}`` (fail-open).

    Args:
        error_event: The structlog event name used when logging the exception.

    Returns:
        A decorator wrapping an async hook function.
    """

    def decorator(func: Callable[..., Coroutine[Any, Any, dict[str, Any]]]) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
            try:
                return await func(*args, **kwargs)
            except Exception:
                logger.exception(error_event)
                return {}

        return wrapper

    return decorator


def _extract_tool_content(input_data: dict[str, Any], max_length: int) -> str:
    """Extract and truncate text from a tool response.

    Args:
        input_data: The hook ``input_data`` dict.
        max_length: Maximum character length after extraction.

    Returns:
        Extracted text, or ``""`` if the result is whitespace-only.
    """
    tool_response = input_data.get("tool_response", "")
    content = extract_text(tool_response)[:max_length]
    return content if content.strip() else ""


# ---------------------------------------------------------------------------
# Guard helpers (private)
# ---------------------------------------------------------------------------


def _skill_guard(
    skills_to_scan: set[str],
    *,
    skill_name_path: str = "tool_input.skill",
) -> Callable[[dict[str, Any]], bool]:
    """Build a guard that only passes for skills in the given set.

    Args:
        skills_to_scan: Set of skill names that should be scanned.
        skill_name_path: Dot-separated path to the skill name in ``input_data``.

    Returns:
        A callable that accepts ``input_data`` and returns ``True`` if the
        skill should be scanned.
    """

    def guard(input_data: dict[str, Any]) -> bool:
        skill_name = _extract_nested(input_data, skill_name_path)
        return skill_name in skills_to_scan

    return guard


# ---------------------------------------------------------------------------
# Factory: PreToolUse hook
# ---------------------------------------------------------------------------


def pre_tool_use_hook(
    content_filter: BaseFilter,
    *,
    input_path: str = "tool_input.url",
    source_risk: Literal["low", "high", "unknown"] = "low",
) -> HookCallback:
    """Build a PreToolUse hook that filters an input field before tool execution.

    Extracts a value from ``input_data`` at *input_path*, runs it through the
    filter pipeline, and returns a hook response.  If the filter returns BLOCK,
    the hook denies the tool call via ``permissionDecision``.  On FLAG, a
    ``systemMessage`` warning is injected.  Scanner errors are handled by the
    filter (fail-closed as BLOCK).  The ``_fail_open`` decorator serves as a
    last-resort safety net for unexpected errors in the hook logic itself.

    Args:
        content_filter: A ``BaseFilter`` instance (e.g. ``InputFilter``).
        input_path: Dot-separated path to the field inside ``input_data``.
        source_risk: Risk level of the content source, forwarded to
            ``afilter()`` as ``{"source_risk": source_risk}``.  Use ``"high"``
            for untrusted external content to trigger Tier 3 scanning.

    Returns:
        An async hook callback.
    """
    metadata = {"source_risk": source_risk}

    @_fail_open("pre_tool_use_hook_error")
    async def hook(
        input_data: dict[str, Any],
        _tool_use_id: str | None,
        _context: dict[str, Any],
    ) -> dict[str, Any]:
        """Filter input field and deny tool call if blocked."""
        value = _extract_nested(input_data, input_path)
        if not value:
            return {}

        logger.info("pre_tool_use_scan", input_path=input_path, value=value)
        result = await content_filter.afilter(value, metadata)

        action = getattr(result, "action", None)
        logger.info("pre_tool_use_result", action=action.value if action else None)

        if action == Action.BLOCK:
            blocked_by = getattr(result, "blocked_by", [])
            descriptions = "; ".join(r.description for r in blocked_by)
            return {
                "systemMessage": getattr(result, "system_message", None),
                "hookSpecificOutput": {
                    "hookEventName": input_data.get("hook_event_name", ""),
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"Blocked: {descriptions}",
                },
            }

        system_message = getattr(result, "system_message", None)
        if system_message:
            return {"systemMessage": system_message}

        return {}

    return cast("HookCallback", hook)


# ---------------------------------------------------------------------------
# Factory: PostToolUse hook
# ---------------------------------------------------------------------------


def post_tool_use_hook(
    content_filter: BaseFilter,
    *,
    only_skills: list[str] | set[str] | None = None,
    max_content_length: int = _DEFAULT_MAX_CONTENT_LENGTH,
    source_risk: Literal["low", "high", "unknown"] = "low",
) -> HookCallback:
    """Build a PostToolUse hook that filters tool response content.

    Extracts text from ``input_data["tool_response"]``, runs it through the
    filter, and injects a ``systemMessage`` if content is flagged or blocked.

    When *only_skills* is provided the hook only runs the filter for skill
    invocations whose name (``tool_input.skill``) appears in the list.  All
    other invocations return ``{}`` immediately without scanning.

    Args:
        content_filter: A ``BaseFilter`` instance (e.g. ``InputFilter``).
        only_skills: Optional list or set of skill names to scan.  When
            provided, invocations for other skills are skipped entirely.
        max_content_length: Truncate content to this length before scanning.
        source_risk: Risk level of the content source, forwarded to
            ``afilter()`` as ``{"source_risk": source_risk}``.  Use ``"high"``
            for untrusted external content to trigger Tier 3 scanning.

    Returns:
        An async hook callback.
    """
    guard = _skill_guard(set(only_skills)) if only_skills is not None else None
    metadata = {"source_risk": source_risk}

    @_fail_open("post_tool_use_hook_error")
    async def hook(
        input_data: dict[str, Any],
        _tool_use_id: str | None,
        _context: dict[str, Any],
    ) -> dict[str, Any]:
        """Filter tool response content and inject warnings."""
        if guard is not None and not guard(input_data):
            logger.debug("post_tool_use_guard_skipped")
            return {}

        content = _extract_tool_content(input_data, max_content_length)
        if not content:
            return {}

        logger.info("post_tool_use_scan", content_length=len(content))

        result = await content_filter.afilter(content, metadata)

        system_message = getattr(result, "system_message", None)
        if system_message:
            return {"systemMessage": system_message}

        return {}

    return cast("HookCallback", hook)
