"""Hook factories for the Claude Agent SDK.

Provides factory functions that build async hook callbacks from llm_io_guard
scanners and filters.  The returned callbacks conform to the Agent SDK hook
signature ``(input_data, tool_use_id, context) -> dict`` and return plain
dicts — no dependency on ``claude_agent_sdk`` at import time.

Example usage::

    from llm_io_guard.integrations.claude_agent_sdk import (
        pre_tool_use_url_hook,
        post_tool_use_filter_hook,
        post_tool_use_skill_hook,
    )

    hooks = {
        "PreToolUse": [
            HookMatcher(matcher="WebFetch", hooks=[
                pre_tool_use_url_hook(url_scanner),
            ]),
        ],
        "PostToolUse": [
            HookMatcher(matcher="WebFetch", hooks=[
                post_tool_use_filter_hook(webfetch_filter),
            ]),
            HookMatcher(matcher="Skill", hooks=[
                post_tool_use_skill_hook(email_filter, {"read-email"}),
            ]),
        ],
    }
"""

from __future__ import annotations

import json
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any

import structlog

from ..models import Action

if TYPE_CHECKING:
    from ..filter import BaseFilter
    from ..scanner import Scanner

logger = structlog.get_logger()

HookCallback = Callable[
    [dict[str, Any], str, dict[str, Any]],
    Coroutine[Any, Any, dict[str, Any]],
]
"""Async hook callback signature expected by the Claude Agent SDK."""

_DEFAULT_MAX_CONTENT_LENGTH = 50_000


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


# ---------------------------------------------------------------------------
# Factory: PreToolUse URL hook
# ---------------------------------------------------------------------------


def pre_tool_use_url_hook(
    scanner: Scanner,
    *,
    url_path: str = "tool_input.url",
) -> HookCallback:
    """Build a PreToolUse hook that scans a URL before the tool executes.

    If the scanner returns BLOCK, the hook denies the tool call via
    ``permissionDecision``.  On FLAG, a ``systemMessage`` warning is
    injected.  On errors the hook fails open (returns ``{}``).

    Args:
        scanner: A ``Scanner`` instance (e.g. ``UrlScanner``).
        url_path: Dot-separated path to the URL inside ``input_data``.

    Returns:
        An async hook callback.
    """

    async def hook(
        input_data: dict[str, Any],
        _tool_use_id: str,
        _context: dict[str, Any],
    ) -> dict[str, Any]:
        """Scan URL and deny tool call if blocked."""
        try:
            url = _extract_nested(input_data, url_path)
            if not url:
                return {}

            logger.info("pre_tool_use_url_scan", url=url)
            result = await scanner.ascan(url)
            logger.info(
                "pre_tool_use_url_result",
                action=result.action.value,
                description=result.description,
            )

            if result.action == Action.BLOCK:
                return {
                    "systemMessage": result.system_message,
                    "hookSpecificOutput": {
                        "hookEventName": input_data.get("hook_event_name", ""),
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"URL blocked: {result.description}",
                    },
                }

            if result.system_message:
                return {"systemMessage": result.system_message}

            return {}

        except Exception:
            logger.exception("pre_tool_use_url_error")
            return {}

    return hook


# ---------------------------------------------------------------------------
# Factory: PostToolUse content filter hook
# ---------------------------------------------------------------------------


def post_tool_use_filter_hook(
    content_filter: BaseFilter,
    *,
    max_content_length: int = _DEFAULT_MAX_CONTENT_LENGTH,
    metadata: dict[str, Any] | None = None,
) -> HookCallback:
    """Build a PostToolUse hook that filters tool response content.

    Extracts text from ``input_data["tool_response"]``, runs it through the
    filter, and injects a ``systemMessage`` if content is flagged or blocked.

    Args:
        content_filter: A ``BaseFilter`` instance (e.g. ``InputFilter``).
        max_content_length: Truncate content to this length before scanning.
        metadata: Extra metadata forwarded to ``afilter()``.

    Returns:
        An async hook callback.
    """

    async def hook(
        input_data: dict[str, Any],
        _tool_use_id: str,
        _context: dict[str, Any],
    ) -> dict[str, Any]:
        """Filter tool response content and inject warnings."""
        try:
            tool_response = input_data.get("tool_response", "")
            content = extract_text(tool_response)[:max_content_length]

            if not content.strip():
                return {}

            logger.info("post_tool_use_filter_scan", content_length=len(content))

            result = await content_filter.afilter(content, metadata)

            system_message = getattr(result, "system_message", None)
            if system_message:
                return {"systemMessage": system_message}

            return {}

        except Exception:
            logger.exception("post_tool_use_filter_error")
            return {}

    return hook


# ---------------------------------------------------------------------------
# Factory: PostToolUse selective skill hook
# ---------------------------------------------------------------------------


def post_tool_use_skill_hook(
    content_filter: BaseFilter,
    skills_to_scan: set[str],
    *,
    max_content_length: int = _DEFAULT_MAX_CONTENT_LENGTH,
    metadata: dict[str, Any] | None = None,
    skill_name_path: str = "tool_input.skill",
) -> HookCallback:
    """Build a PostToolUse hook that selectively scans skill responses.

    Only scans skills whose name is in *skills_to_scan*.  Other skills
    are skipped immediately (returns ``{}``) to avoid unnecessary latency.

    Args:
        content_filter: A ``BaseFilter`` instance (e.g. ``InputFilter``).
        skills_to_scan: Set of skill names that return untrusted content.
        max_content_length: Truncate content to this length before scanning.
        metadata: Extra metadata forwarded to ``afilter()``.
        skill_name_path: Dot-separated path to the skill name in ``input_data``.

    Returns:
        An async hook callback.
    """

    async def hook(
        input_data: dict[str, Any],
        _tool_use_id: str,
        _context: dict[str, Any],
    ) -> dict[str, Any]:
        """Selectively scan skill response and inject warnings."""
        try:
            skill_name = _extract_nested(input_data, skill_name_path)

            if skill_name not in skills_to_scan:
                logger.debug("post_tool_use_skill_skipped", skill=skill_name)
                return {}

            tool_response = input_data.get("tool_response", "")
            content = extract_text(tool_response)[:max_content_length]

            if not content.strip():
                return {}

            logger.info(
                "post_tool_use_skill_scan",
                skill=skill_name,
                content_length=len(content),
            )

            result = await content_filter.afilter(content, metadata)

            system_message = getattr(result, "system_message", None)
            logger.info(
                "post_tool_use_skill_result",
                skill=skill_name,
                has_warning=system_message is not None,
            )

            if system_message:
                return {"systemMessage": system_message}

            return {}

        except Exception:
            logger.exception("post_tool_use_skill_error")
            return {}

    return hook
