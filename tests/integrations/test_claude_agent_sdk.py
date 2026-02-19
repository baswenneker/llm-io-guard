"""Tests for Claude Agent SDK hook factories."""

import warnings
from typing import Any

from helpers import BlockScanner, ErrorScanner, FlagScanner, PassScanner

from llm_io_guard import InputFilter
from llm_io_guard.integrations.claude_agent_sdk import (
    _extract_nested,
    _extract_tool_content,
    _fail_open,
    extract_text,
    post_tool_use_filter_hook,
    post_tool_use_hook,
    post_tool_use_skill_hook,
    pre_tool_use_hook,
    pre_tool_use_url_hook,
    skill_guard,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_input_data(**overrides: Any) -> dict[str, Any]:
    """Build a minimal input_data dict for hook callbacks."""
    base: dict[str, Any] = {"hook_event_name": "PreToolUse"}
    base.update(overrides)
    return base


def _build_filter(*scanners: Any) -> InputFilter:
    """Build an InputFilter with the given scanners added."""
    f = InputFilter()
    for s in scanners:
        f.add(s)
    return f


# ---------------------------------------------------------------------------
# extract_text
# ---------------------------------------------------------------------------


class TestExtractText:
    """Tests for extract_text utility."""

    def test_string(self):
        assert extract_text("hello") == "hello"

    def test_dict_common_keys(self):
        for key in ("text", "content", "result", "body", "output"):
            assert extract_text({key: "value"}) == "value"

    def test_dict_fallback_json(self):
        result = extract_text({"custom_key": 42})
        assert '"custom_key": 42' in result

    def test_list(self):
        result = extract_text(["a", "b", "c"])
        assert result == "a\nb\nc"

    def test_other_types(self):
        assert extract_text(42) == "42"
        assert extract_text(None) == "None"

    def test_empty_string(self):
        assert extract_text("") == ""

    def test_dict_prefers_first_key(self):
        """When multiple common keys exist, the first match wins."""
        result = extract_text({"text": "first", "content": "second"})
        assert result == "first"


# ---------------------------------------------------------------------------
# _extract_nested
# ---------------------------------------------------------------------------


class TestExtractNested:
    """Tests for _extract_nested helper."""

    def test_simple_path(self):
        assert _extract_nested({"a": "v"}, "a") == "v"

    def test_nested_path(self):
        assert _extract_nested({"a": {"b": "v"}}, "a.b") == "v"

    def test_missing_key(self):
        assert _extract_nested({"a": "v"}, "b") == ""

    def test_non_dict_intermediate(self):
        assert _extract_nested({"a": "string"}, "a.b") == ""

    def test_empty_value(self):
        assert _extract_nested({"a": ""}, "a") == ""


# ---------------------------------------------------------------------------
# _fail_open
# ---------------------------------------------------------------------------


class TestFailOpen:
    """Tests for _fail_open decorator."""

    async def test_returns_result_on_success(self):
        @_fail_open("test_error")
        async def hook() -> dict[str, Any]:
            return {"key": "value"}

        assert await hook() == {"key": "value"}

    async def test_returns_empty_dict_on_error(self):
        @_fail_open("test_error")
        async def hook() -> dict[str, Any]:
            raise RuntimeError("boom")

        assert await hook() == {}

    async def test_preserves_function_name(self):
        @_fail_open("test_error")
        async def my_hook() -> dict[str, Any]:
            return {}

        assert my_hook.__name__ == "my_hook"


# ---------------------------------------------------------------------------
# _extract_tool_content
# ---------------------------------------------------------------------------


class TestExtractToolContent:
    """Tests for _extract_tool_content helper."""

    def test_extracts_string_response(self):
        data = {"tool_response": "hello world"}
        assert _extract_tool_content(data, 50_000) == "hello world"

    def test_truncates_to_max_length(self):
        data = {"tool_response": "a" * 100}
        assert _extract_tool_content(data, 10) == "a" * 10

    def test_returns_empty_for_whitespace(self):
        data = {"tool_response": "   \n  "}
        assert _extract_tool_content(data, 50_000) == ""

    def test_returns_empty_for_missing_response(self):
        assert _extract_tool_content({}, 50_000) == ""


# ---------------------------------------------------------------------------
# skill_guard
# ---------------------------------------------------------------------------


class TestSkillGuard:
    """Tests for skill_guard factory."""

    def test_skill_in_set(self):
        guard = skill_guard({"read-email", "send-email"})
        assert guard({"tool_input": {"skill": "read-email"}}) is True

    def test_skill_not_in_set(self):
        guard = skill_guard({"read-email"})
        assert guard({"tool_input": {"skill": "label-email"}}) is False

    def test_missing_skill_name(self):
        guard = skill_guard({"read-email"})
        assert guard({"tool_input": {}}) is False

    def test_custom_path(self):
        guard = skill_guard({"read-email"}, skill_name_path="params.skill_name")
        assert guard({"params": {"skill_name": "read-email"}}) is True


# ---------------------------------------------------------------------------
# pre_tool_use_hook
# ---------------------------------------------------------------------------


class TestPreToolUseHook:
    """Tests for pre_tool_use_hook factory."""

    async def test_pass_result(self):
        hook = pre_tool_use_hook(_build_filter(PassScanner()))
        input_data = _make_input_data(tool_input={"url": "https://example.com"})
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_block_result(self):
        hook = pre_tool_use_hook(_build_filter(BlockScanner()))
        input_data = _make_input_data(tool_input={"url": "https://evil.com"})
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    async def test_flag_result(self):
        hook = pre_tool_use_hook(_build_filter(FlagScanner()))
        input_data = _make_input_data(tool_input={"url": "https://suspicious.com"})
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert "hookSpecificOutput" not in result

    async def test_empty_value(self):
        hook = pre_tool_use_hook(_build_filter(PassScanner()))
        input_data = _make_input_data(tool_input={"url": ""})
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_missing_field(self):
        hook = pre_tool_use_hook(_build_filter(PassScanner()))
        input_data = _make_input_data(tool_input={})
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_custom_input_path(self):
        hook = pre_tool_use_hook(_build_filter(PassScanner()), input_path="params.target_url")
        input_data = _make_input_data(params={"target_url": "https://example.com"})
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_scanner_error_produces_block(self):
        """Scanner errors are fail-closed by the filter (BLOCK), surfacing a systemMessage."""
        hook = pre_tool_use_hook(_build_filter(ErrorScanner()))
        input_data = _make_input_data(tool_input={"url": "https://example.com"})
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert "BLOCKED" in result["systemMessage"]

    async def test_block_includes_hook_event_name(self):
        hook = pre_tool_use_hook(_build_filter(BlockScanner()))
        input_data = _make_input_data(
            hook_event_name="PreToolUse",
            tool_input={"url": "https://evil.com"},
        )
        result = await hook(input_data, "tool-1", {})
        assert result["hookSpecificOutput"]["hookEventName"] == "PreToolUse"


# ---------------------------------------------------------------------------
# post_tool_use_hook
# ---------------------------------------------------------------------------


class TestPostToolUseHook:
    """Tests for post_tool_use_hook factory."""

    async def test_pass_result(self):
        hook = post_tool_use_hook(_build_filter(PassScanner()))
        input_data = _make_input_data(tool_response="safe content")
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_block_result(self):
        hook = post_tool_use_hook(_build_filter(BlockScanner()))
        input_data = _make_input_data(tool_response="malicious content")
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert "BLOCKED" in result["systemMessage"]

    async def test_flag_result(self):
        hook = post_tool_use_hook(_build_filter(FlagScanner()))
        input_data = _make_input_data(tool_response="suspicious content")
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert "CAUTION" in result["systemMessage"]

    async def test_empty_response(self):
        hook = post_tool_use_hook(_build_filter(PassScanner()))
        input_data = _make_input_data(tool_response="")
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_whitespace_only_response(self):
        hook = post_tool_use_hook(_build_filter(PassScanner()))
        input_data = _make_input_data(tool_response="   \n  ")
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_truncation(self):
        hook = post_tool_use_hook(
            _build_filter(PassScanner()),
            max_content_length=10,
        )
        input_data = _make_input_data(tool_response="a" * 100)
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_metadata_forwarding(self):
        """Metadata is passed through to afilter."""
        captured: list[dict | None] = []

        class CapturingFilter(InputFilter):
            async def afilter(self, content, metadata=None):
                captured.append(metadata)
                return await super().afilter(content, metadata)

        f = CapturingFilter()
        f.add(PassScanner())
        hook = post_tool_use_hook(f, metadata={"source_risk": "high"})
        input_data = _make_input_data(tool_response="test")
        await hook(input_data, "tool-1", {})
        assert captured[0] == {"source_risk": "high"}

    async def test_scanner_error_produces_block(self):
        """Scanner errors are fail-closed by the filter (BLOCK), surfacing a systemMessage."""
        hook = post_tool_use_hook(_build_filter(ErrorScanner()))
        input_data = _make_input_data(tool_response="content")
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert "BLOCKED" in result["systemMessage"]

    async def test_dict_tool_response(self):
        hook = post_tool_use_hook(_build_filter(PassScanner()))
        input_data = _make_input_data(tool_response={"text": "hello"})
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_guard_passes(self):
        """Hook runs the filter when the guard returns True."""
        hook = post_tool_use_hook(
            _build_filter(BlockScanner()),
            guard=lambda _: True,
        )
        input_data = _make_input_data(tool_response="content")
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result

    async def test_guard_blocks(self):
        """Hook skips filtering when the guard returns False."""
        hook = post_tool_use_hook(
            _build_filter(BlockScanner()),
            guard=lambda _: False,
        )
        input_data = _make_input_data(tool_response="content")
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_with_skill_guard(self):
        """Integration: post_tool_use_hook + skill_guard."""
        hook = post_tool_use_hook(
            _build_filter(PassScanner()),
            guard=skill_guard({"read-email"}),
        )
        # Matching skill — runs filter
        input_data = _make_input_data(
            tool_input={"skill": "read-email"},
            tool_response="email body",
        )
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_with_skill_guard_skips_other_skills(self):
        """Integration: skill_guard skips non-matching skills."""
        hook = post_tool_use_hook(
            _build_filter(BlockScanner()),
            guard=skill_guard({"read-email"}),
        )
        input_data = _make_input_data(
            tool_input={"skill": "label-email"},
            tool_response="content",
        )
        result = await hook(input_data, "tool-1", {})
        assert result == {}


# ---------------------------------------------------------------------------
# Deprecated aliases — existing tests via old API
# ---------------------------------------------------------------------------


class TestPreToolUseUrlHook:
    """Tests for deprecated pre_tool_use_url_hook alias."""

    async def test_pass_result(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = pre_tool_use_url_hook(PassScanner())
        input_data = _make_input_data(tool_input={"url": "https://example.com"})
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_block_result(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = pre_tool_use_url_hook(BlockScanner())
        input_data = _make_input_data(tool_input={"url": "https://evil.com"})
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    async def test_flag_result(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = pre_tool_use_url_hook(FlagScanner())
        input_data = _make_input_data(tool_input={"url": "https://suspicious.com"})
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert "hookSpecificOutput" not in result

    async def test_empty_url(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = pre_tool_use_url_hook(PassScanner())
        input_data = _make_input_data(tool_input={"url": ""})
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_missing_url(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = pre_tool_use_url_hook(PassScanner())
        input_data = _make_input_data(tool_input={})
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_custom_path(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = pre_tool_use_url_hook(PassScanner(), url_path="params.target_url")
        input_data = _make_input_data(params={"target_url": "https://example.com"})
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_scanner_error_produces_block(self):
        """Scanner errors are fail-closed by the filter (BLOCK), surfacing a systemMessage."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = pre_tool_use_url_hook(ErrorScanner())
        input_data = _make_input_data(tool_input={"url": "https://example.com"})
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert "BLOCKED" in result["systemMessage"]

    async def test_block_includes_hook_event_name(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = pre_tool_use_url_hook(BlockScanner())
        input_data = _make_input_data(
            hook_event_name="PreToolUse",
            tool_input={"url": "https://evil.com"},
        )
        result = await hook(input_data, "tool-1", {})
        assert result["hookSpecificOutput"]["hookEventName"] == "PreToolUse"

    async def test_emits_deprecation_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            pre_tool_use_url_hook(PassScanner())
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "pre_tool_use_hook" in str(w[0].message)


class TestPostToolUseFilterHook:
    """Tests for deprecated post_tool_use_filter_hook alias."""

    async def test_pass_result(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_filter_hook(_build_filter(PassScanner()))
        input_data = _make_input_data(tool_response="safe content")
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_block_result(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_filter_hook(_build_filter(BlockScanner()))
        input_data = _make_input_data(tool_response="malicious content")
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert "BLOCKED" in result["systemMessage"]

    async def test_flag_result(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_filter_hook(_build_filter(FlagScanner()))
        input_data = _make_input_data(tool_response="suspicious content")
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert "CAUTION" in result["systemMessage"]

    async def test_empty_response(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_filter_hook(_build_filter(PassScanner()))
        input_data = _make_input_data(tool_response="")
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_whitespace_only_response(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_filter_hook(_build_filter(PassScanner()))
        input_data = _make_input_data(tool_response="   \n  ")
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_truncation(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_filter_hook(
                _build_filter(PassScanner()),
                max_content_length=10,
            )
        input_data = _make_input_data(tool_response="a" * 100)
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_metadata_forwarding(self):
        """Metadata is passed through to afilter."""
        captured: list[dict | None] = []

        class CapturingFilter(InputFilter):
            async def afilter(self, content, metadata=None):
                captured.append(metadata)
                return await super().afilter(content, metadata)

        f = CapturingFilter()
        f.add(PassScanner())
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_filter_hook(f, metadata={"source_risk": "high"})
        input_data = _make_input_data(tool_response="test")
        await hook(input_data, "tool-1", {})
        assert captured[0] == {"source_risk": "high"}

    async def test_scanner_error_produces_block(self):
        """Scanner errors are fail-closed by the filter (BLOCK), surfacing a systemMessage."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_filter_hook(_build_filter(ErrorScanner()))
        input_data = _make_input_data(tool_response="content")
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert "BLOCKED" in result["systemMessage"]

    async def test_dict_tool_response(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_filter_hook(_build_filter(PassScanner()))
        input_data = _make_input_data(tool_response={"text": "hello"})
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_emits_deprecation_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            post_tool_use_filter_hook(_build_filter(PassScanner()))
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "post_tool_use_hook" in str(w[0].message)


class TestPostToolUseSkillHook:
    """Tests for deprecated post_tool_use_skill_hook alias."""

    async def test_skill_in_set(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_skill_hook(
                _build_filter(PassScanner()),
                {"read-email"},
            )
        input_data = _make_input_data(
            tool_input={"skill": "read-email"},
            tool_response="email body",
        )
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_skill_not_in_set(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_skill_hook(
                _build_filter(PassScanner()),
                {"read-email"},
            )
        input_data = _make_input_data(
            tool_input={"skill": "label-email"},
            tool_response="ok",
        )
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_block_result(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_skill_hook(
                _build_filter(BlockScanner()),
                {"read-email"},
            )
        input_data = _make_input_data(
            tool_input={"skill": "read-email"},
            tool_response="malicious email",
        )
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert "BLOCKED" in result["systemMessage"]

    async def test_empty_response(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_skill_hook(
                _build_filter(PassScanner()),
                {"read-email"},
            )
        input_data = _make_input_data(
            tool_input={"skill": "read-email"},
            tool_response="",
        )
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_metadata_forwarding(self):
        """Metadata is passed through to afilter."""
        captured: list[dict | None] = []

        class CapturingFilter(InputFilter):
            async def afilter(self, content, metadata=None):
                captured.append(metadata)
                return await super().afilter(content, metadata)

        f = CapturingFilter()
        f.add(PassScanner())
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_skill_hook(
                f,
                {"read-email"},
                metadata={"source_risk": "high"},
            )
        input_data = _make_input_data(
            tool_input={"skill": "read-email"},
            tool_response="email body",
        )
        await hook(input_data, "tool-1", {})
        assert captured[0] == {"source_risk": "high"}

    async def test_custom_skill_name_path(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_skill_hook(
                _build_filter(PassScanner()),
                {"read-email"},
                skill_name_path="params.skill_name",
            )
        input_data = _make_input_data(
            params={"skill_name": "read-email"},
            tool_response="email body",
        )
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_scanner_error_produces_block(self):
        """Scanner errors are fail-closed by the filter (BLOCK), surfacing a systemMessage."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_skill_hook(
                _build_filter(ErrorScanner()),
                {"read-email"},
            )
        input_data = _make_input_data(
            tool_input={"skill": "read-email"},
            tool_response="content",
        )
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result
        assert "BLOCKED" in result["systemMessage"]

    async def test_missing_skill_name(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            hook = post_tool_use_skill_hook(
                _build_filter(PassScanner()),
                {"read-email"},
            )
        input_data = _make_input_data(tool_input={}, tool_response="content")
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_emits_deprecation_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            post_tool_use_skill_hook(_build_filter(PassScanner()), {"read-email"})
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "skill_guard" in str(w[0].message)
