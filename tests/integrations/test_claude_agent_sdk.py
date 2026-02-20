"""Tests for Claude Agent SDK hook factories."""

from typing import Any

from helpers import BlockScanner, ErrorScanner, FlagScanner, PassScanner

from llm_io_guard import InputFilter
from llm_io_guard.integrations.claude_agent_sdk import (
    _extract_nested,
    _extract_tool_content,
    _fail_open,
    _skill_guard,
    extract_text,
    post_tool_use_hook,
    pre_tool_use_hook,
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
# _skill_guard (private)
# ---------------------------------------------------------------------------


class TestSkillGuard:
    """Tests for _skill_guard factory."""

    def test_skill_in_set(self):
        guard = _skill_guard({"read-email", "send-email"})
        assert guard({"tool_input": {"skill": "read-email"}}) is True

    def test_skill_not_in_set(self):
        guard = _skill_guard({"read-email"})
        assert guard({"tool_input": {"skill": "label-email"}}) is False

    def test_missing_skill_name(self):
        guard = _skill_guard({"read-email"})
        assert guard({"tool_input": {}}) is False

    def test_custom_path(self):
        guard = _skill_guard({"read-email"}, skill_name_path="params.skill_name")
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

    async def test_source_risk_forwarding(self):
        """source_risk is passed as {'source_risk': value} to afilter."""
        captured: list[dict | None] = []

        class CapturingFilter(InputFilter):
            async def afilter(self, content, metadata=None):
                captured.append(metadata)
                return await super().afilter(content, metadata)

        f = CapturingFilter()
        f.add(PassScanner())
        hook = pre_tool_use_hook(f, source_risk="high")
        input_data = _make_input_data(tool_input={"url": "https://example.com"})
        await hook(input_data, "tool-1", {})
        assert captured[0] == {"source_risk": "high"}

    async def test_default_source_risk(self):
        """Default source_risk='low' is forwarded to afilter."""
        captured: list[dict | None] = []

        class CapturingFilter(InputFilter):
            async def afilter(self, content, metadata=None):
                captured.append(metadata)
                return await super().afilter(content, metadata)

        f = CapturingFilter()
        f.add(PassScanner())
        hook = pre_tool_use_hook(f)
        input_data = _make_input_data(tool_input={"url": "https://example.com"})
        await hook(input_data, "tool-1", {})
        assert captured[0] == {"source_risk": "low"}


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

    async def test_source_risk_forwarding(self):
        """source_risk='high' is passed as {'source_risk': 'high'} to afilter."""
        captured: list[dict | None] = []

        class CapturingFilter(InputFilter):
            async def afilter(self, content, metadata=None):
                captured.append(metadata)
                return await super().afilter(content, metadata)

        f = CapturingFilter()
        f.add(PassScanner())
        hook = post_tool_use_hook(f, source_risk="high")
        input_data = _make_input_data(tool_response="test")
        await hook(input_data, "tool-1", {})
        assert captured[0] == {"source_risk": "high"}

    async def test_default_source_risk(self):
        """Default source_risk='low' is forwarded to afilter."""
        captured: list[dict | None] = []

        class CapturingFilter(InputFilter):
            async def afilter(self, content, metadata=None):
                captured.append(metadata)
                return await super().afilter(content, metadata)

        f = CapturingFilter()
        f.add(PassScanner())
        hook = post_tool_use_hook(f)
        input_data = _make_input_data(tool_response="test")
        await hook(input_data, "tool-1", {})
        assert captured[0] == {"source_risk": "low"}

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

    async def test_only_skills_matches(self):
        """Hook runs the filter when the skill is in only_skills."""
        hook = post_tool_use_hook(
            _build_filter(BlockScanner()),
            only_skills=["read-email"],
        )
        input_data = _make_input_data(
            tool_input={"skill": "read-email"},
            tool_response="content",
        )
        result = await hook(input_data, "tool-1", {})
        assert "systemMessage" in result

    async def test_only_skills_skips_other_skills(self):
        """Hook skips filtering when the skill is not in only_skills."""
        hook = post_tool_use_hook(
            _build_filter(BlockScanner()),
            only_skills=["read-email"],
        )
        input_data = _make_input_data(
            tool_input={"skill": "label-email"},
            tool_response="content",
        )
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_only_skills_accepts_set(self):
        """only_skills accepts a set as well as a list."""
        hook = post_tool_use_hook(
            _build_filter(PassScanner()),
            only_skills={"read-email"},
        )
        input_data = _make_input_data(
            tool_input={"skill": "read-email"},
            tool_response="email body",
        )
        result = await hook(input_data, "tool-1", {})
        assert result == {}

    async def test_no_only_skills_scans_all(self):
        """Without only_skills every invocation is scanned."""
        hook = post_tool_use_hook(_build_filter(BlockScanner()))
        for skill in ("read-email", "label-email", "any-skill"):
            input_data = _make_input_data(
                tool_input={"skill": skill},
                tool_response="content",
            )
            result = await hook(input_data, "tool-1", {})
            assert "systemMessage" in result
