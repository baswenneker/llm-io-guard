"""Tests for action validation."""

from unittest.mock import AsyncMock

from llm_io_guard.actions import ActionCategory, ActionRequest, validate_action


class TestActionRequestPostInit:
    """Tests for ActionRequest post_init behavior."""

    def test_action_request_post_init(self):
        read_action = ActionRequest(
            category=ActionCategory.READ, tool_name="read_file", description="Read a file"
        )
        assert read_action.requires_confirmation is False

        delete_action = ActionRequest(
            category=ActionCategory.DELETE, tool_name="rm", description="Delete a file"
        )
        assert delete_action.requires_confirmation is True

        send_action = ActionRequest(
            category=ActionCategory.SEND, tool_name="email", description="Send email"
        )
        assert send_action.requires_confirmation is True

        execute_action = ActionRequest(
            category=ActionCategory.EXECUTE, tool_name="run", description="Run command"
        )
        assert execute_action.requires_confirmation is True

        create_action = ActionRequest(
            category=ActionCategory.CREATE, tool_name="touch", description="Create file"
        )
        assert create_action.requires_confirmation is True


class TestAutoAllowedActions:
    """Tests for actions that are auto-allowed."""

    async def test_read_action_auto_allowed(self):
        action = ActionRequest(
            category=ActionCategory.READ, tool_name="read_file", description="Read a file"
        )
        assert await validate_action(action) is True

    async def test_notify_action_auto_allowed(self):
        action = ActionRequest(
            category=ActionCategory.NOTIFY, tool_name="notify", description="Send notification"
        )
        assert await validate_action(action) is True

    async def test_create_action_requires_confirmation(self):
        action = ActionRequest(
            category=ActionCategory.CREATE, tool_name="touch", description="Create a file"
        )
        assert await validate_action(action) is False


class TestConfirmationRequired:
    """Tests for actions that require confirmation."""

    async def test_delete_requires_confirmation(self):
        action = ActionRequest(
            category=ActionCategory.DELETE, tool_name="rm", description="Delete a file"
        )
        assert await validate_action(action) is False

    async def test_send_requires_confirmation(self):
        action = ActionRequest(
            category=ActionCategory.SEND, tool_name="email", description="Send an email"
        )
        assert await validate_action(action) is False

    async def test_execute_requires_confirmation(self):
        action = ActionRequest(
            category=ActionCategory.EXECUTE, tool_name="run", description="Run a command"
        )
        assert await validate_action(action) is False

    async def test_delete_confirmed(self):
        action = ActionRequest(
            category=ActionCategory.DELETE, tool_name="rm", description="Delete a file"
        )
        callback = AsyncMock(return_value=True)
        assert await validate_action(action, confirm_callback=callback) is True
        callback.assert_called_once()

    async def test_delete_rejected(self):
        action = ActionRequest(
            category=ActionCategory.DELETE, tool_name="rm", description="Delete a file"
        )
        callback = AsyncMock(return_value=False)
        assert await validate_action(action, confirm_callback=callback) is False
        callback.assert_called_once()
