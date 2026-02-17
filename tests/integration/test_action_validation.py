"""Integration tests for human-in-the-loop action validation."""

from unittest.mock import AsyncMock

from llm_io_guard.actions import (
    AUTO_ALLOWED,
    REQUIRES_CONFIRMATION,
    ActionCategory,
    ActionRequest,
    validate_action,
)


class TestActionRequestCreation:
    """Test ActionRequest construction and auto-confirmation detection."""

    def test_read_action_no_confirmation(self):
        """READ actions should not require confirmation."""
        action = ActionRequest(
            category=ActionCategory.READ,
            tool_name="read_file",
            description="Read customer data",
        )
        assert action.requires_confirmation is False

    def test_notify_action_no_confirmation(self):
        """NOTIFY actions should not require confirmation."""
        action = ActionRequest(
            category=ActionCategory.NOTIFY,
            tool_name="send_notification",
            description="Send status update",
        )
        assert action.requires_confirmation is False

    def test_delete_action_requires_confirmation(self):
        """DELETE actions should require confirmation."""
        action = ActionRequest(
            category=ActionCategory.DELETE,
            tool_name="delete_record",
            description="Delete customer record #123",
        )
        assert action.requires_confirmation is True

    def test_send_action_requires_confirmation(self):
        """SEND actions should require confirmation."""
        action = ActionRequest(
            category=ActionCategory.SEND,
            tool_name="send_email",
            description="Send email to customer",
        )
        assert action.requires_confirmation is True

    def test_execute_action_requires_confirmation(self):
        """EXECUTE actions should require confirmation."""
        action = ActionRequest(
            category=ActionCategory.EXECUTE,
            tool_name="run_script",
            description="Execute cleanup script",
        )
        assert action.requires_confirmation is True

    def test_create_action_no_confirmation(self):
        """CREATE actions should not require confirmation (not in REQUIRES_CONFIRMATION)."""
        action = ActionRequest(
            category=ActionCategory.CREATE,
            tool_name="create_record",
            description="Create new record",
        )
        assert action.requires_confirmation is False

    def test_modify_action_no_confirmation(self):
        """MODIFY actions should not require confirmation."""
        action = ActionRequest(
            category=ActionCategory.MODIFY,
            tool_name="update_record",
            description="Update record field",
        )
        assert action.requires_confirmation is False


class TestValidateActionAutoAllowed:
    """Test validate_action with auto-allowed categories."""

    async def test_read_auto_allowed(self):
        """READ actions should be auto-allowed without callback."""
        action = ActionRequest(
            category=ActionCategory.READ,
            tool_name="read_data",
            description="Read records",
        )
        result = await validate_action(action)
        assert result is True

    async def test_notify_auto_allowed(self):
        """NOTIFY actions should be auto-allowed without callback."""
        action = ActionRequest(
            category=ActionCategory.NOTIFY,
            tool_name="notify",
            description="Send notification",
        )
        result = await validate_action(action)
        assert result is True


class TestValidateActionWithConfirmation:
    """Test validate_action with actions requiring confirmation."""

    async def test_delete_blocked_without_callback(self):
        """DELETE action without callback should be blocked."""
        action = ActionRequest(
            category=ActionCategory.DELETE,
            tool_name="delete_file",
            description="Delete important file",
        )
        result = await validate_action(action, confirm_callback=None)
        assert result is False

    async def test_delete_approved_with_callback(self):
        """DELETE action approved by callback should return True."""
        callback = AsyncMock(return_value=True)
        action = ActionRequest(
            category=ActionCategory.DELETE,
            tool_name="delete_record",
            description="Delete record #456",
        )
        result = await validate_action(action, confirm_callback=callback)
        assert result is True
        callback.assert_called_once()

    async def test_delete_rejected_with_callback(self):
        """DELETE action rejected by callback should return False."""
        callback = AsyncMock(return_value=False)
        action = ActionRequest(
            category=ActionCategory.DELETE,
            tool_name="delete_record",
            description="Delete record #789",
        )
        result = await validate_action(action, confirm_callback=callback)
        assert result is False
        callback.assert_called_once()

    async def test_send_approved_with_callback(self):
        """SEND action approved by callback should return True."""
        callback = AsyncMock(return_value=True)
        action = ActionRequest(
            category=ActionCategory.SEND,
            tool_name="send_email",
            description="Send email to client",
        )
        result = await validate_action(action, confirm_callback=callback)
        assert result is True

    async def test_execute_blocked_without_callback(self):
        """EXECUTE action without callback should be blocked."""
        action = ActionRequest(
            category=ActionCategory.EXECUTE,
            tool_name="run_command",
            description="Execute system command",
        )
        result = await validate_action(action, confirm_callback=None)
        assert result is False

    async def test_callback_receives_description(self):
        """Callback should receive a message with the action description."""
        received_messages = []

        async def capture_callback(msg: str) -> bool:
            received_messages.append(msg)
            return True

        action = ActionRequest(
            category=ActionCategory.SEND,
            tool_name="send_email",
            description="Send quarterly report",
        )
        await validate_action(action, confirm_callback=capture_callback)
        assert len(received_messages) == 1
        assert "Send quarterly report" in received_messages[0]
        assert "send_email" in received_messages[0]


class TestValidateActionMiddleTier:
    """Test validate_action with CREATE/MODIFY categories (auto-allowed, not in AUTO_ALLOWED)."""

    async def test_create_auto_allowed_without_callback(self):
        """CREATE action should be auto-allowed even without callback."""
        action = ActionRequest(
            category=ActionCategory.CREATE,
            tool_name="create_ticket",
            description="Create support ticket",
        )
        result = await validate_action(action)
        assert result is True

    async def test_modify_auto_allowed_without_callback(self):
        """MODIFY action should be auto-allowed even without callback."""
        action = ActionRequest(
            category=ActionCategory.MODIFY,
            tool_name="update_status",
            description="Update ticket status",
        )
        result = await validate_action(action)
        assert result is True


class TestActionCategoryConstants:
    """Test that the category constants are correctly defined."""

    def test_requires_confirmation_set(self):
        """Verify REQUIRES_CONFIRMATION contains the right categories."""
        assert ActionCategory.DELETE in REQUIRES_CONFIRMATION
        assert ActionCategory.SEND in REQUIRES_CONFIRMATION
        assert ActionCategory.EXECUTE in REQUIRES_CONFIRMATION
        assert ActionCategory.READ not in REQUIRES_CONFIRMATION

    def test_auto_allowed_set(self):
        """Verify AUTO_ALLOWED contains the right categories."""
        assert ActionCategory.READ in AUTO_ALLOWED
        assert ActionCategory.NOTIFY in AUTO_ALLOWED
        assert ActionCategory.DELETE not in AUTO_ALLOWED
